//! Module handling the recursive proving of mapping entries specically
//! inside a storage trie.

use crate::{
    array::{Array, Vector, VectorWire},
    eth::left_pad32,
    group_hashing::{self, CircuitBuilderGroupHashing},
    keccak::{
        ByteKeccakWires, InputData, KeccakCircuit, KeccakWires, OutputHash, HASH_LEN,
        PACKED_HASH_LEN,
    },
    mpt_sequential::{Circuit as MPTCircuit, MPTKeyWire, PAD_LEN},
    rlp::{decode_fixed_list, MAX_ITEMS_IN_LIST, MAX_KEY_NIBBLE_LEN},
    utils::{convert_u8_targets_to_u32, keccak256},
};
use core::array::from_fn as create_array;
use ethers::types::spoof::Storage;
use plonky2::{
    field::{extension::Extendable, goldilocks_field::GoldilocksField, types::Field},
    hash::{
        hash_types::{RichField, NUM_HASH_OUT_ELTS},
        keccak,
    },
    iop::{
        target::{BoolTarget, Target},
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::circuit_builder::CircuitBuilder,
};
use plonky2_crypto::u32::arithmetic_u32::U32Target;
use plonky2_ecgfp5::gadgets::curve::CircuitBuilderEcGFp5;
use plonky2_ecgfp5::gadgets::{base_field::QuinticExtensionTarget, curve::CurveTarget};

pub struct BranchCircuit<const NODE_LEN: usize, const N_CHILDRENS: usize> {}

// This is a wrapper around an array of targets set as public inputs
// of any proof generated in this module. They all share the same
// structure.
// `K` Full key for a leaf inside this subtree
// `T` Index of the part “processed” on the full key
// `S`  storage slot of the mapping
// `n` number of items seen so far up to this node
// `C` MPT root (of the current node)
// `D` Accumulator digest of the values
// K = 64, T = 1, S = 1, n = 1, C = 4, D = 5*2
// total = 81
pub struct PublicInputs<'a> {
    proof_inputs: &'a [Target],
}

impl<'a> PublicInputs<'a> {
    const MAX_ELEMENTS: usize = 81;
    const KEY_IDX: usize = 0;
    const T_IDX: usize = 64;
    const S_IDX: usize = 65;
    const N_IDX: usize = 66;
    const C_IDX: usize = 67;
    const D_IDX: usize = 71;
    pub fn from(arr: &'a [Target]) -> Self {
        Self { proof_inputs: arr }
    }

    pub fn register(
        b: &mut CircuitBuilder<GoldilocksField, 2>,
        key: &MPTKeyWire,
        slot: Target,
        n: Target,
        c: &OutputHash,
        d: &CurveTarget,
    ) {
        key.register_as_input(b);
        b.register_public_input(slot);
        b.register_public_input(n);
        c.register_as_input(b);
        b.register_curve_public_input(*d);
    }
    /// Returns the mapping slot used to prove the derivation of the
    /// MPT keys
    pub fn mapping_slot(&self) -> Target {
        self.proof_inputs[Self::S_IDX]
    }
    /// Returns the number of mapping leaf entries seen so
    /// far up to the givne node.
    pub fn n(&self) -> Target {
        self.proof_inputs[Self::N_IDX]
    }
    /// Returns the MPT key defined over the public inputs
    pub fn mpt_key(&self) -> MPTKeyWire {
        let key_range = Self::KEY_IDX..Self::KEY_IDX + MAX_KEY_NIBBLE_LEN;
        let key = &self.proof_inputs[key_range];
        let ptr_range = Self::T_IDX..Self::T_IDX + 1;
        let ptr = self.proof_inputs[ptr_range][0];
        MPTKeyWire {
            key: Array {
                arr: create_array(|i| key[i]),
            },
            pointer: ptr,
        }
    }
    /// Returns the accumulator digest defined over the public inputs
    pub fn accumulator(&self) -> CurveTarget {
        curve_target_from_slice(&self.proof_inputs[Self::D_IDX..])
    }
    /// Returns the merkle hash C of the subtree this proof has processed.
    pub fn root_hash(&self) -> OutputHash {
        // poseidon merkle root hash is 4 F elements
        let hash_range = Self::C_IDX..Self::C_IDX + PACKED_HASH_LEN;
        let hash = &self.proof_inputs[hash_range];
        Array::<U32Target, PACKED_HASH_LEN>::from_array(create_array(|i| U32Target(hash[i])))
    }
}

// small utility function to transform a list of target to a curvetarget.
// TODO: move that to ecgfp5 repo
fn curve_target_from_slice(slice: &[Target]) -> CurveTarget {
    const EXTENSION: usize = 5;
    // 5 F for each coordinates + 1 bool flag
    #[warn(clippy::int_plus_one)]
    assert!(slice.len() >= 5 * 2 + 1);
    let x = QuinticExtensionTarget(slice[0..EXTENSION].try_into().unwrap());
    let y = QuinticExtensionTarget(slice[EXTENSION..2 * EXTENSION].try_into().unwrap());
    let flag = BoolTarget::new_unsafe(slice[2 * EXTENSION]);
    CurveTarget(([x, y], flag))
}

/// Circuit implementing the circuit to prove the correct derivation of the
/// MPT key from a mapping key and mapping slot. It also do the usual recursive
/// MPT proof verification logic.
struct LeafCircuit<const NODE_LEN: usize> {
    node: Vec<u8>,
    slot: MappingSlot,
}

struct LeafWires<const NODE_LEN: usize>
where
    [(); PAD_LEN(NODE_LEN)]:,
{
    node: VectorWire<{ PAD_LEN(NODE_LEN) }>,
    mapping_slot: MappingSlotWires,
}
impl<const N: usize> LeafWires<N> {
    pub fn mapping_key(&self) -> Array<Target, MAPPING_KEY_LEN> {
        self.storage_wires.mapping_key
    }

    pub fn mapping_slot(&self) -> Target {
        self.mapping_slot.mapping_slot
    }
}

impl<const NODE_LEN: usize> LeafCircuit<NODE_LEN>
where
    [(); PAD_LEN(NODE_LEN)]:,
{
    pub fn build(b: &mut CircuitBuilder<GoldilocksField, 2>) -> LeafWires<NODE_LEN> {
        let zero = b.zero();
        let tru = b._true();
        let node = VectorWire::<{ PAD_LEN(NODE_LEN) }>::new(b);
        // always ensure theThanks all node is bytes at the beginning
        node.assert_bytes(b);

        // First expose the keccak root of this subtree starting at this node
        let root = KeccakCircuit::<{ PAD_LEN(NODE_LEN) }>::hash_vector(b, &node);

        // Then derives the correct MPT key from this (mappingkey,mappingslot) pair
        let mapping_slot_wires = MappingSlot::mpt_key(b);

        // Then advance the key and extract the value
        // only decode two headers in the case of leaf
        let rlp_headers = decode_fixed_list::<_, _, 2>(b, &node.arr.arr, zero);
        let (new_key, value, is_valid) = MPTCircuit::<1, NODE_LEN>::advance_key_leaf_or_extension(
            b,
            &node.arr,
            &mapping_slot_wires.mpt_key,
            &rlp_headers,
        );
        b.connect(tru.target, is_valid.target);
        // Then creates the initial accumulator from the (mapping_key, value)
        let mut inputs = [b.zero(); HASH_LEN * 2];
        inputs[0..HASH_LEN].copy_from_slice(&mapping_slot_wires.mapping_key().arr);
        inputs[HASH_LEN..2 * HASH_LEN].copy_from_slice(&value.arr);
        let leaf_accumulator = b.map_to_curve_point(&inputs);

        // and register the public inputs
        let n = b.one(); // only one leaf seen in that leaf !
        PublicInputs::register(
            b,
            &new_key,
            *mapping_slot_wires.mapping_slot(),
            n,
            &root.output_array,
            &leaf_accumulator,
        );
        LeafWires {
            node,
            mapping_slot: mapping_slot_wires,
        }
    }

    pub fn assign(&self, pw: &mut PartialWitness<GoldilocksField>, wires: &LeafWires<NODE_LEN>) {
        let pad_node = Vector::<{ PAD_LEN(NODE_LEN) }>::from_vec(self.node.clone())
            .expect("invalid node given");
        wires.node.assign(pw, &pad_node);
        wires.slot.assign(pw, &wires.mapping_slot);
    }
}

#[cfg(test)]
mod test {
    use eth_trie::Trie;

    use crate::{circuit::UserCircuit, mpt_sequential::test::generate_random_storage_mpt};

    use super::{LeafCircuit, LeafWires};

    impl<F, const D: usize, const NODE_LEN: usize> UserCircuit<F, D> for LeafCircuit<NODE_LEN> {
        type Wires = LeafWires;

        fn build(b: &mut CircuitBuilder<F, D>) -> Self::Wires {
            Self::build(b);
        }

        fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
            self.assign(pw, wires)
        }
    }

    #[test]
    fn test_leaf_circuit() {
        let mapping_key = hex::decode("1234").unwrap();
        let mapping_slot = 2;
        let slot = StorageSlot::Mapping(mapping_key.clone(), mapping_slot);
        let (mut trie, _) = generate_random_storage_mpt();
        let mut random_value = vec![0u8; 32];
        thread_rng().fill(&mut random_value);
        trie.insert(slot.mpt_key(), &random_value);
        trie.root_hash().unwrap();
        trie.get_proof(slot.mpt_key());
    }
}
