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

pub struct BranchWires<const NODE_LEN: usize>
where
    [(); PAD_LEN(NODE_LEN)]:,
{
    /// TODO replace by proof when we have the framework in place
    inputs: Vec<Target>,
    /// input node - right now only branch
    node: VectorWire<{ PAD_LEN(NODE_LEN) }>,
    /// key provided by prover as a "point of reference" to verify
    /// all children proofs's exposed keys
    common_prefix: MPTKeyWire,
}

impl<const NODE_LEN: usize, const N_CHILDREN: usize> BranchCircuit<NODE_LEN, N_CHILDREN>
where
    [(); PAD_LEN(NODE_LEN)]:,
    [(); HASH_LEN / 4]:,
    [(); HASH_LEN]:,
{
    pub fn build(b: &mut CircuitBuilder<GoldilocksField, 2>) {
        let inputs = (0..N_CHILDREN)
            .map(|_| b.add_virtual_targets(PublicInputs::MAX_ELEMENTS))
            .collect::<Vec<_>>();
        let node = VectorWire::<{ PAD_LEN(NODE_LEN) }>::new(b);
        // always ensure the node is bytes at the beginning
        node.assert_bytes(b);
        // WIll be exposed as common prefix. We need to make sure all children proofs share the same common prefix
        let common_prefix = MPTKeyWire::new(b);
        // mapping slot will be exposed as public input. Need to make sure all
        // children proofs are valid with respect to the same mapping slot.
        let mapping_slot = b.add_virtual_target();

        let one = b.one();
        let zero = b.zero();
        let tru = b._true();
        // First expose the keccak root of this subtree starting at this node
        let root = KeccakCircuit::<{ PAD_LEN(NODE_LEN) }>::hash_vector(b, &node);

        // Then do the work for each children proofs
        // accumulator being the addition of all children accumulator
        let mut accumulator = b.curve_zero();
        // n being the total number of entries recursively verified
        let mut n = b.zero();
        // we already decode the rlp headers here since we need it to verify
        // the validity of the hash exposed by the proofs
        let headers = decode_fixed_list::<_, _, MAX_ITEMS_IN_LIST>(b, &node.arr.arr, zero);
        for i in 0..N_CHILDREN {
            let proof_inputs = PublicInputs::from(&inputs[i]);
            let child_accumulator = proof_inputs.accumulator();
            accumulator = b.curve_add(accumulator, child_accumulator);
            // add the number of leaves this proof has processed
            n = b.add(n, proof_inputs.n());
            let child_key = proof_inputs.mpt_key();
            let (new_key, hash, is_valid) =
                MPTCircuit::<1, NODE_LEN>::advance_key_branch(b, &node.arr, &child_key, &headers);
            // we always enforce it's a branch node
            // TODO: this is a redundant check and should be moved out from ^
            b.connect(is_valid.target, tru.target);
            // we check the hash is the one exposed by the proof
            // first convert the extracted hash to packed one to compare
            let packed_hash = Array::<U32Target, PACKED_HASH_LEN> {
                arr: convert_u8_targets_to_u32(b, &hash.arr).try_into().unwrap(),
            };
            let child_hash = proof_inputs.root_hash();
            let hash_equals = packed_hash.equals(b, &child_hash);
            b.connect(hash_equals.target, tru.target);
            // we now check that the MPT key at this point is equal to the one given
            // by the prover. Reason why it is secure is because this circuit only cares
            // that _all_ keys share the _same_ prefix, so if they're all equal
            // to `common_prefix`, they're all equal.
            let have_common_prefix = common_prefix.is_prefix_equal(b, &new_key);
            b.connect(have_common_prefix.target, tru.target);
            // We also check proof is valid for the _same_ mapping slot
            b.connect(mapping_slot, proof_inputs.mapping_slot());
        }

        // we now extract the public input to register for this proofs
        let c = root.output_array;
        PublicInputs::register(b, &common_prefix, mapping_slot, n, &c, &accumulator);
    }
}

struct LeafCircuit<const NODE_LEN: usize> {
    node: Vec<u8>,
}

struct LeafWires<const NODE_LEN: usize>
where
    [(); PAD_LEN(NODE_LEN)]:,
{
    node: VectorWire<{ PAD_LEN(NODE_LEN) }>,
    mapping_key: Array<Target, MAPPING_KEY_LEN>,
    mapping_slot: Target,
    storage_wires: MappingSlotWires,
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
        let (mapping_key, mapping_slot) = (
            &mapping_slot_wires.mapping_key,
            &mapping_slot_wires.mapping_slot,
        );

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
        inputs[0..HASH_LEN].copy_from_slice(&mapping_key.arr);
        inputs[HASH_LEN..2 * HASH_LEN].copy_from_slice(&value.arr);
        let leaf_accumulator = b.map_to_curve_point(&inputs);

        // and register the public inputs
        let n = b.one(); // only one leaf seen in that leaf !
        PublicInputs::register(
            b,
            &new_key,
            *mapping_slot,
            n,
            &root.output_array,
            &leaf_accumulator,
        );
        LeafWires {
            node,
            mapping_key: mapping_key.clone(),
            mapping_slot: *mapping_slot,
            storage_wires: mapping_slot_wires,
        }
    }

    pub fn assign(&self, pw: &mut PartialWitness<GoldilocksField>, wires: &LeafWires<NODE_LEN>) {
        let pad_node = Vector::<{ PAD_LEN(NODE_LEN) }>::from_vec(self.node.clone())
            .expect("invalid node given");
    }
}

/// Circuit gadget that proves the correct derivation of a MPT key from a given mapping slot and storage slot.
/// Deriving a MPT key from mapping slot is done like:
/// 1. location = keccak(left_pad32(key), left_pad32(slot))
/// 2. mpt_key = keccak(location)
/// WARNING: Currently takes the assumption that the storage slot number fits inside a single byte.
#[derive(Clone, Debug)]
struct MappingSlot {
    mapping_slot: u8,
    mapping_key: Vec<u8>,
}

/// Contains the wires associated with the storage slot's mpt key
/// derivation logic.
/// NOTE: currently specific only for mapping slots.
struct MappingSlotWires {
    /// "input" mapping key which is maxed out at 32 bytes
    mapping_key: Array<Target, MAPPING_KEY_LEN>,
    /// "input" mapping slot which is assumed to fit in a single byte
    mapping_slot: Target,
    /// Actual keccak wires created for the computation of the "location"
    /// for the mapping storage slot
    keccak_location: ByteKeccakWires<MAPPING_INPUT_PADDED_LEN>,
    /// Actual keccak wires created for the computation of the final MPT key
    /// from the location. THIS is the one to use to look up a key in the
    /// associated MPT trie
    keccak_mpt: ByteKeccakWires<{ PAD_LEN(HASH_LEN) }>,
    /// The MPT key derived in circuit from the storage slot, in NIBBLES
    /// TODO: it represents the same information as "exp" but in nibbles.
    /// It doesn't need to be assigned, but is used in the higher level circuits
    mpt_key: MPTKeyWire,
}

/// Maximum size of the key for a mapping
const MAPPING_KEY_LEN: usize = 32;
const MAPPING_INPUT_TOTAL_LEN: usize = 2 * MAPPING_KEY_LEN;
/// Value but with the padding taken into account.
const MAPPING_INPUT_PADDED_LEN: usize = PAD_LEN(MAPPING_INPUT_TOTAL_LEN);
impl MappingSlot {
    /// Derives the mpt_key in circuit according to which type of storage slot
    /// Remember the rules to get the mpt key is as follow:
    /// * location = keccak256(pad32(mapping_key), pad32(mapping_slot))
    /// * mpt_key = keccak256(path)
    pub fn mpt_key<F: RichField + Extendable<D>, const D: usize>(
        b: &mut CircuitBuilder<F, D>,
    ) -> MappingSlotWires {
        let mapping_key = Array::<Target, MAPPING_KEY_LEN>::new(b);
        // always ensure whatever goes into hash function, it's bytes
        //mapping_key.assert_bytes(b);
        let mapping_slot = b.add_virtual_target();
        let mut input = [b.zero(); MAPPING_INPUT_PADDED_LEN];
        input[0..MAPPING_KEY_LEN].copy_from_slice(&mapping_key.arr);
        input[2 * MAPPING_KEY_LEN - 1] = mapping_slot;

        // keccak(left_pad32(mapping_key), left_pad32(mapping_slot))
        let vector = VectorWire::<MAPPING_INPUT_PADDED_LEN> {
            real_len: b.constant(F::from_canonical_usize(MAPPING_INPUT_TOTAL_LEN)),
            arr: Array { arr: input },
        };
        let keccak_location =
            KeccakCircuit::<{ MAPPING_INPUT_PADDED_LEN }>::hash_to_bytes(b, &vector);
        // keccak ( location ) - take the output and copy it in a slice large enough for padding
        let mut padded_location = [b.zero(); PAD_LEN(HASH_LEN)];
        padded_location[0..HASH_LEN].copy_from_slice(&keccak_location.output.arr);
        // TODO : make nice APIs for that in array.rs
        let hash_len = b.constant(F::from_canonical_usize(HASH_LEN));
        let keccak_mpt = KeccakCircuit::<{ PAD_LEN(HASH_LEN) }>::hash_to_bytes(
            b,
            &VectorWire {
                real_len: hash_len,
                arr: Array {
                    arr: padded_location,
                },
            },
        );

        // make sure we transform from the bytes to the nibbles
        // TODO: actually maybe better to give the nibbles directly and pack them into U32
        // in one go. For the future...
        let mpt_key = MPTKeyWire::init_from_bytes(b, &keccak_mpt.output);
        MappingSlotWires {
            mapping_key,
            mapping_slot,
            keccak_location,
            keccak_mpt,
            mpt_key,
        }
    }
    pub fn assign<F: RichField>(&self, pw: &mut PartialWitness<F>, wires: &MappingSlotWires) {
        // first assign the "inputs"
        let padded_mkey = left_pad32(&self.mapping_key);
        let padded_slot = left_pad32(&[self.mapping_slot]);
        // the "padding" is done in circuit for slot
        pw.set_target(wires.mapping_slot, F::from_canonical_u8(self.mapping_slot));
        // already give 32 bytes for the mapping key
        wires.mapping_key.assign_bytes(pw, &padded_mkey);
        // Then compute the entire expected array to derive the mpt key
        // H ( pad32(mapping_key), pad32(mapping_slot))
        let input = padded_mkey
            .into_iter()
            .chain(padded_slot)
            .collect::<Vec<_>>();
        // then compute the expected resulting hash for mpt key derivation.
        let exp_location = keccak256(&input);
        // assign the keccak necessary values for keccak_location
        KeccakCircuit::<{ MAPPING_INPUT_PADDED_LEN }>::assign_byte_keccak(
            pw,
            &wires.keccak_location,
            // no need to create a new input wire array since we create it in circuit
            &InputData::Assigned(
                &Vector::from_vec(input).expect("can't create vector input for keccak_location"),
            ),
        );
        // assign the keccak necessary values for keccak_mpt = H(keccak_location)
        KeccakCircuit::<{ PAD_LEN(HASH_LEN) }>::assign_byte_keccak(
            pw,
            &wires.keccak_mpt,
            &InputData::Assigned(
                &Vector::from_vec(exp_location).expect("can't create vector input for keccak_mpt"),
            ),
        )
    }
}

#[cfg(test)]
mod test {
    use std::array::from_fn as create_array;

    use plonky2::{
        field::extension::Extendable,
        hash::hash_types::RichField,
        iop::{target::Target, witness::PartialWitness},
        plonk::{
            circuit_builder::CircuitBuilder,
            config::{GenericConfig, PoseidonGoldilocksConfig},
        },
    };

    use crate::{
        array::Array,
        circuit::{test::test_simple_circuit, UserCircuit},
        eth::StorageSlot,
        keccak::HASH_LEN,
        mpt_sequential::bytes_to_nibbles,
        rlp::MAX_KEY_NIBBLE_LEN,
    };

    use super::{MappingSlot, MappingSlotWires};

    #[derive(Clone, Debug)]
    struct TestMappingSlot {
        m: MappingSlot,
        // 64 nibbles
        exp_mpt_key_nibbles: Vec<u8>,
        exp_keccak_location: Vec<u8>,
    }
    impl<F, const D: usize> UserCircuit<F, D> for TestMappingSlot
    where
        F: RichField + Extendable<D>,
    {
        type Wires = (MappingSlotWires, Array<Target, MAX_KEY_NIBBLE_LEN>);

        fn build(b: &mut CircuitBuilder<F, D>) -> Self::Wires {
            let mapping_slot_wires = MappingSlot::mpt_key(b);
            let exp_key = Array::<Target, MAX_KEY_NIBBLE_LEN>::new(b);
            let good_key = mapping_slot_wires.mpt_key.key.equals(b, &exp_key);
            let tru = b._true();
            //b.connect(tru.target, good_key.target);
            let exp_keccak_location = Array::<Target, HASH_LEN>::new(b);
            let good_keccak_location = mapping_slot_wires
                .keccak_location
                .output
                .equals(b, &exp_keccak_location);
            //b.connect(tru.target, good_keccak_location.target);
            (mapping_slot_wires, exp_key)
        }

        fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
            // assign the expected mpt key we should see
            wires.1.assign(
                pw,
                &create_array(|i| F::from_canonical_u8(self.exp_mpt_key_nibbles[i])),
            );
            self.m.assign(pw, &wires.0);
        }
    }

    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    #[test]
    fn test_mapping_slot_key_derivation() {
        let mapping_key = hex::decode("1234").unwrap();
        let mapping_slot = 2;
        let slot = StorageSlot::Mapping(mapping_key.clone(), mapping_slot);
        let mpt_key = slot.mpt_key();
        let circuit = TestMappingSlot {
            m: MappingSlot {
                mapping_key,
                mapping_slot: mapping_slot as u8,
            },
            exp_mpt_key_nibbles: bytes_to_nibbles(&mpt_key),
            exp_keccak_location: slot.location().as_bytes().to_vec(),
        };
        test_simple_circuit::<F, D, C, _>(circuit);
    }
}
