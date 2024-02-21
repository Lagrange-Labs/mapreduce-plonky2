//! Module handling the recursive proving of mapping entries specically
//! inside a storage trie.

use crate::mpt_sequential::MAX_LEAF_VALUE_LEN;
use crate::storage::key::MappingSlotWires;
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
use plonky2::field::extension::quintic::QuinticExtension;
use plonky2::field::extension::FieldExtension;
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
use plonky2_ecgfp5::curve::curve::WeierstrassPoint;
use plonky2_ecgfp5::gadgets::curve::CircuitBuilderEcGFp5;
use plonky2_ecgfp5::gadgets::{base_field::QuinticExtensionTarget, curve::CurveTarget};

use super::key::{MappingSlot, MAPPING_KEY_LEN};

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
pub struct PublicInputs<'a, T> {
    proof_inputs: &'a [T],
}

impl<'a> PublicInputs<'a, Target> {
    pub fn register(
        b: &mut CircuitBuilder<GoldilocksField, 2>,
        key: &MPTKeyWire,
        slot: Target,
        n: Target,
        c: &OutputHash,
        d: &CurveTarget,
    ) {
        b.register_curve_public_input(*d);
        key.register_as_input(b);
        b.register_public_input(slot);
        b.register_public_input(n);
        c.register_as_input(b);
    }
    /// Returns the MPT key defined over the public inputs
    pub fn mpt_key(&self) -> MPTKeyWire {
        let (key, ptr) = self.mpt_key_info();
        MPTKeyWire {
            key: Array {
                arr: create_array(|i| key[i]),
            },
            pointer: ptr,
        }
    }
    /// Returns the accumulator digest defined over the public inputs
    // TODO: move that to ecgfp5 repo
    pub fn accumulator(&self) -> CurveTarget {
        let (x, y, is_inf) = self.accumulator_info();
        let x = QuinticExtensionTarget(x);
        let y = QuinticExtensionTarget(y);
        let flag = BoolTarget::new_unsafe(is_inf);
        CurveTarget(([x, y], flag))
    }

    /// Returns the merkle hash C of the subtree this proof has processed.
    pub fn root_hash(&self) -> OutputHash {
        let hash = self.root_hash_info();
        Array::<U32Target, PACKED_HASH_LEN>::from_array(create_array(|i| U32Target(hash[i])))
    }
}
impl<'a> PublicInputs<'a, GoldilocksField> {
    /// Returns the accumulator digest defined over the public inputs
    pub fn accumulator(&self) -> WeierstrassPoint {
        // TODO: put that in ecgfp5 crate publicly
        pub(crate) type GFp5 = QuinticExtension<GoldilocksField>;
        let ptr = Self::D_IDX;
        let (x, y, is_inf) = self.accumulator_info();
        WeierstrassPoint {
            x: GFp5::from_basefield_array(create_array::<GoldilocksField, 5, _>(|i| x[i])),
            y: GFp5::from_basefield_array(create_array::<GoldilocksField, 5, _>(|i| y[i])),
            is_inf: is_inf.is_nonzero(),
        }
    }
    // Returns in packed representation
    pub fn root_hash(&self) -> Vec<u32> {
        let hash = self.root_hash_info();
        hash.iter().map(|t| t.0 as u32).collect()
    }
}
impl<'a, T: Copy> PublicInputs<'a, T> {
    const D_IDX: usize = 0; // 5F for each coordinates + 1 bool flag
    const KEY_IDX: usize = 11; // 64 nibbles
    const T_IDX: usize = 75; // 1 index
    const S_IDX: usize = 76; // 1 index
    const N_IDX: usize = 77; // 1 index
    const C_IDX: usize = 78; // packed hash = 4 F elements
    const EXTENSION: usize = 5;
    pub fn from(arr: &'a [T]) -> Self {
        Self { proof_inputs: arr }
    }

    // small utility function to transform a list of target to a curvetarget.
    fn accumulator_info(&self) -> ([T; 5], [T; 5], T) {
        // 5 F for each coordinates + 1 bool flag
        let slice = &self.proof_inputs[Self::D_IDX..];
        #[allow(clippy::int_plus_one)]
        let within_bound = slice.len() >= 5 * 2 + 1;
        assert!(within_bound);
        let x = slice[0..Self::EXTENSION].try_into().unwrap();
        let y = slice[Self::EXTENSION..2 * Self::EXTENSION]
            .try_into()
            .unwrap();
        let flag = slice[2 * Self::EXTENSION];
        (x, y, flag)
    }
    fn mpt_key_info(&self) -> (&[T], T) {
        let key_range = Self::KEY_IDX..Self::KEY_IDX + MAX_KEY_NIBBLE_LEN;
        let key = &self.proof_inputs[key_range];
        let ptr_range = Self::T_IDX..Self::T_IDX + 1;
        let ptr = self.proof_inputs[ptr_range][0];
        (key, ptr)
    }
    fn root_hash_info(&self) -> &[T] {
        // poseidon merkle root hash is 4 F elements
        let hash_range = Self::C_IDX..Self::C_IDX + PACKED_HASH_LEN;
        &self.proof_inputs[hash_range]
    }
    /// Returns the mapping slot used to prove the derivation of the
    /// MPT keys
    pub fn mapping_slot(&self) -> T {
        self.proof_inputs[Self::S_IDX]
    }
    /// Returns the number of mapping leaf entries seen so
    /// far up to the givne node.
    pub fn n(&self) -> T {
        self.proof_inputs[Self::N_IDX]
    }
}

/// Circuit implementing the circuit to prove the correct derivation of the
/// MPT key from a mapping key and mapping slot. It also do the usual recursive
/// MPT proof verification logic.
#[derive(Clone, Debug)]
struct LeafCircuit<const NODE_LEN: usize> {
    node: Vec<u8>,
    slot: MappingSlot,
}

struct LeafWires<const NODE_LEN: usize>
where
    [(); PAD_LEN(NODE_LEN)]:,
{
    node: VectorWire<{ PAD_LEN(NODE_LEN) }>,
    root: KeccakWires<{ PAD_LEN(NODE_LEN) }>,
    mapping_slot: MappingSlotWires,
    value: Array<Target, MAX_LEAF_VALUE_LEN>,
}
impl<const N: usize> LeafWires<N>
where
    [(); PAD_LEN(N)]:,
{
    pub fn mapping_key(&self) -> Array<Target, MAPPING_KEY_LEN> {
        self.mapping_slot.mapping_key.clone()
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
        inputs[0..HASH_LEN].copy_from_slice(&mapping_slot_wires.mapping_key.arr);
        inputs[HASH_LEN..2 * HASH_LEN].copy_from_slice(&value.arr);
        let leaf_accumulator = b.map_to_curve_point(&inputs);

        // and register the public inputs
        let n = b.one(); // only one leaf seen in that leaf !
        PublicInputs::register(
            b,
            &new_key,
            mapping_slot_wires.mapping_slot,
            n,
            &root.output_array,
            &leaf_accumulator,
        );
        LeafWires {
            node,
            root,
            mapping_slot: mapping_slot_wires,
            value,
        }
    }

    pub fn assign(&self, pw: &mut PartialWitness<GoldilocksField>, wires: &LeafWires<NODE_LEN>) {
        let pad_node = Vector::<{ PAD_LEN(NODE_LEN) }>::from_vec(self.node.clone())
            .expect("invalid node given");
        wires.node.assign(pw, &pad_node);
        KeccakCircuit::<{ PAD_LEN(NODE_LEN) }>::assign(
            pw,
            &wires.root,
            &InputData::Assigned(&pad_node),
        );
        self.slot.assign(pw, &wires.mapping_slot);
    }
}

#[cfg(test)]
mod test {
    use std::array::from_fn as create_array;

    use crate::rlp::MAX_KEY_NIBBLE_LEN;
    use crate::utils::keccak256;
    use eth_trie::{Nibbles, Trie};
    use plonky2::field::goldilocks_field::GoldilocksField;
    use plonky2::iop::target::Target;
    use plonky2::iop::witness::{PartialWitness, WitnessWrite};
    use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
    use plonky2::{
        field::extension::Extendable, hash::hash_types::RichField,
        plonk::circuit_builder::CircuitBuilder,
    };
    use plonky2_crypto::u32::arithmetic_u32::U32Target;
    use plonky2_ecgfp5::curve::curve::WeierstrassPoint;
    use plonky2_ecgfp5::gadgets::curve::CurveTarget;
    use rand::{thread_rng, Rng};
    use rlp::Rlp;

    use super::{LeafCircuit, LeafWires, PublicInputs};
    use crate::array::Array;
    use crate::circuit::test::run_circuit;
    use crate::eth::{left_pad32, StorageSlot};
    use crate::group_hashing::{map_to_curve_point, CircuitBuilderGroupHashing};
    use crate::keccak::PACKED_HASH_LEN;
    use crate::mpt_sequential::{bytes_to_nibbles, MPTKeyWire, MAX_LEAF_VALUE_LEN};
    use crate::storage::key::MappingSlot;
    use crate::storage::mapping::PAD_LEN;
    use crate::utils::convert_u8_to_u32_slice;
    use crate::utils::test::random_vector;
    use crate::{circuit::UserCircuit, mpt_sequential::test::generate_random_storage_mpt};
    use plonky2::field::types::Field;
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    #[derive(Clone, Debug)]
    struct TestPublicInputs {
        key: Vec<u8>,
        ptr: usize,
        slot: usize,
        n: usize,
        c: Vec<u32>,
    }

    impl UserCircuit<F, D> for TestPublicInputs {
        type Wires = (
            MPTKeyWire,
            Target,
            Target,
            Array<U32Target, PACKED_HASH_LEN>,
            CurveTarget,
        );
        fn build(b: &mut CircuitBuilder<F, D>) -> Self::Wires {
            let key = MPTKeyWire::new(b);
            let slot = b.add_virtual_target();
            let n = b.add_virtual_target();
            let c = Array::<U32Target, PACKED_HASH_LEN>::new(b);
            let one = b.one();
            let accumulator = b.map_to_curve_point(&[one]);
            PublicInputs::register(b, &key, slot, n, &c, &accumulator);
            (key, slot, n, c, accumulator)
        }

        fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
            wires
                .0
                .assign(pw, &self.key.clone().try_into().unwrap(), self.ptr);
            pw.set_target(wires.1, F::from_canonical_usize(self.slot));
            pw.set_target(wires.2, F::from_canonical_usize(self.n));
            wires
                .3
                .assign(pw, &create_array(|i| F::from_canonical_u32(self.c[i])));
        }
    }
    #[test]
    fn test_public_inputs() {
        let p = map_to_curve_point(&[F::ONE]).to_weierstrass();
        let key = random_vector::<u8>(64);
        let ptr = 2;
        let slot = 3;
        let n = 4;
        let c = random_vector::<u32>(8);
        let test = TestPublicInputs {
            key: key.clone(),
            ptr,
            slot,
            n,
            c: c.clone(),
        };
        let proof = run_circuit::<F, D, C, _>(test);
        let pi = PublicInputs::<F>::from(&proof.public_inputs);
        {
            let (found_key, found_ptr) = pi.mpt_key_info();
            let key = key
                .iter()
                .cloned()
                .map(F::from_canonical_u8)
                .collect::<Vec<_>>();
            let ptr = F::from_canonical_usize(ptr);
            assert_eq!(found_key, key);
            assert_eq!(found_ptr, ptr);
        }
        {
            let found_slot = pi.mapping_slot();
            assert_eq!(found_slot, F::from_canonical_usize(slot));
        }
        {
            let found_n = pi.n();
            assert_eq!(found_n, F::from_canonical_usize(n));
        }
        {
            let found_c = pi.root_hash();
            assert_eq!(found_c, c);
        }
        {
            let found_p = pi.accumulator();
            assert_eq!(found_p, p);
        }
    }

    #[derive(Clone, Debug)]
    struct TestLeafCircuit<const NODE_LEN: usize> {
        c: LeafCircuit<NODE_LEN>,
        exp_value: Vec<u8>,
    }
    impl<const NODE_LEN: usize> UserCircuit<F, D> for TestLeafCircuit<NODE_LEN>
    where
        [(); PAD_LEN(NODE_LEN)]:,
    {
        // normal wires + expected extracted value
        type Wires = (LeafWires<NODE_LEN>, Array<Target, MAX_LEAF_VALUE_LEN>);

        fn build(b: &mut CircuitBuilder<F, D>) -> Self::Wires {
            let exp_value = Array::<Target, MAX_LEAF_VALUE_LEN>::new(b);
            let leaf_wires = LeafCircuit::<NODE_LEN>::build(b);
            let eq = leaf_wires.value.equals(b, &exp_value);
            let tt = b._true();
            b.connect(tt.target, eq.target);
            (leaf_wires, exp_value)
        }

        fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
            self.c.assign(pw, &wires.0);
            wires
                .1
                .assign_bytes(pw, &self.exp_value.clone().try_into().unwrap());
        }
    }

    #[test]
    fn test_leaf_circuit() {
        let mapping_key = hex::decode("1234").unwrap();
        let mapping_slot = 2;
        let slot = StorageSlot::Mapping(mapping_key.clone(), mapping_slot);
        let (mut trie, _) = generate_random_storage_mpt::<3, 32>();
        let mut random_value = [0u8; 32];
        thread_rng().fill(&mut random_value);
        trie.insert(&slot.mpt_key(), &random_value).unwrap();
        trie.root_hash().unwrap();
        let proof = trie.get_proof(&slot.mpt_key()).unwrap();
        let node = proof.last().unwrap().clone(); // proof from RPC gives leaf as last
        let mpt_key = slot.mpt_key();
        let slot = MappingSlot::new(mapping_slot as u8, mapping_key.clone());
        let circuit = LeafCircuit::<80> {
            node: node.clone(),
            slot,
        };
        let test = TestLeafCircuit {
            c: circuit,
            exp_value: random_value.to_vec(),
        };
        let proof = run_circuit::<F, D, C, _>(test);
        let pi = PublicInputs::<F>::from(&proof.public_inputs);
        {
            // expected accumulator Acc((mappping_key,value))
            let inputs_field = left_pad32(&mapping_key)
                .into_iter()
                .chain(left_pad32(&random_value))
                .map(F::from_canonical_u8)
                .collect::<Vec<_>>();
            let exp_accumulator = map_to_curve_point(&inputs_field).to_weierstrass();
            let found_accumulator = pi.accumulator();
            assert_eq!(exp_accumulator, found_accumulator);
        }
        {
            // expected MPT hash
            let exp_hash = keccak256(&node);
            let found_hash = pi.root_hash();
            let exp_packed = convert_u8_to_u32_slice(&exp_hash);
            assert_eq!(exp_packed, found_hash);
        }
        {
            // expected mpt key wire
            let (key, ptr) = pi.mpt_key_info();
            let exp_key = bytes_to_nibbles(&mpt_key)
                .into_iter()
                .map(F::from_canonical_u8)
                .collect::<Vec<_>>();
            assert_eq!(key, exp_key);
            let leaf_key: Vec<Vec<u8>> = rlp::decode_list(&node);
            let nib = Nibbles::from_compact(&leaf_key[0].clone());
            let exp_ptr = F::from_canonical_usize(MAX_KEY_NIBBLE_LEN - 1 - nib.nibbles().len());
            assert_eq!(exp_ptr, ptr);
        }
        {
            // expected mapping slot
            let ms = pi.mapping_slot();
            let exp_ms = F::from_canonical_usize(mapping_slot);
            assert_eq!(ms, exp_ms);
        }
        {
            // expected number of leaf seen
            let n = pi.n();
            let exp_n = F::ONE;
            assert_eq!(n, exp_n);
        }
    }
}
