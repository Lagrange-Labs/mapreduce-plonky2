//! Module handling the recursive proving of mapping entries specically
//! inside a storage trie.

use crate::{
    array::{Array, VectorWire},
    keccak::{KeccakCircuit, OutputHash, HASH_LEN, PACKED_HASH_LEN},
    mpt_sequential::{Circuit as MPTCircuit, MPTKeyWire, PAD_LEN},
    rlp::{decode_fixed_list, MAX_ITEMS_IN_LIST, MAX_KEY_NIBBLE_LEN},
    utils::convert_u8_targets_to_u32,
};
use core::array::from_fn as create_array;
use plonky2::{
    field::{extension::Extendable, goldilocks_field::GoldilocksField},
    hash::hash_types::{RichField, NUM_HASH_OUT_ELTS},
    iop::target::{BoolTarget, Target},
    plonk::circuit_builder::CircuitBuilder,
};
use plonky2_crypto::u32::arithmetic_u32::U32Target;
use plonky2_ecgfp5::gadgets::curve::CircuitBuilderEcGFp5;
use plonky2_ecgfp5::gadgets::{base_field::QuinticExtensionTarget, curve::CurveTarget};

pub struct BranchCircuit<const NODE_LEN: usize, const N_CHILDRENS: usize> {}

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
    pub fn accumulator(&self) -> CurveTarget {
        curve_target_from_slice(&self.proof_inputs[Self::D_IDX..])
    }
    pub fn root_hash(&self) -> OutputHash {
        // poseidon merkle root hash is 4 F elements
        let hash_range = Self::C_IDX..Self::C_IDX + PACKED_HASH_LEN;
        let hash = &self.proof_inputs[hash_range];
        Array::<U32Target, PACKED_HASH_LEN>::from_array(create_array(|i| U32Target(hash[i])))
    }
}

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

pub struct Wires<const NODE_LEN: usize>
where
    [(); PAD_LEN(NODE_LEN)]:,
{
    // TODO replace by proof when we have the framework in place
    inputs: Vec<Target>,
    node: VectorWire<{ PAD_LEN(NODE_LEN) }>,
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
        let common_prefix = MPTKeyWire::new(b);

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
            n = b.add(n, one);
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
        }
    }
}
