use std::array::from_fn as create_array;

use plonky2::{
    field::{
        extension::{quintic::QuinticExtension, FieldExtension},
        goldilocks_field::GoldilocksField,
        types::Field,
    },
    iop::target::{BoolTarget, Target},
    plonk::circuit_builder::CircuitBuilder,
};
use plonky2_crypto::u32::arithmetic_u32::U32Target;
use plonky2_ecgfp5::{
    curve::curve::WeierstrassPoint,
    gadgets::{
        base_field::QuinticExtensionTarget,
        curve::{CircuitBuilderEcGFp5, CurveTarget},
    },
};

use crate::{
    array::Array,
    keccak::{OutputHash, PACKED_HASH_LEN},
    mpt_sequential::MPTKeyWire,
    rlp::MAX_KEY_NIBBLE_LEN,
};
// This is a wrapper around an array of targets set as public inputs
// of any proof generated in this module. They all share the same
// structure.
// `K` Full key for a leaf inside this subtree
// `T` Index of the part “processed” on the full key
// `S`  storage slot of the mapping
// `n` number of items seen so far up to this node
// `C` MPT root (of the current node)
// `D` Accumulator digest of the values
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
    pub(super) fn mpt_key_info(&self) -> (&[T], T) {
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
