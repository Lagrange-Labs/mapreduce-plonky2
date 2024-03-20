use std::array;

use ethers::types::BlockNumber;
use plonky2::hash::hash_types::RichField;
use rand::{rngs::StdRng, RngCore, SeedableRng};

use crate::{query2::epilogue::Provenance, types::CURVE_TARGET_LEN};

use super::{CommonInput, PublicInputs};

impl<'a, T: Copy + 'a, const L: usize> PublicInputs<'a, T, Provenance, L> {
    /// Writes the parts of the block liking public inputs into the provided target array.
    pub fn parts_into_values(
        values: &mut [T; Self::TOTAL_COMMON_LEN + CURVE_TARGET_LEN],
        b: &[T; CommonInput::BlockNumber.len()],
        r: &[T; CommonInput::Range.len()],
        c: &[T; CommonInput::Root.len()],
        b_min: &[T; CommonInput::MinBlockNumber.len()],
        b_max: &[T; CommonInput::MaxBlockNumber.len()],
        a: &[T; CommonInput::SmartContractAddress.len()],
        x: &[T; CommonInput::UserAddress.len()],
        m: &[T; CommonInput::MappingSlot.len()],
        s: &[T; CommonInput::LengthSlot.len()],
    ) {
        use CommonInput::*;

        values[BlockNumber.offset()..BlockNumber.offset() + BlockNumber.len()].copy_from_slice(b);
        values[Range.offset()..Range.offset() + Range.len()].copy_from_slice(r);
        values[Root.offset()..Root.offset() + Root.len()].copy_from_slice(c);
        values[MinBlockNumber.offset()..MinBlockNumber.offset() + MinBlockNumber.len()]
            .copy_from_slice(b_min);
        values[MaxBlockNumber.offset()..MaxBlockNumber.offset() + MaxBlockNumber.len()]
            .copy_from_slice(b_max);
        values[SmartContractAddress.offset()
            ..SmartContractAddress.offset() + SmartContractAddress.len()]
            .copy_from_slice(a);
        values[UserAddress.offset()..UserAddress.offset() + UserAddress.len()].copy_from_slice(x);
        values[MappingSlot.offset()..MappingSlot.offset() + MappingSlot.len()].copy_from_slice(m);
        values[LengthSlot.offset()..LengthSlot.offset() + LengthSlot.len()].copy_from_slice(s);
    }
}

impl<'a, F: RichField, const L: usize> PublicInputs<'a, F, Provenance, L> {
    pub fn values_from_seed(seed: u64) -> [F; Self::TOTAL_COMMON_LEN + CURVE_TARGET_LEN] {
        let rng = &mut StdRng::seed_from_u64(seed);

        let b = array::from_fn(|_| F::from_canonical_u32(rng.next_u32()));
        let r = [F::ONE];
        let c = array::from_fn(|_| F::from_canonical_u32(rng.next_u32()));
        let b_min = array::from_fn(|_| F::from_canonical_u32(rng.next_u32()));
        let b_max = array::from_fn(|_| F::from_canonical_u32(rng.next_u32()));
        let a = array::from_fn(|_| F::from_canonical_u32(rng.next_u32()));
        let x = array::from_fn(|_| F::from_canonical_u32(rng.next_u32()));
        let m = array::from_fn(|_| F::from_canonical_u8(rng.next_u32().to_le_bytes()[0]));
        let s = array::from_fn(|_| F::from_canonical_u8(rng.next_u32().to_le_bytes()[0]));

        let mut values = array::from_fn(|_| F::ZERO);
        Self::parts_into_values(&mut values, &b, &r, &c, &b_min, &b_max, &a, &x, &m, &s);

        values
    }
}

#[test]
fn public_inputs_len_matches() {
    assert_eq!(
        CommonInput::total_len(),
        PublicInputs::<(), (), 2>::TOTAL_COMMON_LEN,
        "The specified total length of the inputs does not match the expected value"
    );
    assert_eq!(
        CommonInput::total_len() + CURVE_TARGET_LEN,
        PublicInputs::<(), Provenance, 2>::total_len(),
        "The specified total length of the inputs does not match the expected value"
    );
}
