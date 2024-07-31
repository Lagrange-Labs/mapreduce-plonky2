//! Public inputs for Contract Extraction circuits

use mp2_common::{D, F};
use plonky2::{iop::target::Target, plonk::circuit_builder::CircuitBuilder};
use plonky2_ecgfp5::gadgets::curve::CurveTarget;
use serde::{de::DeserializeOwned, Serialize};

pub trait ExtractionPI<'a> {
    const TOTAL_LEN: usize;
    fn from_slice(s: &'a [Target]) -> Self;
    fn commitment(&self) -> Vec<Target>;
    fn prev_commitment(&self) -> Vec<Target>;
    fn value_set_digest(&self) -> CurveTarget;
    fn metadata_set_digest(&self) -> CurveTarget;
    fn primary_index_value(&self) -> Vec<Target>;
    fn register_args(&self, cb: &mut CircuitBuilder<F, D>);
}

/// Wrap trait getting rid of the lifetime
pub trait ExtractionPIWrap: Serialize + DeserializeOwned {
    type PI<'a>: ExtractionPI<'a>;
}

#[cfg(test)]
pub mod test {

    use alloy::primitives::U256;
    use mp2_common::{
        keccak::{OutputHash, PACKED_HASH_LEN},
        public_inputs::{PublicInputCommon, PublicInputRange},
        types::{CBuilder, GFp, CURVE_TARGET_LEN},
        u256::{self},
        utils::{FromFields, FromTargets, ToTargets},
        D, F,
    };
    use plonky2_ecgfp5::curve::curve::WeierstrassPoint;
    use serde::Deserialize;
    use u256::UInt256Target;

    use super::*;
    impl<'a> ExtractionPIWrap for PublicInputs<'a, Target> {
        type PI<'b> = PublicInputs<'b, Target>;
    }

    impl<'a> ExtractionPI<'a> for PublicInputs<'a, Target> {
        const TOTAL_LEN: usize = Self::TOTAL_LEN;

        fn from_slice(s: &'a [Target]) -> Self {
            PublicInputs::from_slice(s)
        }

        fn commitment(&self) -> Vec<Target> {
            self.block_hash().to_targets()
        }

        fn prev_commitment(&self) -> Vec<Target> {
            self.previous_block_hash().to_targets()
        }

        fn value_set_digest(&self) -> CurveTarget {
            self.digest_value()
        }

        fn metadata_set_digest(&self) -> CurveTarget {
            self.digest_metadata()
        }

        fn primary_index_value(&self) -> Vec<Target> {
            self.block_number().to_targets()
        }
        fn register_args(&self, cb: &mut CircuitBuilder<F, D>) {
            self.generic_register_args(cb)
        }
    }

    // Contract extraction public Inputs:
    // - `H : [8]F` : packed block hash
    // - `PH : [8]F` : *previous* packed block hash
    // - `DV : Digest[F]` : value digest of all rows to extract
    // - `DM : Digest[F]` : metadata digest to extract
    // - `BN : Uint256` : block number
    const H_RANGE: PublicInputRange = 0..PACKED_HASH_LEN;
    const PH_RANGE: PublicInputRange = PACKED_HASH_LEN..H_RANGE.end + PACKED_HASH_LEN;
    const DV_RANGE: PublicInputRange = PH_RANGE.end..PH_RANGE.end + CURVE_TARGET_LEN;
    const DM_RANGE: PublicInputRange = DV_RANGE.end..DV_RANGE.end + CURVE_TARGET_LEN;
    // TODO : replace by uint256 constant
    const BN_RANGE: PublicInputRange = DM_RANGE.end..DM_RANGE.end + u256::NUM_LIMBS;

    /// Public inputs for contract extraction
    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct PublicInputs<'a, T> {
        #[serde(skip)]
        pub(crate) h: &'a [T],
        #[serde(skip)]
        pub(crate) ph: &'a [T],
        #[serde(skip)]
        pub(crate) dv: &'a [T],
        #[serde(skip)]
        pub(crate) dm: &'a [T],
        #[serde(skip)]
        pub(crate) bn: &'a [T],
    }

    impl<'a> PublicInputCommon for PublicInputs<'a, Target> {
        const RANGES: &'static [PublicInputRange] =
            &[H_RANGE, PH_RANGE, DV_RANGE, DM_RANGE, BN_RANGE];

        fn register_args(&self, cb: &mut CBuilder) {
            self.generic_register_args(cb)
        }
    }

    impl<'a> PublicInputs<'a, GFp> {
        /// Get the metadata point.
        pub fn metadata_point(&self) -> WeierstrassPoint {
            WeierstrassPoint::from_fields(self.dm)
        }
        /// Get the digest holding the values .
        pub fn value_point(&self) -> WeierstrassPoint {
            WeierstrassPoint::from_fields(self.dv)
        }
        /// Get block number as U64
        pub fn block_number(&self) -> u64 {
            U256::from_fields(self.bn).to()
        }
    }

    impl<'a, T> PublicInputs<'a, T> {
        /// Create a new public inputs.
        pub fn new(h: &'a [T], ph: &'a [T], dv: &'a [T], dm: &'a [T], bn: &'a [T]) -> Self {
            Self { h, ph, dv, dm, bn }
        }
    }

    impl<'a> PublicInputs<'a, Target> {
        pub fn generic_register_args(&self, cb: &mut CBuilder) {
            cb.register_public_inputs(self.h);
            cb.register_public_inputs(self.ph);
            cb.register_public_inputs(self.dv);
            cb.register_public_inputs(self.dm);
            cb.register_public_inputs(self.bn);
        }

        /// Get the blockchain block hash corresponding to the values extracted
        pub fn block_hash(&self) -> OutputHash {
            OutputHash::from_targets(self.h)
        }

        /// Get the predecessor block hash
        pub fn previous_block_hash(&self) -> OutputHash {
            OutputHash::from_targets(self.ph)
        }

        pub fn digest_value(&self) -> CurveTarget {
            CurveTarget::from_targets(self.dv)
        }

        pub fn digest_metadata(&self) -> CurveTarget {
            CurveTarget::from_targets(self.dm)
        }

        pub fn block_number(&self) -> UInt256Target {
            UInt256Target::from_targets(self.bn)
        }
    }

    impl<'a, T: Copy> PublicInputs<'a, T> {
        /// Total length of the public inputs
        pub const TOTAL_LEN: usize = BN_RANGE.end;

        /// Create from a slice.
        pub fn from_slice(pi: &'a [T]) -> Self {
            assert!(pi.len() >= Self::TOTAL_LEN);

            Self {
                h: &pi[H_RANGE],
                ph: &pi[PH_RANGE],
                dm: &pi[DM_RANGE],
                dv: &pi[DV_RANGE],
                bn: &pi[BN_RANGE],
            }
        }

        /// Combine to a vector.
        pub fn to_vec(&self) -> Vec<T> {
            self.h
                .iter()
                .chain(self.ph.iter())
                .chain(self.dv.iter())
                .chain(self.dm.iter())
                .chain(self.bn.iter())
                .cloned()
                .collect()
        }

        pub fn block_hash_raw(&self) -> &[T] {
            self.h
        }

        pub fn prev_block_hash_raw(&self) -> &[T] {
            self.ph
        }

        pub fn block_number_raw(&self) -> &[T] {
            self.bn
        }

        pub fn digest_metadata_raw(&self) -> &[T] {
            self.dm
        }
    }
}
