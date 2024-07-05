//! Public inputs for Contract Extraction circuits

use ethers::{
    core::k256::elliptic_curve::Curve,
    types::{U256, U64},
};
use mp2_common::{
    array::Array,
    group_hashing::EXTENSION_DEGREE,
    keccak::{OutputHash, PACKED_HASH_LEN},
    mpt_sequential::MPTKeyWire,
    public_inputs::{PublicInputCommon, PublicInputRange},
    rlp::MAX_KEY_NIBBLE_LEN,
    types::{CBuilder, GFp, GFp5, CURVE_TARGET_LEN},
    u256::{self, U256PubInputs},
    utils::{FromFields, FromTargets, ToTargets},
    D, F,
};
use plonky2::{
    field::{
        extension::{Extendable, FieldExtension},
        types::Field,
    },
    hash::hash_types::RichField,
    iop::target::Target,
    plonk::{circuit_builder::CircuitBuilder, config::GenericConfig},
};
use plonky2_crypto::u32::arithmetic_u32::U32Target;
use plonky2_ecgfp5::{curve::curve::WeierstrassPoint, gadgets::curve::CurveTarget};
use serde::{de::DeserializeOwned, Serialize};
use std::{array, iter};

pub trait ExtractionPI<'a> {
    const TOTAL_LEN: usize;
    fn from_slice(s: &'a [Target]) -> Self;
    fn commitment(&self) -> Vec<Target>;
    fn prev_commitment(&self) -> Vec<Target>;
    fn digest_value(&self) -> Vec<Target>;
    fn digest_metadata(&self) -> Vec<Target>;
    fn primary_index_value(&self) -> Vec<Target>;
    fn register_args(&self, cb: &mut CircuitBuilder<F, D>);
}

/// Wrap trait getting rid of the lifetime
pub trait ExtractionPIWrap: Serialize + DeserializeOwned {
    type PI<'a>: ExtractionPI<'a>;
}

#[cfg(test)]
pub mod test {
    use serde::Deserialize;
    use u256::UInt256Target;

    use super::*;
    impl<'a> ExtractionPIWrap for PublicInputs<'a, Target> {
        type PI<'b> = PublicInputs<'b, Target>;
    }

    impl<'a> ExtractionPI<'a> for PublicInputs<'a, Target> {
        const TOTAL_LEN: usize = Self::TOTAL_LEN;

        fn from_slice(s: &'a [Target]) -> Self {
            PublicInputs::from_slice(&s)
        }

        fn commitment(&self) -> Vec<Target> {
            self.block_hash().to_targets()
        }

        fn prev_commitment(&self) -> Vec<Target> {
            self.previous_block_hash().to_targets()
        }

        fn digest_value(&self) -> Vec<Target> {
            self.digest_value().to_targets()
        }

        fn digest_metadata(&self) -> Vec<Target> {
            let dm = self.digest_metadata();
            dm.to_targets()
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
            WeierstrassPoint::from_fields(&self.dm)
        }
        /// Get the digest holding the values .
        pub fn value_point(&self) -> WeierstrassPoint {
            WeierstrassPoint::from_fields(&self.dv)
        }
        /// Get block number as U64
        pub fn block_number(&self) -> U64 {
            let mut bytes = vec![0u8; 32];
            let number = U256::from(U256PubInputs::try_from(self.bn).unwrap());
            number.to_little_endian(&mut bytes);
            U64::from_little_endian(&bytes[..8])
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
            cb.register_public_inputs(&self.h);
            cb.register_public_inputs(&self.ph);
            cb.register_public_inputs(&self.dv);
            cb.register_public_inputs(&self.dm);
            cb.register_public_inputs(&self.bn);
        }

        /// Get the blockchain block hash corresponding to the values extracted
        pub fn block_hash(&self) -> OutputHash {
            OutputHash::from_targets(&self.h)
        }

        /// Get the predecessor block hash
        pub fn previous_block_hash(&self) -> OutputHash {
            OutputHash::from_targets(&self.ph)
        }

        pub fn digest_value(&self) -> CurveTarget {
            CurveTarget::from_targets(&self.dv)
        }

        pub fn digest_metadata(&self) -> CurveTarget {
            CurveTarget::from_targets(&self.dm)
        }

        pub fn block_number(&self) -> UInt256Target {
            UInt256Target::from_targets(&self.bn)
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
            &self.h
        }

        pub fn prev_block_hash_raw(&self) -> &[T] {
            &self.ph
        }

        pub fn block_number_raw(&self) -> &[T] {
            &self.bn
        }

        pub fn digest_metadata_raw(&self) -> &[T] {
            &self.dm
        }
    }
}
