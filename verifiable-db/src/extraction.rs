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
use std::{array, iter};

pub trait ExtractionPI<'a> {
    const TOTAL_LEN: usize;
    fn from_slice(s: &'a [Target]) -> Self;
    fn commitment(&self) -> Vec<Target>;
    fn prev_commitment(&self) -> Vec<Target>;
    fn digest_value(&self) -> Vec<Target>;
    fn digest_metadata(&self) -> Vec<Target>;
    fn additional_info(&self) -> Vec<Target>;
    fn register_args<F: RichField + Extendable<D>, C: GenericConfig<D>, const D: usize>(
        &self,
        cb: &mut CircuitBuilder<F, D>,
    );
}

#[cfg(test)]
impl<'a> ExtractionPI<'a> for mp2_v1::final_extraction::PublicInputs<'a, Target> {
    const TOTAL_LEN: usize = Self::TOTAL_LEN;

    fn from_slice(s: &'a [Target]) -> Self {
        mp2_v1::final_extraction::PublicInputs::from_slice(&s)
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
        self.digest_metadata().to_targets()
    }

    fn additional_info(&self) -> Vec<Target> {
        self.block_number_targets()
    }
    fn register_args<F: RichField + Extendable<D>, C: GenericConfig<D>, const D: usize>(
        &self,
        cb: &mut CircuitBuilder<F, D>,
    ) {
        self.generic_register_args(cb)
    }
}
