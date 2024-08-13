//! The public inputs of a set of circuits to extract the actual results
//! to be returned from the results tree

use alloy::primitives::U256;
use itertools::Itertools;
use mp2_common::{
    public_inputs::{PublicInputCommon, PublicInputRange},
    types::{CBuilder, CURVE_TARGET_LEN},
    u256::{UInt256Target, NUM_LIMBS},
    utils::{FromFields, FromTargets},
    F,
};
use plonky2::{
    hash::hash_types::{HashOut, HashOutTarget, NUM_HASH_OUT_ELTS},
    iop::target::Target,
};
use plonky2_ecgfp5::{curve::curve::WeierstrassPoint, gadgets::curve::CurveTarget};
use std::iter::once;

/// Public inputs of the circuits to extract results from the results tree
pub enum ResultsExtractionPublicInputs {
    /// `H`: `hash` Hash of the subtree rooted in the current node
    TreeHash,
    /// `min`: `u256` Minimum value of the indexed items for the subtree rooted
    /// in the current node; it will correspond to the secondary indexed item for nodes
    /// of the rows trees, and to the primary indexed item for nodes of the index tree
    MinValue,
    /// `max`: `u256` Maximum value of the indexed item for the subtree rooted in the current node;
    /// it will correspond to the secondary indexed item for nodes of the rows trees,
    /// and to the primary indexed item for nodes on the index tree
    MaxValue,
    /// `I`: `u256` Value of the primary indexed item for the rows stored in the subtree
    /// of rows tree in the current node
    PrimaryIndexValue,
    /// `index_ids`: `[2]F` Integer identifiers of the indexed items
    IndexIds,
    /// `min_counter`: `F` Minimum counter across the records in the
    /// subtree rooted in the current node
    MinCounter,
    /// `max_counter`: `F` Maximum counter across the records in the
    /// subtree rooted in the current node
    MaxCounter,
    /// `offset_range_min`: `F` Lower bound of the range `[offset, limit + offset]` derived from the query
    OffsetRangeMin,
    /// `offset_range_max`: `F` Upper bound of the range `[offset, limit + offset]` derived from the query
    OffsetRangeMax,
    /// `D`: `Digest` order-agnostic digested employed to accumulate the result to be returned
    Accumulator,
}

#[derive(Clone, Debug)]
pub struct PublicInputs<'a, T> {
    h: &'a [T],
    min_val: &'a [T],
    max_val: &'a [T],
    pri_idx_val: &'a [T],
    idx_ids: &'a [T],
    min_cnt: &'a T,
    max_cnt: &'a T,
    offset_range_min: &'a T,
    offset_range_max: &'a T,
    acc: &'a [T],
}

const NUM_PUBLIC_INPUTS: usize = ResultsExtractionPublicInputs::Accumulator as usize + 1;

impl<'a, T: Clone> PublicInputs<'a, T> {
    const PI_RANGES: [PublicInputRange; NUM_PUBLIC_INPUTS] = [
        Self::to_range(ResultsExtractionPublicInputs::TreeHash),
        Self::to_range(ResultsExtractionPublicInputs::MinValue),
        Self::to_range(ResultsExtractionPublicInputs::MaxValue),
        Self::to_range(ResultsExtractionPublicInputs::PrimaryIndexValue),
        Self::to_range(ResultsExtractionPublicInputs::IndexIds),
        Self::to_range(ResultsExtractionPublicInputs::MinCounter),
        Self::to_range(ResultsExtractionPublicInputs::MaxCounter),
        Self::to_range(ResultsExtractionPublicInputs::OffsetRangeMin),
        Self::to_range(ResultsExtractionPublicInputs::OffsetRangeMax),
        Self::to_range(ResultsExtractionPublicInputs::Accumulator),
    ];

    const SIZES: [usize; NUM_PUBLIC_INPUTS] = [
        // Tree hash
        NUM_HASH_OUT_ELTS,
        // Minimum value
        NUM_LIMBS,
        // Maximum value
        NUM_LIMBS,
        // Primary index value
        NUM_LIMBS,
        // Indexed column IDs
        2,
        // Minimum counter
        1,
        // Maximum counter
        1,
        // Offset Range Min
        1,
        // Offset Range Max
        1,
        // accumulator
        CURVE_TARGET_LEN,
    ];

    pub(crate) const fn to_range(pi: ResultsExtractionPublicInputs) -> PublicInputRange {
        let mut i = 0;
        let mut offset = 0;
        let pi_pos = pi as usize;
        while i < pi_pos {
            offset += Self::SIZES[i];
            i += 1;
        }
        offset..offset + Self::SIZES[pi_pos]
    }

    pub(crate) const fn total_len() -> usize {
        Self::to_range(ResultsExtractionPublicInputs::Accumulator).end
    }

    pub(crate) fn to_tree_hash_raw(&self) -> &[T] {
        self.h
    }

    pub(crate) fn to_min_value_raw(&self) -> &[T] {
        self.min_val
    }

    pub(crate) fn to_max_value_raw(&self) -> &[T] {
        self.max_val
    }

    pub(crate) fn to_primary_index_value_raw(&self) -> &[T] {
        self.pri_idx_val
    }

    pub(crate) fn to_index_ids_raw(&self) -> &[T] {
        self.idx_ids
    }

    pub(crate) fn to_min_counter_raw(&self) -> &T {
        self.min_cnt
    }

    pub(crate) fn to_max_counter_raw(&self) -> &T {
        self.max_cnt
    }

    pub(crate) fn to_offset_range_min_raw(&self) -> &T {
        self.offset_range_min
    }

    pub(crate) fn to_offset_range_max_raw(&self) -> &T {
        self.offset_range_max
    }

    pub(crate) fn to_accumulator_raw(&self) -> &[T] {
        self.acc
    }

    pub fn from_slice(input: &'a [T]) -> Self {
        assert!(
            input.len() >= Self::total_len(),
            "Input slice too short to build results public inputs, must be at least {} elements",
            Self::total_len(),
        );
        Self {
            h: &input[Self::PI_RANGES[0].clone()],
            min_val: &input[Self::PI_RANGES[1].clone()],
            max_val: &input[Self::PI_RANGES[2].clone()],
            pri_idx_val: &input[Self::PI_RANGES[3].clone()],
            idx_ids: &input[Self::PI_RANGES[4].clone()],
            min_cnt: &input[Self::PI_RANGES[5].clone()][0],
            max_cnt: &input[Self::PI_RANGES[6].clone()][0],
            offset_range_min: &input[Self::PI_RANGES[7].clone()][0],
            offset_range_max: &input[Self::PI_RANGES[8].clone()][0],
            acc: &input[Self::PI_RANGES[9].clone()],
        }
    }

    pub fn new(
        h: &'a [T],
        min_val: &'a [T],
        max_val: &'a [T],
        pri_idx_val: &'a [T],
        idx_ids: &'a [T],
        min_cnt: &'a [T],
        max_cnt: &'a [T],
        offset_range_min: &'a [T],
        offset_range_max: &'a [T],
        acc: &'a [T],
    ) -> Self {
        Self {
            h,
            min_val,
            max_val,
            pri_idx_val,
            idx_ids,
            min_cnt: &min_cnt[0],
            max_cnt: &max_cnt[0],
            offset_range_min: &offset_range_min[0],
            offset_range_max: &offset_range_max[0],
            acc,
        }
    }

    pub fn to_vec(&self) -> Vec<T> {
        self.h
            .iter()
            .chain(self.min_val.iter())
            .chain(self.max_val.iter())
            .chain(self.pri_idx_val.iter())
            .chain(self.idx_ids.iter())
            .chain(once(self.min_cnt))
            .chain(once(self.max_cnt))
            .chain(once(self.offset_range_min))
            .chain(once(self.offset_range_max))
            .chain(self.acc.iter())
            .cloned()
            .collect_vec()
    }
}

impl<'a> PublicInputCommon for PublicInputs<'a, Target> {
    const RANGES: &'static [PublicInputRange] = &Self::PI_RANGES;

    fn register_args(&self, cb: &mut CBuilder) {
        cb.register_public_inputs(self.h);
        cb.register_public_inputs(self.min_val);
        cb.register_public_inputs(self.max_val);
        cb.register_public_inputs(self.pri_idx_val);
        cb.register_public_inputs(self.idx_ids);
        cb.register_public_input(*self.min_cnt);
        cb.register_public_input(*self.max_cnt);
        cb.register_public_input(*self.offset_range_min);
        cb.register_public_input(*self.offset_range_max);
        cb.register_public_inputs(self.acc);
    }
}

impl<'a> PublicInputs<'a, Target> {
    pub fn tree_hash_target(&self) -> HashOutTarget {
        HashOutTarget::try_from(self.to_tree_hash_raw()).unwrap()
    }

    pub fn min_value_target(&self) -> UInt256Target {
        UInt256Target::from_targets(self.to_min_value_raw())
    }

    pub fn max_value_target(&self) -> UInt256Target {
        UInt256Target::from_targets(self.to_max_value_raw())
    }

    pub fn primary_index_value_target(&self) -> UInt256Target {
        UInt256Target::from_targets(self.to_primary_index_value_raw())
    }

    pub fn index_ids_target(&self) -> [Target; 2] {
        self.to_index_ids_raw().try_into().unwrap()
    }

    pub fn min_counter_target(&self) -> Target {
        *self.to_min_counter_raw()
    }

    pub fn max_counter_target(&self) -> Target {
        *self.to_max_counter_raw()
    }

    pub fn offset_range_min_target(&self) -> Target {
        *self.to_offset_range_min_raw()
    }

    pub fn offset_range_max_target(&self) -> Target {
        *self.to_offset_range_max_raw()
    }

    pub fn accumulator_target(&self) -> CurveTarget {
        CurveTarget::from_targets(self.to_accumulator_raw())
    }
}

impl<'a> PublicInputs<'a, F> {
    pub fn tree_hash(&self) -> HashOut<F> {
        HashOut::try_from(self.to_tree_hash_raw()).unwrap()
    }

    pub fn min_value(&self) -> U256 {
        U256::from_fields(self.to_min_value_raw())
    }

    pub fn max_value(&self) -> U256 {
        U256::from_fields(self.to_max_value_raw())
    }

    pub fn primary_index_value(&self) -> U256 {
        U256::from_fields(self.to_primary_index_value_raw())
    }

    pub fn index_ids(&self) -> [F; 2] {
        self.to_index_ids_raw().try_into().unwrap()
    }

    pub fn min_counter(&self) -> F {
        *self.to_min_counter_raw()
    }

    pub fn max_counter(&self) -> F {
        *self.to_max_counter_raw()
    }

    pub fn offset_range_min(&self) -> F {
        *self.to_offset_range_min_raw()
    }

    pub fn offset_range_max(&self) -> F {
        *self.to_offset_range_max_raw()
    }

    pub fn accumulator(&self) -> WeierstrassPoint {
        WeierstrassPoint::from_fields(self.to_accumulator_raw())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mp2_common::{public_inputs::PublicInputCommon, utils::ToFields, C, D, F};
    use mp2_test::{
        circuit::{run_circuit, UserCircuit},
        utils::random_vector,
    };
    use plonky2::{
        iop::{
            target::Target,
            witness::{PartialWitness, WitnessWrite},
        },
        plonk::circuit_builder::CircuitBuilder,
    };

    const S: usize = 10;
    #[derive(Clone, Debug)]
    struct TestPublicInputs<'a> {
        pis: &'a [F],
    }

    impl<'a> UserCircuit<F, D> for TestPublicInputs<'a> {
        type Wires = Vec<Target>;

        fn build(c: &mut CircuitBuilder<F, D>) -> Self::Wires {
            let targets = c.add_virtual_target_arr::<{ PublicInputs::<Target>::total_len() }>();
            let pi_targets = PublicInputs::<Target>::from_slice(targets.as_slice());
            pi_targets.register_args(c);
            pi_targets.to_vec()
        }

        fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
            pw.set_target_arr(wires, self.pis)
        }
    }

    #[test]
    fn test_results_extraction_public_inputs() {
        let pis_raw = random_vector::<u32>(PublicInputs::<F>::total_len()).to_fields();

        // use public inputs in circuit
        let test_circuit = TestPublicInputs { pis: &pis_raw };
        let proof = run_circuit::<F, D, C, _>(test_circuit);
        assert_eq!(proof.public_inputs, pis_raw);

        // check public inputs are constructed correctly
        let pis = PublicInputs::<F>::from_slice(&proof.public_inputs);
        assert_eq!(
            &pis_raw[PublicInputs::<F>::to_range(ResultsExtractionPublicInputs::TreeHash)],
            pis.to_tree_hash_raw(),
        );
        assert_eq!(
            &pis_raw[PublicInputs::<F>::to_range(ResultsExtractionPublicInputs::MinValue)],
            pis.to_min_value_raw(),
        );
        assert_eq!(
            &pis_raw[PublicInputs::<F>::to_range(ResultsExtractionPublicInputs::MaxValue)],
            pis.to_max_value_raw(),
        );
        assert_eq!(
            &pis_raw[PublicInputs::<F>::to_range(ResultsExtractionPublicInputs::PrimaryIndexValue)],
            pis.to_primary_index_value_raw(),
        );
        assert_eq!(
            &pis_raw[PublicInputs::<F>::to_range(ResultsExtractionPublicInputs::IndexIds)],
            pis.to_index_ids_raw(),
        );
        assert_eq!(
            &pis_raw[PublicInputs::<F>::to_range(ResultsExtractionPublicInputs::MinCounter)],
            &[*pis.to_min_counter_raw()],
        );
        assert_eq!(
            &pis_raw[PublicInputs::<F>::to_range(ResultsExtractionPublicInputs::MaxCounter)],
            &[*pis.to_max_counter_raw()],
        );
        assert_eq!(
            &pis_raw[PublicInputs::<F>::to_range(ResultsExtractionPublicInputs::OffsetRangeMin)],
            &[*pis.to_offset_range_min_raw()],
        );
        assert_eq!(
            &pis_raw[PublicInputs::<F>::to_range(ResultsExtractionPublicInputs::OffsetRangeMax)],
            &[*pis.to_offset_range_max_raw()],
        );
        assert_eq!(
            &pis_raw[PublicInputs::<F>::to_range(ResultsExtractionPublicInputs::Accumulator)],
            pis.to_accumulator_raw(),
        );
    }
}
