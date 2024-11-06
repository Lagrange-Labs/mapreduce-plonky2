//! The public inputs of a set of circuits to build a results tree

use alloy::primitives::U256;
use itertools::Itertools;
use mp2_common::{
    public_inputs::{PublicInputCommon, PublicInputRange},
    types::{CBuilder, CURVE_TARGET_LEN},
    u256::{UInt256Target, NUM_LIMBS},
    utils::{FromFields, FromTargets, TryIntoBool},
    F,
};
use plonky2::{
    hash::hash_types::{HashOut, HashOutTarget, NUM_HASH_OUT_ELTS},
    iop::target::{BoolTarget, Target},
};
use plonky2_ecgfp5::{curve::curve::WeierstrassPoint, gadgets::curve::CurveTarget};
use std::iter::once;

/// Public inputs of the circuits to build a results tree
pub enum ResultsConstructionPublicInputs {
    /// `H`: `hash` Hash of the tree
    TreeHash,
    /// `min` : `u256` Minimum value of the indexed column among all the records stored in the
    /// subtree rooted in the current node; values of secondary indexed column are employed for
    /// rows tree nodes, while values of primary indexed column are employed for index tree nodes
    MinValue,
    /// `max` : `u256` Maximum value of the indexed column among all the records stored in the
    /// subtree rooted in the current node; values of secondary indexed column are employed for
    /// rows tree nodes, while values of primary indexed column are employed for index tree nodes
    MaxValue,
    /// `min_items` : `[u256; S - 2]` Minimum set of `S-2` items (according to our order-relationship)
    /// across all the records stored in the subtree rooted in the current node; this is necessary to
    /// enforce that there are no duplicate records in the results tree, and so those inputs are
    /// meaningful only in case we are building a results tree for queries with `DISTINCT` keyword
    MinItems,
    /// `max_items` : `[u256; S - 2]` Maximum set of `S-2` items (according to our order-relationship)
    /// across all the records stored in the subtree rooted in the current node; this is necessary to
    /// enforce that there are no duplicate records in the results tree, and so those inputs are
    /// meaningful only in case we are building a results tree for queries with `DISTINCT` keyword
    MaxItems,
    /// `min_counter` : `F` Minimum counter value across all the records stored in the subtree rooted
    /// in the current node; the counter of a record corresponds to the position of the node storing
    /// the record in the enumeration of nodes of the rows tree
    MinCounter,
    /// `max_counter` : `F` Maximum counter value across all the records stored in the subtree rooted
    /// in the current node; the counter of a record corresponds to the position of the node storing
    /// the record in the enumeration of nodes of the rows tree
    MaxCounter,
    /// `I` : `u256` Value of the primary indexed item for all the rows stored in the subtree rooted
    /// in the current node (meaningful only for nodes of rows trees)
    PrimaryIndexValue,
    /// `index_ids` : `[2]F` Integer identifiers of the indexed items
    IndexIds,
    /// `no_duplicates` : `bool` flag specifying whether we are building the tree without duplicates or not
    NoDuplicates,
    /// `D` : `Digest` Accumulator of the items inserted in the subtree rooted in the current node,
    /// later employed to check that we are inserting the same values extracted from the original tree
    Accumulator,
}

#[derive(Clone, Debug)]
pub struct PublicInputs<'a, T, const S: usize> {
    h: &'a [T],
    min_val: &'a [T],
    max_val: &'a [T],
    min_items: &'a [T],
    max_items: &'a [T],
    min_cnt: &'a T,
    max_cnt: &'a T,
    pri_idx_val: &'a [T],
    idx_ids: &'a [T],
    no_dup: &'a T,
    acc: &'a [T],
}

const NUM_PUBLIC_INPUTS: usize = ResultsConstructionPublicInputs::Accumulator as usize + 1;

impl<'a, T: Clone, const S: usize> PublicInputs<'a, T, S> {
    const PI_RANGES: [PublicInputRange; NUM_PUBLIC_INPUTS] = [
        Self::to_range(ResultsConstructionPublicInputs::TreeHash),
        Self::to_range(ResultsConstructionPublicInputs::MinValue),
        Self::to_range(ResultsConstructionPublicInputs::MaxValue),
        Self::to_range(ResultsConstructionPublicInputs::MinItems),
        Self::to_range(ResultsConstructionPublicInputs::MaxItems),
        Self::to_range(ResultsConstructionPublicInputs::MinCounter),
        Self::to_range(ResultsConstructionPublicInputs::MaxCounter),
        Self::to_range(ResultsConstructionPublicInputs::PrimaryIndexValue),
        Self::to_range(ResultsConstructionPublicInputs::IndexIds),
        Self::to_range(ResultsConstructionPublicInputs::NoDuplicates),
        Self::to_range(ResultsConstructionPublicInputs::Accumulator),
    ];

    const SIZES: [usize; NUM_PUBLIC_INPUTS] = [
        // Tree hash
        NUM_HASH_OUT_ELTS,
        // Minimum value
        NUM_LIMBS,
        // Maximum value
        NUM_LIMBS,
        // Minimum items
        NUM_LIMBS * (S - 2),
        // Maximum items
        NUM_LIMBS * (S - 2),
        // Minimum counter
        1,
        // Maximum counter
        1,
        // Primary index value
        NUM_LIMBS,
        // Indexed column IDs
        2,
        // No duplicates flag
        1,
        // Item accumulator
        CURVE_TARGET_LEN,
    ];

    pub(crate) const fn to_range(pi: ResultsConstructionPublicInputs) -> PublicInputRange {
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
        Self::to_range(ResultsConstructionPublicInputs::Accumulator).end
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

    pub(crate) fn to_min_items_raw(&self) -> &[T] {
        self.min_items
    }

    pub(crate) fn to_max_items_raw(&self) -> &[T] {
        self.max_items
    }

    pub(crate) fn to_min_counter_raw(&self) -> &T {
        self.min_cnt
    }

    pub(crate) fn to_max_counter_raw(&self) -> &T {
        self.max_cnt
    }

    pub(crate) fn to_primary_index_value_raw(&self) -> &[T] {
        self.pri_idx_val
    }

    pub(crate) fn to_index_ids_raw(&self) -> &[T] {
        self.idx_ids
    }

    pub(crate) fn to_no_duplicates_raw(&self) -> &T {
        self.no_dup
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
            min_items: &input[Self::PI_RANGES[3].clone()],
            max_items: &input[Self::PI_RANGES[4].clone()],
            min_cnt: &input[Self::PI_RANGES[5].clone()][0],
            max_cnt: &input[Self::PI_RANGES[6].clone()][0],
            pri_idx_val: &input[Self::PI_RANGES[7].clone()],
            idx_ids: &input[Self::PI_RANGES[8].clone()],
            no_dup: &input[Self::PI_RANGES[9].clone()][0],
            acc: &input[Self::PI_RANGES[10].clone()],
        }
    }

    pub fn new(
        h: &'a [T],
        min_val: &'a [T],
        max_val: &'a [T],
        min_items: &'a [T],
        max_items: &'a [T],
        min_cnt: &'a [T],
        max_cnt: &'a [T],
        pri_idx_val: &'a [T],
        idx_ids: &'a [T],
        no_dup: &'a [T],
        acc: &'a [T],
    ) -> Self {
        Self {
            h,
            min_val,
            max_val,
            min_items,
            max_items,
            min_cnt: &min_cnt[0],
            max_cnt: &max_cnt[0],
            pri_idx_val,
            idx_ids,
            no_dup: &no_dup[0],
            acc,
        }
    }

    pub fn to_vec(&self) -> Vec<T> {
        self.h
            .iter()
            .chain(self.min_val.iter())
            .chain(self.max_val.iter())
            .chain(self.min_items.iter())
            .chain(self.max_items.iter())
            .chain(once(self.min_cnt))
            .chain(once(self.max_cnt))
            .chain(self.pri_idx_val.iter())
            .chain(self.idx_ids.iter())
            .chain(once(self.no_dup))
            .chain(self.acc.iter())
            .cloned()
            .collect_vec()
    }
}

impl<const S: usize> PublicInputCommon for PublicInputs<'_, Target, S> {
    const RANGES: &'static [PublicInputRange] = &Self::PI_RANGES;

    fn register_args(&self, cb: &mut CBuilder) {
        cb.register_public_inputs(self.h);
        cb.register_public_inputs(self.min_val);
        cb.register_public_inputs(self.max_val);
        cb.register_public_inputs(self.min_items);
        cb.register_public_inputs(self.max_items);
        cb.register_public_input(*self.min_cnt);
        cb.register_public_input(*self.max_cnt);
        cb.register_public_inputs(self.pri_idx_val);
        cb.register_public_inputs(self.idx_ids);
        cb.register_public_input(*self.no_dup);
        cb.register_public_inputs(self.acc);
    }
}

impl<const S: usize> PublicInputs<'_, Target, S> {
    pub fn tree_hash_target(&self) -> HashOutTarget {
        HashOutTarget::try_from(self.to_tree_hash_raw()).unwrap()
    }

    pub fn min_value_target(&self) -> UInt256Target {
        UInt256Target::from_targets(self.to_min_value_raw())
    }

    pub fn max_value_target(&self) -> UInt256Target {
        UInt256Target::from_targets(self.to_max_value_raw())
    }

    pub fn min_items_target(&self) -> [UInt256Target; S - 2] {
        self.to_min_items_raw()
            .chunks(NUM_LIMBS)
            .map(UInt256Target::from_targets)
            .collect_vec()
            .try_into()
            .unwrap()
    }

    pub fn max_items_target(&self) -> [UInt256Target; S - 2] {
        self.to_max_items_raw()
            .chunks(NUM_LIMBS)
            .map(UInt256Target::from_targets)
            .collect_vec()
            .try_into()
            .unwrap()
    }

    pub fn min_counter_target(&self) -> Target {
        *self.to_min_counter_raw()
    }

    pub fn max_counter_target(&self) -> Target {
        *self.to_max_counter_raw()
    }

    pub fn primary_index_value_target(&self) -> UInt256Target {
        UInt256Target::from_targets(self.to_primary_index_value_raw())
    }

    pub fn index_ids_target(&self) -> [Target; 2] {
        self.to_index_ids_raw().try_into().unwrap()
    }

    pub fn no_duplicates_flag_target(&self) -> BoolTarget {
        BoolTarget::new_unsafe(*self.to_no_duplicates_raw())
    }

    pub fn accumulator_target(&self) -> CurveTarget {
        CurveTarget::from_targets(self.to_accumulator_raw())
    }
}

impl<const S: usize> PublicInputs<'_, F, S> {
    pub fn tree_hash(&self) -> HashOut<F> {
        HashOut::try_from(self.to_tree_hash_raw()).unwrap()
    }

    pub fn min_value(&self) -> U256 {
        U256::from_fields(self.to_min_value_raw())
    }

    pub fn max_value(&self) -> U256 {
        U256::from_fields(self.to_max_value_raw())
    }

    pub fn min_items(&self) -> [U256; S - 2] {
        self.to_min_items_raw()
            .chunks(NUM_LIMBS)
            .map(U256::from_fields)
            .collect_vec()
            .try_into()
            .unwrap()
    }

    pub fn max_items(&self) -> [U256; S - 2] {
        self.to_max_items_raw()
            .chunks(NUM_LIMBS)
            .map(U256::from_fields)
            .collect_vec()
            .try_into()
            .unwrap()
    }

    pub fn min_counter(&self) -> F {
        *self.to_min_counter_raw()
    }

    pub fn max_counter(&self) -> F {
        *self.to_max_counter_raw()
    }

    pub fn primary_index_value(&self) -> U256 {
        U256::from_fields(self.to_primary_index_value_raw())
    }

    pub fn index_ids(&self) -> [F; 2] {
        self.to_index_ids_raw().try_into().unwrap()
    }

    pub fn no_duplicates_flag(&self) -> bool {
        (*self.to_no_duplicates_raw())
            .try_into_bool()
            .expect("no_duplicates flag public input different from 0 or 1")
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

    impl UserCircuit<F, D> for TestPublicInputs<'_> {
        type Wires = Vec<Target>;

        fn build(c: &mut CircuitBuilder<F, D>) -> Self::Wires {
            let targets = c.add_virtual_target_arr::<{ PublicInputs::<Target, S>::total_len() }>();
            let pi_targets = PublicInputs::<Target, S>::from_slice(targets.as_slice());
            pi_targets.register_args(c);
            pi_targets.to_vec()
        }

        fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
            pw.set_target_arr(wires, self.pis)
        }
    }

    #[test]
    fn test_results_construction_public_inputs() {
        let pis_raw = random_vector::<u32>(PublicInputs::<F, S>::total_len()).to_fields();

        // use public inputs in circuit
        let test_circuit = TestPublicInputs { pis: &pis_raw };
        let proof = run_circuit::<F, D, C, _>(test_circuit);
        assert_eq!(proof.public_inputs, pis_raw);

        // check public inputs are constructed correctly
        let pis = PublicInputs::<F, S>::from_slice(&proof.public_inputs);
        assert_eq!(
            &pis_raw[PublicInputs::<F, S>::to_range(ResultsConstructionPublicInputs::TreeHash)],
            pis.to_tree_hash_raw(),
        );
        assert_eq!(
            &pis_raw[PublicInputs::<F, S>::to_range(ResultsConstructionPublicInputs::MinValue)],
            pis.to_min_value_raw(),
        );
        assert_eq!(
            &pis_raw[PublicInputs::<F, S>::to_range(ResultsConstructionPublicInputs::MaxValue)],
            pis.to_max_value_raw(),
        );
        assert_eq!(
            &pis_raw[PublicInputs::<F, S>::to_range(ResultsConstructionPublicInputs::MinItems)],
            pis.to_min_items_raw(),
        );
        assert_eq!(
            &pis_raw[PublicInputs::<F, S>::to_range(ResultsConstructionPublicInputs::MaxItems)],
            pis.to_max_items_raw(),
        );
        assert_eq!(
            &pis_raw[PublicInputs::<F, S>::to_range(ResultsConstructionPublicInputs::MinCounter)],
            &[*pis.to_min_counter_raw()],
        );
        assert_eq!(
            &pis_raw[PublicInputs::<F, S>::to_range(ResultsConstructionPublicInputs::MaxCounter)],
            &[*pis.to_max_counter_raw()],
        );
        assert_eq!(
            &pis_raw[PublicInputs::<F, S>::to_range(
                ResultsConstructionPublicInputs::PrimaryIndexValue
            )],
            pis.to_primary_index_value_raw(),
        );
        assert_eq!(
            &pis_raw[PublicInputs::<F, S>::to_range(ResultsConstructionPublicInputs::IndexIds)],
            pis.to_index_ids_raw(),
        );
        assert_eq!(
            &pis_raw[PublicInputs::<F, S>::to_range(ResultsConstructionPublicInputs::NoDuplicates)],
            &[*pis.to_no_duplicates_raw()],
        );
        assert_eq!(
            &pis_raw[PublicInputs::<F, S>::to_range(ResultsConstructionPublicInputs::Accumulator)],
            pis.to_accumulator_raw(),
        );
    }
}
