use std::iter::once;

use crate::{CBuilder, F};
use alloy::primitives::U256;
use itertools::Itertools;
use mp2_common::{
    public_inputs::{PublicInputCommon, PublicInputRange},
    types::CURVE_TARGET_LEN,
    u256::{UInt256Target, NUM_LIMBS},
    utils::{FromFields, FromTargets, TryIntoBool},
};
use plonky2::{
    hash::hash_types::{HashOut, HashOutTarget, NUM_HASH_OUT_ELTS},
    iop::target::{BoolTarget, Target},
};
use plonky2_ecgfp5::{curve::curve::WeierstrassPoint, gadgets::curve::CurveTarget};

use crate::query::universal_circuit::universal_query_gadget::{
    CurveOrU256Target, OutputValues, OutputValuesTarget,
};

/// Query circuits public inputs
pub enum QueryPublicInputs {
    /// `H`: Hash of the tree
    TreeHash,
    /// `V`: Set of `S` values representing the cumulative results of the query, where`S` is a parameter
    /// specifying the maximum number of cumulative results we support;
    /// the first value could be either a `u256` or a `CurveTarget`, depending on the query, and so we always
    /// represent this value with `CURVE_TARGET_LEN` elements; all the other `S-1` values are always `u256`
    OutputValues,
    /// `count`: `F` Number of matching records in the query
    NumMatching,
    /// `ops` : `[F; S]` Set of identifiers of the aggregation operations for each of the `S` items found in `V`
    /// (like "SUM", "MIN", "MAX", "COUNT" operations)
    OpIds,
    /// `I` : `u256` value of the indexed column for the given node (meaningful only for rows tree nodes)
    IndexValue,
    /// `min` : `u256` Minimum value of the indexed column among all the records stored in the subtree rooted
    /// in the current node; values of secondary indexed column are employed for rows tree nodes,
    /// while values of primary indexed column are employed for index tree nodes
    MinValue,
    /// `max`` :  Maximum value of the indexed column among all the records stored in the subtree rooted
    /// in the current node; values of secondary indexed column are employed for rows tree nodes,
    /// while values of primary indexed column are employed for index tree nodes
    MaxValue,
    /// `index_ids`` : `[2]F` Identifiers of indexed columns
    IndexIds,
    /// `MIN_I`: `u256` Lower bound of the range of indexed column values specified in the query
    MinQuery,
    /// `MAX_I`: `u256` Upper bound of the range of indexed column values specified in the query
    MaxQuery,
    /// `overflow` : `bool` Flag specifying whether an overflow error has occurred in arithmetic
    Overflow,
    /// `C`: computational hash
    ComputationalHash,
    /// `H_p` : placeholder hash
    PlaceholderHash,
}

#[derive(Clone, Debug)]
pub struct PublicInputs<'a, T, const S: usize> {
    h: &'a [T],
    v: &'a [T],
    ops: &'a [T],
    count: &'a T,
    i: &'a [T],
    min: &'a [T],
    max: &'a [T],
    ids: &'a [T],
    min_q: &'a [T],
    max_q: &'a [T],
    overflow: &'a T,
    ch: &'a [T],
    ph: &'a [T],
}

const NUM_PUBLIC_INPUTS: usize = QueryPublicInputs::PlaceholderHash as usize + 1;

impl<'a, T: Clone, const S: usize> PublicInputs<'a, T, S> {
    const PI_RANGES: [PublicInputRange; NUM_PUBLIC_INPUTS] = [
        Self::to_range(QueryPublicInputs::TreeHash),
        Self::to_range(QueryPublicInputs::OutputValues),
        Self::to_range(QueryPublicInputs::NumMatching),
        Self::to_range(QueryPublicInputs::OpIds),
        Self::to_range(QueryPublicInputs::IndexValue),
        Self::to_range(QueryPublicInputs::MinValue),
        Self::to_range(QueryPublicInputs::MaxValue),
        Self::to_range(QueryPublicInputs::IndexIds),
        Self::to_range(QueryPublicInputs::MinQuery),
        Self::to_range(QueryPublicInputs::MaxQuery),
        Self::to_range(QueryPublicInputs::Overflow),
        Self::to_range(QueryPublicInputs::ComputationalHash),
        Self::to_range(QueryPublicInputs::PlaceholderHash),
    ];

    const SIZES: [usize; NUM_PUBLIC_INPUTS] = [
        // Tree hash
        NUM_HASH_OUT_ELTS,
        // Output values
        CURVE_TARGET_LEN + NUM_LIMBS * (S - 1),
        // Number of matching records
        1,
        // Operation identifiers
        S,
        // Index column value
        NUM_LIMBS,
        // Minimum indexed column value
        NUM_LIMBS,
        // Maximum indexed column value
        NUM_LIMBS,
        // Indexed column IDs
        2,
        // Lower bound for indexed column specified in query
        NUM_LIMBS,
        // Upper bound for indexed column specified in query
        NUM_LIMBS,
        // Overflow flag
        1,
        // Computational hash
        NUM_HASH_OUT_ELTS,
        // Placeholder hash
        NUM_HASH_OUT_ELTS,
    ];

    pub const fn to_range(query_pi: QueryPublicInputs) -> PublicInputRange {
        let mut i = 0;
        let mut offset = 0;
        let pi_pos = query_pi as usize;
        while i < pi_pos {
            offset += Self::SIZES[i];
            i += 1;
        }
        offset..offset + Self::SIZES[pi_pos]
    }

    pub(crate) const fn total_len() -> usize {
        Self::to_range(QueryPublicInputs::PlaceholderHash).end
    }

    pub(crate) fn to_hash_raw(&self) -> &[T] {
        self.h
    }

    pub(crate) fn to_values_raw(&self) -> &[T] {
        self.v
    }

    pub(crate) fn to_count_raw(&self) -> &T {
        self.count
    }

    pub(crate) fn to_ops_raw(&self) -> &[T] {
        self.ops
    }

    pub(crate) fn to_index_value_raw(&self) -> &[T] {
        self.i
    }

    pub(crate) fn to_min_value_raw(&self) -> &[T] {
        self.min
    }

    pub(crate) fn to_max_value_raw(&self) -> &[T] {
        self.max
    }

    pub(crate) fn to_index_ids_raw(&self) -> &[T] {
        self.ids
    }

    pub(crate) fn to_min_query_raw(&self) -> &[T] {
        self.min_q
    }

    pub(crate) fn to_max_query_raw(&self) -> &[T] {
        self.max_q
    }

    pub(crate) fn to_overflow_raw(&self) -> &T {
        self.overflow
    }

    pub(crate) fn to_computational_hash_raw(&self) -> &[T] {
        self.ch
    }

    pub(crate) fn to_placeholder_hash_raw(&self) -> &[T] {
        self.ph
    }

    pub fn from_slice(input: &'a [T]) -> Self {
        assert!(
            input.len() >= Self::total_len(),
            "input slice too short to build query public inputs, must be at least {} elements",
            Self::total_len()
        );
        Self {
            h: &input[Self::PI_RANGES[0].clone()],
            v: &input[Self::PI_RANGES[1].clone()],
            count: &input[Self::PI_RANGES[2].clone()][0],
            ops: &input[Self::PI_RANGES[3].clone()],
            i: &input[Self::PI_RANGES[4].clone()],
            min: &input[Self::PI_RANGES[5].clone()],
            max: &input[Self::PI_RANGES[6].clone()],
            ids: &input[Self::PI_RANGES[7].clone()],
            min_q: &input[Self::PI_RANGES[8].clone()],
            max_q: &input[Self::PI_RANGES[9].clone()],
            overflow: &input[Self::PI_RANGES[10].clone()][0],
            ch: &input[Self::PI_RANGES[11].clone()],
            ph: &input[Self::PI_RANGES[12].clone()],
        }
    }
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        h: &'a [T],
        v: &'a [T],
        count: &'a [T],
        ops: &'a [T],
        i: &'a [T],
        min: &'a [T],
        max: &'a [T],
        ids: &'a [T],
        min_q: &'a [T],
        max_q: &'a [T],
        overflow: &'a [T],
        ch: &'a [T],
        ph: &'a [T],
    ) -> Self {
        Self {
            h,
            v,
            count: &count[0],
            ops,
            i,
            min,
            max,
            ids,
            min_q,
            max_q,
            overflow: &overflow[0],
            ch,
            ph,
        }
    }

    pub fn to_vec(&self) -> Vec<T> {
        self.h
            .iter()
            .chain(self.v.iter())
            .chain(once(self.count))
            .chain(self.ops.iter())
            .chain(self.i.iter())
            .chain(self.min.iter())
            .chain(self.max.iter())
            .chain(self.ids.iter())
            .chain(self.min_q.iter())
            .chain(self.max_q.iter())
            .chain(once(self.overflow))
            .chain(self.ch.iter())
            .chain(self.ph.iter())
            .cloned()
            .collect_vec()
    }
}

impl<const S: usize> PublicInputCommon for PublicInputs<'_, Target, S> {
    const RANGES: &'static [PublicInputRange] = &Self::PI_RANGES;

    fn register_args(&self, cb: &mut CBuilder) {
        cb.register_public_inputs(self.h);
        cb.register_public_inputs(self.v);
        cb.register_public_input(*self.count);
        cb.register_public_inputs(self.ops);
        cb.register_public_inputs(self.i);
        cb.register_public_inputs(self.min);
        cb.register_public_inputs(self.max);
        cb.register_public_inputs(self.ids);
        cb.register_public_inputs(self.min_q);
        cb.register_public_inputs(self.max_q);
        cb.register_public_input(*self.overflow);
        cb.register_public_inputs(self.ch);
        cb.register_public_inputs(self.ph);
    }
}

impl<const S: usize> PublicInputs<'_, Target, S> {
    pub fn tree_hash_target(&self) -> HashOutTarget {
        HashOutTarget::try_from(self.to_hash_raw()).unwrap() // safe to unwrap as we know the slice has correct length
    }
    /// Return the first output value as a `CurveTarget`
    pub fn first_value_as_curve_target(&self) -> CurveTarget {
        let targets = self.to_values_raw();
        CurveOrU256Target::from_targets(targets).as_curve_target()
    }

    /// Return the first output value as a `UInt256Target`
    pub fn first_value_as_u256_target(&self) -> UInt256Target {
        let targets = self.to_values_raw();
        CurveOrU256Target::from_targets(targets).as_u256_target()
    }

    /// Return the `UInt256` targets for the last `S-1` values
    pub fn values_target(&self) -> [UInt256Target; S - 1] {
        OutputValuesTarget::from_targets(self.to_values_raw()).other_outputs
    }

    /// Return the value as a `UInt256Target` at the specified index
    pub fn value_target_at_index(&self, i: usize) -> UInt256Target
    where
        [(); S - 1]:,
    {
        OutputValuesTarget::from_targets(self.to_values_raw()).value_target_at_index(i)
    }

    pub fn num_matching_rows_target(&self) -> Target {
        *self.to_count_raw()
    }

    pub fn operation_ids_target(&self) -> [Target; S] {
        self.to_ops_raw().try_into().unwrap()
    }

    pub fn index_value_target(&self) -> UInt256Target {
        UInt256Target::from_targets(self.to_index_value_raw())
    }

    pub fn min_value_target(&self) -> UInt256Target {
        UInt256Target::from_targets(self.to_min_value_raw())
    }

    pub fn max_value_target(&self) -> UInt256Target {
        UInt256Target::from_targets(self.to_max_value_raw())
    }

    pub fn index_ids_target(&self) -> [Target; 2] {
        self.to_index_ids_raw().try_into().unwrap()
    }

    pub fn min_query_target(&self) -> UInt256Target {
        UInt256Target::from_targets(self.to_min_query_raw())
    }

    pub fn max_query_target(&self) -> UInt256Target {
        UInt256Target::from_targets(self.to_max_query_raw())
    }

    pub fn overflow_flag_target(&self) -> BoolTarget {
        BoolTarget::new_unsafe(*self.to_overflow_raw())
    }

    pub fn computational_hash_target(&self) -> HashOutTarget {
        HashOutTarget::try_from(self.to_computational_hash_raw()).unwrap() // safe to unwrap as we know the slice has correct length
    }

    pub fn placeholder_hash_target(&self) -> HashOutTarget {
        HashOutTarget::try_from(self.to_placeholder_hash_raw()).unwrap() // safe to unwrap as we know the slice has correct length
    }
}

impl<const S: usize> PublicInputs<'_, F, S>
where
    [(); S - 1]:,
{
    pub fn tree_hash(&self) -> HashOut<F> {
        HashOut::try_from(self.to_hash_raw()).unwrap() // safe to unwrap as we know the slice has correct length
    }

    pub fn first_value_as_curve_point(&self) -> WeierstrassPoint {
        OutputValues::<S>::from_fields(self.to_values_raw()).first_value_as_curve_point()
    }

    pub fn first_value_as_u256(&self) -> U256 {
        OutputValues::<S>::from_fields(self.to_values_raw()).first_value_as_u256()
    }

    pub fn values(&self) -> [U256; S - 1] {
        OutputValues::<S>::from_fields(self.to_values_raw()).other_outputs
    }

    /// Return the value as a UInt256 at the specified index
    pub fn value_at_index(&self, i: usize) -> U256
    where
        [(); S - 1]:,
    {
        OutputValues::<S>::from_fields(self.to_values_raw()).value_at_index(i)
    }

    pub fn num_matching_rows(&self) -> F {
        *self.to_count_raw()
    }

    pub fn operation_ids(&self) -> [F; S] {
        self.to_ops_raw().try_into().unwrap()
    }

    pub fn index_value(&self) -> U256 {
        U256::from_fields(self.to_index_value_raw())
    }

    pub fn min_value(&self) -> U256 {
        U256::from_fields(self.to_min_value_raw())
    }

    pub fn max_value(&self) -> U256 {
        U256::from_fields(self.to_max_value_raw())
    }

    pub fn index_ids(&self) -> [F; 2] {
        self.to_index_ids_raw().try_into().unwrap()
    }

    pub fn min_query_value(&self) -> U256 {
        U256::from_fields(self.to_min_query_raw())
    }

    pub fn max_query_value(&self) -> U256 {
        U256::from_fields(self.to_max_query_raw())
    }

    pub fn overflow_flag(&self) -> bool {
        (*self.to_overflow_raw())
            .try_into_bool()
            .expect("overflow flag public input different from 0 or 1")
    }

    pub fn computational_hash(&self) -> HashOut<F> {
        HashOut::try_from(self.to_computational_hash_raw()).unwrap() // safe to unwrap as we know the slice has correct length
    }

    pub fn placeholder_hash(&self) -> HashOut<F> {
        HashOut::try_from(self.to_placeholder_hash_raw()).unwrap() // safe to unwrap as we know the slice has correct length
    }
}

#[cfg(test)]
mod tests {

    use crate::{C, D, F};
    use mp2_common::{public_inputs::PublicInputCommon, utils::ToFields};
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

    use super::QueryPublicInputs;

    use super::PublicInputs;

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
    fn test_query_public_inputs() {
        let pis_raw: Vec<F> = random_vector::<u32>(PublicInputs::<F, S>::total_len()).to_fields();
        let pis = PublicInputs::<F, S>::from_slice(pis_raw.as_slice());
        // check public inputs are constructed correctly
        assert_eq!(
            &pis_raw[PublicInputs::<F, S>::to_range(QueryPublicInputs::TreeHash)],
            pis.to_hash_raw(),
        );
        assert_eq!(
            &pis_raw[PublicInputs::<F, S>::to_range(QueryPublicInputs::OutputValues)],
            pis.to_values_raw(),
        );
        assert_eq!(
            &pis_raw[PublicInputs::<F, S>::to_range(QueryPublicInputs::NumMatching)],
            &[*pis.to_count_raw()],
        );
        assert_eq!(
            &pis_raw[PublicInputs::<F, S>::to_range(QueryPublicInputs::OpIds)],
            pis.to_ops_raw(),
        );
        assert_eq!(
            &pis_raw[PublicInputs::<F, S>::to_range(QueryPublicInputs::IndexValue)],
            pis.to_index_value_raw(),
        );
        assert_eq!(
            &pis_raw[PublicInputs::<F, S>::to_range(QueryPublicInputs::MinValue)],
            pis.to_min_value_raw(),
        );
        assert_eq!(
            &pis_raw[PublicInputs::<F, S>::to_range(QueryPublicInputs::MaxValue)],
            pis.to_max_value_raw(),
        );
        assert_eq!(
            &pis_raw[PublicInputs::<F, S>::to_range(QueryPublicInputs::MinQuery)],
            pis.to_min_query_raw(),
        );
        assert_eq!(
            &pis_raw[PublicInputs::<F, S>::to_range(QueryPublicInputs::MaxQuery)],
            pis.to_max_query_raw(),
        );
        assert_eq!(
            &pis_raw[PublicInputs::<F, S>::to_range(QueryPublicInputs::IndexIds)],
            pis.to_index_ids_raw(),
        );
        assert_eq!(
            &pis_raw[PublicInputs::<F, S>::to_range(QueryPublicInputs::Overflow)],
            &[*pis.to_overflow_raw()],
        );
        assert_eq!(
            &pis_raw[PublicInputs::<F, S>::to_range(QueryPublicInputs::ComputationalHash)],
            pis.to_computational_hash_raw(),
        );
        assert_eq!(
            &pis_raw[PublicInputs::<F, S>::to_range(QueryPublicInputs::PlaceholderHash)],
            pis.to_placeholder_hash_raw(),
        );
        // use public inputs in circuit
        let test_circuit = TestPublicInputs { pis: &pis_raw };
        let proof = run_circuit::<F, D, C, _>(test_circuit);
        assert_eq!(proof.public_inputs, pis_raw);
    }
}
