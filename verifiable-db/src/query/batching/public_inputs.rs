use std::iter::once;

use alloy::primitives::U256;
use itertools::Itertools;
use mp2_common::{
    public_inputs::{PublicInputCommon, PublicInputRange},
    types::CBuilder,
    u256::UInt256Target,
    utils::{FromFields, FromTargets, TryIntoBool},
    F,
};
use plonky2::{
    hash::hash_types::{HashOut, HashOutTarget},
    iop::target::{BoolTarget, Target},
};
use plonky2_ecgfp5::{curve::curve::WeierstrassPoint, gadgets::curve::CurveTarget};

use crate::query::{
    aggregation::output_computation::compute_dummy_output_targets,
    universal_circuit::universal_query_gadget::{
        CurveOrU256Target, OutputValues, OutputValuesTarget, UniversalQueryOutputWires,
    },
};

use super::row_chunk::{BoundaryRowDataTarget, RowChunkDataTarget};

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
    /// Data associated to the left boundary row of the row chunk being proven
    LeftBoundaryRow,
    /// Data associated to the right boundary row of the row chunk being proven
    RightBoundaryRow,
    /// `MIN_primary`: `u256` Lower bound of the range of primary indexed column values specified in the query
    MinPrimary,
    /// `MAX_primary`: `u256` Upper bound of the range of primary indexed column values specified in the query
    MaxPrimary,
    /// `MIN_primary`: `u256` Lower bound of the range of secondary indexed column values specified in the query
    MinSecondary,
    /// `MAX_secondary`: `u256` Upper bound of the range of secondary indexed column values specified in the query
    MaxSecondary,
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
    left_row: &'a [T],
    right_row: &'a [T],
    min_p: &'a [T],
    max_p: &'a [T],
    min_s: &'a [T],
    max_s: &'a [T],
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
        Self::to_range(QueryPublicInputs::LeftBoundaryRow),
        Self::to_range(QueryPublicInputs::RightBoundaryRow),
        Self::to_range(QueryPublicInputs::MinPrimary),
        Self::to_range(QueryPublicInputs::MaxPrimary),
        Self::to_range(QueryPublicInputs::MinSecondary),
        Self::to_range(QueryPublicInputs::MaxSecondary),
        Self::to_range(QueryPublicInputs::Overflow),
        Self::to_range(QueryPublicInputs::ComputationalHash),
        Self::to_range(QueryPublicInputs::PlaceholderHash),
    ];

    const SIZES: [usize; NUM_PUBLIC_INPUTS] = [
        // Tree hash
        HashOutTarget::NUM_TARGETS,
        // Output values
        CurveTarget::NUM_TARGETS + UInt256Target::NUM_TARGETS * (S - 1),
        // Number of matching records
        1,
        // Operation identifiers
        S,
        // Left boundary row
        BoundaryRowDataTarget::NUM_TARGETS,
        // Right boundary row
        BoundaryRowDataTarget::NUM_TARGETS,
        // Min primary index
        UInt256Target::NUM_TARGETS,
        // Max primary index
        UInt256Target::NUM_TARGETS,
        // Min secondary index
        UInt256Target::NUM_TARGETS,
        // Max secondary index
        UInt256Target::NUM_TARGETS,
        // Overflow flag
        1,
        // Computational hash
        HashOutTarget::NUM_TARGETS,
        // Placeholder hash
        HashOutTarget::NUM_TARGETS,
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

    pub(crate) fn to_left_row_raw(&self) -> &[T] {
        self.left_row
    }

    pub(crate) fn to_right_row_raw(&self) -> &[T] {
        self.right_row
    }

    pub(crate) fn to_min_primary_raw(&self) -> &[T] {
        self.min_p
    }

    pub(crate) fn to_max_primary_raw(&self) -> &[T] {
        self.max_p
    }

    pub(crate) fn to_min_secondary_raw(&self) -> &[T] {
        self.min_s
    }

    pub(crate) fn to_max_secondary_raw(&self) -> &[T] {
        self.max_s
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
            left_row: &input[Self::PI_RANGES[4].clone()],
            right_row: &input[Self::PI_RANGES[5].clone()],
            min_p: &input[Self::PI_RANGES[6].clone()],
            max_p: &input[Self::PI_RANGES[7].clone()],
            min_s: &input[Self::PI_RANGES[8].clone()],
            max_s: &input[Self::PI_RANGES[9].clone()],
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
        left_row: &'a [T],
        right_row: &'a [T],
        min_p: &'a [T],
        max_p: &'a [T],
        min_s: &'a [T],
        max_s: &'a [T],
        overflow: &'a [T],
        ch: &'a [T],
        ph: &'a [T],
    ) -> Self {
        Self {
            h,
            v,
            count: &count[0],
            ops,
            left_row,
            right_row,
            min_p,
            max_p,
            min_s,
            max_s,
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
            .chain(self.left_row.iter())
            .chain(self.right_row.iter())
            .chain(self.min_p.iter())
            .chain(self.max_p.iter())
            .chain(self.min_s.iter())
            .chain(self.max_s.iter())
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
        cb.register_public_inputs(self.left_row);
        cb.register_public_inputs(self.right_row);
        cb.register_public_inputs(self.min_p);
        cb.register_public_inputs(self.max_p);
        cb.register_public_inputs(self.min_s);
        cb.register_public_inputs(self.max_s);
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

    pub(crate) fn to_row_chunk_target(&self) -> RowChunkDataTarget<S>
    where
        [(); S - 1]:,
    {
        RowChunkDataTarget::<S> {
            left_boundary_row: self.left_boundary_row_target(),
            right_boundary_row: self.right_boundary_row_target(),
            chunk_outputs: UniversalQueryOutputWires {
                tree_hash: self.tree_hash_target(),
                values: OutputValuesTarget::from_targets(self.to_values_raw()),
                count: self.num_matching_rows_target(),
                num_overflows: self.overflow_flag_target().target,
            },
        }
    }

    /// Build an instance of `RowChunkDataTarget` from `self`; if `is_non_dummy_chunk` is
    /// `false`, then build an instance of `RowChunkDataTarget` for a dummy chunk
    pub(crate) fn to_dummy_row_chunk_target(
        &self,
        b: &mut CBuilder,
        is_non_dummy_chunk: BoolTarget,
    ) -> RowChunkDataTarget<S>
    where
        [(); S - 1]:,
    {
        let dummy_values = compute_dummy_output_targets(b, &self.operation_ids_target());
        let output_values = self
            .to_values_raw()
            .iter()
            .zip_eq(&dummy_values)
            .map(|(&value, &dummy_value)| b.select(is_non_dummy_chunk, value, dummy_value))
            .collect_vec();

        RowChunkDataTarget::<S> {
            left_boundary_row: self.left_boundary_row_target(),
            right_boundary_row: self.right_boundary_row_target(),
            chunk_outputs: UniversalQueryOutputWires {
                tree_hash: self.tree_hash_target(),
                values: OutputValuesTarget::from_targets(&output_values),
                // `count` is zeroed if chunk is dummy
                count: b.mul(self.num_matching_rows_target(), is_non_dummy_chunk.target),
                num_overflows: self.overflow_flag_target().target,
            },
        }
    }

    pub(crate) fn left_boundary_row_target(&self) -> BoundaryRowDataTarget {
        BoundaryRowDataTarget::from_targets(self.to_left_row_raw())
    }

    pub(crate) fn right_boundary_row_target(&self) -> BoundaryRowDataTarget {
        BoundaryRowDataTarget::from_targets(self.to_right_row_raw())
    }

    pub fn min_primary_target(&self) -> UInt256Target {
        UInt256Target::from_targets(self.to_min_primary_raw())
    }

    pub fn max_primary_target(&self) -> UInt256Target {
        UInt256Target::from_targets(self.to_max_primary_raw())
    }

    pub fn min_secondary_target(&self) -> UInt256Target {
        UInt256Target::from_targets(self.to_min_secondary_raw())
    }

    pub fn max_secondary_target(&self) -> UInt256Target {
        UInt256Target::from_targets(self.to_max_secondary_raw())
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

    pub fn min_primary(&self) -> U256 {
        U256::from_fields(self.to_min_primary_raw())
    }

    pub fn max_primary(&self) -> U256 {
        U256::from_fields(self.to_max_primary_raw())
    }

    pub fn min_secondary(&self) -> U256 {
        U256::from_fields(self.to_min_secondary_raw())
    }

    pub fn max_secondary(&self) -> U256 {
        U256::from_fields(self.to_max_secondary_raw())
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
pub(crate) mod tests {
    use std::array;

    use alloy::primitives::U256;
    use itertools::Itertools;
    use mp2_common::{array::ToField, public_inputs::PublicInputCommon, utils::ToFields, C, D, F};
    use mp2_test::{
        circuit::{run_circuit, UserCircuit},
        utils::{gen_random_field_hash, gen_random_u256, random_vector},
    };
    use plonky2::{
        field::types::{Field, Sample},
        iop::{
            target::Target,
            witness::{PartialWitness, WitnessWrite},
        },
        plonk::circuit_builder::CircuitBuilder,
    };
    use plonky2_ecgfp5::curve::curve::Point;
    use rand::{thread_rng, Rng};

    use crate::query::{
        aggregation::{QueryBoundSource, QueryBounds},
        batching::{public_inputs::QueryPublicInputs, row_chunk::tests::BoundaryRowData},
        computational_hash_ids::{AggregationOperation, Identifiers},
        universal_circuit::universal_circuit_inputs::Placeholders,
    };

    use super::{OutputValues, PublicInputs};

    /// Generate a set of values in a given range ensuring that the i+1-th generated value is
    /// bigger than the i-th generated value    
    pub(crate) fn gen_values_in_range<const N: usize, R: Rng>(
        rng: &mut R,
        lower: U256,
        upper: U256,
    ) -> [U256; N] {
        assert!(upper >= lower, "{upper} is smaller than {lower}");
        let mut prev_value = lower;
        array::from_fn(|_| {
            let range = (upper - prev_value).checked_add(U256::from(1));
            let gen_value = match range {
                Some(range) => prev_value + gen_random_u256(rng) % range,
                None => gen_random_u256(rng),
            };
            prev_value = gen_value;
            gen_value
        })
    }

    impl<const S: usize> PublicInputs<'_, F, S> {
        pub(crate) fn sample_from_ops<const NUM_INPUTS: usize>(ops: &[F; S]) -> [Vec<F>; NUM_INPUTS]
        where
            [(); S - 1]:,
        {
            let rng = &mut thread_rng();

            let tree_hash = gen_random_field_hash();
            let computational_hash = gen_random_field_hash();
            let placeholder_hash = gen_random_field_hash();
            let [min_primary, max_primary] = gen_values_in_range(rng, U256::ZERO, U256::MAX);
            let [min_secondary, max_secondary] = gen_values_in_range(rng, U256::ZERO, U256::MAX);

            let query_bounds = {
                let placeholders = Placeholders::new_empty(min_primary, max_primary);
                QueryBounds::new(
                    &placeholders,
                    Some(QueryBoundSource::Constant(min_secondary)),
                    Some(QueryBoundSource::Constant(max_secondary)),
                )
                .unwrap()
            };

            let is_first_op_id =
                ops[0] == Identifiers::AggregationOperations(AggregationOperation::IdOp).to_field();

            let mut previous_row: Option<BoundaryRowData> = None;
            array::from_fn(|_| {
                // generate output values
                let output_values = if is_first_op_id {
                    // generate random curve point
                    OutputValues::<S>::new_outputs_no_aggregation(&Point::sample(rng))
                } else {
                    let values = (0..S).map(|_| gen_random_u256(rng)).collect_vec();
                    OutputValues::<S>::new_aggregation_outputs(&values)
                };
                // generate random count and overflow flag
                let count = F::rand();
                let overflow = F::from_bool(rng.gen());
                // generate boundary rows
                let left_boundary_row = if let Some(row) = &previous_row {
                    row.sample_consecutive_row(rng, &query_bounds)
                } else {
                    BoundaryRowData::sample(rng, &query_bounds)
                };
                let right_boundary_row = BoundaryRowData::sample(rng, &query_bounds);
                assert!(
                    left_boundary_row.index_node_info.predecessor_info.value >= min_primary
                        && left_boundary_row.index_node_info.predecessor_info.value <= max_primary
                );
                assert!(
                    left_boundary_row.index_node_info.successor_info.value >= min_primary
                        && left_boundary_row.index_node_info.successor_info.value <= max_primary
                );
                assert!(
                    right_boundary_row.index_node_info.predecessor_info.value >= min_primary
                        && right_boundary_row.index_node_info.predecessor_info.value <= max_primary
                );
                assert!(
                    right_boundary_row.index_node_info.successor_info.value >= min_primary
                        && right_boundary_row.index_node_info.successor_info.value <= max_primary
                );
                previous_row = Some(right_boundary_row.clone());

                PublicInputs::<F, S>::new(
                    &tree_hash.to_fields(),
                    &output_values.to_fields(),
                    &[count],
                    ops,
                    &left_boundary_row.to_fields(),
                    &right_boundary_row.to_fields(),
                    &min_primary.to_fields(),
                    &max_primary.to_fields(),
                    &min_secondary.to_fields(),
                    &max_secondary.to_fields(),
                    &[overflow],
                    &computational_hash.to_fields(),
                    &placeholder_hash.to_fields(),
                )
                .to_vec()
            })
        }
    }

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
    fn test_batching_query_public_inputs() {
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
            &pis_raw[PublicInputs::<F, S>::to_range(QueryPublicInputs::LeftBoundaryRow)],
            pis.to_left_row_raw(),
        );
        assert_eq!(
            &pis_raw[PublicInputs::<F, S>::to_range(QueryPublicInputs::RightBoundaryRow)],
            pis.to_right_row_raw(),
        );
        assert_eq!(
            &pis_raw[PublicInputs::<F, S>::to_range(QueryPublicInputs::MinPrimary)],
            pis.to_min_primary_raw(),
        );
        assert_eq!(
            &pis_raw[PublicInputs::<F, S>::to_range(QueryPublicInputs::MaxPrimary)],
            pis.to_max_primary_raw(),
        );
        assert_eq!(
            &pis_raw[PublicInputs::<F, S>::to_range(QueryPublicInputs::MinSecondary)],
            pis.to_min_secondary_raw(),
        );
        assert_eq!(
            &pis_raw[PublicInputs::<F, S>::to_range(QueryPublicInputs::MaxSecondary)],
            pis.to_max_secondary_raw(),
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
