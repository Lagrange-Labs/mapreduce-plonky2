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
    output_computation::compute_dummy_output_targets,
    universal_circuit::universal_query_gadget::{
        CurveOrU256Target, OutputValues, OutputValuesTarget, UniversalQueryOutputWires,
    },
};

use super::row_chunk_gadgets::{BoundaryRowDataTarget, RowChunkDataTarget};

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
    /// `MIN_secondary`: `u256` Lower bound of the range of secondary indexed column values specified in the query
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

/// Public inputs for the universal query circuit. They are mostly the same as `QueryPublicInputs`, the only
/// difference is that the query range on secondary index is replaced by the value of the indexed columns for
/// the columns being proven
pub enum QueryPublicInputsUniversalCircuit {
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
    /// Data associated to the left boundary row of the row chunk being proven; it is dummy in case of universal query 
    /// circuit, it is just empoyed to re-use the same public inputs
    LeftBoundaryRow,
    /// Data associated to the right boundary row of the row chunk being proven; it is dummy in case of universal query 
    /// circuit, it is just empoyed to re-use the same public inputs
    RightBoundaryRow,
    /// `MIN_primary`: `u256` Lower bound of the range of primary indexed column values specified in the query
    MinPrimary,
    /// `MAX_primary`: `u256` Upper bound of the range of primary indexed column values specified in the query
    MaxPrimary,
    /// Value of secondary indexed column for the row being proven
    SecondaryIndexValue,
    /// Value of primary indexed column for the row being proven
    PrimaryIndexValue,
    /// `overflow` : `bool` Flag specifying whether an overflow error has occurred in arithmetic
    Overflow,
    /// `C`: computational hash
    ComputationalHash,
    /// `H_p` : placeholder hash
    PlaceholderHash,
}

impl From<QueryPublicInputsUniversalCircuit> for QueryPublicInputs {
    fn from(value: QueryPublicInputsUniversalCircuit) -> Self {
        match value {
            QueryPublicInputsUniversalCircuit::TreeHash => QueryPublicInputs::TreeHash,
            QueryPublicInputsUniversalCircuit::OutputValues => QueryPublicInputs::OutputValues,
            QueryPublicInputsUniversalCircuit::NumMatching => QueryPublicInputs::NumMatching,
            QueryPublicInputsUniversalCircuit::OpIds => QueryPublicInputs::NumMatching,
            QueryPublicInputsUniversalCircuit::LeftBoundaryRow => QueryPublicInputs::LeftBoundaryRow,
            QueryPublicInputsUniversalCircuit::RightBoundaryRow => QueryPublicInputs::RightBoundaryRow,
            QueryPublicInputsUniversalCircuit::MinPrimary => QueryPublicInputs::MinPrimary,
            QueryPublicInputsUniversalCircuit::MaxPrimary => QueryPublicInputs::MaxPrimary,
            QueryPublicInputsUniversalCircuit::SecondaryIndexValue => QueryPublicInputs::MinSecondary,
            QueryPublicInputsUniversalCircuit::PrimaryIndexValue => QueryPublicInputs::MaxSecondary,
            QueryPublicInputsUniversalCircuit::Overflow => QueryPublicInputs::Overflow,
            QueryPublicInputsUniversalCircuit::ComputationalHash => QueryPublicInputs::ComputationalHash,
            QueryPublicInputsUniversalCircuit::PlaceholderHash => QueryPublicInputs::PlaceholderHash,
        }
    }
} 
/// Public inputs for generic query circuits
pub type PublicInputs<'a, T, const S: usize> = PublicInputsFactory<'a, T, S, false>;
/// Public inputs for universal query circuit
pub type PublicInputsUniversalCircuit<'a, T, const S: usize> = PublicInputsFactory<'a, T, S, true>;

/// This is the data structure employed for both public inputs of generic query circuits
/// and for public inputs of the universal circuit. Since the 2 public inputs are the
/// same, except for the semantic of 2 U256 elements, they can be represented by the
/// same data structure. The `UNIVERSAL_CIRCUIT` const generic is employed to
/// define 2 type aliases: 1 for public inputs of generic query circuits, and 1 for
/// public inputs of universal query circuit. The methods being common between the
/// 2 public inputs are implemented for this data structure, while the methods that
/// are specific to each public input type are implemented for the corresponding alias.
/// In this way, the methods implemented for the type alias define the correct semantics 
/// of each of the items in both types of public inputs. 
#[derive(Clone, Debug)]
pub struct PublicInputsFactory<'a, T, const S: usize, const UNIVERSAL_CIRCUIT: bool> {
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

impl<
    'a, 
    T: Clone, 
    const S: usize,
    const UNIVERSAL_CIRCUIT: bool,
> PublicInputsFactory<'a, T, S, UNIVERSAL_CIRCUIT> {
    const PI_RANGES: [PublicInputRange; NUM_PUBLIC_INPUTS] = [
        Self::to_range_internal(QueryPublicInputs::TreeHash),
        Self::to_range_internal(QueryPublicInputs::OutputValues),
        Self::to_range_internal(QueryPublicInputs::NumMatching),
        Self::to_range_internal(QueryPublicInputs::OpIds),
        Self::to_range_internal(QueryPublicInputs::LeftBoundaryRow),
        Self::to_range_internal(QueryPublicInputs::RightBoundaryRow),
        Self::to_range_internal(QueryPublicInputs::MinPrimary),
        Self::to_range_internal(QueryPublicInputs::MaxPrimary),
        Self::to_range_internal(QueryPublicInputs::MinSecondary),
        Self::to_range_internal(QueryPublicInputs::MaxSecondary),
        Self::to_range_internal(QueryPublicInputs::Overflow),
        Self::to_range_internal(QueryPublicInputs::ComputationalHash),
        Self::to_range_internal(QueryPublicInputs::PlaceholderHash),
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

    const fn to_range_internal(query_pi: QueryPublicInputs) -> PublicInputRange {
        let mut i = 0;
        let mut offset = 0;
        let pi_pos = query_pi as usize;
        while i < pi_pos {
            offset += Self::SIZES[i];
            i += 1;
        }
        offset..offset + Self::SIZES[pi_pos]
    }

    pub fn to_range<Q: Into<QueryPublicInputs>>(query_pi: Q) -> PublicInputRange 
    {
        Self::to_range_internal(query_pi.into())
    }

    pub(crate) const fn total_len() -> usize {
        Self::to_range_internal(QueryPublicInputs::PlaceholderHash).end
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

impl<const S: usize, const UNIVERSAL_CIRCUIT: bool> PublicInputCommon for PublicInputsFactory<'_, Target, S, UNIVERSAL_CIRCUIT> {
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

impl<const S: usize, const UNIVERSAL_CIRCUIT: bool> PublicInputsFactory<'_, Target, S, UNIVERSAL_CIRCUIT> {
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

    pub fn min_primary_target(&self) -> UInt256Target {
        UInt256Target::from_targets(self.to_min_primary_raw())
    }

    pub fn max_primary_target(&self) -> UInt256Target {
        UInt256Target::from_targets(self.to_max_primary_raw())
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

impl<const S: usize> PublicInputs<'_, Target, S> {
    pub(crate) fn left_boundary_row_target(&self) -> BoundaryRowDataTarget {
        BoundaryRowDataTarget::from_targets(self.to_left_row_raw())
    }

    pub(crate) fn right_boundary_row_target(&self) -> BoundaryRowDataTarget {
        BoundaryRowDataTarget::from_targets(self.to_right_row_raw())
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

    pub fn min_secondary_target(&self) -> UInt256Target {
        UInt256Target::from_targets(self.to_min_secondary_raw())
    }

    pub fn max_secondary_target(&self) -> UInt256Target {
        UInt256Target::from_targets(self.to_max_secondary_raw())
    }
}

impl<const S: usize> PublicInputsUniversalCircuit<'_, Target, S> {
    pub fn secondary_index_value_target(&self) -> UInt256Target {
        // secondary index value is found in `self.min_s` for 
        // `PublicInputsUniversalCircuit`
        UInt256Target::from_targets(self.min_s)
    }

    pub fn primary_index_value_target(&self) -> UInt256Target {
        // primary index value is found in `self.max_s` for 
        // `PublicInputsUniversalCircuit`
        UInt256Target::from_targets(self.max_s)
    }
}

impl<const S: usize, const UNIVERSAL_CIRCUIT: bool> PublicInputsFactory<'_, F, S, UNIVERSAL_CIRCUIT>
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

impl<const S: usize> PublicInputs<'_, F, S> {
    pub fn min_secondary(&self) -> U256 {
        U256::from_fields(self.to_min_secondary_raw())
    }

    pub fn max_secondary(&self) -> U256 {
        U256::from_fields(self.to_max_secondary_raw())
    }
}

impl<const S: usize> PublicInputsUniversalCircuit<'_, F, S> {
    pub fn secondary_index_value(&self) -> U256 {
        // secondary index value is found in `self.min_s` for 
        // `PublicInputsUniversalCircuit`
        U256::from_fields(self.min_s)
    }

    pub fn primary_index_value(&self) -> U256 {
        // primary index value is found in `self.max_s` for 
        // `PublicInputsUniversalCircuit`
        U256::from_fields(self.max_s)
    }
}

#[cfg(test)]
pub(crate) mod tests {
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

    use super::{PublicInputs, QueryPublicInputs};

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
