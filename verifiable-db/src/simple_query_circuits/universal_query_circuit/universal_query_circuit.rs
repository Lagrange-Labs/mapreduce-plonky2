use std::{fmt::Debug, iter::once};

use alloy::primitives::U256;
use itertools::Itertools;
use mp2_common::{
    poseidon::empty_poseidon_hash,
    public_inputs::PublicInputCommon,
    serialization::{deserialize, deserialize_long_array, serialize, serialize_long_array},
    types::CBuilder,
    u256::{CircuitBuilderU256, UInt256Target, WitnessWriteU256},
    utils::{SelectHashBuilder, ToTargets},
    CHasher, D, F,
};
use plonky2::{
    hash::hash_types::HashOutTarget,
    iop::{
        target::{BoolTarget, Target},
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::circuit_builder::CircuitBuilder,
};
use serde::{Deserialize, Serialize};

use crate::simple_query_circuits::{
    public_inputs::PublicInputs, universal_query_circuit::basic_operation::BasicOperationInputs,
};

use super::{
    basic_operation::{BasicOperationInputWires, BasicOperationWires},
    column_extraction::{ColumnExtractionInputWires, ColumnExtractionInputs},
};

#[derive(Clone, Debug, Serialize, Deserialize)]
/// Input wires for the universal query circuit
pub struct UniversalQueryCircuitWires<
    const MAX_NUM_COLUMNS: usize,
    const MAX_NUM_PREDICATE_OPS: usize,
    const MAX_NUM_RESULT_OPS: usize,
    const MAX_NUM_RESULTS: usize,
    T: OutputComponent,
> {
    /// Input wires for column extraction component
    column_extraction_wires: ColumnExtractionInputWires<MAX_NUM_COLUMNS>,
    /// flag specifying whether the given row is stored in a leaf node of a rows tree or not
    #[serde(serialize_with = "serialize", deserialize_with = "deserialize")]
    is_leaf: BoolTarget,
    /// Lower bound of the range for the secondary index specified in the query
    min_query: UInt256Target,
    /// Upper bound of the range for the secondary index specified in the query
    max_query: UInt256Target,
    /// Input wires for the `MAX_NUM_PREDICATE_OPS` basic operation components necessary
    /// to evaluate the filtering predicate
    #[serde(
        serialize_with = "serialize_long_array",
        deserialize_with = "deserialize_long_array"
    )]
    filtering_predicate_ops: [BasicOperationInputWires; MAX_NUM_PREDICATE_OPS],
    /// Input wires for the `MAX_NUM_RESULT_OPS` basic operation components necessary
    /// to compute the results for the current row
    #[serde(
        serialize_with = "serialize_long_array",
        deserialize_with = "deserialize_long_array"
    )]
    result_value_ops: [BasicOperationInputWires; MAX_NUM_RESULT_OPS],
    /// Input wires for the `MAX_NUM_RESULTS` output components that computes the
    /// output values for the current row
    output_component_wires: <T::Wires as OutputComponentWires>::InputWires,
}

/// Trait for the 2 different variants of output components we currently support
/// in query circuits
pub(crate) trait OutputComponent {
    type Wires: OutputComponentWires;

    fn build(
        b: &mut CBuilder,
        column_values: &[UInt256Target],
        column_hash: &[HashOutTarget],
        item_values: &[UInt256Target],
        item_hash: &[HashOutTarget],
        predicate_value: &BoolTarget,
        predicate_hash: &HashOutTarget,
    ) -> Self::Wires;

    fn assign(
        &self,
        pw: &mut PartialWitness<F>,
        wires: &<Self::Wires as OutputComponentWires>::InputWires,
    );
}
/// Trait representing the wires that need to be exposed by an `OutputComponent`
/// employed in query circuits
pub(crate) trait OutputComponentWires {
    /// Associated type specifying the type of the first output value computed by this output
    /// component; this type varies depending on the particular component:
    /// - It is a `CurveTarget` in the output component for queries without aggregation operations
    /// - It is a `UInt256Target` in the output for queries with aggregation operations
    type FirstT: ToTargets;
    /// Input wires of the output component
    type InputWires: Serialize + for<'a> Deserialize<'a> + Clone + Debug;

    /// Get the identifiers of the aggregation operations specified in the query to aggregate the
    /// results (e.g., `SUM`, `AVG`)
    fn get_ops_ids(&self) -> &[Target];
    /// Get the first output value returned by the output component; this is accessed by an ad-hoc
    /// method since such output value could be a `UInt256Target` or a `CurveTarget`, depending
    /// on the output component instance
    fn get_first_output_value(&self) -> Self::FirstT;
    /// Get the subsequent output values returned by the output component
    fn get_other_output_values(&self) -> &[UInt256Target];
    /// Get the computational hash returned by the output component
    fn get_computational_hash(&self) -> HashOutTarget;
    /// Get the input wires for the output component
    fn get_input_wires(&self) -> Self::InputWires;
}
/// Witness input values for the universal query circuit
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UniversalQueryCircuitInputs<
    const MAX_NUM_COLUMNS: usize,
    const MAX_NUM_PREDICATE_OPS: usize,
    const MAX_NUM_RESULT_OPS: usize,
    const MAX_NUM_RESULTS: usize,
    T: OutputComponent,
> {
    column_extraction_inputs: ColumnExtractionInputs<MAX_NUM_COLUMNS>,
    is_leaf: bool,
    min_query: U256,
    max_query: U256,
    #[serde(
        serialize_with = "serialize_long_array",
        deserialize_with = "deserialize_long_array"
    )]
    filtering_predicate_inputs: [BasicOperationInputs; MAX_NUM_PREDICATE_OPS],
    #[serde(
        serialize_with = "serialize_long_array",
        deserialize_with = "deserialize_long_array"
    )]
    result_values_inputs: [BasicOperationInputs; MAX_NUM_RESULT_OPS],
    output_component_inputs: T,
}

impl<
        const MAX_NUM_COLUMNS: usize,
        const MAX_NUM_PREDICATE_OPS: usize,
        const MAX_NUM_RESULT_OPS: usize,
        const MAX_NUM_RESULTS: usize,
        T: OutputComponent,
    >
    UniversalQueryCircuitInputs<
        MAX_NUM_COLUMNS,
        MAX_NUM_PREDICATE_OPS,
        MAX_NUM_RESULT_OPS,
        MAX_NUM_RESULTS,
        T,
    >
where
    [(); MAX_NUM_RESULTS - 1]:,
{
    pub(crate) fn build(
        b: &mut CircuitBuilder<F, D>,
    ) -> UniversalQueryCircuitWires<
        MAX_NUM_COLUMNS,
        MAX_NUM_PREDICATE_OPS,
        MAX_NUM_RESULT_OPS,
        MAX_NUM_RESULTS,
        T,
    > {
        let column_extraction_wires = ColumnExtractionInputs::<MAX_NUM_COLUMNS>::build(b);
        let is_leaf = b.add_virtual_bool_target_safe();
        let _true = b._true();
        let zero = b.zero();
        let one = b.one();
        // min and max for secondary indexed column
        let node_min = &column_extraction_wires.input_wires.column_values[1];
        let node_max = node_min;
        // column ids for primary and seconday indexed columns
        let (primary_index_id, second_index_id) = (
            &column_extraction_wires.input_wires.column_ids[0],
            &column_extraction_wires.input_wires.column_ids[1],
        );
        // value of the primary indexed column for the current row
        let index_value = &column_extraction_wires.input_wires.column_values[0];
        // compute hash of the node in case the current row is stored in a leaf of the rows tree
        let empty_hash = b.constant_hash(empty_poseidon_hash().clone());
        let leaf_hash_inputs = empty_hash
            .elements
            .iter()
            .chain(empty_hash.elements.iter())
            .chain(node_min.to_targets().iter())
            .chain(node_max.to_targets().iter())
            .chain(once(second_index_id))
            .chain(node_min.to_targets().iter())
            .chain(column_extraction_wires.tree_hash.elements.iter())
            .cloned()
            .collect();
        let leaf_hash = b.hash_n_to_hash_no_pad::<CHasher>(leaf_hash_inputs);
        let tree_hash = b.select_hash(is_leaf, &leaf_hash, &column_extraction_wires.tree_hash);
        // ensure that the value of second indexed column for the current record is in
        // the range specified by the query
        let min_query = b.add_virtual_u256();
        let max_query = b.add_virtual_u256();
        let less_than_max = b.is_less_or_equal_than_u256(node_max, &max_query);
        let greater_than_min = b.is_less_or_equal_than_u256(&min_query, node_min);
        b.connect(less_than_max.target, _true.target);
        b.connect(greater_than_min.target, _true.target);
        // initialize input_values and input_hash input vectors for basic operation components employed to
        // evaluate the filtering predicate
        let mut input_values = column_extraction_wires.input_wires.column_values.to_vec();
        let mut input_hash = column_extraction_wires.column_hash.to_vec();
        // initialize counter of overflows to 0
        let mut num_overflows = zero;
        // Set of input wires for each of the `MAX_NUM_PREDICATE_OPS` basic operation components employed to
        // evaluate the filtering predicate
        let mut filtering_predicate_wires = Vec::with_capacity(MAX_NUM_PREDICATE_OPS);
        // Payload to compute the placeholder hash public input
        let mut placeholder_hash_payload = vec![];
        for _ in 0..MAX_NUM_PREDICATE_OPS {
            let BasicOperationWires {
                input_wires,
                output_value,
                output_hash,
                num_overflows: new_num_overflows,
            } = BasicOperationInputs::build(b, &input_values, &input_hash, num_overflows);
            // add the output_value computed by the last basic operation component to the input values
            // for the next basic operation components employed to evaluate the filtering predicate
            input_values.push(output_value);
            // and the corresponding output_hash to the input hash as well
            input_hash.push(output_hash);
            // update the counter of overflows detected
            num_overflows = new_num_overflows;
            // add placeholder data to payload for placeholder hash
            placeholder_hash_payload.push(input_wires.placeholder_ids[0]);
            placeholder_hash_payload
                .extend_from_slice(&input_wires.placeholder_values[0].to_targets());
            placeholder_hash_payload.push(input_wires.placeholder_ids[1]);
            placeholder_hash_payload
                .extend_from_slice(&input_wires.placeholder_values[1].to_targets());
            filtering_predicate_wires.push(input_wires);
        }
        // Place the evaluation of the filtering predicate, and the corresponding computational hash, in
        // two variables; the evaluation and the corresponding hash are expected to be the output of the
        // last basic operation component among the `MAX_NUM_PREDICATE_OPS` ones employed to evaluate
        // the filtering predicate
        let predicate_value =
            BoolTarget::new_unsafe(*input_values.last().unwrap().to_targets().last().unwrap());
        b.assert_bool(predicate_value); // ToDo: might be redundant, but it's cheap
        let predicate_hash = input_hash.last().unwrap();
        // initialize input_values and input_hash input vectors for basic operation components employed to
        // compute the results to be returned for the current row
        let mut input_values = column_extraction_wires.input_wires.column_values.to_vec();
        let mut input_hash = column_extraction_wires.column_hash.to_vec();
        // Set of input wires for each of the `MAX_NUM_RESULT_OPS` basic operation components employed to
        // compute the results to be returned for the current row
        let mut result_value_wires = Vec::with_capacity(MAX_NUM_RESULT_OPS);
        for _ in 0..MAX_NUM_RESULT_OPS {
            let BasicOperationWires {
                input_wires,
                output_value,
                output_hash,
                num_overflows: new_num_overflows,
            } = BasicOperationInputs::build(b, &input_values, &input_hash, num_overflows);
            // add the output_value computed by the last basic operation component to the input values
            // for the next basic operation components employed to compute results for current row
            input_values.push(output_value);
            // and the corresponding output_hash to the input hash as well
            input_hash.push(output_hash);
            // update the counter of overflows detected
            num_overflows = new_num_overflows;
            // add placeholder data to payload for placeholder hash
            placeholder_hash_payload.push(input_wires.placeholder_ids[0]);
            placeholder_hash_payload
                .extend_from_slice(&input_wires.placeholder_values[0].to_targets());
            placeholder_hash_payload.push(input_wires.placeholder_ids[1]);
            placeholder_hash_payload
                .extend_from_slice(&input_wires.placeholder_values[1].to_targets());
            result_value_wires.push(input_wires);
        }
        // Place the results to be returned for the current row, and the corresponding computational hashes,
        // in the arrays `item_values` and `item_hash`; such results are expected to be found as the last
        // items computed by the last `MAX_NUM_RESULTS` basic operation components among the `MAX_NUM_RESULT_OPS`
        // ones employed to compute such results
        let item_values = &input_values[input_values.len() - MAX_NUM_RESULTS..];
        let item_hash = &input_hash[input_hash.len() - MAX_NUM_RESULTS..];
        let output_component_wires = T::build(
            b,
            column_extraction_wires.input_wires.column_values.as_slice(),
            &column_extraction_wires.column_hash.as_slice(),
            item_values,
            item_hash,
            &predicate_value,
            predicate_hash,
        );
        // counter of number of matching records, to be exposed as public input
        let count = b.select(predicate_value, one, zero);
        // compute overflow flag
        let not_overflow = b.is_equal(num_overflows, zero);
        let overflow = b.not(not_overflow);
        // placeholder_hash = H(H(placeholder_hash_payload) || min_query || max_query))
        let placeholder_hash = b.hash_n_to_hash_no_pad::<CHasher>(placeholder_hash_payload);
        let placeholder_hash = b.hash_n_to_hash_no_pad::<CHasher>(
            placeholder_hash
                .elements
                .iter()
                .chain(min_query.to_targets().iter())
                .chain(max_query.to_targets().iter())
                .cloned()
                .collect(),
        );
        // compute output_values to be exposed; we call `pad_slice_to_curve_len` to ensure that the
        // first output value is always padded to the size of a `CurveTarget`
        let mut output_values = PublicInputs::<_, MAX_NUM_RESULTS>::pad_slice_to_curve_len(
            &output_component_wires.get_first_output_value().to_targets(),
        );
        // Append the other `MAX_NUM_RESULTS-1` output values
        output_values.extend_from_slice(
            &output_component_wires
                .get_other_output_values()
                .into_iter()
                .flat_map(|t| t.to_targets())
                .collect_vec(),
        );
        PublicInputs::<Target, MAX_NUM_RESULTS>::new(
            &tree_hash.to_targets(),
            &output_values.as_slice(),
            &[count],
            output_component_wires.get_ops_ids(),
            &index_value.to_targets(),
            &node_min.to_targets(),
            &node_max.to_targets(),
            &[*primary_index_id, *second_index_id],
            &min_query.to_targets(),
            &max_query.to_targets(),
            &[overflow.target],
            &output_component_wires.get_computational_hash().to_targets(),
            &placeholder_hash.to_targets(),
        )
        .register(b);

        UniversalQueryCircuitWires {
            column_extraction_wires: column_extraction_wires.input_wires,
            is_leaf,
            min_query,
            max_query,
            filtering_predicate_ops: filtering_predicate_wires.try_into().unwrap(),
            result_value_ops: result_value_wires.try_into().unwrap(),
            output_component_wires: output_component_wires.get_input_wires(),
        }
    }

    pub(crate) fn assign(
        &self,
        pw: &mut PartialWitness<F>,
        wires: &UniversalQueryCircuitWires<
            MAX_NUM_COLUMNS,
            MAX_NUM_PREDICATE_OPS,
            MAX_NUM_RESULT_OPS,
            MAX_NUM_RESULTS,
            T,
        >,
    ) {
        self.column_extraction_inputs
            .assign(pw, &wires.column_extraction_wires);
        pw.set_bool_target(wires.is_leaf, self.is_leaf);
        pw.set_u256_target(&wires.min_query, self.min_query);
        pw.set_u256_target(&wires.max_query, self.max_query);
        self.filtering_predicate_inputs
            .iter()
            .zip(wires.filtering_predicate_ops.iter())
            .for_each(|(inputs, wires)| inputs.assign(pw, wires));
        self.result_values_inputs
            .iter()
            .zip(wires.result_value_ops.iter())
            .for_each(|(inputs, wires)| inputs.assign(pw, wires));
        self.output_component_inputs
            .assign(pw, &wires.output_component_wires);
    }
}
