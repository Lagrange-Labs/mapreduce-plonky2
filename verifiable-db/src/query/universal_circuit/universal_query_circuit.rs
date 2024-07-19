use std::{fmt::Debug, iter::{once, repeat}};

use alloy::primitives::U256;
use itertools::Itertools;
use mp2_common::{
    array::ToField, poseidon::empty_poseidon_hash, public_inputs::PublicInputCommon, serialization::{deserialize, deserialize_long_array, serialize, serialize_long_array}, types::CBuilder, u256::{CircuitBuilderU256, UInt256Target, WitnessWriteU256}, utils::{SelectHashBuilder, ToFields, ToTargets}, CHasher, D, F
};
use plonky2::{
    field::types::Field, gadgets::arithmetic, hash::{hash_types::{HashOut, HashOutTarget}, hashing::hash_n_to_hash_no_pad}, iop::{
        target::{BoolTarget, Target},
        witness::{PartialWitness, WitnessWrite},
    }, plonk::{circuit_builder::CircuitBuilder, config::GenericHashOut}
};
use serde::{Deserialize, Serialize};

use crate::query::{
    computational_hash_ids::{HashPermutation, Operation}, public_inputs::PublicInputs, universal_circuit::basic_operation::BasicOperationInputs
};

use super::{
    basic_operation::{BasicOperationInputWires, BasicOperationWires},
    column_extraction::{ColumnExtractionInputWires, ColumnExtractionInputs},
};
use anyhow::{ensure, Result};

#[derive(Clone, Copy, Debug)]
/// Data structure representing a placeholder in the query, given by its value and its identifier
pub(crate) struct Placeholder {
    value: U256,
    id: F,
}
#[derive(Clone, Copy, Debug)]
/// Enumeration representing all the possible types of input operands for a basic operation
pub(crate) enum InputOperand {
    // Input operand is a placeholder in the query
    Placeholder(Placeholder),
    // Input operand is a constant value in the query
    Constant(U256),
    /// Input operand is a column of the table
    Column(usize),
    /// Input operand is the output of a previous basic operation
    PreviousValue(usize),
}
#[derive(Clone, Copy, Debug)]
pub(crate) struct BasicOperation {
    first_operand: InputOperand,
    /// Can be None in case of unary operation
    second_operand: Option<InputOperand>,
    op: Operation,
}

impl BasicOperation {
    /// Compute the results of the `operations` provided as input, employing the provided 
    /// `column_values` as the operands for the operations having `InputOperand::Column`
    /// operands. The method returns also a flag which specifies if an arithemtic error 
    /// has occurred throughout any of these operations
    pub(crate) fn compute_operations(
        operations: &[Self],
        column_values: &[U256],     
    ) -> Result<(Vec<U256>, bool)> {
        let mut results = Vec::with_capacity(operations.len());
        let mut arithmetic_error = false;
        let num_columns = column_values.len(); 
        for (i, op) in operations.into_iter().enumerate() {
            let get_input_value = |operand| {
                Ok(
                    match operand {
                        &InputOperand::Placeholder(p) => p.value,
                        &InputOperand::Constant(v) => v,
                        &InputOperand::Column(index) => {
                            ensure!(index < num_columns,
                                "invalid input operation: column index out of range for operation {}", i);
                            column_values[index]
                        },
                        &InputOperand::PreviousValue(index) => {
                            ensure!(index < results.len(),
                                "invalid input operation: accessing a value that has not been computed yet in operation {}", i);
                            results[index]
                        },
                    }
                )
            };
            let first_input = get_input_value(&op.first_operand)?;
            let second_input = op.second_operand.as_ref().map(|operand|
                get_input_value(operand)
            ).unwrap_or( 
                // op.second_operand = None means it's a unary operation, so we can choose a dummy input value
                Ok(U256::ZERO)
            )?;
            let result = match op.op {
                Operation::AddOp => {
                    let (res, overflow) = first_input.overflowing_add(second_input);
                    arithmetic_error |= overflow;
                    res
                },
                Operation::SubOp => {
                    let (res, overflow) = first_input.overflowing_sub(second_input);
                    arithmetic_error |= overflow;
                    res
                },
                Operation::MulOp => {
                    let (res, overflow) = first_input.overflowing_mul(second_input);
                    arithmetic_error |= overflow;
                    res
                },
                Operation::DivOp => {
                    arithmetic_error |= second_input.is_zero();
                    first_input.div_rem(second_input).0
                },
                Operation::ModOp => {
                    arithmetic_error |= second_input.is_zero();
                    first_input.div_rem(second_input).1
                },
                Operation::LessThanOp => U256::from(
                    (first_input < second_input) as u8 
                ),
                Operation::EqOp => U256::from(
                    (first_input == second_input) as u8 
                ),
                Operation::NeOp => U256::from(
                    (first_input != second_input) as u8 
                ),
                Operation::GreaterThanOp => U256::from(
                    (first_input > second_input) as u8 
                ),
                Operation::LessThanOrEqOp => U256::from(
                    (first_input <= second_input) as u8 
                ),
                Operation::GreaterThanOrEqOp => U256::from(
                    (first_input >= second_input) as u8 
                ),
                Operation::AndOp => {
                    ensure!(first_input.is_zero() || first_input == U256::from(1), 
                        "first input value to AND op is not Boolean for operation {}", i);
                    ensure!(second_input.is_zero() || second_input == U256::from(1), 
                        "second input value to AND op is not Boolean for operation {}", i);
                    first_input*second_input
                },
                Operation::OrOp => {
                    ensure!(first_input.is_zero() || first_input == U256::from(1), 
                        "first input value to OR op is not Boolean for operation {}", i);
                    ensure!(second_input.is_zero() || second_input == U256::from(1), 
                        "second input value to OR op is not Boolean for operation {}", i);
                    first_input + second_input - first_input*second_input 
                },
                Operation::NotOp => {
                    ensure!(first_input.is_zero() || first_input == U256::from(1), 
                        "input value to NOT op is not Boolean for operation {}", i);
                    U256::from(1) - first_input
                },
                Operation::XorOp => {
                    ensure!(first_input.is_zero() || first_input == U256::from(1), 
                        "first input value to XOR op is not Boolean for operation {}", i);
                    ensure!(second_input.is_zero() || second_input == U256::from(1), 
                        "secondinput value to XOR op is not Boolean for operation {}", i);
                    first_input + second_input - U256::from(2)*first_input*second_input
                },
            };
            results.push(result);
        }

        Ok((
            results,
            arithmetic_error,
        ))
    }
}

#[derive(Clone, Copy, Debug)]
/// Enumeration representing the type of output values that can be returned for each row
pub(crate) enum OutputItem {
    /// Output value is a column of the table
    Column(usize),
    /// Output value is computed in one of the `MAX_NUM_RESULT_OPS` operations
    ComputedValue,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
/// Input wires for the universal query circuit
pub struct UniversalQueryCircuitWires<
    const MAX_NUM_COLUMNS: usize,
    const MAX_NUM_PREDICATE_OPS: usize,
    const MAX_NUM_RESULT_OPS: usize,
    const MAX_NUM_RESULTS: usize,
    T: OutputComponent<MAX_NUM_RESULTS>,
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
pub(crate) trait OutputComponent<const MAX_NUM_RESULTS: usize>: Clone {
    type Wires: OutputComponentWires;

    fn new(
        selector: &[F],
        ids: &[F],
        num_outputs: usize,
    ) -> Result<Self>;

    fn build(
        b: &mut CBuilder,
        column_values: &[UInt256Target],
        column_hash: &[HashOutTarget],
        item_values: [UInt256Target; MAX_NUM_RESULTS],
        item_hash: [HashOutTarget; MAX_NUM_RESULTS],
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
    fn ops_ids(&self) -> &[Target];
    /// Get the first output value returned by the output component; this is accessed by an ad-hoc
    /// method since such output value could be a `UInt256Target` or a `CurveTarget`, depending
    /// on the output component instance
    fn first_output_value(&self) -> Self::FirstT;
    /// Get the subsequent output values returned by the output component
    fn other_output_values(&self) -> &[UInt256Target];
    /// Get the computational hash returned by the output component
    fn computational_hash(&self) -> HashOutTarget;
    /// Get the input wires for the output component
    fn input_wires(&self) -> Self::InputWires;
}
/// Witness input values for the universal query circuit
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UniversalQueryCircuitInputs<
    const MAX_NUM_COLUMNS: usize,
    const MAX_NUM_PREDICATE_OPS: usize,
    const MAX_NUM_RESULT_OPS: usize,
    const MAX_NUM_RESULTS: usize,
    T: OutputComponent<MAX_NUM_RESULTS>,
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
        T: OutputComponent<MAX_NUM_RESULTS>,
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
    /// Instantiate `Self` from the necessary inputs. Note that the following assumptions are expected on the
    /// structure of the inputs:
    /// - The output of the last operation in `predicate_operations` will be taken as the filtering predicate evaluation
    /// - The last `n` operations in `result_operations` are employed as the output values of the corresponding `n`
    ///   `OutputItem::ComputedValue` found in `output_items`
    pub(crate) fn new(
        column_values: &[U256],
        column_ids: &[F],
        predicate_operations: &[BasicOperation],
        result_operations: &[BasicOperation],
        is_leaf: bool,
        min_query: U256,
        max_query: U256,
        output_items: &[OutputItem],
        output_ids: &[F],
    ) -> Result<Self> {
        let num_columns = column_values.len();
        ensure!(column_ids.len() == num_columns, 
            "column_ids and column_values have different length");
        ensure!(num_columns <= MAX_NUM_COLUMNS,
            "number of columns is higher than the maximum value allowed");
        let padded_column_values = column_values.into_iter()
            .chain(repeat(&U256::ZERO))
            .take(MAX_NUM_COLUMNS)
            .cloned()
            .collect_vec();
        let padded_column_ids = column_ids.into_iter()
            .chain(repeat(&F::NEG_ONE))
            .take(MAX_NUM_COLUMNS)
            .cloned()
            .collect_vec();
        let column_extraction_inputs = ColumnExtractionInputs::<MAX_NUM_COLUMNS> {
            real_num_columns: num_columns,
            column_values: padded_column_values.try_into().unwrap(),
            column_ids: padded_column_ids.try_into().unwrap(),
        };
        let num_predicate_ops = predicate_operations.len();
        ensure!(num_predicate_ops <= MAX_NUM_PREDICATE_OPS,
            "Number of operations to compute filtering predicate is higher than the maximum number allowed");
        let num_result_ops = result_operations.len();
            ensure!(num_result_ops <= MAX_NUM_RESULT_OPS,
                "Number of operations to compute results is higher than the maximum number allowed");
        let default_placeholder = Self::compute_default_placeholder(
            predicate_operations.iter().chain(result_operations.iter())
        );
        let predicate_ops_inputs = Self::compute_operation_inputs::<MAX_NUM_PREDICATE_OPS>(
            predicate_operations, 
            &default_placeholder
        )?;
        let result_ops_inputs = Self::compute_operation_inputs::<MAX_NUM_RESULT_OPS>(
            result_operations, 
            &default_placeholder
        )?;
        let selectors = output_items.into_iter().enumerate().map(|(i, item)| {
            Ok(
                match item {
                    &OutputItem::Column(index) => {
                        ensure!(index < MAX_NUM_COLUMNS,
                        "Column index provided as {}-th output value is higher than the maximum number of columns", i);
                    F::from_canonical_usize(index)
                    },
                    &OutputItem::ComputedValue => F::from_canonical_usize(MAX_NUM_COLUMNS),
            })
        }).collect::<Result<Vec<_>>>()?;
        let output_component_inputs = T::new(
            &selectors, 
            output_ids, 
            output_ids.len(),
        )?;
        

        Ok(
            Self {
                column_extraction_inputs,
                is_leaf,
                min_query,
                max_query,
                filtering_predicate_inputs: predicate_ops_inputs,
                result_values_inputs: result_ops_inputs,
                output_component_inputs,
            })
    }
    
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
        let empty_hash = b.constant_hash(*empty_poseidon_hash());
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
        let predicate_value = input_values.last().unwrap().to_bool_target();
        //b.assert_bool(predicate_value); // ToDo: might be redundant, but it's cheap
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
        let item_values = input_values[input_values.len() - MAX_NUM_RESULTS..]
            .to_vec()
            .try_into()
            .unwrap();
        let item_hash = input_hash[input_hash.len() - MAX_NUM_RESULTS..]
            .to_vec()
            .try_into()
            .unwrap();
        let output_component_wires = T::build(
            b,
            column_extraction_wires.input_wires.column_values.as_slice(),
            column_extraction_wires.column_hash.as_slice(),
            item_values,
            item_hash,
            &predicate_value,
            predicate_hash,
        );
        // counter of number of matching records, to be exposed as public input
        //let count = b.select(predicate_value, one, zero);
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
            &output_component_wires.first_output_value().to_targets(),
        );
        // Append the other `MAX_NUM_RESULTS-1` output values
        output_values.extend_from_slice(
            &output_component_wires
                .other_output_values()
                .iter()
                .flat_map(|t| t.to_targets())
                .collect_vec(),
        );
        PublicInputs::<Target, MAX_NUM_RESULTS>::new(
            &tree_hash.to_targets(),
            &output_values.as_slice(),
            &[predicate_value.target],
            output_component_wires.ops_ids(),
            &index_value.to_targets(),
            &node_min.to_targets(),
            &node_max.to_targets(),
            &[*primary_index_id, *second_index_id],
            &min_query.to_targets(),
            &max_query.to_targets(),
            &[overflow.target],
            &output_component_wires.computational_hash().to_targets(),
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
            output_component_wires: output_component_wires.input_wires(),
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

    /// Compute the placeholder hash for the given instance of `self`
    pub(crate) fn compute_placeholder_hash(
        &self
    ) -> HashOut<F> {
        let inputs = self.filtering_predicate_inputs.iter().flat_map(|op_inputs| {
            once(op_inputs.placeholder_ids[0])
            .chain(op_inputs.placeholder_values[0].to_fields())
            .chain(once(op_inputs.placeholder_ids[1]))
            .chain(op_inputs.placeholder_values[1].to_fields())
            .collect_vec()
        }).chain(
            self.result_values_inputs.iter().flat_map(|op_inputs| {
                once(op_inputs.placeholder_ids[0])
                .chain(op_inputs.placeholder_values[0].to_fields())
                .chain(once(op_inputs.placeholder_ids[1]))
                .chain(op_inputs.placeholder_values[1].to_fields())
                .collect_vec()
            })
        ).collect_vec();
        let placeholders_hash = hash_n_to_hash_no_pad::<_, HashPermutation>(&inputs);
        // add query bounds to placeholder hash
        hash_n_to_hash_no_pad::<_, HashPermutation>(&
            placeholders_hash.to_vec().into_iter()
            .chain(self.min_query.to_fields())
            .chain(self.max_query.to_fields())
            .collect_vec()
        )
    } 
    
    /// Compute the default placeholder to be employed as placeholder operand when an operation operand is not 
    /// a placeholder
    fn compute_default_placeholder<'a, OpIter: Iterator<Item = &'a BasicOperation>>(
        mut operations: OpIter,
    ) -> Placeholder {
        operations.find_map(|op| {
            match op.first_operand {
                InputOperand::Placeholder(p) => return Some(p),
                _ => (),
            };
            if let Some(op) = &op.second_operand {
                match op {
                    &InputOperand::Placeholder(p) => Some(p),
                    _ => None,
                }
            } else {
                None
            }
        }).unwrap_or(
            // in this case, no placeholder is employed in the query at all, so we can just return a dummy value
            Placeholder {
                value: U256::ZERO,
                id: F::NEG_ONE,
            }
        )
    }

    /// Utility function to compute the `BasicOperationInputs` corresponding to the set of `operations` specified
    /// as input. The set of `BasicOperationInputs` is padded to `MAX_NUM_OPS` with dummy operations, which is
    /// the expected number of operations expected as input by the circuit.
    fn compute_operation_inputs<
        const MAX_NUM_OPS: usize
    >(
        operations: &[BasicOperation],
        default_placeholder: &Placeholder,
    ) -> Result<[BasicOperationInputs; MAX_NUM_OPS]> {
        // starting offset in the input values provided to basic operation component where the output values
        // of `operations` will be found. It is computed as follows since these operations will be placed
        // at the end of these functions in the last slots among the `MAX_NUM_OPS` available, as expected
        // by the circuit
        let start_actual_ops = MAX_NUM_COLUMNS + MAX_NUM_OPS - operations.len();
        let ops_wires = operations.into_iter().enumerate().map(|(i, op)| {
            let mut constant_operand = U256::ZERO;
            // the number of input values provided to the basic operation component 
            // computing the current predicate operation
            let num_inputs = start_actual_ops + i;
            let mut compute_op_inputs = |is_first_op: bool| {
                let operand = if is_first_op {
                    &op.first_operand
                } else {
                    if let Some(operand) = &op.second_operand {
                        operand
                    } else {
                        // There is no second operand in this operation since it is a unary operation, 
                        // so just use a dummy one
                        &InputOperand::Column(0)
                    }
                };
                Ok(
                match operand {
                    &InputOperand::Placeholder(p) => (
                        Some(p.value),
                        Some(p.id),
                        if is_first_op {
                            BasicOperationInputs::first_placeholder_offset(num_inputs)
                        } else {
                            BasicOperationInputs::second_placeholder_offset(num_inputs)
                        },
                    ),
                    &InputOperand::Constant(val) => {
                        constant_operand = val;
                        (
                            None,
                            None,
                            BasicOperationInputs::constant_operand_offset(num_inputs),
                        )
                    },
                    &InputOperand::Column(index) => {
                        ensure!(index < MAX_NUM_COLUMNS, 
                            "column index specified as input for {}-th predicate operation is higher than number of columns", i);
                        (
                            None,
                            None,
                            BasicOperationInputs::input_value_offset(index),
                        )
                    },
                    &InputOperand::PreviousValue(index) => {
                        ensure!(index < i,
                            "previous value index specified as input for {}-th predicate operation is higher than the number of values already computed by previous operations", i);
                        (
                            None,
                            None,
                            BasicOperationInputs::input_value_offset(start_actual_ops+index),
                        )    
                    },
                }
            )};
            let (first_placeholder_value, first_placeholder_id, first_selector) = compute_op_inputs(
                true
            )?;
            let (second_placeholder_value, second_placeholder_id, second_selector) = compute_op_inputs(
                false
            )?;
            let placeholder_values = [
                first_placeholder_value.unwrap_or(default_placeholder.value),
                second_placeholder_value.unwrap_or(default_placeholder.value)
            ];
            let placeholder_ids = [
                first_placeholder_id.unwrap_or(default_placeholder.id),
                second_placeholder_id.unwrap_or(default_placeholder.id),
            ];
            Ok(BasicOperationInputs {
                constant_operand,
                placeholder_values,
                placeholder_ids,
                first_input_selector: F::from_canonical_usize(first_selector),
                second_input_selector: F::from_canonical_usize(second_selector),
                op_selector: op.op.to_field(),
            })
        }).collect::<Result<Vec<_>>>()?;
        // we pad ops_wires up to `MAX_NUM_OPS` with dummy operations; we pad at
        // the beginning of the array since the circuits expects to find the operation computing
        // the actual result values as the last of the `MAX_NUM_OPS` operations 
        Ok(repeat(
            // dummy operation
        BasicOperationInputs {
                constant_operand: U256::ZERO,
                placeholder_values: [default_placeholder.value, default_placeholder.value],
                placeholder_ids: [default_placeholder.id, default_placeholder.id],
                first_input_selector: F::ZERO,
                second_input_selector: F::ZERO,
                op_selector: Operation::EqOp.to_field(),
            }
        ).take(MAX_NUM_OPS - operations.len())
        .chain(ops_wires.into_iter())
        .collect_vec().try_into().unwrap())
    }
}

#[cfg(test)]
mod tests {
    use std::iter::once;

    use alloy::primitives::U256;
    use itertools::Itertools;
    use mp2_common::{array::ToField, poseidon::empty_poseidon_hash, utils::ToFields, C, D, F};
    use mp2_test::{cells_tree::{compute_cells_tree_hash, TestCell}, circuit::{run_circuit, UserCircuit}, utils::gen_random_u256};
    use plonky2::{field::types::{Field, Sample}, hash::hashing::hash_n_to_hash_no_pad, iop::witness::PartialWitness, plonk::{circuit_builder::CircuitBuilder, config::GenericHashOut}};
    use rand::{thread_rng, Rng};

    use crate::query::{computational_hash_ids::{AggregationOperation, HashPermutation, Operation}, public_inputs::PublicInputs, universal_circuit::{output_with_aggregation::Circuit, universal_query_circuit::{BasicOperation, InputOperand, OutputItem, Placeholder}, COLUMN_INDEX_NUM}};

    use super::{OutputComponent, UniversalQueryCircuitInputs, UniversalQueryCircuitWires};
    
    impl<
        const MAX_NUM_COLUMNS: usize,
        const MAX_NUM_PREDICATE_OPS: usize,
        const MAX_NUM_RESULT_OPS: usize,
        const MAX_NUM_RESULTS: usize,
        T: OutputComponent<MAX_NUM_RESULTS>, 
    > UserCircuit<F, D> for UniversalQueryCircuitInputs<
        MAX_NUM_COLUMNS,
        MAX_NUM_PREDICATE_OPS,
        MAX_NUM_RESULT_OPS,
        MAX_NUM_RESULTS,
        T
    > 
    where [(); MAX_NUM_RESULTS - 1]: ,
    {
        type Wires = UniversalQueryCircuitWires<MAX_NUM_COLUMNS, MAX_NUM_PREDICATE_OPS, MAX_NUM_RESULT_OPS, MAX_NUM_RESULTS, T>;
    
        fn build(c: &mut CircuitBuilder<F, D>) -> Self::Wires {
            UniversalQueryCircuitInputs::build(c)
        }
    
        fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
            self.assign(pw, wires)
        }
    }

    // test the following query:
    // SELECT SUM(C1+C2), AVG(C2*C3), MIN(C1+$1), MAX(C4-2), AVG(C5) FROM T WHERE (C5 > 5 AND C1*C3 <= C4+C5 OR C3 == $2) AND C2 >= 75 AND C2 < 99
    #[test]
    fn test_query_with_aggregation() {
        const NUM_ACTUAL_COLUMNS: usize = 5;
        const MAX_NUM_COLUMNS: usize = 20;
        const MAX_NUM_PREDICATE_OPS: usize = 15;
        const MAX_NUM_RESULT_OPS: usize = 15;
        const MAX_NUM_RESULTS: usize = 10;
        let rng = &mut thread_rng();
        let min_query = U256::from(74);
        let max_query = U256::from(99);
        let column_values = (0..NUM_ACTUAL_COLUMNS).map(|i|
            if i == 1 {
                // ensure that second column value is in the range specified by the query:
                // we sample a random u256 in range [0, max_query - min_query - 1) and then we
                // add min_query + 1 
                let min_query_value = min_query + U256::from(1);
                gen_random_u256(rng).div_rem(max_query-min_query_value).1 + min_query_value 
            } else {
                gen_random_u256(rng)
            }
        ).collect_vec();
        let column_ids = (0..NUM_ACTUAL_COLUMNS).map(|_| 
            F::rand()
        ).collect_vec();
        // build predicate operations
        let mut predicate_operations = vec![];
        // C5 > 5
        let c5_comparison = BasicOperation {
            first_operand: InputOperand::Column(4),
            second_operand: Some(InputOperand::Constant(U256::from(5))),
            op: Operation::GreaterThanOp,
        };
        predicate_operations.push(c5_comparison);
        // C1*C3
        let column_prod = BasicOperation {
            first_operand: InputOperand::Column(0),
            second_operand: Some(InputOperand::Column(2)),
            op: Operation::MulOp,
        };
        predicate_operations.push(column_prod);
        // C4+C5
        let column_add = BasicOperation {
            first_operand: InputOperand::Column(3),
            second_operand: Some(InputOperand::Column(4)),
            op: Operation::AddOp,
        };
        predicate_operations.push(column_add);
        // C1*C3 <= C4 + C5
        let expr_comparison = BasicOperation {
            first_operand: InputOperand::PreviousValue(1),
            second_operand: Some(InputOperand::PreviousValue(2)),
            op: Operation::LessThanOrEqOp,
        };
        predicate_operations.push(expr_comparison);
        // C3 == $2
        let placeholder_eq = BasicOperation {
            first_operand: InputOperand::Column(2),
            second_operand: Some(InputOperand::Placeholder(
                Placeholder {
                    value: gen_random_u256(rng),
                    id: F::from_canonical_usize(2),
                })),
            op: Operation::EqOp,
        };
        predicate_operations.push(placeholder_eq);
        // c5_comparison AND expr_comparison
        let and_comparisons = BasicOperation {
            first_operand: InputOperand::PreviousValue(0),
            second_operand: Some(InputOperand::PreviousValue(3)),
            op: Operation::AndOp,
        };
        predicate_operations.push(and_comparisons);
        // final filtering predicate: and_comparisons OR placeholder_eq
        let predicate = BasicOperation {
            first_operand: InputOperand::PreviousValue(5),
            second_operand: Some(InputOperand::PreviousValue(4)),
            op: Operation::OrOp,
        };
        predicate_operations.push(predicate);
        // result computations operations
        let mut result_operations = vec![];
        // C1+C2
        let column_add = BasicOperation {
            first_operand: InputOperand::Column(0),
            second_operand: Some(InputOperand::Column(1)),
            op: Operation::AddOp,
        };
        result_operations.push(column_add);
        let column_prod = BasicOperation {
            first_operand: InputOperand::Column(1),
            second_operand: Some(InputOperand::Column(2)),
            op: Operation::MulOp,
        };
        result_operations.push(column_prod);
        let column_placeholder = BasicOperation {
            first_operand: InputOperand::Column(0),
            second_operand: Some(InputOperand::Placeholder(
                Placeholder{
                    value: gen_random_u256(rng),
                    id: F::ONE,
                }
            )),
            op: Operation::AddOp,
        };
        result_operations.push(column_placeholder);
        let column_sub_const = BasicOperation {
            first_operand: InputOperand::Column(3),
            second_operand: Some(InputOperand::Constant(U256::from(2))),
            op: Operation::SubOp,
        };
        result_operations.push(column_sub_const);

        let is_leaf: bool = rng.gen();
        // output items are all computed values in this query, expect for the last item
        // which is a column
        let mut output_items = vec![OutputItem::ComputedValue; 4];
        output_items.push(OutputItem::Column(4));
        let output_ops = [
            AggregationOperation::SumOp.to_field(),
            AggregationOperation::AvgOp.to_field(),
            AggregationOperation::MinOp.to_field(),
            AggregationOperation::MaxOp.to_field(),
            AggregationOperation::AvgOp.to_field(),
        ];

        let circuit = UniversalQueryCircuitInputs::<
            MAX_NUM_COLUMNS,
            MAX_NUM_PREDICATE_OPS,
            MAX_NUM_RESULT_OPS,
            MAX_NUM_RESULTS,
            Circuit<MAX_NUM_RESULTS>,
        >::new(
            &column_values,
            &column_ids,
            &predicate_operations,
            &result_operations,
            is_leaf,
            min_query,
            max_query,
            &output_items,
            &output_ops,
        ).unwrap();

        // computed expected public inputs
        // expected tree hash
        let cells = column_values.iter().zip(
            column_ids.iter()
        ).skip(2)
        .map(|(value, id)| 
            TestCell::new(*value, *id)
        ).collect_vec();
        let mut tree_hash = compute_cells_tree_hash(&cells);
        if is_leaf {
            tree_hash = hash_n_to_hash_no_pad::<_, HashPermutation>(&
                empty_poseidon_hash().to_vec().into_iter()
                .chain(empty_poseidon_hash().to_vec())
                .chain(column_values[1].to_fields())
                .chain(column_values[1].to_fields())
                .chain(once(column_ids[1]))
                .chain(column_values[1].to_fields())
                .chain(tree_hash.to_vec())
                .collect_vec()
            );
        }

        // compute predicate value
        let (res, overflow) = BasicOperation::compute_operations(
            &predicate_operations, 
            &column_values
        ).unwrap();
        let predicate_value = match res.last().unwrap() {
            &val if val.is_zero() => F::ZERO,
            &val if val == U256::from(1) => F::ONE,
            _ => panic!("predicate value not Boolean"),
        };

        let placeholder_hash = circuit.compute_placeholder_hash();

        let proof = run_circuit::<F, D, C, _>(circuit);
        
        let pi = PublicInputs::<_, MAX_NUM_RESULTS>::from_slice(&proof.public_inputs);
        assert_eq!(tree_hash, pi.tree_hash());
        assert_eq!(predicate_value, pi.num_matching_rows(), 
            "{:?} {}", column_values, overflow);
        assert_eq!(column_values[0], pi.index_value());
        assert_eq!(column_values[1], pi.min_value());
        assert_eq!(column_values[1], pi.max_value());
        assert_eq!([column_ids[0], column_ids[1]], pi.index_ids());
        assert_eq!(min_query, pi.min_query_value());
        assert_eq!(max_query, pi.max_query_value());
        assert_eq!(placeholder_hash, pi.placeholder_hash());
    } 
}