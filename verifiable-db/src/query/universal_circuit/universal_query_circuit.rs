use std::{
    fmt::Debug,
    iter::{once, repeat},
};

use alloy::primitives::U256;
use anyhow::{bail, ensure, Result};
use itertools::Itertools;
use mp2_common::{
    array::ToField,
    poseidon::{empty_poseidon_hash, H},
    public_inputs::PublicInputCommon,
    serialization::{deserialize, deserialize_long_array, serialize, serialize_long_array},
    types::CBuilder,
    u256::{CircuitBuilderU256, UInt256Target},
    utils::{FromFields, SelectHashBuilder, ToFields, ToTargets},
    CHasher, D, F,
};
use plonky2::{
    field::types::Field,
    hash::hashing::hash_n_to_hash_no_pad,
    iop::{
        target::{BoolTarget, Target},
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        config::{GenericHashOut, Hasher},
        proof::ProofWithPublicInputsTarget,
    },
};
use recursion_framework::circuit_builder::CircuitLogicWires;
use serde::{Deserialize, Serialize};

use crate::query::{
    aggregation::{QueryBoundSecondary, QueryBoundSource, QueryBounds},
    computational_hash_ids::{
        ComputationalHashCache, HashPermutation, Operation, Output, PlaceholderIdentifier,
    },
    public_inputs::PublicInputs,
    universal_circuit::{
        basic_operation::BasicOperationInputs, universal_circuit_inputs::OutputItem,
    },
    PI_LEN,
};

use super::{
    basic_operation::{BasicOperationInputWires, BasicOperationWires},
    column_extraction::{ColumnExtractionInputWires, ColumnExtractionInputs},
    output_no_aggregation::Circuit as NoAggOutputCircuit,
    output_with_aggregation::Circuit as AggOutputCircuit,
    universal_circuit_inputs::{
        BasicOperation, InputOperand, Placeholder, PlaceholderId, Placeholders, ResultStructure,
        RowCells,
    },
    ComputationalHash, ComputationalHashTarget, PlaceholderHash, PlaceholderHashTarget,
};

/// Wires representing a query bound in the universal circuit
pub(crate) type QueryBoundTarget = BasicOperationWires;

/// Input wires for `QueryBoundTarget` (i.e., the wires that need to be assigned)
pub(crate) type QueryBoundTargetInputs = BasicOperationInputWires;

impl From<QueryBoundTarget> for QueryBoundTargetInputs {
    fn from(value: QueryBoundTarget) -> Self {
        value.input_wires
    }
}

impl QueryBoundTarget {
    pub(crate) fn new(b: &mut CBuilder) -> Self {
        let zero_u256 = b.zero_u256();
        let zero = b.zero();
        let empty_hash = b.constant_hash(*empty_poseidon_hash());
        // The 0 constant provided as input value is used as a dummy operand in case the query bound
        // is taken from a constant in the query: in this case, the query bound in the circuit is
        // computed with the operation `InputOperand::Constant(query_bound) + input_values[0]`, which
        // yields `query_bound` as output since `input_values[0] = 0`. The constant input values 0 is
        // associated to the empty hash in the computational hash, which is provided as `input_hash[0]`
        BasicOperationInputs::build(b, &[zero_u256], &[empty_hash], zero)
    }

    /// Get the actual value of this query bound computed in the circuit
    pub(crate) fn get_bound_value(&self) -> &UInt256Target {
        &self.output_value
    }

    // Compute the number of overflows occurred during operations to compute query bounds
    pub(crate) fn num_overflows_for_query_bound_operations(
        b: &mut CBuilder,
        min_query: &Self,
        max_query: &Self,
    ) -> Target {
        b.add(min_query.num_overflows, max_query.num_overflows)
    }

    pub(crate) fn add_query_bounds_to_placeholder_hash(
        b: &mut CBuilder,
        min_query_bound: &Self,
        max_query_bound: &Self,
        placeholder_hash: &PlaceholderHashTarget,
    ) -> PlaceholderHashTarget {
        b.hash_n_to_hash_no_pad::<CHasher>(
            placeholder_hash
                .elements
                .iter()
                .chain(once(&min_query_bound.input_wires.placeholder_ids[0]))
                .chain(&min_query_bound.input_wires.placeholder_values[0].to_targets())
                .chain(once(&min_query_bound.input_wires.placeholder_ids[1]))
                .chain(&min_query_bound.input_wires.placeholder_values[1].to_targets())
                .chain(once(&max_query_bound.input_wires.placeholder_ids[0]))
                .chain(&max_query_bound.input_wires.placeholder_values[0].to_targets())
                .chain(once(&max_query_bound.input_wires.placeholder_ids[1]))
                .chain(&max_query_bound.input_wires.placeholder_values[1].to_targets())
                .cloned()
                .collect(),
        )
    }

    pub(crate) fn add_query_bounds_to_computational_hash(
        b: &mut CBuilder,
        min_query_bound: &Self,
        max_query_bound: &Self,
        computational_hash: &ComputationalHashTarget,
    ) -> ComputationalHashTarget {
        b.hash_n_to_hash_no_pad::<CHasher>(
            computational_hash
                .to_targets()
                .into_iter()
                .chain(min_query_bound.output_hash.to_targets())
                .chain(max_query_bound.output_hash.to_targets())
                .collect_vec(),
        )
    }
}

impl QueryBoundTargetInputs {
    pub(crate) fn assign(&self, pw: &mut PartialWitness<F>, bound: &QueryBound) {
        bound.operation.assign(pw, &self);
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct QueryBound {
    pub(crate) operation: BasicOperationInputs,
}

impl QueryBound {
    /// Number of input values provided to the basic operation component computing the query bounds
    /// in the circuit; currently it is 1 since the constant input value 0 is provided as a dummy
    /// input value (see QueryBoundTarget::new()).
    const NUM_INPUT_VALUES: usize = 1;

    /// Initialize a query bound for the primary index, from the set of `placeholders` employed in the query,
    /// which include also the primary index bounds by construction. The flag `is_min_bound`
    /// must be true iff the bound to be initialized is a lower bound in the range specified in the query
    pub(crate) fn new_primary_index_bound(
        placeholders: &Placeholders,
        is_min_bound: bool,
    ) -> Result<Self> {
        let source = QueryBoundSource::Placeholder(if is_min_bound {
            PlaceholderIdentifier::MinQueryOnIdx1
        } else {
            PlaceholderIdentifier::MaxQueryOnIdx1
        });
        Self::new_bound(placeholders, &source)
    }

    /// Initialize a query bound for the secondary index, from the set of placeholders employed in the query
    /// and from the provided `bound`, which specifies how the query bound should be computed in the circuit
    pub(crate) fn new_secondary_index_bound(
        placeholders: &Placeholders,
        bound: &QueryBoundSecondary,
    ) -> Result<Self> {
        let source = bound.into();
        Self::new_bound(placeholders, &source)
    }

    /// Internal function employed to instantiate a new query bound
    fn new_bound(placeholders: &Placeholders, source: &QueryBoundSource) -> Result<Self> {
        let dummy_placeholder = dummy_placeholder(placeholders);
        let op_inputs = match source {
            QueryBoundSource::Constant(value) =>
            // if the query bound is computed from a constant `value`, we instantiate the operation
            // `value + input_values[0]` in the circuit, as in `QueryBoundTarget` construction we
            // always set `input_values[0] = 0`. This trick allows to get the same constant `value`
            // as output of the basic operation employed in the circuit to compute the query bound
            {
                BasicOperationInputs {
                    constant_operand: *value,
                    placeholder_values: [dummy_placeholder.value, dummy_placeholder.value],
                    placeholder_ids: [
                        dummy_placeholder.id.to_field(),
                        dummy_placeholder.id.to_field(),
                    ],
                    first_input_selector: BasicOperationInputs::constant_operand_offset(
                        Self::NUM_INPUT_VALUES,
                    )
                    .to_field(),
                    second_input_selector: BasicOperationInputs::input_value_offset(0).to_field(),
                    op_selector: Operation::AddOp.to_field(),
                }
            }
            QueryBoundSource::Placeholder(id) =>
            // if the query bound is computed from a placeholder with id `id`, we instantiate
            // the operation `$id + 0` in the circuit, which will yield the value of placeholder
            // $id (which should correspond to the query bound) as output
            {
                BasicOperationInputs {
                    constant_operand: U256::ZERO,
                    placeholder_values: [placeholders.get(id)?, dummy_placeholder.value],
                    placeholder_ids: [id.to_field(), dummy_placeholder.id.to_field()],
                    first_input_selector: BasicOperationInputs::first_placeholder_offset(
                        Self::NUM_INPUT_VALUES,
                    )
                    .to_field(),
                    second_input_selector: BasicOperationInputs::constant_operand_offset(
                        Self::NUM_INPUT_VALUES,
                    )
                    .to_field(),
                    op_selector: Operation::AddOp.to_field(),
                }
            }
            QueryBoundSource::Operation(op) => {
                // In this case we instantiate the basic operation `op`, checking that the operation
                // satisfies the requirements for query bound operations (i.e., it involves only
                // constant values and placeholders)
                let mut constant_operand = U256::ZERO;
                let mut process_input_op = |operand: &InputOperand| {
                    Ok(match operand {
                        InputOperand::Placeholder(id) =>
                            (
                                *id,
                                None,
                            ),
                        InputOperand::Constant(value) => {
                            constant_operand = *value;
                            (
                                dummy_placeholder.id,
                                Some(BasicOperationInputs::constant_operand_offset(Self::NUM_INPUT_VALUES))
                            )
                        },
                        _ => bail!("Invalid operand for query bound operation: must be either a placeholder or a constant"),
                    })
                };

                let (first_placeholder_id, first_selector) = process_input_op(&op.first_operand)?;
                let (second_placeholder_id, second_selector) = process_input_op(
                    &op.second_operand.unwrap_or_default(), // Unary operation, so use a dummy operand
                )?;
                BasicOperationInputs {
                    constant_operand,
                    placeholder_values: [
                        placeholders.get(&first_placeholder_id)?,
                        placeholders.get(&second_placeholder_id)?,
                    ],
                    placeholder_ids: [
                        first_placeholder_id.to_field(),
                        second_placeholder_id.to_field(),
                    ],
                    first_input_selector: first_selector
                        .unwrap_or(BasicOperationInputs::first_placeholder_offset(
                            Self::NUM_INPUT_VALUES,
                        ))
                        .to_field(),
                    second_input_selector: second_selector
                        .unwrap_or(BasicOperationInputs::second_placeholder_offset(
                            Self::NUM_INPUT_VALUES,
                        ))
                        .to_field(),
                    op_selector: op.op.to_field(),
                }
            }
        };
        Ok(Self {
            operation: op_inputs,
        })
    }

    /// This method computes the value of a query bound
    pub(crate) fn compute_bound_value(
        placeholders: &Placeholders,
        source: &QueryBoundSource,
    ) -> Result<(U256, bool)> {
        Ok(match source {
            QueryBoundSource::Constant(value) => (*value, false),
            QueryBoundSource::Placeholder(id) => (placeholders.get(id)?, false),
            QueryBoundSource::Operation(op) => {
                let (values, overflow) =
                    BasicOperation::compute_operations(&[*op], &[], placeholders)?;
                (values[0], overflow)
            }
        })
    }

    /// This method returns the basic operation employed in the circuit for the query bound which is
    /// taken fromthe query as specify by the input `source`. It basically returns the same operations
    /// that are instantiated in the circuit by the `new_bound` internal method
    pub(crate) fn get_basic_operation(source: &QueryBoundSource) -> Result<BasicOperation> {
        Ok(match source {
            QueryBoundSource::Constant(value) =>
            // convert to operation `value + input_value[0]`, which yield value as `input_value[0] = 0` in the circuit
            {
                BasicOperation {
                    first_operand: InputOperand::Constant(*value),
                    second_operand: Some(InputOperand::Column(0)),
                    op: Operation::AddOp,
                }
            }
            QueryBoundSource::Placeholder(id) =>
            // convert to operation $id + 0
            {
                BasicOperation {
                    first_operand: InputOperand::Placeholder(*id),
                    second_operand: Some(InputOperand::Constant(U256::ZERO)),
                    op: Operation::AddOp,
                }
            }
            QueryBoundSource::Operation(op) => {
                // validate operation for query bound
                match op.first_operand {
                    InputOperand::Constant(_) | InputOperand::Placeholder(_) => (),
                    _ => bail!("Invalid operand for query bound operation: must be either a placeholder or a constant")
                }
                if let Some(operand) = op.second_operand {
                    match operand {
                        InputOperand::Constant(_) | InputOperand::Placeholder(_) => (),
                        _ => bail!("Invalid operand for query bound operation: must be either a placeholder or a constant")
                    }
                }
                *op
            }
        })
    }

    pub(crate) fn add_secondary_query_bounds_to_placeholder_hash(
        min_query: &Self,
        max_query: &Self,
        placeholder_hash: &PlaceholderHash,
    ) -> PlaceholderHash {
        hash_n_to_hash_no_pad::<_, HashPermutation>(
            &placeholder_hash
                .to_vec()
                .into_iter()
                .chain(once(min_query.operation.placeholder_ids[0]))
                .chain(min_query.operation.placeholder_values[0].to_fields())
                .chain(once(min_query.operation.placeholder_ids[1]))
                .chain(min_query.operation.placeholder_values[1].to_fields())
                .chain(once(max_query.operation.placeholder_ids[0]))
                .chain(max_query.operation.placeholder_values[0].to_fields())
                .chain(once(max_query.operation.placeholder_ids[1]))
                .chain(max_query.operation.placeholder_values[1].to_fields())
                .collect_vec(),
        )
    }

    pub(crate) fn add_secondary_query_bounds_to_computational_hash(
        min_query: &QueryBoundSource,
        max_query: &QueryBoundSource,
        computational_hash: &ComputationalHash,
    ) -> Result<ComputationalHash> {
        let min_query_op = Self::get_basic_operation(&min_query)?;
        let max_query_op = Self::get_basic_operation(&max_query)?;
        // initialize computational hash cache with the empty hash associated to the only input value (hardcoded to 0
        // in the circuit) of the basic operation components employed for query bounds
        let mut cache = ComputationalHashCache::new_from_column_hash(
            Self::NUM_INPUT_VALUES,
            &[*empty_poseidon_hash()],
        )?;
        let min_query_hash = Operation::basic_operation_hash(&mut cache, &[], &min_query_op)?;
        let max_query_hash = Operation::basic_operation_hash(&mut cache, &[], &max_query_op)?;
        let inputs = computational_hash
            .to_vec()
            .into_iter()
            .chain(min_query_hash.to_fields())
            .chain(max_query_hash.to_fields())
            .collect_vec();
        Ok(H::hash_no_pad(&inputs))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
/// Input wires for the universal query circuit
pub struct UniversalQueryCircuitWires<
    const MAX_NUM_COLUMNS: usize,
    const MAX_NUM_PREDICATE_OPS: usize,
    const MAX_NUM_RESULT_OPS: usize,
    const MAX_NUM_RESULTS: usize,
    T: OutputComponent<MAX_NUM_RESULTS>,
> {
    /// Input wires for column extraction component
    pub(crate) column_extraction_wires: ColumnExtractionInputWires<MAX_NUM_COLUMNS>,
    /// flag specifying whether the given row is stored in a leaf node of a rows tree or not
    #[serde(serialize_with = "serialize", deserialize_with = "deserialize")]
    is_leaf: BoolTarget,
    /// Lower bound of the range for the secondary index specified in the query
    min_query: QueryBoundTargetInputs,
    /// Upper bound of the range for the secondary index specified in the query
    max_query: QueryBoundTargetInputs,
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
pub trait OutputComponent<const MAX_NUM_RESULTS: usize>: Clone {
    type Wires: OutputComponentWires;

    fn new(selector: &[F], ids: &[F], num_outputs: usize) -> Result<Self>;

    fn build<const NUM_OUTPUT_VALUES: usize>(
        b: &mut CBuilder,
        possible_output_values: [UInt256Target; NUM_OUTPUT_VALUES],
        possible_output_hash: [ComputationalHashTarget; NUM_OUTPUT_VALUES],
        predicate_value: &BoolTarget,
        predicate_hash: &ComputationalHashTarget,
    ) -> Self::Wires;

    fn assign(
        &self,
        pw: &mut PartialWitness<F>,
        wires: &<Self::Wires as OutputComponentWires>::InputWires,
    );

    /// Return the type of output component, specified as an instance of `Output` enum
    fn output_variant() -> Output;
}
/// Trait representing the wires that need to be exposed by an `OutputComponent`
/// employed in query circuits
pub trait OutputComponentWires {
    /// Associated type specifying the type of the first output value computed by this output
    /// component; this type varies depending on the particular component:
    /// - It is a `CurveTarget` in the output component for queries without aggregation operations
    /// - It is a `UInt256Target` in the output for queries with aggregation operations
    type FirstT: ToTargets;
    /// Input wires of the output component
    type InputWires: Serialize + for<'a> Deserialize<'a> + Clone + Debug + Eq + PartialEq;

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
    fn computational_hash(&self) -> ComputationalHashTarget;
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
    min_query: QueryBound,
    max_query: QueryBound,
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
    [(); MAX_NUM_COLUMNS + MAX_NUM_RESULT_OPS]:,
{
    /// Instantiate `Self` from the necessary inputs. Note that the following assumption is expected on the
    /// structure of the inputs:
    /// The output of the last operation in `predicate_operations` will be taken as the filtering predicate evaluation;
    /// this is an assumption exploited in the circuit for efficiency, and it is a simple assumption to be required for
    /// the caller of this method
    pub(crate) fn new(
        row_cells: &RowCells,
        predicate_operations: &[BasicOperation],
        placeholders: &Placeholders,
        is_leaf: bool,
        query_bounds: &QueryBounds,
        results: &ResultStructure,
    ) -> Result<Self> {
        let num_columns = row_cells.num_columns();
        ensure!(
            num_columns <= MAX_NUM_COLUMNS,
            "number of columns is higher than the maximum value allowed"
        );
        let column_cells = row_cells.to_cells();
        let padded_column_values = column_cells
            .iter()
            .map(|cell| cell.value)
            .chain(repeat(U256::ZERO))
            .take(MAX_NUM_COLUMNS)
            .collect_vec();
        let padded_column_ids = column_cells
            .iter()
            .map(|cell| cell.id)
            .chain(repeat(F::NEG_ONE))
            .take(MAX_NUM_COLUMNS)
            .collect_vec();
        let column_extraction_inputs = ColumnExtractionInputs::<MAX_NUM_COLUMNS> {
            real_num_columns: num_columns,
            column_values: padded_column_values.try_into().unwrap(),
            column_ids: padded_column_ids.try_into().unwrap(),
        };
        let num_predicate_ops = predicate_operations.len();
        ensure!(num_predicate_ops <= MAX_NUM_PREDICATE_OPS,
            "Number of operations to compute filtering predicate is higher than the maximum number allowed");
        let num_result_ops = results.result_operations.len();
        ensure!(
            num_result_ops <= MAX_NUM_RESULT_OPS,
            "Number of operations to compute results is higher than the maximum number allowed"
        );
        let predicate_ops_inputs = Self::compute_operation_inputs::<MAX_NUM_PREDICATE_OPS>(
            predicate_operations,
            placeholders,
        )?;
        let result_ops_inputs = Self::compute_operation_inputs::<MAX_NUM_RESULT_OPS>(
            &results.result_operations,
            placeholders,
        )?;
        let selectors = results.output_items.iter().enumerate().map(|(i, item)| {
            Ok(
                match item {
                    OutputItem::Column(index) => {
                        ensure!(*index < MAX_NUM_COLUMNS,
                        "Column index provided as {}-th output value is higher than the maximum number of columns", i);
                    F::from_canonical_usize(*index)
                    },
                    OutputItem::ComputedValue(index) => {
                        ensure!(*index < num_result_ops,
                            "an operation computing an output results not found in set of result operations");
                        // the output will be placed in the `num_result_ops - index` last slot in the set of
                        // `possible_output_values` provided as input in the circuit to the output component,
                        // i.e., the input array found in `OutputComponent::build` method.
                        // Therefore, since the `possible_output_values` array in the circuit has
                        // `MAX_NUM_COLUMNS + MAX_NUM_RESULT_OPS` entries, the selector for such output value
                        // can be computed as the length of `possible_output_values.len() - (num_result_ops - index)`,
                        // which correspond to the `num_result_ops - index`-th entry from the end of the array
                        F::from_canonical_usize(MAX_NUM_COLUMNS + MAX_NUM_RESULT_OPS - (num_result_ops - *index))
                    },
            })
        }).collect::<Result<Vec<_>>>()?;
        let output_component_inputs =
            T::new(&selectors, &results.output_ids, results.output_ids.len())?;

        let min_query = QueryBound::new_secondary_index_bound(
            &placeholders,
            &query_bounds.min_query_secondary(),
        )?;

        let max_query = QueryBound::new_secondary_index_bound(
            &placeholders,
            &query_bounds.max_query_secondary(),
        )?;

        Ok(Self {
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
        let min_query = QueryBoundTarget::new(b);
        let max_query = QueryBoundTarget::new(b);
        let min_query_value = min_query.get_bound_value();
        let max_query_value = max_query.get_bound_value();
        let less_than_max = b.is_less_or_equal_than_u256(node_max, max_query_value);
        let greater_than_min = b.is_less_or_equal_than_u256(min_query_value, node_min);
        b.connect(less_than_max.target, _true.target);
        b.connect(greater_than_min.target, _true.target);
        // initialize input_values and input_hash input vectors for basic operation components employed to
        // evaluate the filtering predicate
        let mut input_values = column_extraction_wires.input_wires.column_values.to_vec();
        let mut input_hash = column_extraction_wires.column_hash.to_vec();
        // Set of input wires for each of the `MAX_NUM_PREDICATE_OPS` basic operation components employed to
        // evaluate the filtering predicate
        let mut filtering_predicate_wires = Vec::with_capacity(MAX_NUM_PREDICATE_OPS);
        // Payload to compute the placeholder hash public input
        let mut placeholder_hash_payload = vec![];
        // initialize counter of overflows to number of overflows occurred during query bound operations
        let mut num_overflows =
            QueryBoundTarget::num_overflows_for_query_bound_operations(b, &min_query, &max_query);

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
        // the filtering predicate. This placement is done in order to have a fixed slot where we can
        // find the predicate value, without the need for a further random_access operation just to extract
        // this value from the set of predicate operations
        let predicate_value = input_values.last().unwrap().to_bool_target();
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
        // `possible_output_values` to be provided to output component are the set of `MAX_NUM_COLUMNS`
        // and the `MAX_NUM_RESULT_OPS` results of results operations, which are all already accumulated
        // in the `input_values` vector
        let possible_output_values: [UInt256Target; MAX_NUM_COLUMNS + MAX_NUM_RESULT_OPS] =
            input_values.try_into().unwrap();
        // same for `possible_output_hash`, all the hashes are already accumulated in the `input_hash` vector
        let possible_output_hash: [ComputationalHashTarget; MAX_NUM_COLUMNS + MAX_NUM_RESULT_OPS] =
            input_hash.try_into().unwrap();
        let output_component_wires = T::build(
            b,
            possible_output_values,
            possible_output_hash,
            &predicate_value,
            predicate_hash,
        );
        // compute overflow flag
        let not_overflow = b.is_equal(num_overflows, zero);
        let overflow = b.not(not_overflow);
        let placeholder_hash = b.hash_n_to_hash_no_pad::<CHasher>(placeholder_hash_payload);
        let placeholder_hash = QueryBoundTarget::add_query_bounds_to_placeholder_hash(
            b,
            &min_query,
            &max_query,
            &placeholder_hash,
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
        // add query bounds to computational hash
        let computational_hash = QueryBoundTarget::add_query_bounds_to_computational_hash(
            b,
            &min_query,
            &max_query,
            &output_component_wires.computational_hash(),
        );
        PublicInputs::<Target, MAX_NUM_RESULTS>::new(
            &tree_hash.to_targets(),
            output_values.as_slice(),
            &[predicate_value.target],
            output_component_wires.ops_ids(),
            &index_value.to_targets(),
            &node_min.to_targets(),
            &node_max.to_targets(),
            &[*primary_index_id, *second_index_id],
            &min_query_value.to_targets(),
            &max_query_value.to_targets(),
            &[overflow.target],
            &computational_hash.to_targets(),
            &placeholder_hash.to_targets(),
        )
        .register(b);

        UniversalQueryCircuitWires {
            column_extraction_wires: column_extraction_wires.input_wires,
            is_leaf,
            min_query: min_query.into(),
            max_query: max_query.into(),
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
        wires.min_query.assign(pw, &self.min_query);
        wires.max_query.assign(pw, &self.max_query);
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

    /// This method returns the ids of the placeholders employed to compute the placeholder hash,
    /// in the same order, so that those ids can be provided as input to other circuits that need
    /// to recompute this hash
    pub(crate) fn ids_for_placeholder_hash(&self) -> Vec<PlaceholderId> {
        self.filtering_predicate_inputs
            .iter()
            .flat_map(|op_inputs| vec![op_inputs.placeholder_ids[0], op_inputs.placeholder_ids[1]])
            .chain(self.result_values_inputs.iter().flat_map(|op_inputs| {
                vec![op_inputs.placeholder_ids[0], op_inputs.placeholder_ids[1]]
            }))
            .map(|id| PlaceholderIdentifier::from_fields(&[id]))
            .collect_vec()
    }

    /// Utility function to compute the `BasicOperationInputs` corresponding to the set of `operations` specified
    /// as input. The set of `BasicOperationInputs` is padded to `MAX_NUM_OPS` with dummy operations, which is
    /// the expected number of operations expected as input by the circuit.
    fn compute_operation_inputs<const MAX_NUM_OPS: usize>(
        operations: &[BasicOperation],
        placeholders: &Placeholders,
    ) -> Result<[BasicOperationInputs; MAX_NUM_OPS]> {
        let dummy_placeholder = dummy_placeholder(placeholders);
        // starting offset in the input values provided to basic operation component where the output values
        // of `operations` will be found. It is computed as follows since these operations will be placed
        // at the end of these functions in the last slots among the `MAX_NUM_OPS` available, as expected
        // by the circuit
        let start_actual_ops = MAX_NUM_COLUMNS + MAX_NUM_OPS - operations.len();
        let ops_wires = operations.iter().enumerate().map(|(i, op)| {
            let mut constant_operand = U256::ZERO;
            // the number of input values provided to the basic operation component
            // computing the current predicate operation
            let num_inputs = start_actual_ops + i;
            let mut compute_op_inputs = |is_first_op: bool| {
                let operand = if is_first_op {
                    op.first_operand
                } else {
                    op.second_operand.unwrap_or_default()
                };
                Ok(
                match operand {
                    InputOperand::Placeholder(p) => {
                        let placeholder_value = placeholders.get(&p)?;
                        (
                            Some(placeholder_value),
                            Some(p),
                            if is_first_op {
                                BasicOperationInputs::first_placeholder_offset(num_inputs)
                            } else {
                                BasicOperationInputs::second_placeholder_offset(num_inputs)
                            },
                        )
                    },
                    InputOperand::Constant(val) => {
                        constant_operand = val;
                        (
                            None,
                            None,
                            BasicOperationInputs::constant_operand_offset(num_inputs),
                        )
                    },
                    InputOperand::Column(index) => {
                        ensure!(index < MAX_NUM_COLUMNS,
                            "column index specified as input for {}-th predicate operation is higher than number of columns", i);
                        (
                            None,
                            None,
                            BasicOperationInputs::input_value_offset(index),
                        )
                    },
                    InputOperand::PreviousValue(index) => {
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
                first_placeholder_value.unwrap_or(dummy_placeholder.value),
                second_placeholder_value.unwrap_or(dummy_placeholder.value)
            ];
            let placeholder_ids = [
                first_placeholder_id.unwrap_or(dummy_placeholder.id).to_field(),
                second_placeholder_id.unwrap_or(dummy_placeholder.id).to_field(),
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
                placeholder_values: [dummy_placeholder.value, dummy_placeholder.value],
                placeholder_ids: [
                    dummy_placeholder.id.to_field(),
                    dummy_placeholder.id.to_field(),
                ],
                first_input_selector: F::ZERO,
                second_input_selector: F::ZERO,
                op_selector: Operation::EqOp.to_field(),
            },
        )
        .take(MAX_NUM_OPS - operations.len())
        .chain(ops_wires)
        .collect_vec()
        .try_into()
        .unwrap())
    }
}

/// Placeholder to be employed in the universal circuit as a dummy placeholder
/// in the circuit
fn dummy_placeholder(placeholders: &Placeholders) -> Placeholder {
    Placeholder {
        value: placeholders.get(&dummy_placeholder_id()).unwrap(), // cannot fail since default placeholder is always associated to a value
        id: dummy_placeholder_id(),
    }
}

fn dummy_placeholder_from_query_bounds(query_bounds: &QueryBounds) -> Placeholder {
    let placeholders = Placeholders::new_empty(
        query_bounds.min_query_primary(),
        query_bounds.max_query_primary(),
    );
    dummy_placeholder(&placeholders)
}

pub(crate) fn dummy_placeholder_id() -> PlaceholderId {
    PlaceholderIdentifier::default()
}

/// Utility method to compute the placeholder hash for the placeholders provided as input, without including the
/// query bounds on the secondary index
pub(crate) fn placeholder_hash_without_query_bounds(
    placeholder_ids: &[PlaceholderId],
    placeholders: &Placeholders,
) -> Result<PlaceholderHash> {
    let inputs = placeholder_ids
        .iter()
        .map(|id| {
            Ok(once(id.to_field())
                .chain(placeholders.get(id)?.to_fields())
                .collect_vec())
        })
        .flatten_ok()
        .collect::<Result<Vec<F>>>()?;
    Ok(hash_n_to_hash_no_pad::<_, HashPermutation>(&inputs))
}

/// Compute the placeholder hash for the placeholders and query bounds provided as input
pub(crate) fn placeholder_hash(
    placeholder_ids: &[PlaceholderId],
    placeholders: &Placeholders,
    query_bounds: &QueryBounds,
) -> Result<PlaceholderHash> {
    let placeholder_hash = placeholder_hash_without_query_bounds(placeholder_ids, placeholders)?;
    // add query bounds to placeholder hash, which depend on whether such query bounds come from
    // a constant or a placeholder. This information is available in `query_bounds`, so we just
    // process it
    let min_query =
        QueryBound::new_secondary_index_bound(placeholders, &query_bounds.min_query_secondary())?;
    let max_query =
        QueryBound::new_secondary_index_bound(placeholders, &query_bounds.max_query_secondary())?;
    Ok(QueryBound::add_secondary_query_bounds_to_placeholder_hash(
        &min_query,
        &max_query,
        &placeholder_hash,
    ))
}

impl<
        const MAX_NUM_COLUMNS: usize,
        const MAX_NUM_PREDICATE_OPS: usize,
        const MAX_NUM_RESULT_OPS: usize,
        const MAX_NUM_RESULTS: usize,
        T: OutputComponent<MAX_NUM_RESULTS>,
    > CircuitLogicWires<F, D, 0>
    for UniversalQueryCircuitWires<
        MAX_NUM_COLUMNS,
        MAX_NUM_PREDICATE_OPS,
        MAX_NUM_RESULT_OPS,
        MAX_NUM_RESULTS,
        T,
    >
where
    [(); MAX_NUM_COLUMNS + MAX_NUM_RESULT_OPS]:,
    [(); MAX_NUM_RESULTS - 1]:,
{
    type CircuitBuilderParams = ();

    type Inputs = UniversalQueryCircuitInputs<
        MAX_NUM_COLUMNS,
        MAX_NUM_PREDICATE_OPS,
        MAX_NUM_RESULT_OPS,
        MAX_NUM_RESULTS,
        T,
    >;

    const NUM_PUBLIC_INPUTS: usize = PI_LEN::<MAX_NUM_RESULTS>;

    fn circuit_logic(
        builder: &mut CircuitBuilder<F, D>,
        _verified_proofs: [&ProofWithPublicInputsTarget<D>; 0],
        _builder_parameters: Self::CircuitBuilderParams,
    ) -> Self {
        UniversalQueryCircuitInputs::build(builder)
    }

    fn assign_input(&self, inputs: Self::Inputs, pw: &mut PartialWitness<F>) -> Result<()> {
        inputs.assign(pw, self);
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
/// Inputs for the 2 variant of universal query circuit
pub enum UniversalCircuitInput<
    const MAX_NUM_COLUMNS: usize,
    const MAX_NUM_PREDICATE_OPS: usize,
    const MAX_NUM_RESULT_OPS: usize,
    const MAX_NUM_RESULTS: usize,
> {
    QueryWithAgg(
        UniversalQueryCircuitInputs<
            MAX_NUM_COLUMNS,
            MAX_NUM_PREDICATE_OPS,
            MAX_NUM_RESULT_OPS,
            MAX_NUM_RESULTS,
            AggOutputCircuit<MAX_NUM_RESULTS>,
        >,
    ),
    QueryNoAgg(
        UniversalQueryCircuitInputs<
            MAX_NUM_COLUMNS,
            MAX_NUM_PREDICATE_OPS,
            MAX_NUM_RESULT_OPS,
            MAX_NUM_RESULTS,
            NoAggOutputCircuit<MAX_NUM_RESULTS>,
        >,
    ),
}

impl<
        const MAX_NUM_COLUMNS: usize,
        const MAX_NUM_PREDICATE_OPS: usize,
        const MAX_NUM_RESULT_OPS: usize,
        const MAX_NUM_RESULTS: usize,
    >
    UniversalCircuitInput<
        MAX_NUM_COLUMNS,
        MAX_NUM_PREDICATE_OPS,
        MAX_NUM_RESULT_OPS,
        MAX_NUM_RESULTS,
    >
where
    [(); MAX_NUM_RESULTS - 1]:,
    [(); MAX_NUM_COLUMNS + MAX_NUM_RESULT_OPS]:,
{
    /// Provide input values for universal circuit variant for queries with aggregation operations
    pub(crate) fn new_query_with_agg(
        column_cells: &RowCells,
        predicate_operations: &[BasicOperation],
        placeholders: &Placeholders,
        is_leaf: bool,
        query_bounds: &QueryBounds,
        results: &ResultStructure,
    ) -> Result<Self> {
        Ok(UniversalCircuitInput::QueryWithAgg(
            UniversalQueryCircuitInputs::new(
                column_cells,
                predicate_operations,
                placeholders,
                is_leaf,
                query_bounds,
                results,
            )?,
        ))
    }
    /// Provide input values for universal circuit variant for queries without aggregation operations
    pub(crate) fn new_query_no_agg(
        column_cells: &RowCells,
        predicate_operations: &[BasicOperation],
        placeholders: &Placeholders,
        is_leaf: bool,
        query_bounds: &QueryBounds,
        results: &ResultStructure,
    ) -> Result<Self> {
        Ok(UniversalCircuitInput::QueryNoAgg(
            UniversalQueryCircuitInputs::new(
                column_cells,
                predicate_operations,
                placeholders,
                is_leaf,
                query_bounds,
                results,
            )?,
        ))
    }
}

#[cfg(test)]
mod tests {
    use std::{array, iter::once};

    use alloy::primitives::U256;
    use itertools::Itertools;
    use mp2_common::{
        array::ToField,
        group_hashing::map_to_curve_point,
        poseidon::empty_poseidon_hash,
        proof::ProofWithVK,
        utils::{FromFields, ToFields, TryIntoBool},
        C, D, F,
    };
    use mp2_test::{
        cells_tree::{compute_cells_tree_hash, TestCell},
        circuit::{run_circuit, UserCircuit},
        log::init_logging,
        utils::gen_random_u256,
    };
    use plonky2::{
        field::types::{Field, PrimeField64, Sample},
        hash::hashing::hash_n_to_hash_no_pad,
        iop::witness::PartialWitness,
        plonk::{circuit_builder::CircuitBuilder, config::GenericHashOut},
    };
    use plonky2_ecgfp5::curve::curve::Point;
    use rand::{thread_rng, Rng};

    use crate::query::{
        aggregation::{QueryBoundSource, QueryBounds},
        api::{CircuitInput, Parameters},
        computational_hash_ids::{
            AggregationOperation, ColumnIDs, HashPermutation, Identifiers, Operation,
            PlaceholderIdentifier,
        },
        public_inputs::PublicInputs,
        universal_circuit::{
            universal_circuit_inputs::{
                BasicOperation, ColumnCell, InputOperand, OutputItem, PlaceholderId, Placeholders,
                ResultStructure, RowCells,
            },
            universal_query_circuit::placeholder_hash,
            ComputationalHash,
        },
    };

    use anyhow::{Error, Result};

    use super::{
        OutputComponent, UniversalCircuitInput, UniversalQueryCircuitInputs,
        UniversalQueryCircuitWires,
    };

    impl<
            const MAX_NUM_COLUMNS: usize,
            const MAX_NUM_PREDICATE_OPS: usize,
            const MAX_NUM_RESULT_OPS: usize,
            const MAX_NUM_RESULTS: usize,
            T: OutputComponent<MAX_NUM_RESULTS>,
        > UserCircuit<F, D>
        for UniversalQueryCircuitInputs<
            MAX_NUM_COLUMNS,
            MAX_NUM_PREDICATE_OPS,
            MAX_NUM_RESULT_OPS,
            MAX_NUM_RESULTS,
            T,
        >
    where
        [(); MAX_NUM_RESULTS - 1]:,
        [(); MAX_NUM_COLUMNS + MAX_NUM_RESULT_OPS]:,
    {
        type Wires = UniversalQueryCircuitWires<
            MAX_NUM_COLUMNS,
            MAX_NUM_PREDICATE_OPS,
            MAX_NUM_RESULT_OPS,
            MAX_NUM_RESULTS,
            T,
        >;

        fn build(c: &mut CircuitBuilder<F, D>) -> Self::Wires {
            UniversalQueryCircuitInputs::build(c)
        }

        fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
            self.assign(pw, wires)
        }
    }

    // utility function to locate operation `op` in the set of `previous_ops`
    fn locate_previous_operation(
        previous_ops: &[BasicOperation],
        op: &BasicOperation,
    ) -> Result<usize> {
        previous_ops
            .iter()
            .find_position(|current_op| *current_op == op)
            .map(|(pos, _)| pos)
            .ok_or(Error::msg("operation {} not found in set of previous ops"))
    }

    // test the following query:
    // SELECT AVG(C1+C2/(C2*C3)), SUM(C1+C2), MIN(C1+$1), MAX(C4-2), AVG(C5) FROM T WHERE (C5 > 5 AND C1*C3 <= C4+C5 OR C3 == $2) AND C2 >= 75 AND C2 < $3
    async fn query_with_aggregation(build_parameters: bool) {
        init_logging();
        const NUM_ACTUAL_COLUMNS: usize = 5;
        const MAX_NUM_COLUMNS: usize = 30;
        const MAX_NUM_PREDICATE_OPS: usize = 20;
        const MAX_NUM_RESULT_OPS: usize = 30;
        const MAX_NUM_RESULTS: usize = 10;
        let rng = &mut thread_rng();
        let min_query = U256::from(75);
        let max_query = U256::from(98);
        let column_values = (0..NUM_ACTUAL_COLUMNS)
            .map(|i| {
                if i == 1 {
                    // ensure that second column value is in the range specified by the query:
                    // we sample a random u256 in range [0, max_query - min_query) and then we
                    // add min_query
                    gen_random_u256(rng).div_rem(max_query - min_query).1 + min_query
                } else {
                    gen_random_u256(rng)
                }
            })
            .collect_vec();
        let column_ids = (0..NUM_ACTUAL_COLUMNS).map(|_| F::rand()).collect_vec();
        let column_cells = column_values
            .iter()
            .zip(column_ids.iter())
            .map(|(&value, &id)| ColumnCell { value, id })
            .collect_vec();
        let row_cells = RowCells::new(
            column_cells[0].clone(),
            column_cells[1].clone(),
            column_cells[2..].to_vec(),
        );
        // define placeholders
        let first_placeholder_id = PlaceholderId::Generic(0);
        let second_placeholder_id = PlaceholderIdentifier::Generic(1);
        let mut placeholders = Placeholders::new_empty(
            U256::default(),
            U256::default(), // dummy values
        );
        [first_placeholder_id, second_placeholder_id]
            .iter()
            .for_each(|id| placeholders.insert(*id, gen_random_u256(rng)));
        // 3-rd placeholder is the max query bound
        let third_placeholder_id = PlaceholderId::Generic(2);
        placeholders.insert(third_placeholder_id, max_query);

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
            first_operand: InputOperand::PreviousValue(
                locate_previous_operation(&predicate_operations, &column_prod).unwrap(),
            ),
            second_operand: Some(InputOperand::PreviousValue(
                locate_previous_operation(&predicate_operations, &column_add).unwrap(),
            )),
            op: Operation::LessThanOrEqOp,
        };
        predicate_operations.push(expr_comparison);
        // C3 == $2
        let placeholder_eq = BasicOperation {
            first_operand: InputOperand::Column(2),
            second_operand: Some(InputOperand::Placeholder(second_placeholder_id)),
            op: Operation::EqOp,
        };
        predicate_operations.push(placeholder_eq);
        // c5_comparison AND expr_comparison
        let and_comparisons = BasicOperation {
            first_operand: InputOperand::PreviousValue(
                locate_previous_operation(&predicate_operations, &c5_comparison).unwrap(),
            ),
            second_operand: Some(InputOperand::PreviousValue(
                locate_previous_operation(&predicate_operations, &expr_comparison).unwrap(),
            )),
            op: Operation::AndOp,
        };
        predicate_operations.push(and_comparisons);
        // final filtering predicate: and_comparisons OR placeholder_eq
        let predicate = BasicOperation {
            first_operand: InputOperand::PreviousValue(
                locate_previous_operation(&predicate_operations, &and_comparisons).unwrap(),
            ),
            second_operand: Some(InputOperand::PreviousValue(
                locate_previous_operation(&predicate_operations, &placeholder_eq).unwrap(),
            )),
            op: Operation::OrOp,
        };
        predicate_operations.push(predicate);
        // result computations operations
        let mut result_operations = vec![];
        // C2*C3
        let column_prod = BasicOperation {
            first_operand: InputOperand::Column(1),
            second_operand: Some(InputOperand::Column(2)),
            op: Operation::MulOp,
        };
        result_operations.push(column_prod);
        // C1+C2
        let column_add = BasicOperation {
            first_operand: InputOperand::Column(0),
            second_operand: Some(InputOperand::Column(1)),
            op: Operation::AddOp,
        };
        result_operations.push(column_add);
        // C1 + C2/(C2*C3)
        let div = BasicOperation {
            first_operand: InputOperand::PreviousValue(
                locate_previous_operation(&result_operations, &column_add).unwrap(),
            ),
            second_operand: Some(InputOperand::PreviousValue(
                locate_previous_operation(&result_operations, &column_prod).unwrap(),
            )),
            op: Operation::DivOp,
        };
        result_operations.push(div);
        // C1 + $1
        let column_placeholder = BasicOperation {
            first_operand: InputOperand::Column(0),
            second_operand: Some(InputOperand::Placeholder(first_placeholder_id)),
            op: Operation::AddOp,
        };
        // C4 - 2
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
        let output_items = vec![
            OutputItem::ComputedValue(locate_previous_operation(&result_operations, &div).unwrap()),
            OutputItem::ComputedValue(
                locate_previous_operation(&result_operations, &column_add).unwrap(),
            ),
            OutputItem::ComputedValue(
                locate_previous_operation(&result_operations, &column_placeholder).unwrap(),
            ),
            OutputItem::ComputedValue(
                locate_previous_operation(&result_operations, &column_sub_const).unwrap(),
            ),
            OutputItem::Column(4),
        ];
        let output_ops: [F; 5] = [
            AggregationOperation::SumOp.to_field(),
            AggregationOperation::AvgOp.to_field(),
            AggregationOperation::MinOp.to_field(),
            AggregationOperation::MaxOp.to_field(),
            AggregationOperation::AvgOp.to_field(),
        ];

        let results = ResultStructure::new_for_query_with_aggregation(
            result_operations,
            output_items,
            output_ops
                .iter()
                .map(|op| op.to_canonical_u64())
                .collect_vec(),
        );

        let query_bounds = QueryBounds::new(
            &placeholders,
            Some(QueryBoundSource::Constant(min_query)),
            Some(
                QueryBoundSource::Operation(BasicOperation {
                    first_operand: InputOperand::Placeholder(third_placeholder_id),
                    second_operand: Some(InputOperand::Constant(U256::from(1))),
                    op: Operation::SubOp,
                }), // the bound is computed as $3-1 since in the query we specified that C2 < $3,
                    // while the bound computed in the circuit is expected to represent the maximum value
                    // possible for C2 (i.e., C2 < $3 => C2 <= $3 - 1)
            ),
        )
        .unwrap();
        let min_query_value = query_bounds.min_query_secondary().value;
        let max_query_value = query_bounds.max_query_secondary().value;

        let input = CircuitInput::<
            MAX_NUM_COLUMNS,
            MAX_NUM_PREDICATE_OPS,
            MAX_NUM_RESULT_OPS,
            MAX_NUM_RESULTS,
        >::new_universal_circuit(
            &row_cells,
            &predicate_operations,
            &results,
            &placeholders,
            is_leaf,
            &query_bounds,
        )
        .unwrap();

        // computed expected public inputs
        // expected tree hash
        let cells = column_values
            .iter()
            .zip(column_ids.iter())
            .skip(2)
            .map(|(value, id)| TestCell::new(*value, *id))
            .collect_vec();
        let mut tree_hash = compute_cells_tree_hash(cells).await;
        if is_leaf {
            tree_hash = hash_n_to_hash_no_pad::<_, HashPermutation>(
                &empty_poseidon_hash()
                    .to_vec()
                    .into_iter()
                    .chain(empty_poseidon_hash().to_vec())
                    .chain(column_values[1].to_fields())
                    .chain(column_values[1].to_fields())
                    .chain(once(column_ids[1]))
                    .chain(column_values[1].to_fields())
                    .chain(tree_hash.to_vec())
                    .collect_vec(),
            );
        }

        // compute predicate value
        let (res, predicate_err) = BasicOperation::compute_operations(
            &predicate_operations,
            &column_values,
            &placeholders,
        )
        .unwrap();
        let predicate_value = res.last().unwrap().try_into_bool().unwrap();

        let (res, result_err) = results
            .compute_output_values(&column_values, &placeholders)
            .unwrap();

        let output_values = res
            .iter()
            .zip(output_ops.iter())
            .map(|(value, agg_op)| {
                // if predicate_value is satisfied, then the actual output value
                // is exposed as public input
                if predicate_value {
                    *value
                } else {
                    // otherwise, we just expose identity values for the given aggregation
                    // operation to ensure that the current record doesn't affect the
                    // aggregated result
                    U256::from_fields(
                        AggregationOperation::from_fields(&[*agg_op])
                            .identity_value()
                            .as_slice(),
                    )
                }
            })
            .collect_vec();

        let circuit = if let CircuitInput::UniversalCircuit(UniversalCircuitInput::QueryWithAgg(
            c,
        )) = &input
        {
            c
        } else {
            unreachable!()
        };
        let placeholder_hash_ids = circuit.ids_for_placeholder_hash();
        let placeholder_hash =
            placeholder_hash(&placeholder_hash_ids, &placeholders, &query_bounds).unwrap();
        let computational_hash = ComputationalHash::from_bytes(
            (&Identifiers::computational_hash_universal_circuit(
                &ColumnIDs::new(
                    column_ids[0].to_canonical_u64(),
                    column_ids[1].to_canonical_u64(),
                    column_ids[2..]
                        .iter()
                        .map(|id| id.to_canonical_u64())
                        .collect_vec(),
                ),
                &predicate_operations,
                &results,
                Some(query_bounds.min_query_secondary().into()),
                Some(query_bounds.max_query_secondary().into()),
            )
            .unwrap())
                .into(),
        );
        let proof = if build_parameters {
            let params = Parameters::build();
            params
                .generate_proof(input)
                .and_then(|p| ProofWithVK::deserialize(&p))
                .and_then(|p| Ok(p.proof().clone()))
                .unwrap()
        } else {
            run_circuit::<F, D, C, _>(circuit.clone())
        };

        let pi = PublicInputs::<_, MAX_NUM_RESULTS>::from_slice(&proof.public_inputs);
        assert_eq!(tree_hash, pi.tree_hash());
        assert_eq!(output_values[0], pi.first_value_as_u256());
        assert_eq!(output_values[1..], pi.values()[..output_values.len() - 1]);
        assert_eq!(output_ops, pi.operation_ids()[..output_ops.len()]);
        assert_eq!(
            predicate_value,
            pi.num_matching_rows().try_into_bool().unwrap()
        );
        assert_eq!(column_values[0], pi.index_value());
        assert_eq!(column_values[1], pi.min_value());
        assert_eq!(column_values[1], pi.max_value());
        assert_eq!([column_ids[0], column_ids[1]], pi.index_ids());
        assert_eq!(min_query_value, pi.min_query_value());
        assert_eq!(max_query_value, pi.max_query_value());
        assert_eq!(placeholder_hash, pi.placeholder_hash());
        assert_eq!(computational_hash, pi.computational_hash());
        assert_eq!(predicate_err || result_err, pi.overflow_flag());
    }

    #[tokio::test]
    async fn test_query_with_aggregation() {
        query_with_aggregation(false).await
    }

    #[tokio::test]
    async fn test_parameters_query_with_aggregation() {
        query_with_aggregation(true).await
    }

    // test the following query:
    // SELECT C1 < C2/45, C3*C4, C7, (C5-C6)%C1, C3*C4 - $1 FROM T WHERE ((NOT C5 != 42) OR C1*C7 <= C4/C6+C5 XOR C3 < $2) AND C2 >= $3 AND C2 < 44
    async fn query_without_aggregation(single_result: bool, build_parameters: bool) {
        init_logging();
        const NUM_ACTUAL_COLUMNS: usize = 7;
        const MAX_NUM_COLUMNS: usize = 30;
        const MAX_NUM_PREDICATE_OPS: usize = 20;
        const MAX_NUM_RESULT_OPS: usize = 30;
        const MAX_NUM_RESULTS: usize = 10;
        let rng = &mut thread_rng();
        let min_query = U256::from(43);
        let max_query = U256::from(43);
        let column_values = (0..NUM_ACTUAL_COLUMNS)
            .map(|i| {
                if i == 1 {
                    // ensure that second column value is in the range specified by the query:
                    // we sample a random u256 in range [0, max_query - min_query + 1) and then we
                    // add min_query
                    gen_random_u256(rng)
                        .div_rem(max_query - min_query + U256::from(1))
                        .1
                        + min_query
                } else {
                    gen_random_u256(rng)
                }
            })
            .collect_vec();
        let column_ids = (0..NUM_ACTUAL_COLUMNS).map(|_| F::rand()).collect_vec();
        let column_cells = column_values
            .iter()
            .zip(column_ids.iter())
            .map(|(&value, &id)| ColumnCell { value, id })
            .collect_vec();
        let row_cells = RowCells::new(
            column_cells[0].clone(),
            column_cells[1].clone(),
            column_cells[2..].to_vec(),
        );
        // define placeholders
        let first_placeholder_id = PlaceholderId::Generic(0);
        let second_placeholder_id = PlaceholderIdentifier::Generic(1);
        let mut placeholders = Placeholders::new_empty(
            U256::default(),
            U256::default(), // dummy values
        );
        [first_placeholder_id, second_placeholder_id]
            .iter()
            .for_each(|id| placeholders.insert(*id, gen_random_u256(rng)));
        // 3-rd placeholder is the min query bound
        let third_placeholder_id = PlaceholderId::Generic(2);
        placeholders.insert(third_placeholder_id, min_query);

        // build predicate operations
        let mut predicate_operations = vec![];
        // C5 != 42
        let c5_comparison = BasicOperation {
            first_operand: InputOperand::Column(4),
            second_operand: Some(InputOperand::Constant(U256::from(42))),
            op: Operation::NeOp,
        };
        predicate_operations.push(c5_comparison);
        // C1*C7
        let column_prod = BasicOperation {
            first_operand: InputOperand::Column(0),
            second_operand: Some(InputOperand::Column(6)),
            op: Operation::MulOp,
        };
        predicate_operations.push(column_prod);
        // C4/C6
        let column_div = BasicOperation {
            first_operand: InputOperand::Column(3),
            second_operand: Some(InputOperand::Column(5)),
            op: Operation::DivOp,
        };
        predicate_operations.push(column_div);
        // C4/C6 + C5
        let expr_add = BasicOperation {
            first_operand: InputOperand::PreviousValue(
                locate_previous_operation(&predicate_operations, &column_div).unwrap(),
            ),
            second_operand: Some(InputOperand::Column(4)),
            op: Operation::AddOp,
        };
        predicate_operations.push(expr_add);
        // C1*C7 <= C4/C6 + C5
        let expr_comparison = BasicOperation {
            first_operand: InputOperand::PreviousValue(
                locate_previous_operation(&predicate_operations, &column_prod).unwrap(),
            ),
            second_operand: Some(InputOperand::PreviousValue(
                locate_previous_operation(&predicate_operations, &expr_add).unwrap(),
            )),
            op: Operation::LessThanOrEqOp,
        };
        predicate_operations.push(expr_comparison);
        // C3 < $2
        let placeholder_cmp = BasicOperation {
            first_operand: InputOperand::Column(2),
            second_operand: Some(InputOperand::Placeholder(second_placeholder_id)),
            op: Operation::LessThanOp,
        };
        // NOT c5_comparison
        predicate_operations.push(placeholder_cmp);
        let not_c5 = BasicOperation {
            first_operand: InputOperand::PreviousValue(
                locate_previous_operation(&predicate_operations, &c5_comparison).unwrap(),
            ),
            second_operand: None,
            op: Operation::NotOp,
        };
        predicate_operations.push(not_c5);
        // NOT c5_comparison OR expr_comparison
        let or_comparisons = BasicOperation {
            first_operand: InputOperand::PreviousValue(
                locate_previous_operation(&predicate_operations, &not_c5).unwrap(),
            ),
            second_operand: Some(InputOperand::PreviousValue(
                locate_previous_operation(&predicate_operations, &expr_comparison).unwrap(),
            )),
            op: Operation::OrOp,
        };
        predicate_operations.push(or_comparisons);
        // final filtering predicate: or_comparisons XOR placeholder_cmp
        let predicate = BasicOperation {
            first_operand: InputOperand::PreviousValue(
                locate_previous_operation(&predicate_operations, &or_comparisons).unwrap(),
            ),
            second_operand: Some(InputOperand::PreviousValue(
                locate_previous_operation(&predicate_operations, &placeholder_cmp).unwrap(),
            )),
            op: Operation::XorOp,
        };
        predicate_operations.push(predicate);
        // result computations operations
        let mut result_operations = vec![];
        // C2/45
        let div_const = BasicOperation {
            first_operand: InputOperand::Column(1),
            second_operand: Some(InputOperand::Constant(U256::from(45))),
            op: Operation::DivOp,
        };
        result_operations.push(div_const);
        // C1 < C2/45
        let column_cmp = BasicOperation {
            first_operand: InputOperand::Column(0),
            second_operand: Some(InputOperand::PreviousValue(
                locate_previous_operation(&result_operations, &div_const).unwrap(),
            )),
            op: Operation::LessThanOp,
        };
        result_operations.push(column_cmp);
        // C3*C4
        let column_prod = BasicOperation {
            first_operand: InputOperand::Column(2),
            second_operand: Some(InputOperand::Column(3)),
            op: Operation::MulOp,
        };
        result_operations.push(column_prod);
        // C5 - C6
        let column_sub = BasicOperation {
            first_operand: InputOperand::Column(4),
            second_operand: Some(InputOperand::Column(5)),
            op: Operation::SubOp,
        };
        result_operations.push(column_sub);
        // (C5 - C6) % C1
        let column_mod = BasicOperation {
            first_operand: InputOperand::PreviousValue(
                locate_previous_operation(&result_operations, &column_sub).unwrap(),
            ),
            second_operand: Some(InputOperand::Column(0)),
            op: Operation::AddOp,
        };
        result_operations.push(column_mod);
        // C3*C4 - $1
        let sub_placeholder = BasicOperation {
            first_operand: InputOperand::PreviousValue(
                locate_previous_operation(&result_operations, &column_prod).unwrap(),
            ),
            second_operand: Some(InputOperand::Placeholder(first_placeholder_id)),
            op: Operation::SubOp,
        };
        result_operations.push(sub_placeholder);

        let is_leaf: bool = rng.gen();
        // output items are all computed values in this query, expect for the last item
        // which is a column
        let output_items = if single_result {
            vec![OutputItem::ComputedValue(
                locate_previous_operation(&result_operations, &column_cmp).unwrap(),
            )]
        } else {
            vec![
                OutputItem::ComputedValue(
                    locate_previous_operation(&result_operations, &column_cmp).unwrap(),
                ),
                OutputItem::ComputedValue(
                    locate_previous_operation(&result_operations, &column_prod).unwrap(),
                ),
                OutputItem::Column(6),
                OutputItem::ComputedValue(
                    locate_previous_operation(&result_operations, &column_mod).unwrap(),
                ),
                OutputItem::ComputedValue(
                    locate_previous_operation(&result_operations, &sub_placeholder).unwrap(),
                ),
            ]
        };
        let output_ids = vec![F::rand(); output_items.len()];
        let results = ResultStructure::new_for_query_no_aggregation(
            result_operations,
            output_items,
            output_ids
                .iter()
                .map(|id| id.to_canonical_u64())
                .collect_vec(),
        );
        let query_bounds = QueryBounds::new(
            &placeholders,
            Some(QueryBoundSource::Placeholder(third_placeholder_id)),
            Some(QueryBoundSource::Constant(max_query)),
        )
        .unwrap();
        let input = CircuitInput::<
            MAX_NUM_COLUMNS,
            MAX_NUM_PREDICATE_OPS,
            MAX_NUM_RESULT_OPS,
            MAX_NUM_RESULTS,
        >::new_universal_circuit(
            &row_cells,
            &predicate_operations,
            &results,
            &placeholders,
            is_leaf,
            &query_bounds,
        )
        .unwrap();

        // computed expected public inputs
        // expected tree hash
        let cells = column_values
            .iter()
            .zip(column_ids.iter())
            .skip(2)
            .map(|(value, id)| TestCell::new(*value, *id))
            .collect_vec();
        let mut tree_hash = compute_cells_tree_hash(cells).await;
        if is_leaf {
            tree_hash = hash_n_to_hash_no_pad::<_, HashPermutation>(
                &empty_poseidon_hash()
                    .to_vec()
                    .into_iter()
                    .chain(empty_poseidon_hash().to_vec())
                    .chain(column_values[1].to_fields())
                    .chain(column_values[1].to_fields())
                    .chain(once(column_ids[1]))
                    .chain(column_values[1].to_fields())
                    .chain(tree_hash.to_vec())
                    .collect_vec(),
            );
        }

        // compute predicate value
        let (res, predicate_err) = BasicOperation::compute_operations(
            &predicate_operations,
            &column_values,
            &placeholders,
        )
        .unwrap();
        let predicate_value = res.last().unwrap().try_into_bool().unwrap();

        let (res, result_err) = results
            .compute_output_values(&column_values, &placeholders)
            .unwrap();

        // build cells tree for output items
        let out_cells = res
            .iter()
            .zip(output_ids.iter())
            .map(|(value, id)| TestCell::new(*value, *id))
            .collect_vec();
        let output_acc = if predicate_value {
            // if predicate value is satisfied, then we expose the accumulator of all the output values
            // to be returned for the current row
            map_to_curve_point(
                &once(out_cells[0].id)
                    .chain(out_cells[0].value.to_fields())
                    .chain(once(
                        out_cells.get(1).map(|cell| cell.id).unwrap_or_default(),
                    ))
                    .chain(
                        out_cells
                            .get(1)
                            .map(|cell| cell.value)
                            .unwrap_or_default()
                            .to_fields(),
                    )
                    .chain(
                        compute_cells_tree_hash(out_cells.get(2..).unwrap_or_default().to_vec())
                            .await
                            .to_vec(),
                    )
                    .collect_vec(),
            )
        } else {
            // otherwise, we expose the neutral point to ensure that the results for
            // the current record are not included in the accumulator of all the results
            // of the query
            Point::NEUTRAL
        };

        let circuit =
            if let CircuitInput::UniversalCircuit(UniversalCircuitInput::QueryNoAgg(c)) = &input {
                c
            } else {
                unreachable!()
            };
        let placeholder_hash_ids = circuit.ids_for_placeholder_hash();
        let placeholder_hash =
            placeholder_hash(&placeholder_hash_ids, &placeholders, &query_bounds).unwrap();
        let computational_hash = ComputationalHash::from_bytes(
            (&Identifiers::computational_hash_universal_circuit(
                &ColumnIDs::new(
                    column_ids[0].to_canonical_u64(),
                    column_ids[1].to_canonical_u64(),
                    column_ids[2..]
                        .iter()
                        .map(|id| id.to_canonical_u64())
                        .collect_vec(),
                ),
                &predicate_operations,
                &results,
                Some(query_bounds.min_query_secondary().into()),
                Some(query_bounds.max_query_secondary().into()),
            )
            .unwrap())
                .into(),
        );

        let proof = if build_parameters {
            let params = Parameters::build();
            params
                .generate_proof(input)
                .and_then(|p| ProofWithVK::deserialize(&p))
                .and_then(|p| Ok(p.proof().clone()))
                .unwrap()
        } else {
            run_circuit::<F, D, C, _>(circuit.clone())
        };

        let pi = PublicInputs::<_, MAX_NUM_RESULTS>::from_slice(&proof.public_inputs);
        assert_eq!(tree_hash, pi.tree_hash());
        assert_eq!(output_acc.to_weierstrass(), pi.first_value_as_curve_point());
        // The other MAX_NUM_RESULTS -1 output values are dummy ones, as in queries
        // without aggregation we accumulate all the results in the first output value,
        // and so we don't care about the other ones
        assert_eq!(array::from_fn(|_| U256::ZERO), pi.values());
        assert_eq!(
            <AggregationOperation as ToField<F>>::to_field(&AggregationOperation::IdOp),
            pi.operation_ids()[0]
        );
        // aggregation operation in the other MAX_NUM_RESULTS -1 slots are dummy ones, as in queries
        // without aggregation we accumulate all the results in the first output value,
        // and so we don't care about the other ones
        assert_eq!(
            [<AggregationOperation as ToField<F>>::to_field(&AggregationOperation::default());
                MAX_NUM_RESULTS - 1],
            pi.operation_ids()[1..]
        );
        assert_eq!(
            predicate_value,
            pi.num_matching_rows().try_into_bool().unwrap()
        );
        assert_eq!(column_values[0], pi.index_value());
        assert_eq!(column_values[1], pi.min_value());
        assert_eq!(column_values[1], pi.max_value());
        assert_eq!([column_ids[0], column_ids[1]], pi.index_ids());
        assert_eq!(min_query, pi.min_query_value());
        assert_eq!(max_query, pi.max_query_value());
        assert_eq!(placeholder_hash, pi.placeholder_hash());
        assert_eq!(computational_hash, pi.computational_hash());
        assert_eq!(predicate_err || result_err, pi.overflow_flag());
    }

    #[tokio::test]
    async fn test_query_without_aggregation() {
        query_without_aggregation(false, false).await
    }

    #[tokio::test]
    async fn test_query_without_aggregation_single_output() {
        query_without_aggregation(true, false).await
    }

    #[tokio::test]
    async fn test_parameters_query_no_aggregation() {
        query_without_aggregation(false, true).await
    }
}
