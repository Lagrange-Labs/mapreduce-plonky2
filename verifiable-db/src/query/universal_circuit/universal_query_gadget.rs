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
    serialization::{deserialize, deserialize_long_array, serialize, serialize_long_array},
    types::{CBuilder, CURVE_TARGET_LEN},
    u256::{CircuitBuilderU256, UInt256Target, WitnessWriteU256, NUM_LIMBS},
    utils::{FromFields, FromTargets, ToFields, ToTargets},
    CHasher, F,
};
use plonky2::{
    field::types::Field,
    hash::{hash_types::NUM_HASH_OUT_ELTS, hashing::hash_n_to_hash_no_pad},
    iop::{
        target::{BoolTarget, Target},
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::config::{GenericHashOut, Hasher},
};
use plonky2_ecgfp5::{curve::curve::WeierstrassPoint, gadgets::curve::CurveTarget};
use serde::{Deserialize, Serialize};

use crate::query::{
    computational_hash_ids::{
        ColumnIDs, ComputationalHashCache, HashPermutation, Operation, Output,
        PlaceholderIdentifier,
    },
    universal_circuit::{
        basic_operation::BasicOperationInputs, column_extraction::ColumnExtractionValueWires,
        universal_circuit_inputs::OutputItem,
    },
    utils::{QueryBoundSecondary, QueryBoundSource, QueryBounds},
};

use super::{
    basic_operation::{
        BasicOperationHashWires, BasicOperationInputWires, BasicOperationValueWires,
        BasicOperationWires,
    },
    column_extraction::{ColumnExtractionInputWires, ColumnExtractionInputs},
    universal_circuit_inputs::{
        BasicOperation, InputOperand, Placeholder, Placeholders, ResultStructure, RowCells,
    },
    universal_query_circuit::dummy_placeholder_id,
    ComputationalHash, ComputationalHashTarget, MembershipHashTarget, PlaceholderHash,
    PlaceholderHashTarget,
};

/// Wires representing a query bound in the universal circuit
pub(crate) type QueryBoundTarget = BasicOperationWires;

/// Input wires for `QueryBoundTarget` (i.e., the wires that need to be assigned)
pub(crate) type QueryBoundTargetInputs = BasicOperationInputWires;

impl From<QueryBoundTarget> for QueryBoundTargetInputs {
    fn from(value: QueryBoundTarget) -> Self {
        value.hash_wires.input_wires
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
        &self.value_wires.output_value
    }

    // Compute the number of overflows occurred during operations to compute query bounds
    pub(crate) fn num_overflows_for_query_bound_operations(
        b: &mut CBuilder,
        min_query: &Self,
        max_query: &Self,
    ) -> Target {
        b.add(
            min_query.value_wires.num_overflows,
            max_query.value_wires.num_overflows,
        )
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
                .chain(once(
                    &min_query_bound.hash_wires.input_wires.placeholder_ids[0],
                ))
                .chain(&min_query_bound.hash_wires.input_wires.placeholder_values[0].to_targets())
                .chain(once(
                    &min_query_bound.hash_wires.input_wires.placeholder_ids[1],
                ))
                .chain(&min_query_bound.hash_wires.input_wires.placeholder_values[1].to_targets())
                .chain(once(
                    &max_query_bound.hash_wires.input_wires.placeholder_ids[0],
                ))
                .chain(&max_query_bound.hash_wires.input_wires.placeholder_values[0].to_targets())
                .chain(once(
                    &max_query_bound.hash_wires.input_wires.placeholder_ids[1],
                ))
                .chain(&max_query_bound.hash_wires.input_wires.placeholder_values[1].to_targets())
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
                .chain(min_query_bound.hash_wires.output_hash.to_targets())
                .chain(max_query_bound.hash_wires.output_hash.to_targets())
                .collect_vec(),
        )
    }
}

impl QueryBoundTargetInputs {
    pub(crate) fn assign(&self, pw: &mut PartialWitness<F>, bound: &QueryBound) {
        bound.operation.assign(pw, self);
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
    #[allow(dead_code)] // unused for now, but it could be useful to keep it
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
        let min_query_op = Self::get_basic_operation(min_query)?;
        let max_query_op = Self::get_basic_operation(max_query)?;
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

/// Trait for the 2 different variants of output components we currently support
/// in query circuits
pub trait OutputComponent<const MAX_NUM_RESULTS: usize>: Clone {
    type ValueWires: OutputComponentValueWires;
    type HashWires: OutputComponentHashWires;

    fn new(selector: &[F], ids: &[F], num_outputs: usize) -> Result<Self>;

    #[cfg(test)] // used only in test for now
    fn build<const NUM_OUTPUT_VALUES: usize>(
        b: &mut CBuilder,
        possible_output_values: [UInt256Target; NUM_OUTPUT_VALUES],
        possible_output_hash: [ComputationalHashTarget; NUM_OUTPUT_VALUES],
        predicate_value: &BoolTarget,
        predicate_hash: &ComputationalHashTarget,
    ) -> OutputComponentWires<Self::ValueWires, Self::HashWires> {
        let hash_wires: <Self as OutputComponent<MAX_NUM_RESULTS>>::HashWires =
            Self::build_hash(b, possible_output_hash, predicate_hash);
        let value_wires = Self::build_values(
            b,
            possible_output_values,
            predicate_value,
            &hash_wires.input_wires(),
        );

        OutputComponentWires {
            value_wires,
            hash_wires,
        }
    }

    fn build_values<const NUM_OUTPUT_VALUES: usize>(
        b: &mut CBuilder,
        possible_output_values: [UInt256Target; NUM_OUTPUT_VALUES],
        predicate_value: &BoolTarget,
        input_wires: &<Self::HashWires as OutputComponentHashWires>::InputWires,
    ) -> Self::ValueWires;

    fn build_hash<const NUM_OUTPUT_VALUES: usize>(
        b: &mut CBuilder,
        possible_output_hash: [ComputationalHashTarget; NUM_OUTPUT_VALUES],
        predicate_hash: &ComputationalHashTarget,
    ) -> Self::HashWires;

    fn assign(
        &self,
        pw: &mut PartialWitness<F>,
        wires: &<Self::HashWires as OutputComponentHashWires>::InputWires,
    );

    /// Return the type of output component, specified as an instance of `Output` enum
    fn output_variant() -> Output;
}
/// Trait representing the wires related to the output values computed
/// by an output component implementation
pub trait OutputComponentValueWires: Clone + Debug {
    /// Associated type specifying the type of the first output value computed by this output
    /// component; this type varies depending on the particular component:
    /// - It is a `CurveTarget` in the output component for queries without aggregation operations
    /// - It is a `UInt256Target` in the output for queries with aggregation operations
    type FirstT: ToTargets;

    /// Get the first output value returned by the output component; this is accessed by an ad-hoc
    /// method since such output value could be a `UInt256Target` or a `CurveTarget`, depending
    /// on the output component instance
    fn first_output_value(&self) -> Self::FirstT;
    /// Get the subsequent output values returned by the output component
    fn other_output_values(&self) -> &[UInt256Target];
}

/// Trait representing the input/output wires related to the computational hash
/// computed by an output component implementation
pub trait OutputComponentHashWires: Clone + Debug + Eq + PartialEq {
    /// Input wires of the output component
    type InputWires: Serialize + for<'a> Deserialize<'a> + Clone + Debug + Eq + PartialEq;

    /// Get the identifiers of the aggregation operations specified in the query to aggregate the
    /// results (e.g., `SUM`, `AVG`)
    fn ops_ids(&self) -> &[Target];
    /// Get the computational hash returned by the output component
    fn computational_hash(&self) -> ComputationalHashTarget;
    /// Get the input wires for the output component
    fn input_wires(&self) -> Self::InputWires;
}

/// Wires representing an output component
#[cfg(test)] // used only in test for now
pub struct OutputComponentWires<
    ValueWires: OutputComponentValueWires,
    HashWires: OutputComponentHashWires,
> {
    pub(crate) value_wires: ValueWires,
    pub(crate) hash_wires: HashWires,
}
/// Wires for the universal query hash gadget
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub(crate) struct UniversalQueryHashInputWires<
    const MAX_NUM_COLUMNS: usize,
    const MAX_NUM_PREDICATE_OPS: usize,
    const MAX_NUM_RESULT_OPS: usize,
    const MAX_NUM_RESULTS: usize,
    T: OutputComponent<MAX_NUM_RESULTS>,
> {
    /// Input wires for column extraction component
    pub(crate) column_extraction_wires: ColumnExtractionInputWires<MAX_NUM_COLUMNS>,
    /// Lower bound of the range for the primary index specified in the query
    pub(crate) min_query_primary: UInt256Target,
    /// Upper bound of the range for the primary index specified in the query
    pub(crate) max_query_primary: UInt256Target,
    /// Lower bound of the range for the secondary index specified in the query
    min_query_secondary: QueryBoundTargetInputs,
    /// Upper bound of the range for the secondary index specified in the query
    max_query_secondary: QueryBoundTargetInputs,
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
    output_component_wires: <T::HashWires as OutputComponentHashWires>::InputWires,
}

#[derive(Clone, Debug)]
pub(crate) struct UniversalQueryHashWires<
    const MAX_NUM_COLUMNS: usize,
    const MAX_NUM_PREDICATE_OPS: usize,
    const MAX_NUM_RESULT_OPS: usize,
    const MAX_NUM_RESULTS: usize,
    T: OutputComponent<MAX_NUM_RESULTS>,
> {
    pub(crate) input_wires: UniversalQueryHashInputWires<
        MAX_NUM_COLUMNS,
        MAX_NUM_PREDICATE_OPS,
        MAX_NUM_RESULT_OPS,
        MAX_NUM_RESULTS,
        T,
    >,
    pub(crate) computational_hash: ComputationalHashTarget,
    pub(crate) placeholder_hash: PlaceholderHashTarget,
    pub(crate) min_secondary: UInt256Target,
    pub(crate) max_secondary: UInt256Target,
    pub(crate) num_bound_overflows: Target,
    pub(crate) agg_ops_ids: [Target; MAX_NUM_RESULTS],
}
/// Input values for the universal query hash gadget
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct UniversalQueryHashInputs<
    const MAX_NUM_COLUMNS: usize,
    const MAX_NUM_PREDICATE_OPS: usize,
    const MAX_NUM_RESULT_OPS: usize,
    const MAX_NUM_RESULTS: usize,
    T: OutputComponent<MAX_NUM_RESULTS>,
> {
    column_extraction_inputs: ColumnExtractionInputs<MAX_NUM_COLUMNS>,
    min_query_primary: U256,
    max_query_primary: U256,
    min_query_secondary: QueryBound,
    max_query_secondary: QueryBound,
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
    UniversalQueryHashInputs<
        MAX_NUM_COLUMNS,
        MAX_NUM_PREDICATE_OPS,
        MAX_NUM_RESULT_OPS,
        MAX_NUM_RESULTS,
        T,
    >
where
    [(); MAX_NUM_COLUMNS + MAX_NUM_RESULT_OPS]:,
{
    /// Instantiate `Self` from the necessary inputs. Note that the following assumption is expected on the
    /// structure of the inputs:
    /// The output of the last operation in `predicate_operations` will be taken as the filtering predicate evaluation;
    /// this is an assumption exploited in the circuit for efficiency, and it is a simple assumption to be required for
    /// the caller of this method
    pub(crate) fn new(
        column_ids: &ColumnIDs,
        predicate_operations: &[BasicOperation],
        placeholders: &Placeholders,
        query_bounds: &QueryBounds,
        results: &ResultStructure,
    ) -> Result<Self> {
        let num_columns = column_ids.num_columns();
        ensure!(
            num_columns <= MAX_NUM_COLUMNS,
            "number of columns is higher than the maximum value allowed"
        );
        let padded_column_ids = column_ids
            .to_vec()
            .into_iter()
            .chain(repeat(F::NEG_ONE))
            .take(MAX_NUM_COLUMNS)
            .collect_vec();
        let column_extraction_inputs = ColumnExtractionInputs::<MAX_NUM_COLUMNS> {
            real_num_columns: num_columns,
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
            placeholders,
            query_bounds.min_query_secondary(),
        )?;

        let max_query = QueryBound::new_secondary_index_bound(
            placeholders,
            query_bounds.max_query_secondary(),
        )?;

        Ok(Self {
            column_extraction_inputs,
            min_query_primary: query_bounds.min_query_primary(),
            max_query_primary: query_bounds.max_query_primary(),
            min_query_secondary: min_query,
            max_query_secondary: max_query,
            filtering_predicate_inputs: predicate_ops_inputs,
            result_values_inputs: result_ops_inputs,
            output_component_inputs,
        })
    }

    pub(crate) fn build(
        b: &mut CBuilder,
    ) -> UniversalQueryHashWires<
        MAX_NUM_COLUMNS,
        MAX_NUM_PREDICATE_OPS,
        MAX_NUM_RESULT_OPS,
        MAX_NUM_RESULTS,
        T,
    > {
        let column_extraction_wires = ColumnExtractionInputs::build_hash(b);
        let [min_query_primary, max_query_primary] = b.add_virtual_u256_arr_unsafe();
        let min_query_secondary = QueryBoundTarget::new(b);
        let max_query_secondary = QueryBoundTarget::new(b);
        let mut input_hash = column_extraction_wires.column_hash.to_vec();
        // Payload to compute the placeholder hash public input
        let mut placeholder_hash_payload = vec![];
        // Set of input wires for each of the `MAX_NUM_PREDICATE_OPS` basic operation components employed to
        // evaluate the filtering predicate
        let mut filtering_predicate_wires = Vec::with_capacity(MAX_NUM_PREDICATE_OPS);
        for _ in 0..MAX_NUM_PREDICATE_OPS {
            let BasicOperationHashWires {
                input_wires,
                output_hash,
            } = BasicOperationInputs::build_hash(b, &input_hash);
            // add the output_hash computed by the last basic operation component to the input hashes
            // for the next basic operation components employed to evaluate the filtering predicate
            input_hash.push(output_hash);
            // add placeholder data to payload for placeholder hash
            placeholder_hash_payload.push(input_wires.placeholder_ids[0]);
            placeholder_hash_payload
                .extend_from_slice(&input_wires.placeholder_values[0].to_targets());
            placeholder_hash_payload.push(input_wires.placeholder_ids[1]);
            placeholder_hash_payload
                .extend_from_slice(&input_wires.placeholder_values[1].to_targets());
            filtering_predicate_wires.push(input_wires);
        }
        // Place the computational hash of the evaluation of the filtering predicate in `predicate_hash`
        // variable; the evaluation and the corresponding hash are expected to be the output of the
        // last basic operation component among the `MAX_NUM_PREDICATE_OPS` ones employed to evaluate
        // the filtering predicate. This placement is done in order to have a fixed slot where we can
        // find the predicate hash, without the need for a further random_access operation just to extract
        // this hash from the set of predicate operations
        let predicate_hash = input_hash.last().unwrap();
        let mut input_hash = column_extraction_wires.column_hash.to_vec();
        // Set of input wires for each of the `MAX_NUM_RESULT_OPS` basic operation components employed to
        // compute the result values for the current row
        let mut result_value_wires = Vec::with_capacity(MAX_NUM_RESULT_OPS);
        for _ in 0..MAX_NUM_RESULT_OPS {
            let BasicOperationHashWires {
                input_wires,
                output_hash,
            } = BasicOperationInputs::build_hash(b, &input_hash);
            // add the output_hash computed by the last basic operation component to the input hashes
            // for the next basic operation components employed to compute result values for the current row
            input_hash.push(output_hash);
            // add placeholder data to payload for placeholder hash
            placeholder_hash_payload.push(input_wires.placeholder_ids[0]);
            placeholder_hash_payload
                .extend_from_slice(&input_wires.placeholder_values[0].to_targets());
            placeholder_hash_payload.push(input_wires.placeholder_ids[1]);
            placeholder_hash_payload
                .extend_from_slice(&input_wires.placeholder_values[1].to_targets());
            result_value_wires.push(input_wires);
        }
        // `possible_output_hash` to be provided to output component are the set of `MAX_NUM_COLUMNS`
        // and the `MAX_NUM_RESULT_OPS` computational hash of results operations, which are all already
        // accumulated in the `input_hash` vector
        let possible_output_hash: [ComputationalHashTarget; MAX_NUM_COLUMNS + MAX_NUM_RESULT_OPS] =
            input_hash.try_into().unwrap();

        let output_component_wires = T::build_hash(b, possible_output_hash, predicate_hash);
        let placeholder_hash = b.hash_n_to_hash_no_pad::<CHasher>(placeholder_hash_payload);
        let placeholder_hash = QueryBoundTarget::add_query_bounds_to_placeholder_hash(
            b,
            &min_query_secondary,
            &max_query_secondary,
            &placeholder_hash,
        );
        // add query bounds to computational hash
        let computational_hash = QueryBoundTarget::add_query_bounds_to_computational_hash(
            b,
            &min_query_secondary,
            &max_query_secondary,
            &output_component_wires.computational_hash(),
        );

        let min_secondary = *min_query_secondary.get_bound_value();
        let max_secondary = *max_query_secondary.get_bound_value();
        let num_bound_overflows = QueryBoundTarget::num_overflows_for_query_bound_operations(
            b,
            &min_query_secondary,
            &max_query_secondary,
        );
        UniversalQueryHashWires {
            input_wires: UniversalQueryHashInputWires {
                column_extraction_wires: column_extraction_wires.input_wires,
                min_query_primary,
                max_query_primary,
                min_query_secondary: min_query_secondary.into(),
                max_query_secondary: max_query_secondary.into(),
                filtering_predicate_ops: filtering_predicate_wires.try_into().unwrap(),
                result_value_ops: result_value_wires.try_into().unwrap(),
                output_component_wires: output_component_wires.input_wires(),
            },
            computational_hash,
            placeholder_hash,
            min_secondary,
            max_secondary,
            num_bound_overflows,
            agg_ops_ids: output_component_wires
                .ops_ids()
                .to_vec()
                .try_into()
                .unwrap(),
        }
    }

    pub(crate) fn assign(
        &self,
        pw: &mut PartialWitness<F>,
        wires: &UniversalQueryHashInputWires<
            MAX_NUM_COLUMNS,
            MAX_NUM_PREDICATE_OPS,
            MAX_NUM_RESULT_OPS,
            MAX_NUM_RESULTS,
            T,
        >,
    ) {
        self.column_extraction_inputs
            .assign(pw, &wires.column_extraction_wires);
        pw.set_u256_target(&wires.min_query_primary, self.min_query_primary);
        pw.set_u256_target(&wires.max_query_primary, self.max_query_primary);
        wires
            .min_query_secondary
            .assign(pw, &self.min_query_secondary);
        wires
            .max_query_secondary
            .assign(pw, &self.max_query_secondary);
        self.filtering_predicate_inputs
            .iter()
            .chain(self.result_values_inputs.iter())
            .zip(
                wires
                    .filtering_predicate_ops
                    .iter()
                    .chain(wires.result_value_ops.iter()),
            )
            .for_each(|(value, target)| value.assign(pw, target));
        self.output_component_inputs
            .assign(pw, &wires.output_component_wires);
    }

    /// This method returns the ids of the placeholders employed to compute the placeholder hash,
    /// in the same order, so that those ids can be provided as input to other circuits that need
    /// to recompute this hash
    pub(crate) fn ids_for_placeholder_hash(
        predicate_operations: &[BasicOperation],
        results: &ResultStructure,
        placeholders: &Placeholders,
        query_bounds: &QueryBounds,
    ) -> Result<Vec<PlaceholderIdentifier>> {
        let hash_input_gadget = Self::new(
            &ColumnIDs::default(),
            predicate_operations,
            placeholders,
            query_bounds,
            results,
        )?;
        Ok(hash_input_gadget
            .filtering_predicate_inputs
            .iter()
            .flat_map(|op_inputs| vec![op_inputs.placeholder_ids[0], op_inputs.placeholder_ids[1]])
            .chain(
                hash_input_gadget
                    .result_values_inputs
                    .iter()
                    .flat_map(|op_inputs| {
                        vec![op_inputs.placeholder_ids[0], op_inputs.placeholder_ids[1]]
                    }),
            )
            .map(|id| PlaceholderIdentifier::from_fields(&[id]))
            .collect_vec())
    }

    /// Utility function to compute the `BasicOperationInputs` corresponding to the set of `operations` specified
    /// as input. The set of `BasicOperationInputs` is padded to `MAX_NUM_OPS` with dummy operations, which is
    /// the expected number of operations expected as input by the circuit.
    pub(crate) fn compute_operation_inputs<const MAX_NUM_OPS: usize>(
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

#[derive(Clone, Debug)]
pub(crate) struct CurveOrU256<T>([T; CURVE_TARGET_LEN]);

impl<T: Clone + Debug> CurveOrU256<T> {
    pub(crate) fn from_slice(t: &[T]) -> Self {
        Self(
            t.iter()
                .cloned()
                .chain(repeat(t[0].clone()))
                .take(CURVE_TARGET_LEN)
                .collect_vec()
                .try_into()
                .unwrap(),
        )
    }

    pub(crate) fn to_u256_raw(&self) -> &[T] {
        &self.0[..NUM_LIMBS]
    }

    pub(crate) fn to_vec(&self) -> Vec<T> {
        self.0.to_vec()
    }
}

pub(crate) type CurveOrU256Target = CurveOrU256<Target>;

impl CurveOrU256Target {
    pub(crate) fn as_curve_target(&self) -> CurveTarget {
        CurveTarget::from_targets(self.0.as_slice())
    }

    pub(crate) fn as_u256_target(&self) -> UInt256Target {
        UInt256Target::from_targets(self.to_u256_raw())
    }
}

impl FromTargets for CurveOrU256Target {
    const NUM_TARGETS: usize = CurveTarget::NUM_TARGETS;

    fn from_targets(t: &[Target]) -> Self {
        Self::from_slice(t)
    }
}

impl ToTargets for CurveOrU256Target {
    fn to_targets(&self) -> Vec<Target> {
        self.0.to_vec()
    }
}

#[derive(Clone, Debug)]
pub(crate) struct OutputValuesTarget<const MAX_NUM_RESULTS: usize>
where
    [(); MAX_NUM_RESULTS - 1]:,
{
    pub(crate) first_output: CurveOrU256Target,
    pub(crate) other_outputs: [UInt256Target; MAX_NUM_RESULTS - 1],
}

impl<const MAX_NUM_RESULTS: usize> OutputValuesTarget<MAX_NUM_RESULTS>
where
    [(); MAX_NUM_RESULTS - 1]:,
{
    pub(crate) fn value_target_at_index(&self, i: usize) -> UInt256Target {
        if i == 0 {
            self.first_output.as_u256_target()
        } else {
            self.other_outputs[i - 1]
        }
    }

    #[cfg(test)] // used only in test for now
    pub(crate) fn build(b: &mut CBuilder) -> Self {
        let first_output = CurveOrU256(b.add_virtual_target_arr());
        let other_outputs = b.add_virtual_u256_arr();

        Self {
            first_output,
            other_outputs,
        }
    }

    #[cfg(test)] // used only in test for now
    pub(crate) fn set_target(
        &self,
        pw: &mut PartialWitness<F>,
        inputs: &OutputValues<MAX_NUM_RESULTS>,
    ) {
        pw.set_target_arr(&self.first_output.0, &inputs.first_output.0);
        pw.set_u256_target_arr(&self.other_outputs, &inputs.other_outputs);
    }
}

impl<const MAX_NUM_RESULTS: usize> ToTargets for OutputValuesTarget<MAX_NUM_RESULTS>
where
    [(); MAX_NUM_RESULTS - 1]:,
{
    fn to_targets(&self) -> Vec<Target> {
        self.first_output
            .to_targets()
            .into_iter()
            .chain(self.other_outputs.iter().flat_map(|out| out.to_targets()))
            .collect()
    }
}

impl<const MAX_NUM_RESULTS: usize> FromTargets for OutputValuesTarget<MAX_NUM_RESULTS>
where
    [(); MAX_NUM_RESULTS - 1]:,
{
    const NUM_TARGETS: usize =
        CurveTarget::NUM_TARGETS + (MAX_NUM_RESULTS - 1) * UInt256Target::NUM_TARGETS;

    fn from_targets(t: &[Target]) -> Self {
        assert!(t.len() >= Self::NUM_TARGETS);
        let first_output = CurveOrU256Target::from_targets(&t[..CurveTarget::NUM_TARGETS]);
        let other_outputs = t[CurveTarget::NUM_TARGETS..]
            .chunks(UInt256Target::NUM_TARGETS)
            .map(UInt256Target::from_targets)
            .take(MAX_NUM_RESULTS - 1)
            .collect_vec()
            .try_into()
            .unwrap();

        Self {
            first_output,
            other_outputs,
        }
    }
}
#[derive(Clone, Debug)]
pub(crate) struct OutputValues<const MAX_NUM_RESULTS: usize>
where
    [(); MAX_NUM_RESULTS - 1]:,
{
    pub(crate) first_output: CurveOrU256<F>,
    pub(crate) other_outputs: [U256; MAX_NUM_RESULTS - 1],
}

impl<const MAX_NUM_RESULTS: usize> OutputValues<MAX_NUM_RESULTS>
where
    [(); MAX_NUM_RESULTS - 1]:,
{
    pub(crate) fn new_aggregation_outputs(values: &[U256]) -> Self {
        let first_output = CurveOrU256::<F>::from_slice(&values[0].to_fields());
        let other_outputs = values[1..]
            .iter()
            .copied()
            .chain(repeat(U256::ZERO))
            .take(MAX_NUM_RESULTS - 1)
            .collect_vec();

        Self {
            first_output,
            other_outputs: other_outputs.try_into().unwrap(),
        }
    }

    pub(crate) fn new_outputs_no_aggregation(point: &plonky2_ecgfp5::curve::curve::Point) -> Self {
        let first_output = CurveOrU256::<F>::from_slice(&point.to_fields());
        Self {
            first_output,
            other_outputs: [U256::ZERO; MAX_NUM_RESULTS - 1],
        }
    }

    pub(crate) fn first_value_as_curve_point(&self) -> WeierstrassPoint {
        WeierstrassPoint::from_fields(&self.first_output.0)
    }

    pub(crate) fn first_value_as_u256(&self) -> U256 {
        let fields = self.first_output.to_u256_raw();
        U256::from_fields(fields)
    }

    /// Return the value as a UInt256 at the specified index
    pub(crate) fn value_at_index(&self, i: usize) -> U256 {
        if i == 0 {
            self.first_value_as_u256()
        } else {
            self.other_outputs[i - 1]
        }
    }
}

impl<const MAX_NUM_RESULTS: usize> FromFields<F> for OutputValues<MAX_NUM_RESULTS>
where
    [(); MAX_NUM_RESULTS - 1]:,
{
    fn from_fields(t: &[F]) -> Self {
        let first_output = CurveOrU256::from_slice(&t[..CURVE_TARGET_LEN]);
        let other_outputs = t[CURVE_TARGET_LEN..]
            .chunks(NUM_LIMBS)
            .map(U256::from_fields)
            .take(MAX_NUM_RESULTS - 1)
            .collect_vec()
            .try_into()
            .unwrap();

        Self {
            first_output,
            other_outputs,
        }
    }
}

impl<const MAX_NUM_RESULTS: usize> ToFields<F> for OutputValues<MAX_NUM_RESULTS>
where
    [(); MAX_NUM_RESULTS - 1]:,
{
    fn to_fields(&self) -> Vec<F> {
        self.first_output
            .to_vec()
            .into_iter()
            .chain(self.other_outputs.iter().flat_map(|out| out.to_fields()))
            .collect()
    }
}
/// Input wires for the universal query value gadget
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub(crate) struct UniversalQueryValueInputWires<const MAX_NUM_COLUMNS: usize> {
    #[serde(
        serialize_with = "serialize_long_array",
        deserialize_with = "deserialize_long_array"
    )]
    pub(crate) column_values: [UInt256Target; MAX_NUM_COLUMNS],
    // flag specifying whether this is a non-dummy row
    #[serde(serialize_with = "serialize", deserialize_with = "deserialize")]
    pub(crate) is_non_dummy_row: BoolTarget,
}

#[derive(Clone, Debug)]
pub(crate) struct UniversalQueryOutputWires<const MAX_NUM_RESULTS: usize>
where
    [(); MAX_NUM_RESULTS - 1]:,
{
    pub(crate) tree_hash: MembershipHashTarget,
    pub(crate) values: OutputValuesTarget<MAX_NUM_RESULTS>,
    pub(crate) count: Target,
    pub(crate) num_overflows: Target,
}

impl<const MAX_NUM_RESULTS: usize> FromTargets for UniversalQueryOutputWires<MAX_NUM_RESULTS>
where
    [(); MAX_NUM_RESULTS - 1]:,
{
    const NUM_TARGETS: usize = NUM_HASH_OUT_ELTS + 2 + OutputValuesTarget::NUM_TARGETS;
    fn from_targets(t: &[Target]) -> Self {
        assert!(t.len() >= Self::NUM_TARGETS);
        Self {
            tree_hash: MembershipHashTarget::from_vec(t[..NUM_HASH_OUT_ELTS].to_vec()),
            values: OutputValuesTarget::from_targets(&t[NUM_HASH_OUT_ELTS..]),
            count: t[Self::NUM_TARGETS - 2],
            num_overflows: t[Self::NUM_TARGETS - 1],
        }
    }
}

impl<const MAX_NUM_RESULTS: usize> ToTargets for UniversalQueryOutputWires<MAX_NUM_RESULTS>
where
    [(); MAX_NUM_RESULTS - 1]:,
{
    fn to_targets(&self) -> Vec<Target> {
        self.tree_hash
            .to_targets()
            .into_iter()
            .chain(self.values.to_targets())
            .chain([self.count, self.num_overflows])
            .collect()
    }
}

#[derive(Clone, Debug)]
pub(crate) struct UniversalQueryValueWires<
    const MAX_NUM_COLUMNS: usize,
    const MAX_NUM_RESULTS: usize,
> where
    [(); MAX_NUM_RESULTS - 1]:,
{
    pub(crate) input_wires: UniversalQueryValueInputWires<MAX_NUM_COLUMNS>,
    pub(crate) output_wires: UniversalQueryOutputWires<MAX_NUM_RESULTS>,
}
/// Input values for the universal query value gadget
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct UniversalQueryValueInputs<
    const MAX_NUM_COLUMNS: usize,
    const MAX_NUM_PREDICATE_OPS: usize,
    const MAX_NUM_RESULT_OPS: usize,
    const MAX_NUM_RESULTS: usize,
> {
    #[serde(
        serialize_with = "serialize_long_array",
        deserialize_with = "deserialize_long_array"
    )]
    pub(crate) column_values: [U256; MAX_NUM_COLUMNS],
    pub(crate) is_dummy_row: bool,
}

impl<
        const MAX_NUM_COLUMNS: usize,
        const MAX_NUM_PREDICATE_OPS: usize,
        const MAX_NUM_RESULT_OPS: usize,
        const MAX_NUM_RESULTS: usize,
    >
    UniversalQueryValueInputs<
        MAX_NUM_COLUMNS,
        MAX_NUM_PREDICATE_OPS,
        MAX_NUM_RESULT_OPS,
        MAX_NUM_RESULTS,
    >
where
    [(); MAX_NUM_COLUMNS + MAX_NUM_RESULT_OPS]:,
    [(); MAX_NUM_RESULTS - 1]:,
{
    pub(crate) fn new(row_cells: &RowCells, is_dummy_row: bool) -> Result<Self> {
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
        Ok(Self {
            column_values: padded_column_values.try_into().unwrap(),
            is_dummy_row,
        })
    }

    pub(crate) fn build<T: OutputComponent<MAX_NUM_RESULTS>>(
        b: &mut CBuilder,
        hash_input_wires: &UniversalQueryHashInputWires<
            MAX_NUM_COLUMNS,
            MAX_NUM_PREDICATE_OPS,
            MAX_NUM_RESULT_OPS,
            MAX_NUM_RESULTS,
            T,
        >,
        min_secondary: &UInt256Target,
        max_secondary: &UInt256Target,
        num_overflows: &Target,
    ) -> UniversalQueryValueWires<MAX_NUM_COLUMNS, MAX_NUM_RESULTS> {
        let column_values = ColumnExtractionInputs::build_column_values(b);
        let _true = b._true();
        // allocate dummy row flag only if we aren't in universal circuit, i.e., if min_primary.is_some() is true
        let is_non_dummy_row = b.add_virtual_bool_target_safe();
        let ColumnExtractionValueWires { tree_hash } = ColumnExtractionInputs::build_tree_hash(
            b,
            &column_values,
            &hash_input_wires.column_extraction_wires,
        );

        // Enforce that the value of primary index for the current row is in the range given by these bounds
        let index_value = &column_values[0];
        let less_than_max =
            b.is_less_or_equal_than_u256(index_value, &hash_input_wires.max_query_primary);
        let greater_than_min =
            b.is_less_or_equal_than_u256(&hash_input_wires.min_query_primary, index_value);
        b.connect(less_than_max.target, _true.target);
        b.connect(greater_than_min.target, _true.target);

        // min and max for secondary indexed column
        let node_min = &column_values[1];
        let node_max = node_min;
        // determine whether the value of second indexed column for the current record is in
        // the range specified by the query
        let less_than_max = b.is_less_or_equal_than_u256(node_max, max_secondary);
        let greater_than_min = b.is_less_or_equal_than_u256(min_secondary, node_min);
        let is_in_range = b.and(less_than_max, greater_than_min);

        // initialize input_values vectors for basic operation components employed to
        // evaluate the filtering predicate
        let mut input_values = column_values.to_vec();
        let mut num_overflows = *num_overflows;
        for i in 0..MAX_NUM_PREDICATE_OPS {
            let BasicOperationValueWires {
                output_value,
                num_overflows: new_num_overflows,
            } = BasicOperationInputs::build_values(
                b,
                &input_values,
                &hash_input_wires.filtering_predicate_ops[i],
                num_overflows,
            );
            // add the output_value computed by the last basic operation component to the input values
            // for the next basic operation components employed to evaluate the filtering predicate
            input_values.push(output_value);
            // update the counter of overflows detected
            num_overflows = new_num_overflows;
        }
        // Place the evaluation of the filtering predicate in `predicate_value` variable; the evaluation and
        // the corresponding hash are expected to be the output of the last basic operation component among
        // the `MAX_NUM_PREDICATE_OPS` ones employed to evaluate the filtering predicate. This placement is
        // done in order to have a fixed slot where we can find the predicate value, without the need for a
        // further random_access operation just to extract this value from the set of predicate operations
        let predicate_value = input_values.last().unwrap().to_bool_target();
        // filtering predicate must be false if the secondary index value for the current row is not in the
        // range specified by the query
        let predicate_value = b.and(predicate_value, is_in_range);
        // filtering predicate must be false also if this is a dummy row
        let predicate_value = b.and(predicate_value, is_non_dummy_row);

        // initialize input_values vectors for basic operation components employed to
        // compute results values for current row
        let mut input_values = column_values.to_vec();
        for i in 0..MAX_NUM_RESULT_OPS {
            let BasicOperationValueWires {
                output_value,
                num_overflows: new_num_overflows,
            } = BasicOperationInputs::build_values(
                b,
                &input_values,
                &hash_input_wires.result_value_ops[i],
                num_overflows,
            );
            // add the output_value computed by the last basic operation component to the input values
            // for the next basic operation components employed to evaluate the filtering predicate
            input_values.push(output_value);
            // update the counter of overflows detected
            num_overflows = new_num_overflows;
        }

        // `possible_output_values` to be provided to output component are the set of `MAX_NUM_COLUMNS`
        // and the `MAX_NUM_RESULT_OPS` results of results operations, which are all already accumulated
        // in the `input_values` vector
        let possible_output_values: [UInt256Target; MAX_NUM_COLUMNS + MAX_NUM_RESULT_OPS] =
            input_values.try_into().unwrap();

        let output_component_value_wires = T::build_values(
            b,
            possible_output_values,
            &predicate_value,
            &hash_input_wires.output_component_wires,
        );

        // compute output_values to be exposed; we build the first output value as a `CurveOrU256Target`
        let first_output = CurveOrU256Target::from_targets(
            &output_component_value_wires
                .first_output_value()
                .to_targets(),
        );
        // Append the other `MAX_NUM_RESULTS-1` output values
        let output_values = OutputValuesTarget {
            first_output,
            other_outputs: output_component_value_wires
                .other_output_values()
                .to_vec()
                .try_into()
                .unwrap(),
        };

        // ensure that `num_overflows` is always 0 in case of dummy rows
        let num_overflows = b.mul(num_overflows, is_non_dummy_row.target);

        UniversalQueryValueWires {
            input_wires: UniversalQueryValueInputWires {
                column_values,
                is_non_dummy_row,
            },
            output_wires: UniversalQueryOutputWires {
                tree_hash,
                values: output_values,
                count: predicate_value.target,
                num_overflows,
            },
        }
    }

    pub(crate) fn assign(
        &self,
        pw: &mut PartialWitness<F>,
        wires: &UniversalQueryValueInputWires<MAX_NUM_COLUMNS>,
    ) {
        pw.set_u256_target_arr(&wires.column_values, &self.column_values);
        pw.set_bool_target(wires.is_non_dummy_row, !self.is_dummy_row);
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
