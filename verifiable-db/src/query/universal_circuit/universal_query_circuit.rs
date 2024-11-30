use std::iter::once;

use crate::query::{
    aggregation::QueryBounds, computational_hash_ids::PlaceholderIdentifier, pi_len, public_inputs::PublicInputs
};
use anyhow::Result;
use itertools::Itertools;
use mp2_common::{
    array::ToField,
    poseidon::{empty_poseidon_hash, HashPermutation},
    public_inputs::PublicInputCommon,
    serialization::{deserialize, serialize},
    utils::{SelectHashBuilder, ToFields, ToTargets},
    CHasher, D, F,
};
use plonky2::{
    hash::hashing::hash_n_to_hash_no_pad,
    iop::{
        target::{BoolTarget, Target},
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{circuit_builder::CircuitBuilder, proof::ProofWithPublicInputsTarget},
};
use recursion_framework::circuit_builder::CircuitLogicWires;
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use super::{
    output_no_aggregation::Circuit as NoAggOutputCircuit,
    output_with_aggregation::Circuit as AggOutputCircuit,
    universal_circuit_inputs::{
        BasicOperation, PlaceholderId, Placeholders, ResultStructure, RowCells,
    },
    universal_query_gadget::{
        OutputComponent, QueryBound, UniversalQueryHashInputWires, UniversalQueryHashInputs,
        UniversalQueryValueInputWires, UniversalQueryValueInputs,
    },
    PlaceholderHash,
};

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
/// Input wires for the universal query circuit
pub struct UniversalQueryCircuitWires<
    const MAX_NUM_COLUMNS: usize,
    const MAX_NUM_PREDICATE_OPS: usize,
    const MAX_NUM_RESULT_OPS: usize,
    const MAX_NUM_RESULTS: usize,
    T: OutputComponent<MAX_NUM_RESULTS>,
> {
    /// flag specifying whether the given row is stored in a leaf node of a rows tree or not
    #[serde(serialize_with = "serialize", deserialize_with = "deserialize")]
    is_leaf: BoolTarget,
    hash_wires: UniversalQueryHashInputWires<
        MAX_NUM_COLUMNS,
        MAX_NUM_PREDICATE_OPS,
        MAX_NUM_RESULT_OPS,
        MAX_NUM_RESULTS,
        T,
    >,
    value_wires: UniversalQueryValueInputWires<MAX_NUM_COLUMNS>,
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
    is_leaf: bool,
    hash_gadget_inputs: UniversalQueryHashInputs<
        MAX_NUM_COLUMNS,
        MAX_NUM_PREDICATE_OPS,
        MAX_NUM_RESULT_OPS,
        MAX_NUM_RESULTS,
        T,
    >,
    value_gadget_inputs: UniversalQueryValueInputs<
        MAX_NUM_COLUMNS,
        MAX_NUM_PREDICATE_OPS,
        MAX_NUM_RESULT_OPS,
        MAX_NUM_RESULTS,
    >,
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
        let hash_gadget_inputs = UniversalQueryHashInputs::new(
            &row_cells.column_ids(),
            predicate_operations,
            placeholders,
            query_bounds,
            results,
        )?;

        let value_gadget_inputs = UniversalQueryValueInputs::new(row_cells, true)?;

        Ok(Self {
            is_leaf,
            hash_gadget_inputs,
            value_gadget_inputs,
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
        let hash_wires = UniversalQueryHashInputs::build(b);
        let value_wires = UniversalQueryValueInputs::build(
            b,
            &hash_wires.input_wires,
            &hash_wires.min_secondary,
            &hash_wires.max_secondary,
            None,
            None,
            &hash_wires.num_bound_overflows,
        );
        let is_leaf = b.add_virtual_bool_target_safe();
        let _true = b._true();
        let zero = b.zero();
        // min and max for secondary indexed column
        let node_min = &value_wires.input_wires.column_values[1];
        let node_max = node_min;
        // value of the primary indexed column
        let index_value = &value_wires.input_wires.column_values[0];
        // column ids for primary and seconday indexed columns
        let (primary_index_id, second_index_id) = (
            &hash_wires.input_wires.column_extraction_wires.column_ids[0],
            &hash_wires.input_wires.column_extraction_wires.column_ids[1],
        );
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
            .chain(value_wires.output_wires.tree_hash.elements.iter())
            .cloned()
            .collect();
        let leaf_hash = b.hash_n_to_hash_no_pad::<CHasher>(leaf_hash_inputs);
        let tree_hash = b.select_hash(is_leaf, &leaf_hash, &value_wires.output_wires.tree_hash);

        // compute overflow flag
        let overflow = b.is_not_equal(value_wires.output_wires.num_overflows, zero);

        let output_values_targets = value_wires
            .output_wires
            .values
            .into_iter()
            .flatten()
            .collect_vec();

        PublicInputs::<Target, MAX_NUM_RESULTS>::new(
            &tree_hash.to_targets(),
            &output_values_targets,
            &[value_wires.output_wires.count],
            hash_wires.agg_ops_ids.as_slice(),
            &index_value.to_targets(),
            &node_min.to_targets(),
            &node_max.to_targets(),
            &[*primary_index_id, *second_index_id],
            &hash_wires.min_secondary.to_targets(),
            &hash_wires.max_secondary.to_targets(),
            &[overflow.target],
            &hash_wires.computational_hash.to_targets(),
            &hash_wires.placeholder_hash.to_targets(),
        )
        .register(b);

        UniversalQueryCircuitWires {
            is_leaf,
            hash_wires: hash_wires.input_wires,
            value_wires: value_wires.input_wires,
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
        pw.set_bool_target(wires.is_leaf, self.is_leaf);
        self.hash_gadget_inputs.assign(pw, &wires.hash_wires);
        self.value_gadget_inputs.assign(pw, &wires.value_wires);
    }

    /// This method returns the ids of the placeholders employed to compute the placeholder hash,
    /// in the same order, so that those ids can be provided as input to other circuits that need
    /// to recompute this hash
    pub(crate) fn ids_for_placeholder_hash(&self) -> Vec<PlaceholderId> {
        self.hash_gadget_inputs.ids_for_placeholder_hash()
    }
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
        QueryBound::new_secondary_index_bound(placeholders, query_bounds.min_query_secondary())?;
    let max_query =
        QueryBound::new_secondary_index_bound(placeholders, query_bounds.max_query_secondary())?;
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
        T: OutputComponent<MAX_NUM_RESULTS> + Serialize + DeserializeOwned,
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

    const NUM_PUBLIC_INPUTS: usize = pi_len::<MAX_NUM_RESULTS>();

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
        field::types::{PrimeField64, Sample},
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
        )
        .unwrap();

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
                .map(|p| p.proof().clone())
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
            false,
        )
        .unwrap();
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
                .map(|p| p.proof().clone())
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
