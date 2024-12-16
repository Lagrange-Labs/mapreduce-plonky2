//! Utility functions used for testing

use crate::{
    ivc::public_inputs::H_RANGE as ORIGINAL_TREE_H_RANGE,
    query::{
        computational_hash_ids::{
            AggregationOperation, ColumnIDs, Identifiers, Operation, PlaceholderIdentifier,
        },
        public_inputs::{
            PublicInputsFactory, PublicInputsQueryCircuits as QueryPI, QueryPublicInputs,
        },
        row_chunk_gadgets::BoundaryRowData,
        universal_circuit::{
            universal_circuit_inputs::{
                BasicOperation, ColumnCell, InputOperand, OutputItem, Placeholders, ResultStructure,
            },
            universal_query_gadget::OutputValues,
        },
        utils::{QueryBoundSource, QueryBounds, QueryHashNonExistenceCircuits},
    },
    revelation::NUM_PREPROCESSING_IO,
};
use alloy::primitives::U256;
use itertools::Itertools;
use mp2_common::{
    array::ToField,
    utils::{Fieldable, ToFields},
    F,
};
use mp2_test::utils::{gen_random_field_hash, gen_random_u256};
use plonky2::{
    field::types::{Field, PrimeField64, Sample},
    hash::hash_types::HashOut,
    plonk::config::GenericHashOut,
};
use plonky2_ecgfp5::curve::curve::Point;
use rand::{prelude::SliceRandom, thread_rng, Rng};
use std::array;

// Constants for the common test cases
pub const MAX_NUM_OUTPUTS: usize = 3;
pub const MAX_NUM_ITEMS_PER_OUTPUT: usize = 5;
// NOTE: Since the revelation public inputs is extended by flattening the
// computational hash (increasing 4 fields). This constant cannot be greater
// than 14, otherwise it causes infinite loop when building parameters.
// We could also adjust other generic parameters (as MAX_NUM_OUTPUTS) to
// restrict the length of revelation public inputs.
pub const MAX_NUM_PLACEHOLDERS: usize = 14;
pub const MAX_NUM_COLUMNS: usize = 20;
pub const MAX_NUM_PREDICATE_OPS: usize = 20;
pub const MAX_NUM_RESULT_OPS: usize = 20;
pub const ROW_TREE_MAX_DEPTH: usize = 10;
pub const INDEX_TREE_MAX_DEPTH: usize = 15;
pub const NUM_COLUMNS: usize = 4;

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

/// Generate a random original tree proof for testing.
pub fn random_original_tree_proof(tree_hash: HashOut<F>) -> Vec<F> {
    let mut rng = thread_rng();
    let mut proof = (0..NUM_PREPROCESSING_IO)
        .map(|_| rng.gen())
        .collect::<Vec<u32>>()
        .to_fields();

    // Set the tree hash.
    proof[ORIGINAL_TREE_H_RANGE].copy_from_slice(&tree_hash.to_fields());

    proof
}

/// Generate a field array of S random aggregation operations for testing.
pub fn random_aggregation_operations<const S: usize>() -> [F; S] {
    let ops = [
        AggregationOperation::IdOp,
        AggregationOperation::SumOp,
        AggregationOperation::MinOp,
        AggregationOperation::MaxOp,
        AggregationOperation::AvgOp,
    ];

    let mut rng = thread_rng();
    array::from_fn(|_| {
        let op = *ops.choose(&mut rng).unwrap();
        Identifiers::AggregationOperations(op).to_field()
    })
}

impl<const S: usize, const UNIVERSAL_CIRCUIT: bool>
    PublicInputsFactory<'_, F, S, UNIVERSAL_CIRCUIT>
{
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
            let count = F::from_canonical_u32(rng.gen());
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

            PublicInputsFactory::<F, S, UNIVERSAL_CIRCUIT>::new(
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

/// Revelation related data used for testing
#[derive(Debug)]
pub struct TestRevelationData {
    query_bounds: QueryBounds,
    placeholders: Placeholders,
    results: ResultStructure,
    column_cells: Vec<ColumnCell>,
    predicate_operations: Vec<BasicOperation>,
    user_placeholders: Vec<U256>,
    preprocessing_pi_raw: Vec<F>,
    query_pi_raw: Vec<F>,
}

impl TestRevelationData {
    /// Create a new testing instance.
    pub fn sample(min_block_number: u32, max_block_number: u32) -> Self {
        let rng = &mut thread_rng();

        // generate query proof public inputs. Employ a simple query for test:
        // SELECT AVG(C1*C2), COUNT(C3/$1) FROM T WHERE C4 < $2 AND C1 >= min_block_number AND C1 < max_block_number
        let column_cells = (0..NUM_COLUMNS)
            .map(|_| {
                ColumnCell::new(
                    rng.gen(),
                    U256::from_be_bytes(rng.gen::<[u8; U256::BYTES]>()),
                )
            })
            .collect_vec();
        let placeholder_ids = [0, 1].map(PlaceholderIdentifier::Generic);
        let user_placeholders = [0; 2]
            .map(|_| U256::from_be_bytes(rng.gen::<[u8; U256::BYTES]>()))
            .to_vec();
        let predicate_operations = vec![
            // C4 < $2
            BasicOperation::new_binary_operation(
                InputOperand::Column(3),
                InputOperand::Placeholder(placeholder_ids[1]),
                Operation::LessThanOp,
            ),
        ];
        let result_operations = vec![
            // C1*C2
            BasicOperation::new_binary_operation(
                InputOperand::Column(0),
                InputOperand::Column(1),
                Operation::MulOp,
            ),
            // C3/$1
            BasicOperation::new_binary_operation(
                InputOperand::Column(2),
                InputOperand::Placeholder(placeholder_ids[0]),
                Operation::DivOp,
            ),
        ];
        let output_items = vec![OutputItem::ComputedValue(0), OutputItem::ComputedValue(1)];
        let aggregation_ops = vec![
            AggregationOperation::AvgOp.to_id(),
            AggregationOperation::CountOp.to_id(),
        ];
        let ops_ids = aggregation_ops
            .iter()
            .map(|id| id.to_field())
            .chain(random_aggregation_operations::<MAX_NUM_ITEMS_PER_OUTPUT>())
            .take(MAX_NUM_ITEMS_PER_OUTPUT)
            .collect_vec();
        let results = ResultStructure::new_for_query_with_aggregation(
            result_operations,
            output_items,
            aggregation_ops,
        )
        .unwrap();
        let placeholders = Placeholders::from((
            placeholder_ids
                .into_iter()
                .zip_eq(user_placeholders.iter().cloned())
                .collect(),
            U256::from(min_block_number),
            U256::from(max_block_number),
        ));
        let query_bounds = QueryBounds::new(&placeholders, None, None).unwrap();

        // generate the computational hash and placeholder hash that should be exposed by query proofs
        let non_existence_circuits = QueryHashNonExistenceCircuits::new::<
            MAX_NUM_COLUMNS,
            MAX_NUM_PREDICATE_OPS,
            MAX_NUM_RESULT_OPS,
            MAX_NUM_ITEMS_PER_OUTPUT,
        >(
            &ColumnIDs::new(
                column_cells[0].id.to_canonical_u64(),
                column_cells[1].id.to_canonical_u64(),
                column_cells[2..]
                    .iter()
                    .map(|cell| cell.id.to_canonical_u64())
                    .collect_vec(),
            ),
            &predicate_operations,
            &results,
            &placeholders,
            &query_bounds,
            false, // we need to generate values as if we are in an index tree node
        )
        .unwrap();
        let computational_hash = non_existence_circuits.computational_hash();
        let placeholder_hash = non_existence_circuits.placeholder_hash();

        let [mut query_pi_raw] =
            QueryPI::<F, MAX_NUM_ITEMS_PER_OUTPUT>::sample_from_ops(&ops_ids.try_into().unwrap());
        let [min_query_primary, max_query_primary, min_query_secondary, max_query_secondary, p_hash_range, c_hash_range, left_row_range, right_row_range] =
            [
                QueryPublicInputs::MinPrimary,
                QueryPublicInputs::MaxPrimary,
                QueryPublicInputs::MinSecondary,
                QueryPublicInputs::MaxSecondary,
                QueryPublicInputs::PlaceholderHash,
                QueryPublicInputs::ComputationalHash,
                QueryPublicInputs::LeftBoundaryRow,
                QueryPublicInputs::RightBoundaryRow,
            ]
            .map(QueryPI::<F, MAX_NUM_ITEMS_PER_OUTPUT>::to_range);

        // sample left boundary row and right boundary row to satisfy revelation circuit constraints
        let (left_boundary_row, right_boundary_row) =
            sample_boundary_rows_for_revelation(&query_bounds, rng);

        // Set the minimum, maximum query, placeholder hash andn computational hash to expected values.
        [
            (
                min_query_primary,
                query_bounds.min_query_primary().to_fields(),
            ),
            (
                max_query_primary,
                query_bounds.max_query_primary().to_fields(),
            ),
            (
                min_query_secondary,
                query_bounds.min_query_secondary().value().to_fields(),
            ),
            (
                max_query_secondary,
                query_bounds.max_query_secondary().value().to_fields(),
            ),
            (p_hash_range, placeholder_hash.to_vec()),
            (c_hash_range, computational_hash.to_vec()),
            (left_row_range, left_boundary_row.to_fields()),
            (right_row_range, right_boundary_row.to_fields()),
        ]
        .into_iter()
        .for_each(|(range, fields)| query_pi_raw[range].copy_from_slice(&fields));

        let query_pi = QueryPI::<F, MAX_NUM_ITEMS_PER_OUTPUT>::from_slice(&query_pi_raw);
        assert_eq!(query_pi.min_primary(), query_bounds.min_query_primary(),);
        assert_eq!(query_pi.max_primary(), query_bounds.max_query_primary(),);
        assert_eq!(
            query_pi.min_secondary(),
            query_bounds.min_query_secondary().value,
        );
        assert_eq!(
            query_pi.max_secondary(),
            query_bounds.max_query_secondary().value,
        );
        // generate preprocessing proof public inputs
        let preprocessing_pi_raw = random_original_tree_proof(query_pi.tree_hash());

        Self {
            query_bounds,
            placeholders,
            results,
            column_cells,
            predicate_operations,
            user_placeholders,
            preprocessing_pi_raw,
            query_pi_raw,
        }
    }

    // Getter functions
    pub fn query_bounds(&self) -> &QueryBounds {
        &self.query_bounds
    }
    pub fn placeholders(&self) -> &Placeholders {
        &self.placeholders
    }
    pub fn results(&self) -> &ResultStructure {
        &self.results
    }
    pub fn column_cells(&self) -> &[ColumnCell] {
        &self.column_cells
    }
    pub fn predicate_operations(&self) -> &[BasicOperation] {
        &self.predicate_operations
    }
    pub fn user_placeholders(&self) -> &[U256] {
        &self.user_placeholders
    }
    pub fn preprocessing_pi_raw(&self) -> &[F] {
        &self.preprocessing_pi_raw
    }
    pub fn query_pi_raw(&self) -> &[F] {
        &self.query_pi_raw
    }
}

pub(crate) fn sample_boundary_rows_for_revelation<R: Rng>(
    query_bounds: &QueryBounds,
    rng: &mut R,
) -> (BoundaryRowData, BoundaryRowData) {
    let min_secondary = *query_bounds.min_query_secondary().value();
    let max_secondary = *query_bounds.max_query_secondary().value();
    let mut left_boundary_row = BoundaryRowData::sample(rng, query_bounds);
    // for predecessor of `left_boundary_row` in index tree, we need to either mark it as
    // non-existent or to make its value out of range
    if rng.gen() || query_bounds.min_query_primary() == U256::ZERO {
        left_boundary_row.index_node_info.predecessor_info.is_found = false;
    } else {
        let [predecessor_value] = gen_values_in_range(
            rng,
            U256::ZERO,
            query_bounds.min_query_primary() - U256::from(1),
        );
        left_boundary_row.index_node_info.predecessor_info.value = predecessor_value;
    }
    // for predecessor of `left_boundary_row` in rows tree, we need to either mark it as
    // non-existent or to make its value out of range
    if rng.gen() || min_secondary == U256::ZERO {
        left_boundary_row.row_node_info.predecessor_info.is_found = false;
    } else {
        let [predecessor_value] =
            gen_values_in_range(rng, U256::ZERO, min_secondary - U256::from(1));
        left_boundary_row.row_node_info.predecessor_info.value = predecessor_value;
    }
    let mut right_boundary_row = BoundaryRowData::sample(rng, query_bounds);
    // for successor of `right_boundary_row` in index tree, we need to either mark it as
    // non-existent or to make its value out of range
    if rng.gen() || query_bounds.max_query_primary() == U256::MAX {
        right_boundary_row.index_node_info.successor_info.is_found = false;
    } else {
        let [successor_value] = gen_values_in_range(
            rng,
            query_bounds.max_query_primary() + U256::from(1),
            U256::MAX,
        );
        right_boundary_row.index_node_info.successor_info.value = successor_value;
    }
    // for successor of `right_boundary_row` in rows tree, we need to either mark it as
    // non-existent or to make its value out of range
    if rng.gen() || max_secondary == U256::MAX {
        right_boundary_row.row_node_info.successor_info.is_found = false;
    } else {
        let [successor_value] = gen_values_in_range(rng, max_secondary + U256::from(1), U256::MAX);
        right_boundary_row.row_node_info.successor_info.value = successor_value;
    }

    (left_boundary_row, right_boundary_row)
}
