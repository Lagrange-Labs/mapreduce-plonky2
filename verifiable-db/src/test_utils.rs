//! Utility functions used for testing

use crate::{
    ivc::public_inputs::H_RANGE as ORIGINAL_TREE_H_RANGE,
    query::{
        aggregation::{QueryBounds, QueryHashNonExistenceCircuits},
        computational_hash_ids::{
            AggregationOperation, ColumnIDs, Identifiers, Operation, PlaceholderIdentifier,
        },
        public_inputs::{
            PublicInputs as QueryPI, PublicInputs as QueryProofPublicInputs, PublicInputs,
            QueryPublicInputs,
        },
        universal_circuit::universal_circuit_inputs::{
            BasicOperation, ColumnCell, InputOperand, OutputItem, Placeholders, ResultStructure,
        },
        PI_LEN,
    },
    revelation::NUM_PREPROCESSING_IO,
};
use alloy::primitives::U256;
use itertools::Itertools;
use mp2_common::{
    array::ToField,
    types::CURVE_TARGET_LEN,
    utils::{Fieldable, ToFields},
    F,
};
use plonky2::{
    field::types::{Field, PrimeField64, Sample},
    hash::hash_types::NUM_HASH_OUT_ELTS,
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

/// Generate a random original tree proof for testing.
pub fn random_original_tree_proof<const S: usize>(
    query_pi: &QueryProofPublicInputs<F, S>,
) -> Vec<F> {
    let mut rng = thread_rng();
    let mut proof = (0..NUM_PREPROCESSING_IO)
        .map(|_| rng.gen())
        .collect::<Vec<u32>>()
        .to_fields();

    // Set the tree hash.
    proof[ORIGINAL_TREE_H_RANGE].copy_from_slice(query_pi.to_hash_raw());

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

/// Generate S number of proof public input slices by the specified operations for testing.
/// The each returned proof public inputs could be constructed by
/// `PublicInputs::from_slice` function.
pub fn random_aggregation_public_inputs<const N: usize, const S: usize>(
    ops: &[F; S],
) -> [Vec<F>; N] {
    let [ops_range, overflow_range, index_ids_range, c_hash_range, p_hash_range] = [
        QueryPublicInputs::OpIds,
        QueryPublicInputs::Overflow,
        QueryPublicInputs::IndexIds,
        QueryPublicInputs::ComputationalHash,
        QueryPublicInputs::PlaceholderHash,
    ]
    .map(PublicInputs::<F, S>::to_range);

    let first_value_start = PublicInputs::<F, S>::to_range(QueryPublicInputs::OutputValues).start;
    let is_first_op_id =
        ops[0] == Identifiers::AggregationOperations(AggregationOperation::IdOp).to_field();

    // Generate the index ids, computational hash and placeholder hash,
    // they should be same for a series of public inputs.
    let mut rng = thread_rng();
    let index_ids = (0..2).map(|_| rng.gen()).collect::<Vec<u32>>().to_fields();
    let [computational_hash, placeholder_hash]: [Vec<_>; 2] = array::from_fn(|_| {
        (0..NUM_HASH_OUT_ELTS)
            .map(|_| rng.gen())
            .collect::<Vec<u32>>()
            .to_fields()
    });

    array::from_fn(|_| {
        let mut pi = (0..PI_LEN::<S>)
            .map(|_| rng.gen())
            .collect::<Vec<u32>>()
            .to_fields();

        // Copy the specified operations to the proofs.
        pi[ops_range.clone()].copy_from_slice(ops);

        // Set the overflow flag to a random boolean.
        let overflow = F::from_bool(rng.gen());
        pi[overflow_range.clone()].copy_from_slice(&[overflow]);

        // Set the index ids, computational hash and placeholder hash,
        pi[index_ids_range.clone()].copy_from_slice(&index_ids);
        pi[c_hash_range.clone()].copy_from_slice(&computational_hash);
        pi[p_hash_range.clone()].copy_from_slice(&placeholder_hash);

        // If the first operation is ID, set the value to a random point.
        if is_first_op_id {
            let first_value = Point::sample(&mut rng).to_weierstrass().to_fields();
            pi[first_value_start..first_value_start + CURVE_TARGET_LEN]
                .copy_from_slice(&first_value);
        }

        pi
    })
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

        let [mut query_pi_raw] = random_aggregation_public_inputs::<1, MAX_NUM_ITEMS_PER_OUTPUT>(
            &ops_ids.try_into().unwrap(),
        );
        let [min_query_range, max_query_range, p_hash_range, c_hash_range] = [
            QueryPublicInputs::MinQuery,
            QueryPublicInputs::MaxQuery,
            QueryPublicInputs::PlaceholderHash,
            QueryPublicInputs::ComputationalHash,
        ]
        .map(QueryPI::<F, MAX_NUM_ITEMS_PER_OUTPUT>::to_range);

        // Set the minimum, maximum query, placeholder hash andn computational hash to expected values.
        [
            (
                min_query_range,
                query_bounds.min_query_primary().to_fields(),
            ),
            (
                max_query_range,
                query_bounds.max_query_primary().to_fields(),
            ),
            (p_hash_range, placeholder_hash.to_vec()),
            (c_hash_range, computational_hash.to_vec()),
        ]
        .into_iter()
        .for_each(|(range, fields)| query_pi_raw[range].copy_from_slice(&fields));

        let query_pi = QueryPI::<F, MAX_NUM_ITEMS_PER_OUTPUT>::from_slice(&query_pi_raw);
        // generate preprocessing proof public inputs
        let preprocessing_pi_raw = random_original_tree_proof(&query_pi);

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
