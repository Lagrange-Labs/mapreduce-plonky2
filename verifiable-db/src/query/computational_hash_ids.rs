use std::{
    collections::HashMap,
    iter::{once, repeat},
    mem::variant_count,
};

use alloy::primitives::U256;
use anyhow::{anyhow, ensure, Result};
use itertools::Itertools;

use mp2_common::{
    array::ToField,
    poseidon::{empty_poseidon_hash, H},
    types::{CBuilder, HashOutput},
    u256::UInt256Target,
    utils::{Fieldable, FromFields, SelectHashBuilder, ToFields, ToTargets},
    CHasher, F,
};
use plonky2::{
    field::types::{Field, PrimeField64},
    hash::{
        hash_types::{HashOut, RichField},
        hashing::hash_n_to_hash_no_pad,
    },
    iop::target::{BoolTarget, Target},
    plonk::config::{GenericHashOut, Hasher},
};
use plonky2_ecgfp5::curve::curve::Point;
use serde::{Deserialize, Serialize};

use crate::revelation::placeholders_check::placeholder_ids_hash;

use super::{
    aggregation::QueryBoundSource,
    universal_circuit::{
        universal_circuit_inputs::{
            BasicOperation, InputOperand, OutputItem, PlaceholderIdsSet, ResultStructure,
        },
        universal_query_gadget::QueryBound,
        ComputationalHash, ComputationalHashTarget,
    },
};

pub enum Identifiers {
    Extraction(Extraction),
    Operations(Operation),
    Output(Output),
    AggregationOperations(AggregationOperation),
    PlaceholderIdentifiers(PlaceholderIdentifier),
    ResultIdentifiers(ResultIdentifier),
    // TODO
}

impl Identifiers {
    pub fn offset(&self) -> usize {
        match self {
            Identifiers::Extraction(_) => 0,
            Identifiers::Operations(_) => {
                Identifiers::Extraction(Extraction::default()).offset()
                    + variant_count::<Extraction>()
            }
            Identifiers::Output(_) => {
                Identifiers::Operations(Operation::default()).offset()
                    + variant_count::<Operation>()
            }
            Identifiers::AggregationOperations(_) => {
                Identifiers::Output(Output::default()).offset() + variant_count::<Output>()
            }
            &Identifiers::PlaceholderIdentifiers(_) => {
                Identifiers::AggregationOperations(AggregationOperation::default()).offset()
                    + variant_count::<Output>()
            }
            &Identifiers::ResultIdentifiers(_) => {
                Identifiers::PlaceholderIdentifiers(PlaceholderIdentifier::default()).offset()
                    + variant_count::<Output>()
            }
        }
    }
    pub fn position(&self) -> usize {
        let offset = self.offset();
        offset
            + match self {
                Identifiers::Extraction(e) => *e as usize,
                Identifiers::Operations(o) => *o as usize,
                Identifiers::Output(o) => *o as usize,
                Identifiers::AggregationOperations(ao) => *ao as usize,
                Identifiers::PlaceholderIdentifiers(id) => id.position(),
                Identifiers::ResultIdentifiers(ri) => *ri as usize,
            }
    }
    pub(crate) fn prefix_id_hash(&self, elements: Vec<F>) -> ComputationalHash {
        let inputs: Vec<_> = once(self.to_field()).chain(elements).collect();
        H::hash_no_pad(&inputs)
    }
    pub(crate) fn prefix_id_hash_circuit(
        &self,
        b: &mut CBuilder,
        elements: Vec<Target>,
    ) -> ComputationalHashTarget {
        let inputs = once(b.constant(self.to_field())).chain(elements).collect();
        b.hash_n_to_hash_no_pad::<CHasher>(inputs)
    }

    /// Internal method employed to comput the computational hash corresponding to a query represented by the
    /// provided inputs, without including the query bounds portion of the computational hash
    pub(crate) fn computational_hash_without_query_bounds(
        column_ids: &ColumnIDs,
        predicate_operations: &[BasicOperation],
        results: &ResultStructure,
    ) -> Result<ComputationalHash> {
        let column_ids = column_ids.to_vec();
        let mut cache = ComputationalHashCache::new(column_ids.len());
        let predicate_ops_hash =
            Operation::operation_hash(predicate_operations, &column_ids, &mut cache)?;
        let predicate_hash = predicate_ops_hash.last().unwrap();
        let result_ops_hash =
            Operation::operation_hash(&results.result_operations, &column_ids, &mut cache)?;
        results.output_variant.output_hash(
            predicate_hash,
            &mut cache,
            &column_ids,
            &result_ops_hash,
            &results.output_items,
            &results.output_ids,
        )
    }

    /// Compute the computational hash computed by the universal circuit for the query represented
    /// by the given inputs
    pub fn computational_hash_universal_circuit(
        column_ids: &ColumnIDs,
        predicate_operations: &[BasicOperation],
        results: &ResultStructure,
        min_query_secondary: Option<QueryBoundSource>,
        max_query_secondary: Option<QueryBoundSource>,
    ) -> Result<HashOutput> {
        let computational_hash = Self::computational_hash_without_query_bounds(
            column_ids,
            predicate_operations,
            results,
        )?;
        let min_query = min_query_secondary.unwrap_or(QueryBoundSource::Constant(U256::ZERO));
        let max_query = max_query_secondary.unwrap_or(QueryBoundSource::Constant(U256::MAX));
        // compute values to be hashed for min and max query bounds
        let hash_with_query_bounds = QueryBound::add_secondary_query_bounds_to_computational_hash(
            &min_query,
            &max_query,
            &computational_hash,
        )?;
        Ok(HashOutput::try_from(hash_with_query_bounds.to_bytes()).unwrap())
    }

    /// Compute the computational hash.
    pub fn computational_hash(
        column_ids: &ColumnIDs,
        predicate_operations: &[BasicOperation],
        results: &ResultStructure,
        metadata_hash: &HashOutput,
        min_query_secondary: Option<QueryBoundSource>,
        max_query_secondary: Option<QueryBoundSource>,
    ) -> Result<HashOutput> {
        let hash = Identifiers::computational_hash_universal_circuit(
            column_ids,
            predicate_operations,
            results,
            min_query_secondary.clone(),
            max_query_secondary.clone(),
        )?;
        // compute set of placeholder ids from operations of the query and from query bounds
        let placeholder_ids_set = PlaceholderIdsSet::from(
            predicate_operations
                .iter()
                .chain(&results.result_operations)
                .flat_map(|op| op.extract_placeholder_ids())
                // add special placeholders for primary index query bounds to the (sorted) set of placeholder ids
                .chain([
                    PlaceholderIdentifier::MinQueryOnIdx1,
                    PlaceholderIdentifier::MaxQueryOnIdx1,
                ])
                // add placeholders employed in secondary query bounds (if any)
                .chain(
                    [min_query_secondary, max_query_secondary]
                        .into_iter()
                        .flat_map(|query_bound| {
                            query_bound
                                .and_then(|bound| match bound {
                                    QueryBoundSource::Placeholder(id) => Some(vec![id]),
                                    QueryBoundSource::Operation(op) => {
                                        Some(op.extract_placeholder_ids())
                                    }
                                    QueryBoundSource::Constant(_) => None,
                                })
                                // If None, return a placeholder that is for sure already in the set
                                .unwrap_or(vec![PlaceholderIdentifier::MinQueryOnIdx1])
                        }),
                ),
        );

        // compute placeholder id hash
        let placeholder_id_hash = placeholder_ids_hash(placeholder_ids_set);

        //ToDo: add ORDER BY info and DISTINCT info for queries without the results tree, when adding results tree
        // circuits APIs
        let computational_hash = match results.output_variant {
            Output::Aggregation => ComputationalHash::from_bytes((&hash).into()),
            Output::NoAggregation => ResultIdentifier::result_id_hash(
                ComputationalHash::from_bytes((&hash).into()),
                results.distinct.unwrap_or(false),
            ),
        };

        let inputs = computational_hash
            .to_vec()
            .into_iter()
            .chain(placeholder_id_hash.to_vec())
            .chain(HashOut::<F>::from_bytes(metadata_hash.into()).to_vec())
            .collect_vec();

        HashOutput::try_from(
            hash_n_to_hash_no_pad::<F, HashPermutation>(&inputs)
                .to_fields()
                .iter()
                // The converted `[u8; 32]` could construct a `bytes32` of Solidity directly,
                // and use as an Uint256 in the verifier contract.
                .flat_map(|f| f.to_canonical_u64().to_be_bytes())
                .collect_vec(),
        )
    }
}

impl<F: RichField> ToField<F> for Identifiers {
    fn to_field(&self) -> F {
        F::from_canonical_usize(self.position())
    }
}
/// Data structure to provide identifiers of columns of a table to compute computational hash
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ColumnIDs {
    pub(crate) primary: F,
    pub(crate) secondary: F,
    pub(crate) rest: Vec<F>,
}

impl ColumnIDs {
    pub fn new(primary_id: u64, secondary_id: u64, rest_ids: Vec<u64>) -> Self {
        Self {
            primary: primary_id.to_field(),
            secondary: secondary_id.to_field(),
            rest: rest_ids.into_iter().map(|id| id.to_field()).collect_vec(),
        }
    }

    pub(crate) fn to_vec(&self) -> Vec<F> {
        [self.primary, self.secondary]
            .into_iter()
            .chain(self.rest.clone())
            .collect_vec()
    }

    pub(crate) fn num_columns(&self) -> usize {
        self.rest.len() + 2
    }
}

#[derive(Clone, Debug, Copy, Default)]
pub enum Extraction {
    #[default]
    Column,
}

#[derive(Clone, Copy, Eq, PartialEq, Default, Hash, Serialize, Deserialize)]
/// Set of constant identifiers employed in the
/// computational hash, which is a compact representation
/// of the query being proven by the query circuits
pub enum Operation {
    #[default]
    AddOp,
    SubOp,
    MulOp,
    DivOp,
    ModOp,
    EqOp,
    NeOp,
    LessThanOp,
    GreaterThanOp,
    LessThanOrEqOp,
    GreaterThanOrEqOp,
    AndOp,
    OrOp,
    NotOp,
    XorOp,
}
impl std::fmt::Debug for Operation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Operation::AddOp => '+',
                Operation::SubOp => '-',
                Operation::MulOp => '*',
                Operation::DivOp => '/',
                Operation::ModOp => '%',
                Operation::EqOp => '=',
                Operation::NeOp => '≠',
                Operation::LessThanOp => '<',
                Operation::GreaterThanOp => '>',
                Operation::LessThanOrEqOp => '≤',
                Operation::GreaterThanOrEqOp => '≥',
                Operation::AndOp => '&',
                Operation::OrOp => '|',
                Operation::NotOp => '!',
                Operation::XorOp => '^',
            }
        )
    }
}

impl<F: RichField> ToField<F> for Operation {
    fn to_field(&self) -> F {
        F::from_canonical_usize(self.index())
    }
}

pub(crate) type HashPermutation = <CHasher as Hasher<F>>::Permutation;

/// Data structure to cache previously computed computational hashes
pub(crate) struct ComputationalHashCache {
    max_num_columns: usize,
    // cache the computational hash already computed for columns of the table, identified
    // by the column index
    column_hash: HashMap<usize, ComputationalHash>,
    // cache the computational hash already computed for operations being performed, identified
    // by the position of the operation in the set of operations
    operation_hash: HashMap<usize, ComputationalHash>,
}

impl ComputationalHashCache {
    /// Initialize an empty `ComputationalHashCache`
    pub(crate) fn new(max_num_columns: usize) -> Self {
        Self {
            max_num_columns,
            column_hash: HashMap::new(),
            operation_hash: HashMap::new(),
        }
    }
    /// Initialize a `ComputationalHashCache ` with a set of computational hash for the
    /// columns of the table
    pub(crate) fn new_from_column_hash(
        max_num_columns: usize,
        column_hash: &[ComputationalHash],
    ) -> Result<Self> {
        ensure!(
            column_hash.len() <= max_num_columns,
            "Number of input column hash is higher than the maximum number of columns"
        );
        Ok(Self {
            max_num_columns,
            column_hash: column_hash
                .iter()
                .enumerate()
                .map(|(i, hash)| (i, *hash))
                .collect(),
            operation_hash: HashMap::new(),
        })
    }
    /// Get the column hash for the column with index `column_index`, if available in the cache;
    /// Otherwise, compute this hash from `column_ids` and insert it in the cache
    fn get_or_compute_column_hash(
        &mut self,
        column_index: usize,
        column_ids: &[F],
    ) -> Result<ComputationalHash> {
        ensure!(
            column_index < self.max_num_columns,
            "column index bigger than maximum number of columns"
        );
        Ok(*self.column_hash.entry(column_index).or_insert_with(|| {
            Identifiers::Extraction(Extraction::Column)
                .prefix_id_hash(vec![column_ids[column_index]])
        }))
    }

    /// Get a previously computed hash for the `op-index`-th operation in a set of operations
    fn get_previous_operation_hash(&self, op_index: usize) -> Result<ComputationalHash> {
        self.operation_hash.get(&op_index).cloned().ok_or(anyhow!(
            "input hash for previous value with index {} not found",
            op_index
        ))
    }

    /// Insert the hash computed for the `op-index`-th operation in a set of operations
    fn insert_previous_operation_hash(&mut self, op_index: usize, hash: &ComputationalHash) {
        self.operation_hash.insert(op_index, *hash);
    }
}

impl Operation {
    pub fn index(&self) -> usize {
        *self as usize
    }

    pub fn offset() -> usize {
        Identifiers::Operations(Self::default()).offset()
    }

    /// Compute the computational hash associated to the basic operation provided as input, employing the hash
    /// already computed and cached in `previous_hash` and the set of `column_ids` to compute the column hashes
    /// not found in the cache
    pub(crate) fn basic_operation_hash(
        previous_hash: &mut ComputationalHashCache,
        column_ids: &[F],
        operation: &BasicOperation,
    ) -> Result<ComputationalHash> {
        let mut compute_operand_hash = |operand: &InputOperand| -> Result<ComputationalHash> {
            Ok(match operand {
                InputOperand::Placeholder(p) => {
                    hash_n_to_hash_no_pad::<_, HashPermutation>(&[p.to_field()])
                }
                InputOperand::Constant(value) => {
                    hash_n_to_hash_no_pad::<_, HashPermutation>(&value.to_fields())
                }
                InputOperand::Column(index) => {
                    previous_hash.get_or_compute_column_hash(*index, column_ids)?
                }
                InputOperand::PreviousValue(op_index) => {
                    previous_hash.get_previous_operation_hash(*op_index)?
                }
            })
        };

        let first_hash = compute_operand_hash(&operation.first_operand)?;
        let second_hash = if let Some(op) = operation.second_operand {
            compute_operand_hash(&op)
        } else {
            compute_operand_hash(&InputOperand::default())
        }?;
        let op_identifier = Identifiers::Operations(operation.op).to_field();
        Ok(hash_n_to_hash_no_pad::<_, HashPermutation>(
            &once(op_identifier)
                .chain(first_hash.to_vec())
                .chain(second_hash.to_vec())
                .collect_vec(),
        ))
    }

    /// Compute the computational hash for a set of operations, employing the hash already computed and cached in
    /// `previous_hash`; `column_ids` is employed to compute hashes of columns which are not found in the cache
    pub(crate) fn operation_hash(
        operations: &[BasicOperation],
        column_ids: &[F],
        previous_hash: &mut ComputationalHashCache,
    ) -> Result<Vec<ComputationalHash>> {
        operations
            .iter()
            .enumerate()
            .map(|(op_index, op)| {
                let op_hash = Self::basic_operation_hash(previous_hash, column_ids, op)?;
                previous_hash.insert_previous_operation_hash(op_index, &op_hash);
                Ok(op_hash)
            })
            .collect()
    }

    pub(crate) fn basic_operation_hash_circuit(
        b: &mut CBuilder,
        input_hash: &[ComputationalHashTarget],
        constant_operand: &UInt256Target,
        placeholder_ids: [Target; 2],
        first_selector: Target,
        second_selector: Target,
        op_selector: Target,
    ) -> ComputationalHashTarget {
        let constant_operand_hash =
            b.hash_n_to_hash_no_pad::<CHasher>(constant_operand.to_targets());
        let first_placeholder_id_hash =
            b.hash_n_to_hash_no_pad::<CHasher>(vec![placeholder_ids[0]]);
        let second_placeholder_id_hash =
            b.hash_n_to_hash_no_pad::<CHasher>(vec![placeholder_ids[1]]);
        // Compute the vector of computational hashes associated to each entry in `possible_input_values`.
        // The vector is padded to the next power of 2 to safely use `random_access_hash` gadget
        let pad_len = (input_hash.len() + 3).next_power_of_two(); // length of the padded vector of computational hashes
        let empty_poseidon_hash = b.constant_hash(*empty_poseidon_hash()); // employed for padding
        let possible_input_hash = input_hash
            .iter()
            .chain(
                [
                    constant_operand_hash,
                    first_placeholder_id_hash,
                    second_placeholder_id_hash,
                ]
                .iter(),
            )
            .cloned()
            .chain(repeat(empty_poseidon_hash))
            .take(pad_len)
            .collect_vec();
        assert!(
            possible_input_hash.len() <= 64,
            "random access gadget works only for arrays with at most 64 elements"
        );
        let first_input_hash = b.random_access_hash(first_selector, possible_input_hash.clone());
        let second_input_hash = b.random_access_hash(second_selector, possible_input_hash);
        let op_offset = b.constant(F::from_canonical_usize(Operation::offset()));
        let operation_identifier = b.add(op_offset, op_selector);
        b.hash_n_to_hash_no_pad::<CHasher>(
            // this should be an identifier accross all identifiers
            once(operation_identifier)
                .chain(first_input_hash.to_targets())
                .chain(second_input_hash.to_targets())
                .collect(),
        )
    }
}

#[derive(Clone, Debug, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum Output {
    #[default]
    Aggregation,
    NoAggregation,
}

impl<F: RichField> ToField<F> for Output {
    fn to_field(&self) -> F {
        Identifiers::Output(*self).to_field()
    }
}

impl Output {
    pub(crate) fn output_hash(
        &self,
        predicate_hash: &ComputationalHash,
        previous_hash: &mut ComputationalHashCache,
        column_ids: &[F],
        result_ops_hash: &[ComputationalHash],
        output_items: &[OutputItem],
        output_ids: &[F],
    ) -> Result<ComputationalHash> {
        let init_hash = Identifiers::Output(*self).prefix_id_hash(predicate_hash.to_vec());
        output_items.iter().enumerate().try_fold(
            init_hash,
            |hash, (i, item)| {
                let output_hash = match item {
                    OutputItem::Column(index) => {
                        ensure!(*index < previous_hash.max_num_columns,
                            "column index in output item higher than maximum number of columns");
                        previous_hash.get_or_compute_column_hash(
                            *index,
                            column_ids,
                        )?
                    },
                    OutputItem::ComputedValue(index) => {
                        ensure!(*index < result_ops_hash.len(),
                            "result index in output item higher than the number of computed results");
                        result_ops_hash[*index]
                    },
                };
                Ok(hash_n_to_hash_no_pad::<_, HashPermutation>(
                    &hash
                        .to_vec()
                        .into_iter()
                        .chain(once(output_ids[i]))
                        .chain(output_hash.to_vec())
                        .collect_vec(),
                ))
        })
    }

    pub(crate) fn output_hash_circuit<const MAX_NUM_RESULTS: usize>(
        &self,
        b: &mut CBuilder,
        predicate_hash: &ComputationalHashTarget,
        possible_output_hash: &[ComputationalHashTarget],
        selector: &[Target; MAX_NUM_RESULTS],
        output_ids: &[Target; MAX_NUM_RESULTS],
        is_output_valid: &[BoolTarget; MAX_NUM_RESULTS],
    ) -> ComputationalHashTarget {
        let empty_hash = b.constant_hash(*empty_poseidon_hash());
        let mut output_hash =
            Identifiers::Output(*self).prefix_id_hash_circuit(b, predicate_hash.to_targets());
        let possible_output_hashes = possible_output_hash
            .iter()
            .chain(repeat(&empty_hash))
            .cloned()
            .take(possible_output_hash.len().next_power_of_two())
            .collect_vec();
        assert!(
            possible_output_hashes.len() <= 64,
            "too many inputs for random access gate, at most 64 are allowed"
        );
        for i in 0..MAX_NUM_RESULTS {
            let current_output_hash =
                b.random_access_hash(selector[i], possible_output_hashes.clone());

            let new_output_hash = b.hash_n_to_hash_no_pad::<CHasher>(
                output_hash
                    .to_targets()
                    .into_iter()
                    .chain(once(output_ids[i]))
                    .chain(current_output_hash.to_targets().into_iter())
                    .collect(),
            );

            // Output computational hash is updated only if there is a valid output to be
            // computed for this slot
            output_hash = b.select_hash(is_output_valid[i], &new_output_hash, &output_hash);
        }

        output_hash
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Default, Serialize, Deserialize)]
pub enum AggregationOperation {
    #[default]
    SumOp,
    MinOp,
    MaxOp,
    AvgOp,
    CountOp,
    IdOp,
}

impl<F: RichField> ToField<F> for AggregationOperation {
    fn to_field(&self) -> F {
        Identifiers::AggregationOperations(*self).to_field()
    }
}

impl<F: RichField> FromFields<F> for AggregationOperation {
    fn from_fields(t: &[F]) -> Self {
        match t[0] {
            f if <Self as ToField<F>>::to_field(&Self::SumOp) == f => Self::SumOp,
            f if <Self as ToField<F>>::to_field(&Self::MinOp) == f => Self::MinOp,
            f if <Self as ToField<F>>::to_field(&Self::MaxOp) == f => Self::MaxOp,
            f if <Self as ToField<F>>::to_field(&Self::AvgOp) == f => Self::AvgOp,
            f if <Self as ToField<F>>::to_field(&Self::CountOp) == f => Self::CountOp,
            f if <Self as ToField<F>>::to_field(&Self::IdOp) == f => Self::IdOp,
            _ => panic!("invalid field element for aggregation operation"),
        }
    }
}

impl AggregationOperation {
    /// Return the identity value for `self` operation
    pub(crate) fn identity_value(&self) -> Vec<F> {
        match self {
            AggregationOperation::SumOp => U256::ZERO.to_fields(),
            AggregationOperation::MinOp => U256::MAX.to_fields(),
            AggregationOperation::MaxOp => U256::ZERO.to_fields(),
            AggregationOperation::AvgOp => U256::ZERO.to_fields(),
            AggregationOperation::CountOp => U256::ZERO.to_fields(),
            AggregationOperation::IdOp => Point::NEUTRAL.to_fields(),
        }
    }

    pub fn to_id(&self) -> u64 {
        Identifiers::AggregationOperations(*self).position() as u64
    }
}

/// Placeholder identifiers
#[derive(
    Clone, Debug, Copy, Default, Eq, Hash, PartialEq, PartialOrd, Ord, Serialize, Deserialize,
)]
pub enum PlaceholderIdentifier {
    // MIN_I1
    #[default]
    MinQueryOnIdx1,
    // MAX_I1
    MaxQueryOnIdx1,
    // $1, $2 ...
    Generic(usize),
}

impl<F: RichField> ToField<F> for PlaceholderIdentifier {
    fn to_field(&self) -> F {
        Identifiers::PlaceholderIdentifiers(*self).to_field()
    }
}

impl<F: RichField> FromFields<F> for PlaceholderIdentifier {
    fn from_fields(t: &[F]) -> Self {
        let generic_placeholder_start_value =
            <Self as ToField<F>>::to_field(&Self::Generic(0)).to_canonical_u64();
        match t[0] {
            f if <Self as ToField<F>>::to_field(&Self::MinQueryOnIdx1) == f => Self::MinQueryOnIdx1,
            f if <Self as ToField<F>>::to_field(&Self::MaxQueryOnIdx1) == f => Self::MaxQueryOnIdx1,
            f => Self::Generic(
                f.to_canonical_u64()
                    .checked_sub(generic_placeholder_start_value)
                    .expect("invalid field element for PlaceholderIdentifier")
                    as usize,
            ),
        }
    }
}

impl PlaceholderIdentifier {
    // <https://doc.rust-lang.org/reference/items/enumerations.html#pointer-casting>
    pub(crate) fn discriminant(&self) -> usize {
        unsafe { *(self as *const Self as *const usize) }
    }

    pub(crate) fn position(&self) -> usize {
        match self {
            Self::Generic(i) => self.discriminant() + i,
            _ => self.discriminant(),
        }
    }
}

/// Result identifiers
#[derive(Clone, Debug, Copy, Default)]
pub enum ResultIdentifier {
    #[default]
    ResultNoDistinct,
    ResultWithDistinct,
}

impl<F: RichField> ToField<F> for ResultIdentifier {
    fn to_field(&self) -> F {
        Identifiers::ResultIdentifiers(*self).to_field()
    }
}

impl ResultIdentifier {
    pub(crate) fn result_id_hash(
        computational_hash: ComputationalHash,
        distinct: bool,
    ) -> ComputationalHash {
        let res_id = if distinct {
            ResultIdentifier::ResultWithDistinct
        } else {
            ResultIdentifier::ResultNoDistinct
        };
        let input = once(res_id.to_field())
            .chain(computational_hash.to_fields())
            .collect_vec();
        hash_n_to_hash_no_pad::<_, HashPermutation>(&input)
    }

    pub(crate) fn result_id_hash_circuit(
        b: &mut CBuilder,
        computational_hash: ComputationalHashTarget,
        distinct: &BoolTarget,
    ) -> ComputationalHashTarget {
        let [res_no_distinct, res_with_distinct] = [
            ResultIdentifier::ResultNoDistinct,
            ResultIdentifier::ResultWithDistinct,
        ]
        .map(|id| b.constant(id.to_field()));
        let res_id = b.select(*distinct, res_with_distinct, res_no_distinct);

        // Compute the computational hash:
        // H(res_id || pQ.C)
        let inputs = once(res_id)
            .chain(computational_hash.to_targets())
            .collect();
        b.hash_n_to_hash_no_pad::<CHasher>(inputs)
    }
}
