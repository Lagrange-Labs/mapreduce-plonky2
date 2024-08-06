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
    types::CBuilder,
    u256::UInt256Target,
    utils::{FromFields, SelectHashBuilder, ToFields, ToTargets},
    CHasher, F,
};
use plonky2::{
    field::types::Field,
    hash::{hash_types::RichField, hashing::hash_n_to_hash_no_pad},
    iop::target::{BoolTarget, Target},
    plonk::config::{GenericHashOut, Hasher},
};
use plonky2_ecgfp5::curve::curve::Point;

use super::universal_circuit::{
    universal_circuit_inputs::{BasicOperation, InputOperand, OutputItem},
    ComputationalHash, ComputationalHashTarget,
};

pub enum Identifiers {
    Extraction(Extraction),
    Operations(Operation),
    Output(Output),
    AggregationOperations(AggregationOperation),
    PlaceholderIdentifiers(PlaceholderIdentifier),
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
}

impl<F: RichField> ToField<F> for Identifiers {
    fn to_field(&self) -> F {
        F::from_canonical_usize(self.position())
    }
}

#[derive(Clone, Debug, Copy, Default)]
pub enum Extraction {
    #[default]
    Column,
}

#[derive(Clone, Copy, Eq, PartialEq, Default, Hash)]
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
pub(crate) struct ComputationalHashCache<const MAX_NUM_COLUMNS: usize> {
    // cache the computational hash already computed for columns of the table, identified
    // by the column index
    column_hash: HashMap<usize, ComputationalHash>,
    // cache the computational hash already computed for operations being performed, identified
    // by the position of the operation in the set of operations
    operation_hash: HashMap<usize, ComputationalHash>,
}

impl<const MAX_NUM_COLUMNS: usize> ComputationalHashCache<MAX_NUM_COLUMNS> {
    /// Initialize an empty `ComputationalHashCache`
    pub(crate) fn new() -> Self {
        Self {
            column_hash: HashMap::new(),
            operation_hash: HashMap::new(),
        }
    }
    /// Initialize a `ComputationalHashCache ` with a set of computational hash for the
    /// columns of the table
    pub(crate) fn new_from_column_hash(column_hash: &[ComputationalHash]) -> Result<Self> {
        ensure!(
            column_hash.len() <= MAX_NUM_COLUMNS,
            "Number of input column hash is higher than the maximum number of columns"
        );
        Ok(Self {
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
            column_index < MAX_NUM_COLUMNS,
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
    pub(crate) fn basic_operation_hash<const MAX_NUM_COLUMNS: usize>(
        previous_hash: &mut ComputationalHashCache<MAX_NUM_COLUMNS>,
        column_ids: &[F],
        operation: &BasicOperation,
    ) -> Result<ComputationalHash> {
        let mut compute_operand_hash = |operand: &InputOperand| -> Result<ComputationalHash> {
            Ok(match operand {
                InputOperand::Placeholder(p) => hash_n_to_hash_no_pad::<_, HashPermutation>(&[*p]),
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
    pub(crate) fn operation_hash<const MAX_NUM_COLUMNS: usize>(
        operations: &[BasicOperation],
        column_ids: &[F],
        previous_hash: &mut ComputationalHashCache<MAX_NUM_COLUMNS>,
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

#[derive(Clone, Debug, Copy, Default)]
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
    pub(crate) fn output_hash<const MAX_NUM_COLUMNS: usize>(
        &self,
        predicate_hash: &ComputationalHash,
        previous_hash: &mut ComputationalHashCache<MAX_NUM_COLUMNS>,
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
                        ensure!(*index < MAX_NUM_COLUMNS,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq, Default)]
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
}

/// Placeholder identifiers
#[derive(Clone, Debug, Copy, Default)]
pub enum PlaceholderIdentifier {
    // MIN_I1
    #[default]
    MinQueryOnIdx1,
    // MAX_I1
    MaxQueryOnIdx1,
    // MIN_I2
    MinQueryOnIdx2,
    // MAX_I2
    MaxQueryOnIdx2,
    // $1, $2 ...
    GenericPlaceholder(usize),
}

impl<F: RichField> ToField<F> for PlaceholderIdentifier {
    fn to_field(&self) -> F {
        Identifiers::PlaceholderIdentifiers(*self).to_field()
    }
}

impl PlaceholderIdentifier {
    // <https://doc.rust-lang.org/reference/items/enumerations.html#pointer-casting>
    pub(crate) fn discriminant(&self) -> usize {
        unsafe { *(self as *const Self as *const usize) }
    }

    pub(crate) fn position(&self) -> usize {
        match self {
            Self::GenericPlaceholder(i) => self.discriminant() + i,
            _ => self.discriminant(),
        }
    }
}
