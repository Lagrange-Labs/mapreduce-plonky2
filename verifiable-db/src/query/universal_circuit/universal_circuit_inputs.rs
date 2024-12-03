use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{btree_set, BTreeSet, HashMap};

use alloy::primitives::U256;
use itertools::Itertools;
use mp2_common::{
    array::ToField,
    utils::{Fieldable, TryIntoBool},
    F,
};

use crate::query::computational_hash_ids::{
    AggregationOperation, ColumnIDs, Identifiers, Operation, Output, PlaceholderIdentifier,
};

use super::universal_query_circuit::dummy_placeholder_id;

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
/// Data structure representing a placeholder in the query, given by its value and its identifier
pub struct Placeholder {
    pub(crate) value: U256,
    pub(crate) id: PlaceholderId,
}

pub type PlaceholderId = PlaceholderIdentifier;

/// Define a set of placeholder ids which can be iterated over
/// following the ids expected for placeholders as outputs of
/// the revelation circuit
#[derive(Clone, Debug)]
pub(crate) struct PlaceholderIdsSet(BTreeSet<PlaceholderId>);

impl<I: Iterator<Item = PlaceholderId>> From<I> for PlaceholderIdsSet {
    fn from(value: I) -> Self {
        Self(value.collect::<BTreeSet<PlaceholderId>>())
    }
}

/// Implement an iterator over the set of placeholder ids which return
/// the ids according to the order expected in the public inputs of the
/// revelation circuit
impl IntoIterator for PlaceholderIdsSet {
    type Item = PlaceholderId;

    type IntoIter = btree_set::IntoIter<PlaceholderId>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
/// Data structure employed to represent a set of placeholders, identified by their `PlaceholderId`
pub struct Placeholders(pub HashMap<PlaceholderId, U256>);

impl Placeholders {
    /// Initialize an empty set of placeholders
    pub fn new_empty(min_query_primary: U256, max_query_primary: U256) -> Self {
        Self(
            [
                (PlaceholderId::MinQueryOnIdx1, min_query_primary),
                (PlaceholderId::MaxQueryOnIdx1, max_query_primary),
            ]
            .into_iter()
            .collect(),
        )
    }

    /// Get the placeholder value corresponding to `id`, if found in the set of placeholders
    pub fn get(&self, id: &PlaceholderId) -> Result<U256> {
        let value = self.0.get(id);
        ensure!(value.is_some(), "no placeholder found for id {:?}", id);
        Ok(*value.unwrap())
    }

    /// Add a new placeholder to `self`
    pub fn insert(&mut self, id: PlaceholderId, value: U256) {
        self.0.insert(id, value);
    }

    /// Get the number of placeholders in `self`
    pub fn len(&self) -> usize {
        // number of placeholders in placeholder values
        self.0.len()
    }

    /// Returns whether `self` is empty or not
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Return set of placeholders ids, in the order expected in the public inputs of the final
    /// proof
    pub fn ids(&self) -> Vec<PlaceholderIdentifier> {
        let sorted_ids = PlaceholderIdsSet::from(self.0.keys().cloned());
        sorted_ids.into_iter().collect_vec()
    }

    /// Return placeholder values in the order expected in the public inputs of the final
    /// proof
    pub fn placeholder_values(&self) -> Vec<U256> {
        self.ids()
            .iter()
            .map(
                |id| self.get(id).unwrap(), // safe to unwrap since we get ids from `self.ids`
            )
            .collect_vec()
    }
}

impl From<(Vec<(PlaceholderId, U256)>, U256, U256)> for Placeholders {
    fn from(value: (Vec<(PlaceholderId, U256)>, U256, U256)) -> Self {
        Self(
            [
                (PlaceholderId::MinQueryOnIdx1, value.1),
                (PlaceholderId::MaxQueryOnIdx1, value.2),
            ]
            .into_iter()
            .chain(value.0)
            .collect(),
        )
    }
}

#[derive(Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize)]
/// Enumeration representing all the possible types of input operands for a basic operation
pub enum InputOperand {
    // Input operand is a placeholder in the query
    Placeholder(PlaceholderId),
    // Input operand is a constant value in the query
    Constant(U256),
    /// Input operand is a column of the table: the integer stored in this variant is the index
    /// of the column in the set of columns of the table
    Column(usize),
    /// Input operand is the output of a previous basic operation: the integer stored in this variant
    /// is the position of this previous operation in the set of operations being computed.
    /// Note that this must refer to an operation already computed, so it should refer to
    /// an operation found before the current operation in the set of operations
    PreviousValue(usize),
}
impl std::fmt::Debug for InputOperand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InputOperand::Placeholder(i) => write!(f, "${i:?}"),
            InputOperand::Constant(x) => write!(f, "{x}"),
            InputOperand::Column(id) => write!(f, "C[{id}]"),
            InputOperand::PreviousValue(previous) => write!(f, "@{previous}"),
        }
    }
}
impl Default for InputOperand {
    fn default() -> Self {
        InputOperand::Placeholder(dummy_placeholder_id())
    }
}

#[derive(Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize)]
/// Data structure employed to specify a basic operation to be performed to
/// compute the query
pub struct BasicOperation {
    pub first_operand: InputOperand,
    /// Can be None in case of unary operation
    pub second_operand: Option<InputOperand>,
    pub op: Operation,
}
impl std::fmt::Debug for BasicOperation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(second_operand) = self.second_operand {
            write!(
                f,
                "({:?} {:?} {:?})",
                self.first_operand, self.op, second_operand
            )
        } else {
            write!(f, "({:?} {:?})", self.first_operand, self.op)
        }
    }
}

impl BasicOperation {
    /// Instantiate a new binary operation, i.e., a basic operation with 2 operands
    pub fn new_binary_operation(
        first_operand: InputOperand,
        second_operand: InputOperand,
        op: Operation,
    ) -> Self {
        BasicOperation {
            first_operand,
            second_operand: Some(second_operand),
            op,
        }
    }

    /// Instantiate a new unary operation, i.e., a basic operation with a single operand
    pub fn new_unary_operation(operand: InputOperand, op: Operation) -> Self {
        BasicOperation {
            first_operand: operand,
            second_operand: None,
            op,
        }
    }

    /// Return the ids of the placeholders employed as operands of `self`, if any
    pub(crate) fn extract_placeholder_ids(&self) -> Vec<PlaceholderId> {
        let first_id = match self.first_operand {
            InputOperand::Placeholder(p) => Some(p),
            _ => None,
        };
        let second_id = self.second_operand.map(|op| match op {
            InputOperand::Placeholder(p) => Some(p),
            _ => None,
        });
        [first_id, second_id.flatten()]
            .into_iter()
            .flatten()
            .collect_vec()
    }

    /// Compute the results of the `operations` provided as input, employing the provided
    /// `column_values` as the operands for the operations having `InputOperand::Column`
    /// operands and the provided `placeholders` for the operations having `InputOperand::Placeholder`
    /// operands. The method returns also a flag which specifies if an arithemtic error
    /// has occurred throughout any of these operations
    pub(crate) fn compute_operations(
        operations: &[Self],
        column_values: &[U256],
        placeholders: &Placeholders,
    ) -> Result<(Vec<U256>, bool)> {
        let mut results = Vec::with_capacity(operations.len());
        let mut arithmetic_error = false;
        let num_columns = column_values.len();
        for (i, op) in operations.iter().enumerate() {
            let get_input_value = |operand: &InputOperand| {
                Ok(match operand {
                    InputOperand::Placeholder(p) => placeholders.get(p)?,
                    InputOperand::Constant(v) => *v,
                    InputOperand::Column(index) => {
                        ensure!(
                            *index < num_columns,
                            "invalid input operation: column index out of range for operation {}",
                            i
                        );
                        column_values[*index]
                    }
                    InputOperand::PreviousValue(index) => {
                        ensure!(*index < results.len(),
                                "invalid input operation: accessing a value that has not been computed yet in operation {}", i);
                        results[*index]
                    }
                })
            };
            let first_input = get_input_value(&op.first_operand)?;
            let second_input = op.second_operand.as_ref().map(get_input_value).unwrap_or(
                // op.second_operand = None means it's a unary operation, so we can choose a dummy input value
                Ok(U256::ZERO),
            )?;
            let result = match op.op {
                Operation::AddOp => {
                    let (res, overflow) = first_input.overflowing_add(second_input);
                    arithmetic_error |= overflow;
                    res
                }
                Operation::SubOp => {
                    let (res, overflow) = first_input.overflowing_sub(second_input);
                    arithmetic_error |= overflow;
                    res
                }
                Operation::MulOp => {
                    let (res, overflow) = first_input.overflowing_mul(second_input);
                    arithmetic_error |= overflow;
                    res
                }
                Operation::DivOp => {
                    arithmetic_error |= second_input.is_zero();
                    first_input.div_rem(second_input).0
                }
                Operation::ModOp => {
                    arithmetic_error |= second_input.is_zero();
                    first_input.div_rem(second_input).1
                }
                Operation::LessThanOp => U256::from((first_input < second_input) as u8),
                Operation::EqOp => U256::from((first_input == second_input) as u8),
                Operation::NeOp => U256::from((first_input != second_input) as u8),
                Operation::GreaterThanOp => U256::from((first_input > second_input) as u8),
                Operation::LessThanOrEqOp => U256::from((first_input <= second_input) as u8),
                Operation::GreaterThanOrEqOp => U256::from((first_input >= second_input) as u8),
                Operation::AndOp => {
                    let first_input = first_input
                        .try_into_bool()
                        .context(format!("first input value to AND operation {}: ", i))?;
                    let second_input = second_input
                        .try_into_bool()
                        .context(format!("second input value to AND operation {}: ", i))?;
                    U256::from((first_input && second_input) as u8)
                }
                Operation::OrOp => {
                    let first_input = first_input
                        .try_into_bool()
                        .context(format!("first input value to OR operation {}: ", i))?;
                    let second_input = second_input
                        .try_into_bool()
                        .context(format!("second input value to OR operation {}: ", i))?;
                    U256::from((first_input || second_input) as u8)
                }
                Operation::NotOp => {
                    let input_bool = first_input
                        .try_into_bool()
                        .context(format!("input value to NOT operation {}: ", i))?;
                    U256::from((!input_bool) as u8)
                }
                Operation::XorOp => {
                    let first_input = first_input
                        .try_into_bool()
                        .context(format!("first input value to XOR operation {}: ", i))?;
                    let second_input = second_input
                        .try_into_bool()
                        .context(format!("second input value to XOR operation {}: ", i))?;
                    U256::from((first_input ^ second_input) as u8)
                }
            };
            results.push(result);
        }

        Ok((results, arithmetic_error))
    }

    // utility function to locate operation `op` in the set of `previous_ops`
    #[cfg(test)] // used only in test for now
    pub(crate) fn locate_previous_operation(previous_ops: &[Self], op: &Self) -> Result<usize> {
        previous_ops
            .iter()
            .find_position(|current_op| *current_op == op)
            .map(|(pos, _)| pos)
            .ok_or(anyhow::Error::msg("operation {} not found in set of previous ops"))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
/// Enumeration representing the type of output values that can be returned for each row
pub enum OutputItem {
    /// Output value is a column of the table
    Column(usize),
    /// Output value is computed in one of the `MAX_NUM_RESULT_OPS` operations; the numeric value
    /// stored in this variant is the index of the `BasicOperation` computing the output value in the
    /// set of result operations
    ComputedValue(usize),
}

/// Data structure that contains the description of the output items to be returned and the
/// operations necessary to compute the output items
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResultStructure {
    pub result_operations: Vec<BasicOperation>,
    pub output_items: Vec<OutputItem>,
    pub output_ids: Vec<F>,
    pub output_variant: Output,
    pub distinct: Option<bool>,
}

impl ResultStructure {
    /// Compute output values to be returned for the current row, employing the provided
    /// `column_values` as the operands for the operations having `InputOperand::Column`
    /// operands, and the provided `placeholders` for the operations having `InputOperand::Placeholder`
    /// operands.
    pub fn compute_output_values(
        &self,
        column_values: &[U256],
        placeholders: &Placeholders,
    ) -> Result<(Vec<U256>, bool)> {
        let (res, overflow_err) = BasicOperation::compute_operations(
            &self.result_operations,
            column_values,
            placeholders,
        )?;
        let results = self
            .output_items
            .iter()
            .map(|item| match item {
                OutputItem::Column(index) => column_values[*index],
                OutputItem::ComputedValue(index) => res[*index],
            })
            .collect_vec();
        Ok((results, overflow_err))
    }

    pub fn new_for_query_with_aggregation(
        result_operations: Vec<BasicOperation>,
        output_items: Vec<OutputItem>,
        aggregation_op_ids: Vec<u64>,
    ) -> Result<Self> {
        ensure!(
            output_items.len() == aggregation_op_ids.len(),
            "output items and aggregation operations identifiers have different length"
        );
        Ok(Self {
            result_operations,
            output_items,
            output_ids: aggregation_op_ids
                .into_iter()
                .map(|id| id.to_field())
                .collect_vec(),
            output_variant: Output::Aggregation,
            distinct: None,
        })
    }

    pub fn new_for_query_no_aggregation(
        result_operations: Vec<BasicOperation>,
        output_items: Vec<OutputItem>,
        output_ids: Vec<u64>,
        distinct: bool,
    ) -> Result<Self> {
        ensure!(
            output_items.len() == output_ids.len(),
            "output items and output ids have different length"
        );
        Ok(Self {
            result_operations,
            output_items,
            output_ids: output_ids.into_iter().map(|id| id.to_field()).collect_vec(),
            output_variant: Output::NoAggregation,
            distinct: Some(distinct),
        })
    }

    pub fn aggregation_operations(&self) -> Vec<F> {
        match self.query_variant() {
            Output::Aggregation => self.output_ids.clone(),
            Output::NoAggregation => {
                vec![Identifiers::AggregationOperations(AggregationOperation::IdOp).to_field()]
            }
        }
    }

    pub fn query_variant(&self) -> Output {
        self.output_variant
    }

    /// Validate an instance of `self` with respect to the upper bounds provided as input, that are:
    /// - The upper bound `max_num_results_ops` on the number of basic operations allowed to
    ///   compute the results
    /// - The upper bound `max_num_results` on the number of results returned for each row
    pub fn validate(&self, max_num_result_ops: usize, max_num_results: usize) -> Result<()> {
        ensure!(
            self.result_operations.len() <= max_num_result_ops,
            format!(
                "too many basic operations found in SELECT clause: found {}, maximum allowed is {}",
                self.result_operations.len(),
                max_num_result_ops,
            )
        );
        ensure!(
            self.output_items.len() <= max_num_results,
            format!(
                "too many result items specified in SELECT clause: found {}, maximum allowed is {}",
                self.output_items.len(),
                max_num_results,
            )
        );
        Ok(())
    }
}

#[derive(Clone, Default, Debug, PartialEq, Serialize, Deserialize)]
pub struct ColumnCell {
    pub value: U256,
    pub id: F,
}

impl ColumnCell {
    pub fn new(id: u64, value: U256) -> Self {
        Self {
            value,
            id: id.to_field(),
        }
    }
}

#[derive(Debug, Default, Clone, PartialEq, Deserialize, Serialize)]
pub struct RowCells {
    primary: ColumnCell,
    secondary: ColumnCell,
    rest: Vec<ColumnCell>,
}

impl RowCells {
    pub fn new(primary: ColumnCell, secondary: ColumnCell, rest: Vec<ColumnCell>) -> Self {
        Self {
            primary,
            secondary,
            rest,
        }
    }
    /// Get number of columns in the row represented by `self`
    pub fn num_columns(&self) -> usize {
        self.rest.len() + 2
    }

    /// Return the set of column cells, placing primary and secondary index columns at the beginning of the array
    pub fn to_cells(&self) -> Vec<ColumnCell> {
        [&self.primary, &self.secondary]
            .into_iter()
            .chain(&self.rest)
            .cloned()
            .collect_vec()
    }

    pub fn column_ids(&self) -> ColumnIDs {
        ColumnIDs {
            primary: self.primary.id,
            secondary: self.secondary.id,
            rest: self.rest.iter().map(|cell| cell.id).collect_vec(),
        }
    }
}
