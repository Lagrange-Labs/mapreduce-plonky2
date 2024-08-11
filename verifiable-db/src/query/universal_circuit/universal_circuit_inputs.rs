use anyhow::{anyhow, ensure, Context, Result};
use std::collections::HashMap;

use alloy::primitives::U256;
use itertools::Itertools;
use mp2_common::{
    utils::{Fieldable, TryIntoBool},
    F,
};

use crate::query::computational_hash_ids::{Operation, Output};

#[derive(Clone, Copy, Debug, Default)]
/// Data structure representing a placeholder in the query, given by its value and its identifier
pub struct Placeholder {
    pub(crate) value: U256,
    pub(crate) id: PlaceholderId,
}

pub type PlaceholderId = F;

#[derive(Clone, Copy, Eq, PartialEq, Hash)]
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
            InputOperand::Placeholder(i) => write!(f, "${i}"),
            InputOperand::Constant(x) => write!(f, "{x}"),
            InputOperand::Column(id) => write!(f, "C[{id}]"),
            InputOperand::PreviousValue(previous) => write!(f, "@{previous}"),
        }
    }
}
impl Default for InputOperand {
    fn default() -> Self {
        InputOperand::Column(0)
    }
}

#[derive(Clone, Copy, Eq, PartialEq, Hash)]
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

    /// Compute the results of the `operations` provided as input, employing the provided
    /// `column_values` as the operands for the operations having `InputOperand::Column`
    /// operands and the provided `placeholder_values` for the operations having `InputOperand::Placeholder`
    /// operands. The method returns also a flag which specifies if an arithemtic error
    /// has occurred throughout any of these operations
    pub(crate) fn compute_operations(
        operations: &[Self],
        column_values: &[U256],
        placeholder_values: &HashMap<PlaceholderId, U256>,
    ) -> Result<(Vec<U256>, bool)> {
        let mut results = Vec::with_capacity(operations.len());
        let mut arithmetic_error = false;
        let num_columns = column_values.len();
        for (i, op) in operations.iter().enumerate() {
            let get_input_value = |operand: &InputOperand| {
                Ok(match operand {
                    InputOperand::Placeholder(p) => {
                        *placeholder_values.get(p).ok_or_else(|| {
                            anyhow!("No placeholder value found associated to id {}", p)
                        })?
                    }
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
}

#[derive(Clone, Copy, Debug)]
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
#[derive(Debug)]
pub struct ResultStructure {
    pub result_operations: Vec<BasicOperation>,
    pub output_items: Vec<OutputItem>,
    pub output_ids: Vec<F>,
    pub output_variant: Output,
}

impl ResultStructure {
    /// Compute output values to be returned for the current row, employing the provided
    /// `column_values` as the operands for the operations having `InputOperand::Column`
    /// operands, and the provided `placeholder_values` for the operations having `InputOperand::Placeholder`
    /// operands.
    pub(crate) fn compute_output_values(
        &self,
        column_values: &[U256],
        placeholder_values: &HashMap<PlaceholderId, U256>,
    ) -> Result<(Vec<U256>, bool)> {
        let (res, overflow_err) = BasicOperation::compute_operations(
            &self.result_operations,
            column_values,
            placeholder_values,
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
    ) -> Self {
        Self {
            result_operations,
            output_items,
            output_ids: aggregation_op_ids
                .into_iter()
                .map(|id| id.to_field())
                .collect_vec(),
            output_variant: Output::Aggregation,
        }
    }

    pub fn new_for_query_no_aggregation(
        result_operations: Vec<BasicOperation>,
        output_items: Vec<OutputItem>,
        output_ids: Vec<u64>,
    ) -> Self {
        Self {
            result_operations,
            output_items,
            output_ids: output_ids.into_iter().map(|id| id.to_field()).collect_vec(),
            output_variant: Output::NoAggregation,
        }
    }
}

#[derive(Debug, Clone)]
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
