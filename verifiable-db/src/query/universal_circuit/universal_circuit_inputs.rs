use anyhow::{anyhow, ensure, Context, Result};
use std::collections::HashMap;

use alloy::primitives::U256;
use itertools::Itertools;
use mp2_common::{utils::ToBool, F};

use crate::query::computational_hash_ids::Operation;

#[derive(Clone, Copy, Debug, Default)]
/// Data structure representing a placeholder in the query, given by its value and its identifier
pub(crate) struct Placeholder {
    pub(crate) value: U256,
    pub(crate) id: PlaceholderId,
}

pub(crate) type PlaceholderId = F;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
/// Enumeration representing all the possible types of input operands for a basic operation
pub(crate) enum InputOperand {
    // Input operand is a placeholder in the query
    Placeholder(PlaceholderId),
    // Input operand is a constant value in the query
    Constant(U256),
    /// Input operand is a column of the table
    Column(usize),
    /// Input operand is the output of a previous basic operation
    PreviousValue(usize),
}

impl Default for InputOperand {
    fn default() -> Self {
        InputOperand::Column(0)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
/// Data structure employed to specify a basic operation to be performed to
/// compute the query
pub(crate) struct BasicOperation {
    pub(crate) first_operand: InputOperand,
    /// Can be None in case of unary operation
    pub(crate) second_operand: Option<InputOperand>,
    pub(crate) op: Operation,
}

impl BasicOperation {
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
            let get_input_value = |operand| {
                Ok(match operand {
                    &InputOperand::Placeholder(p) => {
                        *placeholder_values.get(&p).ok_or_else(|| {
                            anyhow!("No placeholder value found associated to id {}", p)
                        })?
                    }
                    &InputOperand::Constant(v) => v,
                    &InputOperand::Column(index) => {
                        ensure!(
                            index < num_columns,
                            "invalid input operation: column index out of range for operation {}",
                            i
                        );
                        column_values[index]
                    }
                    &InputOperand::PreviousValue(index) => {
                        ensure!(index < results.len(),
                                "invalid input operation: accessing a value that has not been computed yet in operation {}", i);
                        results[index]
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
                        .to_bool()
                        .context(format!("first input value to AND operation {}: ", i))?;
                    let second_input = second_input
                        .to_bool()
                        .context(format!("second input value to AND operation {}: ", i))?;
                    U256::from((first_input && second_input) as u8)
                }
                Operation::OrOp => {
                    let first_input = first_input
                        .to_bool()
                        .context(format!("first input value to OR operation {}: ", i))?;
                    let second_input = second_input
                        .to_bool()
                        .context(format!("second input value to OR operation {}: ", i))?;
                    U256::from((first_input || second_input) as u8)
                }
                Operation::NotOp => {
                    let input_bool = first_input
                        .to_bool()
                        .context(format!("input value to NOT operation {}: ", i))?;
                    U256::from((!input_bool) as u8)
                }
                Operation::XorOp => {
                    let first_input = first_input
                        .to_bool()
                        .context(format!("first input value to XOR operation {}: ", i))?;
                    let second_input = second_input
                        .to_bool()
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
pub(crate) enum OutputItem {
    /// Output value is a column of the table
    Column(usize),
    /// Output value is computed in one of the `MAX_NUM_RESULT_OPS` operations; the numeric value
    /// stored in this variant is the index of the `BasicOperation` computing the output value in the
    /// set of result operations
    ComputedValue(usize),
}

/// Data structure that contains the description of the output items to be returned and the
/// operations necessary to compute the output items
pub(crate) struct ResultStructure {
    pub(crate) result_operations: Vec<BasicOperation>,
    pub(crate) output_items: Vec<OutputItem>,
}

impl From<(Vec<BasicOperation>, Vec<OutputItem>)> for ResultStructure {
    fn from(value: (Vec<BasicOperation>, Vec<OutputItem>)) -> Self {
        Self {
            result_operations: value.0,
            output_items: value.1,
        }
    }
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
                &OutputItem::Column(index) => column_values[index],
                &OutputItem::ComputedValue(index) => res[index],
            })
            .collect_vec();
        Ok((results, overflow_err))
    }
}
