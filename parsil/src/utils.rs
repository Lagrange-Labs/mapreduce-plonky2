use alloy::primitives::U256;
use anyhow::*;
use sqlparser::ast::{BinaryOperator, Expr, Query, UnaryOperator, Value};
use std::str::FromStr;
use verifiable_db::query::computational_hash_ids::PlaceholderIdentifier;

use crate::{
    circuit::Assembler, errors::ValidationError, expand, parser,
    placeholders::PlaceholderValidator, symbols::ContextProvider, validate::SqlValidator,
};

/// This register handle all operations related to placeholder registration,
/// lookup an validation.
#[derive(Debug, Clone)]
pub struct PlaceholderRegister {
    /// The set of available placeholders.
    register: Vec<(String, PlaceholderIdentifier)>,
}
impl PlaceholderRegister {
    /// Create a placeholder register with $min_block, $max_block, and `n`
    /// freestanding placeholders.
    pub fn default(n: usize) -> Self {
        Self {
            register: vec![
                (
                    "$min_block".to_string(),
                    PlaceholderIdentifier::MinQueryOnIdx1,
                ),
                (
                    "$max_block".to_string(),
                    PlaceholderIdentifier::MaxQueryOnIdx1,
                ),
            ]
            .into_iter()
            .chain((0..n).map(|i| (format!("${i}"), PlaceholderIdentifier::Generic(i))))
            .collect(),
        }
    }

    /// Given a placeholder name, return, if it exists, the associated
    /// [`Placeholder`].
    pub(crate) fn resolve(&self, s: &str) -> Option<PlaceholderIdentifier> {
        self.register
            .iter()
            .find(|(name, _)| name == s)
            .map(|(_, placeholder)| placeholder.to_owned())
    }
}

#[derive(Debug)]
pub struct ParsilSettings<C: ContextProvider> {
    /// A handle to an object providing a register of the existing virtual
    /// tables and their columns.
    pub context: C,
    pub placeholders: PlaceholderSettings,
}

#[derive(Debug)]
pub struct PlaceholderSettings {
    /// The placeholder for the minimal value of the primary index
    pub min_block_placeholder: String,
    /// The placeholder for the maximal value of the primary index
    pub max_block_placeholder: String,
    /// The number of free-standing `$i` placeholders
    pub max_free_placeholders: usize,
}

pub const DEFAULT_MIN_BLOCK_PLACEHOLDER: &str = "$MIN_BLOCK";
pub const DEFAULT_MAX_BLOCK_PLACEHOLDER: &str = "$MAX_BLOCK";
impl PlaceholderSettings {
    pub fn with_freestanding(n: usize) -> Self {
        Self::with_freestanding_and_blocks(
            DEFAULT_MIN_BLOCK_PLACEHOLDER,
            DEFAULT_MAX_BLOCK_PLACEHOLDER,
            n,
        )
    }

    pub fn with_freestanding_and_blocks(min_block: &str, max_block: &str, n: usize) -> Self {
        Self {
            min_block_placeholder: min_block.to_string(),
            max_block_placeholder: max_block.to_string(),
            max_free_placeholders: n,
        }
    }

    /// Ensure that the given placeholder is valid, and update the validator
    /// internal state accordingly.
    pub fn resolve_placeholder(&self, name: &str) -> Result<PlaceholderIdentifier> {
        if self.min_block_placeholder == name {
            return Ok(PlaceholderIdentifier::MinQueryOnIdx1);
        }

        if self.max_block_placeholder == name {
            return Ok(PlaceholderIdentifier::MaxQueryOnIdx1);
        }

        if name.starts_with('$') {
            let i = name
                .trim_start_matches('$')
                .parse::<usize>()
                .map_err(|_| ValidationError::UnknownPlaceholder(name.to_owned()))?;

            if i > self.max_free_placeholders {
                bail!(ValidationError::UnknownPlaceholder(name.to_owned()))
            } else {
                Ok(PlaceholderIdentifier::Generic(i))
            }
        } else {
            bail!(ValidationError::UnknownPlaceholder(name.to_owned()))
        }
    }
}

pub fn parse_and_validate<C: ContextProvider>(
    query: &str,
    settings: &ParsilSettings<C>,
) -> Result<Query> {
    let mut query = parser::parse(&settings, query)?;
    expand::expand(&mut query);

    PlaceholderValidator::validate(&settings, &mut query)?;
    SqlValidator::validate(&settings, &mut query)?;
    Assembler::validate(&query, &settings)?;
    Ok(query)
}

/// Convert a string to a U256. Case is not conserved, and the string may be
/// prefixed by a radix indicator.
pub fn str_to_u256(s: &str) -> Result<U256> {
    let s = s.to_lowercase();
    U256::from_str(&s).map_err(|e| anyhow!("{s}: invalid U256: {e}"))
}

/// If it is static, evaluate an expression and return its value.
///
/// NOTE: this will be used (i) in optimization and (ii) when boundaries
/// will accept more complex expression.
fn const_eval(expr: &Expr) -> Result<U256> {
    #[allow(non_snake_case)]
    let ONE = U256::from_str_radix("1", 2).unwrap();
    const ZERO: U256 = U256::ZERO;

    match expr {
        Expr::Identifier(_) => todo!(),
        Expr::CompoundIdentifier(_) => todo!(),
        Expr::BinaryOp { left, op, right } => {
            let left = const_eval(left)?;
            let right = const_eval(right)?;
            Ok(match op {
                BinaryOperator::Plus => left + right,
                BinaryOperator::Minus => left - right,
                BinaryOperator::Multiply => left * right,
                BinaryOperator::Divide => left / right,
                BinaryOperator::Modulo => left % right,
                BinaryOperator::Gt => {
                    if left > right {
                        ONE
                    } else {
                        ZERO
                    }
                }
                BinaryOperator::Lt => {
                    if left < right {
                        ONE
                    } else {
                        ZERO
                    }
                }
                BinaryOperator::GtEq => {
                    if left >= right {
                        ONE
                    } else {
                        ZERO
                    }
                }
                BinaryOperator::LtEq => {
                    if left <= right {
                        ONE
                    } else {
                        ZERO
                    }
                }
                BinaryOperator::Eq => {
                    if left == right {
                        ONE
                    } else {
                        ZERO
                    }
                }
                BinaryOperator::NotEq => {
                    if left != right {
                        ONE
                    } else {
                        ZERO
                    }
                }
                BinaryOperator::And => {
                    if !left.is_zero() && !right.is_zero() {
                        ONE
                    } else {
                        ZERO
                    }
                }
                BinaryOperator::Or => {
                    if !left.is_zero() || !right.is_zero() {
                        ONE
                    } else {
                        ZERO
                    }
                }
                BinaryOperator::Xor => {
                    if !left.is_zero() ^ !right.is_zero() {
                        ONE
                    } else {
                        ZERO
                    }
                }
                _ => unreachable!(),
            })
        }
        Expr::UnaryOp { op, expr } => {
            let e = const_eval(expr)?;
            Ok(match op {
                UnaryOperator::Plus => e,
                UnaryOperator::Not => {
                    if e.is_zero() {
                        ONE
                    } else {
                        ZERO
                    }
                }
                _ => unreachable!(),
            })
        }
        Expr::Nested(e) => const_eval(e),
        Expr::Value(value) => match value {
            Value::Number(s, _) | Value::SingleQuotedString(s) => str_to_u256(s),
            Value::Boolean(b) => Ok(if *b { ONE } else { ZERO }),
            Value::Placeholder(_) => todo!(),
            _ => unreachable!(),
        },
        _ => bail!("`{expr}`: non-const expression"),
    }
}
