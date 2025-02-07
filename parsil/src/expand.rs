//! Expand high-level operations (e.g. IN or BETWEEN) into combination of
//! operations supported by the circuits.

use crate::{
    errors::ValidationError,
    symbols::ContextProvider,
    utils::int_to_expr,
    validate::is_query_with_no_aggregation,
    visitor::{AstMutator, VisitMut},
    ParsilSettings,
};
use anyhow::ensure;
use sqlparser::ast::{
    BinaryOperator, Expr, Offset, OffsetRows, Query, SetExpr, UnaryOperator, Value,
};

struct Expander<'a, C: ContextProvider> {
    settings: &'a ParsilSettings<C>,
}

impl<C: ContextProvider> AstMutator for Expander<'_, C> {
    type Error = anyhow::Error;

    fn pre_expr(&mut self, e: &mut Expr) -> anyhow::Result<()> {
        #[allow(non_snake_case)]
        let TRUE = Expr::Value(Value::Number("1".to_string(), false));
        #[allow(non_snake_case)]
        let FALSE = Expr::Value(Value::Number("0".to_string(), false));

        match e {
            // ISFALSE(old) := (old = 0)
            Expr::IsNotTrue(old) | Expr::IsFalse(old) => {
                *e = Expr::Nested(Box::new(Expr::BinaryOp {
                    left: Box::new(*old.clone()),
                    op: BinaryOperator::Eq,
                    right: Box::new(FALSE.clone()),
                }))
            }
            // ISTRUE(old) := (old != 0)
            Expr::IsTrue(old) | Expr::IsNotFalse(old) => {
                *e = Expr::Nested(Box::new(Expr::BinaryOp {
                    left: Box::new(*old.clone()),
                    op: BinaryOperator::NotEq,
                    right: Box::new(FALSE.clone()),
                }))
            }
            Expr::InList {
                expr,
                list,
                negated,
            } => {
                *e = if *negated {
                    // NOT INLIST := old != list[0] AND old != list[1] ... AND TRUE
                    Expr::Nested(Box::new(list.iter_mut().enumerate().fold(
                        TRUE.clone(),
                        |ax, (i, l)| {
                            let eq_op = Expr::BinaryOp {
                                left: Box::new(l.clone()),
                                op: BinaryOperator::NotEq,
                                right: expr.clone(),
                            };
                            if i == 0 {
                                // save first AND, which is a dummy one
                                eq_op
                            } else {
                                Expr::BinaryOp {
                                    left: Box::new(eq_op),
                                    op: BinaryOperator::And,
                                    right: Box::new(ax),
                                }
                            }
                        },
                    )))
                } else {
                    // INLIST := old == list[0] OR old == list[1] ... OR FALSE
                    Expr::Nested(Box::new(list.iter_mut().enumerate().fold(
                        FALSE.clone(),
                        |ax, (i, l)| {
                            let eq_op = Expr::BinaryOp {
                                left: Box::new(l.clone()),
                                op: BinaryOperator::Eq,
                                right: expr.clone(),
                            };
                            if i == 0 {
                                // save first OR, which is a dummy one
                                eq_op
                            } else {
                                Expr::BinaryOp {
                                    left: Box::new(eq_op),
                                    op: BinaryOperator::Or,
                                    right: Box::new(ax),
                                }
                            }
                        },
                    )))
                }
            }
            Expr::Between {
                expr,
                negated,
                low,
                high,
            } => {
                *e = if *negated {
                    // NOT x BETWEEN a AND b := x < a OR x > b
                    Expr::Nested(Box::new(Expr::BinaryOp {
                        left: Box::new(Expr::BinaryOp {
                            left: Box::new(*expr.clone()),
                            op: BinaryOperator::Lt,
                            right: Box::new(*low.clone()),
                        }),
                        op: BinaryOperator::Or,
                        right: Box::new(Expr::BinaryOp {
                            left: Box::new(*expr.clone()),
                            op: BinaryOperator::Gt,
                            right: Box::new(*high.clone()),
                        }),
                    }))
                } else {
                    // x BETWEEN a AND b := x >= a AND x <= b
                    Expr::Nested(Box::new(Expr::BinaryOp {
                        left: Box::new(Expr::BinaryOp {
                            left: Box::new(*expr.clone()),
                            op: BinaryOperator::GtEq,
                            right: Box::new(*low.clone()),
                        }),
                        op: BinaryOperator::And,
                        right: Box::new(Expr::BinaryOp {
                            left: Box::new(*expr.clone()),
                            op: BinaryOperator::LtEq,
                            right: Box::new(*high.clone()),
                        }),
                    }))
                }
            }
            Expr::UnaryOp {
                op: UnaryOperator::Plus,
                expr,
            } => {
                // +E := E
                *e = *expr.clone();
            }
            _ => {}
        }

        Ok(())
    }

    fn pre_query(&mut self, query: &mut Query) -> anyhow::Result<()> {
        ensure!(
            query.limit.is_none(),
            ValidationError::UseInvocationParameter("LIMIT".into())
        );
        ensure!(
            query.offset.is_none(),
            ValidationError::UseInvocationParameter("OFFSET".into())
        );

        if let SetExpr::Select(ref select) = *query.body {
            if is_query_with_no_aggregation(select) {
                query.limit = Some(int_to_expr(self.settings.limit()));
                if let Some(offset) = self.settings.offset {
                    if offset != 0 {
                        query.offset = Some(Offset {
                            value: int_to_expr(self.settings.offset()),
                            rows: OffsetRows::None,
                        });
                    }
                }
            }
        }
        Ok(())
    }
}

pub fn expand<C: ContextProvider>(
    settings: &ParsilSettings<C>,
    q: &mut Query,
) -> anyhow::Result<()> {
    let mut expander = Expander { settings };
    q.visit_mut(&mut expander)
}
