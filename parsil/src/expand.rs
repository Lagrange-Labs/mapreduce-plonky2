//! Expand high-level operations (e.g. IN or BETWEEN) into combination of
//! operations supported by the circuits.

use sqlparser::ast::{BinaryOperator, Expr, Query, Value};

use crate::visitor::{AstPass, Visit};

struct Expander;

impl AstPass for Expander {
    fn pre_expr(&mut self, e: &mut Expr) -> anyhow::Result<()> {
        #[allow(non_snake_case)]
        let TRUE = Expr::Value(Value::Number("1".to_string(), false));
        #[allow(non_snake_case)]
        let FALSE = Expr::Value(Value::Number("0".to_string(), false));

        match e {
            // Expand ISFALSE(old) into (old = 0)
            Expr::IsNotTrue(old) | Expr::IsFalse(old) => {
                *e = Expr::Nested(Box::new(Expr::BinaryOp {
                    left: Box::new(*old.clone()),
                    op: BinaryOperator::Eq,
                    right: Box::new(FALSE.clone()),
                }))
            }
            // Expand ISTRUE(old) into (old != 0)
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
                    // NOT INLIST -> old != list[0] AND old != list[1] ... AND TRUE
                    Expr::Nested(Box::new(list.into_iter().fold(TRUE.clone(), |ax, l| {
                        Expr::BinaryOp {
                            left: Box::new(Expr::BinaryOp {
                                left: Box::new(l.clone()),
                                op: BinaryOperator::NotEq,
                                right: expr.clone(),
                            }),
                            op: BinaryOperator::And,
                            right: Box::new(ax),
                        }
                    })))
                } else {
                    // INLIST -> old == list[0] OR old == list[1] ... OR FALSE
                    Expr::Nested(Box::new(list.into_iter().fold(FALSE.clone(), |ax, l| {
                        Expr::BinaryOp {
                            left: Box::new(Expr::BinaryOp {
                                left: Box::new(l.clone()),
                                op: BinaryOperator::Eq,
                                right: expr.clone(),
                            }),
                            op: BinaryOperator::Or,
                            right: Box::new(ax),
                        }
                    })))
                }
            }
            Expr::Between {
                expr,
                negated,
                low,
                high,
            } => {
                *e = if *negated {
                    // NOT x BETWEEN a AND b -> x < a OR x > b
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
                    // x BETWEEN a AND b -> x >= a AND x <= b
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
            _ => {}
        }

        Ok(())
    }
}

pub fn expand(q: &mut Query) {
    q.visit(&mut Expander).expect("can not fail");
}
