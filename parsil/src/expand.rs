//! Expand high-level operations (e.g. IN or BETWEEN) in combination of
//! operations supported by the circuits.

use sqlparser::ast::{
    BinaryOperator, Expr, JoinConstraint, JoinOperator, OrderBy, Query, Select, SelectItem,
    SetExpr, TableWithJoins, UnaryOperator, Value,
};

fn expand_expr(e: &mut Expr) {
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
        // Expand INLIST(expr, list) into (old = list[0] OR old = list[1] OR ...)
        Expr::InList {
            expr,
            list,
            negated,
        } => {
            let body = Expr::Nested(Box::new(list.into_iter().fold(FALSE.clone(), |ax, l| {
                Expr::BinaryOp {
                    left: Box::new(Expr::BinaryOp {
                        left: Box::new(l.clone()),
                        op: BinaryOperator::Eq,
                        right: expr.clone(),
                    }),
                    op: BinaryOperator::Or,
                    right: Box::new(ax),
                }
            })));

            if *negated {
                *e = Expr::UnaryOp {
                    op: UnaryOperator::Not,
                    expr: Box::new(body),
                };
            } else {
                *e = body;
            }
        }
        // Expand x BETWEEN a AND b into (x >= a AND x <= b)
        Expr::Between {
            expr,
            negated,
            low,
            high,
        } => {
            let body = Expr::Nested(Box::new(Expr::BinaryOp {
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
            }));
            if *negated {
                *e = Expr::UnaryOp {
                    op: UnaryOperator::Not,
                    expr: Box::new(body),
                };
            } else {
                *e = body;
            }
        }
        Expr::BinaryOp { left, right, .. } => {
            expand_expr(left);
            expand_expr(right);
        }
        Expr::UnaryOp { expr: e, .. } | Expr::Nested(e) => expand_expr(e),

        Expr::Identifier(_) | Expr::CompoundIdentifier(_) | Expr::Value(_) | Expr::Tuple(_) => {}

        Expr::Subquery(q) => {
            unreachable!();
            expand_query(q)
        }
        Expr::AnyOp { .. }
        | Expr::AllOp { .. }
        | Expr::InSubquery { .. }
        | Expr::InUnnest { .. }
        | Expr::IsNull(_)
        | Expr::IsNotNull(_)
        | Expr::IsUnknown(_)
        | Expr::IsNotUnknown(_)
        | Expr::IsDistinctFrom(_, _)
        | Expr::IsNotDistinctFrom(_, _)
        | Expr::JsonAccess { .. }
        | Expr::CompositeAccess { .. }
        | Expr::AtTimeZone { .. }
        | Expr::Extract { .. }
        | Expr::Substring { .. }
        | Expr::Overlay { .. }
        | Expr::Trim { .. }
        | Expr::Ceil { .. }
        | Expr::Floor { .. }
        | Expr::Convert { .. }
        | Expr::Cast { .. }
        | Expr::Position { .. }
        | Expr::Collate { .. }
        | Expr::Like { .. }
        | Expr::ILike { .. }
        | Expr::SimilarTo { .. }
        | Expr::RLike { .. }
        | Expr::Interval(_)
        | Expr::MatchAgainst { .. }
        | Expr::Struct { .. }
        | Expr::Dictionary(_)
        | Expr::Subscript { .. }
        | Expr::Array(_)
        | Expr::GroupingSets(_)
        | Expr::Cube(_)
        | Expr::Rollup(_)
        | Expr::IntroducedString { .. }
        | Expr::TypedString { .. }
        | Expr::MapAccess { .. }
        | Expr::Function(_)
        | Expr::Exists { .. }
        | Expr::Case { .. }
        | Expr::Named { .. }
        | Expr::Wildcard
        | Expr::QualifiedWildcard(_)
        | Expr::OuterJoin(_)
        | Expr::Prior(_)
        | Expr::Lambda(_)
        | Expr::Map(_) => unreachable!("{}", e),
    }
}

fn expand_projection(p: &mut SelectItem) {
    match p {
        SelectItem::UnnamedExpr(e) => expand_expr(e),
        SelectItem::ExprWithAlias { expr, .. } => expand_expr(expr),
        SelectItem::QualifiedWildcard(_, _) => unreachable!(),
        SelectItem::Wildcard(_) => {}
    }
}

fn expand_joint_constraint(c: &mut JoinConstraint) {
    match c {
        JoinConstraint::On(e) => expand_expr(e),
        JoinConstraint::Using(_) | JoinConstraint::Natural | JoinConstraint::None => {}
    }
}

fn expand_from(f: &mut TableWithJoins) {
    for join in f.joins.iter_mut() {
        match &mut join.join_operator {
            JoinOperator::Inner(c)
            | JoinOperator::LeftOuter(c)
            | JoinOperator::RightOuter(c)
            | JoinOperator::FullOuter(c) => expand_joint_constraint(c),

            JoinOperator::CrossJoin
            | JoinOperator::LeftSemi(_)
            | JoinOperator::RightSemi(_)
            | JoinOperator::LeftAnti(_)
            | JoinOperator::RightAnti(_)
            | JoinOperator::CrossApply
            | JoinOperator::OuterApply
            | JoinOperator::AsOf { .. } => unreachable!(),
        };
    }
}

fn expand_select(s: &mut Select) {
    for p in s.projection.iter_mut() {
        expand_projection(p);
    }
    for f in s.from.iter_mut() {
        expand_from(f);
    }
    if let Some(selection) = s.selection.as_mut() {
        expand_expr(selection);
    }
    for sort in s.sort_by.iter_mut() {
        expand_expr(sort);
    }
    if let Some(having) = s.having.as_mut() {
        expand_expr(having);
    }
}

fn expand_setexpr(s: &mut SetExpr) {
    match s {
        SetExpr::Select(s) => expand_select(s),
        SetExpr::Query(q) => expand_query(q),
        SetExpr::SetOperation { .. }
        | SetExpr::Values(_)
        | SetExpr::Insert(_)
        | SetExpr::Update(_)
        | SetExpr::Table(_) => unreachable!(),
    }
}

fn expand_order_by(o: &mut OrderBy) {
    for e in o.exprs.iter_mut() {
        expand_expr(&mut e.expr);
    }
}

pub fn expand_query(q: &mut Query) {
    if let Some(o) = q.order_by.as_mut() {
        expand_order_by(o);
    }
    expand_setexpr(&mut q.body);
}
