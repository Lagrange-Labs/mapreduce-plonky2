//! Adapt existing expressions to make them compatible with how the block
//! numbers works in the CoW database system.
use anyhow::*;
use sqlparser::ast::{
    Expr, JoinConstraint, JoinOperator, OrderBy, Query, Select, SelectItem, SetExpr, TableWithJoins,
};

fn inject_expr(e: &mut Expr) -> Result<()> {
    match e {
        Expr::Identifier(_) => todo!(),
        Expr::CompoundIdentifier(_) => todo!(),
        Expr::IsFalse(_) => todo!(),
        Expr::IsNotFalse(_) => todo!(),
        Expr::IsTrue(_) => todo!(),
        Expr::IsNotTrue(_) => todo!(),
        Expr::InList {
            expr,
            list,
            negated,
        } => todo!(),
        Expr::Between {
            expr,
            negated,
            low,
            high,
        } => todo!(),
        Expr::BinaryOp { left, op, right } => todo!(),
        Expr::UnaryOp { op, expr } => todo!(),
        Expr::Nested(_) => todo!(),
        Expr::Value(_) => todo!(),
        Expr::Subquery(_) => todo!(),
        Expr::Tuple(_) => todo!(),

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

fn inject_projection(p: &mut SelectItem) -> Result<()> {
    match p {
        SelectItem::UnnamedExpr(e) => inject_expr(e),
        SelectItem::ExprWithAlias { expr, .. } => inject_expr(expr),
        SelectItem::QualifiedWildcard(_, _) => unreachable!(),
        SelectItem::Wildcard(_) => Ok(()),
    }
}

fn inject_joint_constraint(c: &mut JoinConstraint) -> Result<()> {
    match c {
        JoinConstraint::On(e) => inject_expr(e),
        JoinConstraint::Using(_) | JoinConstraint::Natural | JoinConstraint::None => Ok(()),
    }
}

fn inject_from(f: &mut TableWithJoins) -> Result<()> {
    for join in f.joins.iter_mut() {
        match &mut join.join_operator {
            JoinOperator::Inner(c)
            | JoinOperator::LeftOuter(c)
            | JoinOperator::RightOuter(c)
            | JoinOperator::FullOuter(c) => inject_joint_constraint(c)?,

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
    Ok(())
}

fn inject_select(s: &mut Select) -> Result<()> {
    for p in s.projection.iter_mut() {
        inject_projection(p)?;
    }
    for f in s.from.iter_mut() {
        inject_from(f)?;
    }
    if let Some(selection) = s.selection.as_mut() {
        inject_expr(selection)?;
    }
    for sort in s.sort_by.iter_mut() {
        inject_expr(sort)?;
    }
    if let Some(having) = s.having.as_mut() {
        inject_expr(having)?;
    }
    Ok(())
}

fn inject_setexpr(s: &mut SetExpr) -> Result<()> {
    match s {
        SetExpr::Select(s) => inject_select(s),
        SetExpr::Query(q) => inject_query(q),
        SetExpr::SetOperation { .. }
        | SetExpr::Values(_)
        | SetExpr::Insert(_)
        | SetExpr::Update(_)
        | SetExpr::Table(_) => unreachable!(),
    }
}

fn inject_order_by(o: &mut OrderBy) -> Result<()> {
    for e in o.exprs.iter_mut() {
        inject_expr(&mut e.expr)?;
    }
    Ok(())
}

fn inject_query(q: &mut Query) -> Result<()> {
    inject_setexpr(&mut q.body)?;

    for order_by in q.order_by.iter_mut() {
        for e in order_by.exprs.iter_mut() {
            inject_expr(&mut e.expr)?;
        }
    }

    Ok(())
}
