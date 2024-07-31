use anyhow::*;
use sqlparser::ast::{
    BinaryOperator, Expr, GroupByExpr, JoinConstraint, JoinOperator, OrderBy, Query, Select,
    SelectItem, SetExpr, TableFactor, TableWithJoins, UnaryOperator, Value,
    WildcardAdditionalOptions,
};

fn validate_unary_op(o: &UnaryOperator) -> Result<()> {
    match o {
        UnaryOperator::Plus | UnaryOperator::Not => Ok(()),
        _ => bail!("{o}: unsupported operator"),
    }
}

fn validate_binary_op(op: &BinaryOperator) -> Result<()> {
    match op {
        BinaryOperator::Eq
        | BinaryOperator::NotEq
        | BinaryOperator::Plus
        | BinaryOperator::Minus
        | BinaryOperator::Multiply
        | BinaryOperator::Divide
        | BinaryOperator::Modulo
        | BinaryOperator::Gt
        | BinaryOperator::Lt
        | BinaryOperator::GtEq
        | BinaryOperator::LtEq
        | BinaryOperator::And
        | BinaryOperator::Or
        | BinaryOperator::Xor => Ok(()),

        BinaryOperator::StringConcat
        | BinaryOperator::Spaceship
        | BinaryOperator::BitwiseOr
        | BinaryOperator::BitwiseAnd
        | BinaryOperator::BitwiseXor
        | BinaryOperator::DuckIntegerDivide
        | BinaryOperator::MyIntegerDivide
        | BinaryOperator::Custom(_)
        | BinaryOperator::PGBitwiseXor
        | BinaryOperator::PGBitwiseShiftLeft
        | BinaryOperator::PGBitwiseShiftRight
        | BinaryOperator::PGExp
        | BinaryOperator::PGOverlap
        | BinaryOperator::PGRegexMatch
        | BinaryOperator::PGRegexIMatch
        | BinaryOperator::PGRegexNotMatch
        | BinaryOperator::PGRegexNotIMatch
        | BinaryOperator::PGLikeMatch
        | BinaryOperator::PGILikeMatch
        | BinaryOperator::PGNotLikeMatch
        | BinaryOperator::PGNotILikeMatch
        | BinaryOperator::PGStartsWith
        | BinaryOperator::Arrow
        | BinaryOperator::LongArrow
        | BinaryOperator::HashArrow
        | BinaryOperator::HashLongArrow
        | BinaryOperator::AtAt
        | BinaryOperator::AtArrow
        | BinaryOperator::ArrowAt
        | BinaryOperator::HashMinus
        | BinaryOperator::AtQuestion
        | BinaryOperator::Question
        | BinaryOperator::QuestionAnd
        | BinaryOperator::QuestionPipe
        | BinaryOperator::PGCustomBinaryOperator(_) => bail!("{op}: unsupported operator"),
    }
}

fn validate_expr(e: &Expr) -> Result<()> {
    match e {
        Expr::Identifier(_) | Expr::CompoundIdentifier(_) => {}
        Expr::IsFalse(e) | Expr::IsNotFalse(e) | Expr::IsTrue(e) | Expr::IsNotTrue(e) => {
            validate_expr(e)?;
        }
        Expr::InList { expr, list, .. } => {
            validate_expr(expr)?;
            for e in list.iter() {
                validate_expr(e)?;
            }
        }
        Expr::Between {
            expr, low, high, ..
        } => {
            validate_expr(expr)?;
            validate_expr(low)?;
            validate_expr(high)?;
        }
        Expr::BinaryOp { left, op, right } => {
            validate_binary_op(op)?;
            validate_expr(left)?;
            validate_expr(right)?;
        }
        Expr::UnaryOp { op, expr } => {
            validate_unary_op(op)?;
            validate_expr(expr)?;
        }

        Expr::Nested(e) => {
            validate_expr(e)?;
        }
        Expr::AnyOp { left, right, .. } | Expr::AllOp { left, right, .. } => {
            bail!("unsupported for now");
            validate_expr(left)?;
            validate_expr(right)?;
        }
        Expr::Value(v) => match v {
            Value::Placeholder(_) | Value::Number(_, _) | Value::Boolean(_) => {}
            Value::HexStringLiteral(s) => ensure!(s.len() <= 32, "{s}: more than 32 bytes"),
            Value::SingleQuotedString(_)
            | Value::DollarQuotedString(_)
            | Value::TripleSingleQuotedString(_)
            | Value::TripleDoubleQuotedString(_)
            | Value::EscapedStringLiteral(_)
            | Value::SingleQuotedByteStringLiteral(_)
            | Value::DoubleQuotedByteStringLiteral(_)
            | Value::TripleSingleQuotedByteStringLiteral(_)
            | Value::TripleDoubleQuotedByteStringLiteral(_)
            | Value::SingleQuotedRawStringLiteral(_)
            | Value::DoubleQuotedRawStringLiteral(_)
            | Value::TripleSingleQuotedRawStringLiteral(_)
            | Value::TripleDoubleQuotedRawStringLiteral(_)
            | Value::NationalStringLiteral(_)
            | Value::DoubleQuotedString(_)
            | Value::Null => bail!("{v}: unsupported immediate value"),
        },
        Expr::Tuple(es) => {
            for e in es {
                validate_expr(e)?;
            }
        }

        Expr::Subquery(s) => {
            validate_query(s)?;
            // NOTE: probably soon supported
            bail!("{s}: nested selects not supported");
        }

        Expr::InSubquery { .. }
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
        | Expr::Map(_) => {
            bail!("{}: unsupported", e)
        }
    }
    Ok(())
}

fn validate_projection(p: &SelectItem) -> Result<()> {
    match p {
        SelectItem::UnnamedExpr(e) => validate_expr(e),
        SelectItem::ExprWithAlias { expr, .. } => validate_expr(expr),
        SelectItem::QualifiedWildcard(_, _) => bail!("{p} not supported"),
        SelectItem::Wildcard(w) => validate_wildcard(w),
    }
}

fn validate_wildcard(w: &WildcardAdditionalOptions) -> Result<()> {
    ensure!(w.opt_ilike.is_none(), "ILIKE is not supported");
    ensure!(w.opt_exclude.is_none(), "EXCLUDE is not supported");
    ensure!(w.opt_except.is_none(), "EXCEPT is not supported");
    ensure!(w.opt_replace.is_none(), "REPLACE is not supported");
    ensure!(w.opt_rename.is_none(), "RENAME is not supported");

    Ok(())
}

fn validate_join_constraint(c: &JoinConstraint) -> Result<()> {
    match c {
        JoinConstraint::On(e) => validate_expr(e),
        JoinConstraint::Using(_) | JoinConstraint::Natural | JoinConstraint::None => Ok(()),
    }
}

fn validate_from(f: &TableWithJoins) -> Result<()> {
    match &f.relation {
        // TODO: add symbol resolution
        TableFactor::Table { .. } => Ok(()),
        TableFactor::Derived { .. }
        | TableFactor::TableFunction { .. }
        | TableFactor::Function { .. }
        | TableFactor::UNNEST { .. }
        | TableFactor::JsonTable { .. }
        | TableFactor::NestedJoin { .. }
        | TableFactor::Pivot { .. }
        | TableFactor::Unpivot { .. }
        | TableFactor::MatchRecognize { .. } => bail!("{}: unsupported relation", f.relation),
    }?;

    for join in &f.joins {
        match &join.join_operator {
            JoinOperator::Inner(c)
            | JoinOperator::LeftOuter(c)
            | JoinOperator::RightOuter(c)
            | JoinOperator::FullOuter(c) => validate_join_constraint(c)?,

            JoinOperator::CrossJoin
            | JoinOperator::LeftSemi(_)
            | JoinOperator::RightSemi(_)
            | JoinOperator::LeftAnti(_)
            | JoinOperator::RightAnti(_)
            | JoinOperator::CrossApply
            | JoinOperator::OuterApply
            | JoinOperator::AsOf { .. } => bail!("{:?}: non-standard syntax", join.join_operator),
        }
    }
    Ok(())
}

fn validate_select(s: &Select) -> Result<()> {
    ensure!(s.distinct.is_none(), "DISTINCT is not supported");
    ensure!(s.top.is_none(), "TOP is an MSSQL syntax");
    for p in s.projection.iter() {
        validate_projection(p)?;
    }
    ensure!(s.into.is_none(), "{s}: SELECT ... INTO not supported");
    for f in s.from.iter() {
        validate_from(f)?;
    }
    ensure!(s.lateral_views.is_empty(), "LATERAL VIEW unsupported");
    if let Some(selection) = s.selection.as_ref() {
        validate_expr(selection)?;
    }
    match &s.group_by {
        GroupByExpr::All(_) => bail!("{}: non-standard syntax", s.group_by),
        GroupByExpr::Expressions(es, _) => ensure!(es.is_empty(), "GROUP BY not supported"),
    }
    ensure!(s.cluster_by.is_empty(), "CLUSTER BY not supported");
    ensure!(
        s.distribute_by.is_empty(),
        "DISTRIBUTE BY is a Spark-specific syntax extension"
    );
    for sort in &s.sort_by {
        validate_expr(sort)?;
    }
    if let Some(having) = s.having.as_ref() {
        validate_expr(having)?;
    }
    ensure!(s.named_window.is_empty(), "windows are not supporrted");
    ensure!(
        s.qualify.is_none(),
        "QUALIFY is a Snowflake-specific extension"
    );
    ensure!(
        s.value_table_mode.is_none(),
        "{:?}: BigQuery-specific extension",
        s.value_table_mode
    );
    ensure!(
        s.connect_by.is_none(),
        "STARTING WITH ... CONNECT BY: OracleSQL-specific syntax extension"
    );

    Ok(())
}

fn validate_setexpr(s: &SetExpr) -> Result<()> {
    match s {
        SetExpr::Select(s) => validate_select(s),
        SetExpr::Query(q) => bail!("{s}: nested queries are not supported"),
        SetExpr::SetOperation { .. } => bail!("{s}: set operations are not supported"),
        SetExpr::Values(_) | SetExpr::Insert(_) | SetExpr::Update(_) | SetExpr::Table(_) => {
            bail!("{s}: mutable queries not supported")
        }
    }
}

fn validate_order_by(o: &OrderBy) -> Result<()> {
    for e in &o.exprs {
        ensure!(
            e.nulls_first.is_none(),
            "NULL-related specifiers not supported"
        );
        validate_expr(&e.expr)?;
    }
    ensure!(
        o.interpolate.is_none(),
        "{:?}: unsupported clickhouse extension",
        o.interpolate
    );
    Ok(())
}

/// Ensure that a [`Query`] is compatible with the currently implemented subset
/// of SQL.
fn validate_query(q: &Query) -> Result<()> {
    ensure!(q.with.is_none(), "CTEs are not supported");
    ensure!(q.limit_by.is_empty(), "LIMIT BY not supported");
    ensure!(q.offset.is_none(), "OFFSET is an Oracle syntax");
    ensure!(q.locks.is_empty(), "locks not supported");
    ensure!(q.for_clause.is_none(), "FOR is an MSSQL extension");
    if let Some(o) = q.order_by.as_ref() {
        validate_order_by(o)?;
    }
    validate_setexpr(&q.body)
}

/// Ensure that a top-level [`Query`] is compatible with the currently
/// implemented subset of SQL.
pub fn validate(query: &Query) -> Result<()> {
    ensure!(
        matches!(*query.body, SetExpr::Select(_)),
        "query body should be a SELECT statement"
    );
    validate_query(query)
}
