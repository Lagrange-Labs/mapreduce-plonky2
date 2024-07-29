use anyhow::*;
use sqlparser::ast::{
    BinaryOperator, Expr, GroupByExpr, JoinConstraint, JoinOperator, OrderBy, OrderByExpr, Query,
    Select, SelectItem, SetExpr, TableFactor, TableWithJoins, UnaryOperator, Value,
    WildcardAdditionalOptions,
};

use crate::visitor::{AstPass, Visit};

struct Validator;
impl AstPass for Validator {
    fn pre_unary_operator(&mut self, unary_operator: &mut UnaryOperator) -> Result<()> {
        match unary_operator {
            UnaryOperator::Plus | UnaryOperator::Not => Ok(()),
            _ => bail!("{unary_operator}: unsupported operator"),
        }
    }

    fn pre_binary_operator(&mut self, op: &mut BinaryOperator) -> Result<()> {
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

            _ => bail!("{op}: unsupported operator"),
        }
    }

    fn pre_expr(&mut self, expr: &mut Expr) -> Result<()> {
        match expr {
            Expr::Identifier(_)
            | Expr::CompoundIdentifier(_)
            | Expr::IsFalse(_)
            | Expr::IsNotFalse(_)
            | Expr::IsTrue(_)
            | Expr::IsNotTrue(_)
            | Expr::InList { .. }
            | Expr::Between { .. }
            | Expr::BinaryOp { .. }
            | Expr::UnaryOp { .. }
            | Expr::Nested(_)
            | Expr::Tuple(_) => {}

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
                | Value::Null => bail!("{v}: unsupported type of value"),
            },
            Expr::Subquery(s) => {
                bail!("{s}: nested selects not supported");
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
            | Expr::Map(_) => {
                bail!("{expr}: unsupported")
            }
        }
        Ok(())
    }

    fn pre_select_item(&mut self, p: &mut SelectItem) -> Result<()> {
        match p {
            SelectItem::QualifiedWildcard(_, _) => bail!("{p}: not supported"),
            _ => Ok(()),
        }
    }

    fn pre_table_factor(&mut self, j: &mut TableFactor) -> Result<()> {
        match j {
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
            | TableFactor::MatchRecognize { .. } => bail!("{}: unsupported relation", j),
        }
    }

    fn pre_join_operator(&mut self, j: &mut JoinOperator) -> Result<()> {
        match j {
            JoinOperator::Inner(_)
            | JoinOperator::LeftOuter(_)
            | JoinOperator::RightOuter(_)
            | JoinOperator::FullOuter(_) => Ok(()),

            JoinOperator::CrossJoin
            | JoinOperator::LeftSemi(_)
            | JoinOperator::RightSemi(_)
            | JoinOperator::LeftAnti(_)
            | JoinOperator::RightAnti(_)
            | JoinOperator::CrossApply
            | JoinOperator::OuterApply
            | JoinOperator::AsOf { .. } => bail!("{:?}: non-standard syntax", j),
        }
    }

    fn pre_select(&mut self, s: &mut Select) -> Result<()> {
        ensure!(s.distinct.is_none(), "DISTINCT is not supported");
        ensure!(s.top.is_none(), "TOP is an MSSQL syntax");
        ensure!(s.into.is_none(), "{s}: SELECT ... INTO not supported");
        ensure!(s.lateral_views.is_empty(), "LATERAL VIEW unsupported");
        match &s.group_by {
            GroupByExpr::All(_) => bail!("{}: non-standard syntax", s.group_by),
            GroupByExpr::Expressions(es, _) => ensure!(es.is_empty(), "GROUP BY not supported"),
        };
        ensure!(s.cluster_by.is_empty(), "CLUSTER BY not supported");
        ensure!(
            s.distribute_by.is_empty(),
            "DISTRIBUTE BY is a Spark-specific syntax extension"
        );
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

    fn pre_set_expr(&mut self, s: &mut SetExpr) -> Result<()> {
        match s {
            SetExpr::Select(_) => Ok(()),
            SetExpr::Query(_) => bail!("{s}: nested queries are not supported"),
            SetExpr::SetOperation { .. } => bail!("{s}: set operations are not supported"),
            SetExpr::Values(_) | SetExpr::Insert(_) | SetExpr::Update(_) | SetExpr::Table(_) => {
                bail!("{s}: mutable queries not supported")
            }
        }
    }

    fn pre_order_by(&mut self, o: &mut OrderBy) -> Result<()> {
        ensure!(
            o.interpolate.is_none(),
            "{:?}: unsupported clickhouse extension",
            o.interpolate
        );
        Ok(())
    }

    fn pre_order_by_expr(&mut self, o: &mut OrderByExpr) -> Result<()> {
        ensure!(
            o.nulls_first.is_none(),
            "NULL-related specifiers not supported"
        );
        Ok(())
    }

    fn pre_query(&mut self, q: &mut Query) -> Result<()> {
        ensure!(q.with.is_none(), "CTEs are not supported");
        ensure!(q.limit_by.is_empty(), "LIMIT BY not supported");
        ensure!(q.offset.is_none(), "OFFSET is an Oracle syntax");
        ensure!(q.locks.is_empty(), "locks not supported");
        ensure!(q.for_clause.is_none(), "FOR is an MSSQL extension");
        Ok(())
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

/// Ensure that a top-level [`Query`] is compatible with the currently
/// implemented subset of SQL.
pub fn validate(query: &mut Query) -> Result<()> {
    ensure!(
        matches!(*query.body, SetExpr::Select(_)),
        "query body should be a SELECT statement"
    );
    query.visit(&mut Validator)
}
