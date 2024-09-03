use anyhow::*;
use sqlparser::ast::{
    BinaryOperator, Distinct, Expr, FunctionArg, FunctionArgExpr, FunctionArguments, GroupByExpr,
    JoinOperator, Offset, OffsetRows, OrderBy, OrderByExpr, Query, Select, SelectItem, SetExpr,
    TableFactor, UnaryOperator, Value,
};

use crate::{
    errors::ValidationError,
    symbols::ContextProvider,
    utils::{str_to_u256, ParsilSettings},
    visitor::{AstPass, Visit},
};

/// Ensure that a top-level [`Query`] is compatible with the currently
/// implemented subset of SQL.
pub struct SqlValidator<'a, C: ContextProvider> {
    settings: &'a ParsilSettings<C>,
}
impl<'a, C: ContextProvider> AstPass for SqlValidator<'a, C> {
    fn pre_unary_operator(&mut self, unary_operator: &mut UnaryOperator) -> Result<()> {
        match unary_operator {
            UnaryOperator::Plus | UnaryOperator::Not => Ok(()),
            _ => bail!(ValidationError::UnsupportedUnaryOperator(*unary_operator)),
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

            _ => bail!(ValidationError::UnsupportedBinaryOperator(op.clone())),
        }
    }

    fn pre_expr(&mut self, expr: &mut Expr) -> Result<()> {
        match expr {
            Expr::Identifier(name) => {
                ensure!(
                    !name.value.starts_with("__"),
                    ValidationError::ReservedIdentifier(name.value.to_owned())
                );
            }
            Expr::CompoundIdentifier(names) => {
                let latest = names.last().unwrap();
                ensure!(
                    !latest.value.starts_with("__"),
                    ValidationError::ReservedIdentifier(latest.value.to_owned())
                );
            }
            Expr::IsFalse(_)
            | Expr::IsNotFalse(_)
            | Expr::IsTrue(_)
            | Expr::IsNotTrue(_)
            | Expr::InList { .. }
            | Expr::Between { .. }
            | Expr::BinaryOp { .. }
            | Expr::UnaryOp { .. }
            | Expr::Nested(_) => {}

            Expr::Function(funcall) => {
                ensure!(
                    funcall.name.0.len() == 1,
                    ValidationError::UnknownFunction(funcall.name.to_string())
                );

                if let FunctionArguments::List(arglist) = &mut funcall.args {
                    ensure!(
                        arglist.args.len() == 1,
                        ValidationError::InvalidArity(
                            funcall.name.to_string(),
                            1,
                            arglist.args.len()
                        )
                    );
                    match &mut arglist.args[0] {
                        FunctionArg::Unnamed(FunctionArgExpr::Expr(_)) => {}
                        _ => bail!(ValidationError::InvalidFunctionArgument(
                            arglist.args[0].to_string()
                        )),
                    }
                } else {
                    bail!(ValidationError::InvalidFunctionArgument(format!(
                        "{}",
                        funcall.args
                    )));
                }
            }

            Expr::Value(v) => match v {
                Value::Number(_, _) | Value::Boolean(_) => {}
                Value::Placeholder(p) => {
                    self.settings.placeholders.resolve_placeholder(p)?;
                }
                Value::SingleQuotedString(s) => str_to_u256(s).map(|_| ())?,
                Value::HexStringLiteral(_)
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
                | Value::Null => bail!(ValidationError::UnsupportedImmediateValue(v.to_string())),
            },
            Expr::Subquery(s) => {
                bail!(ValidationError::NestedSelect(s.to_string()));
            }

            Expr::AnyOp { .. }
            | Expr::Tuple(_)
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
            | Expr::Exists { .. }
            | Expr::Case { .. }
            | Expr::Named { .. }
            | Expr::Wildcard
            | Expr::QualifiedWildcard(_)
            | Expr::OuterJoin(_)
            | Expr::Prior(_)
            | Expr::Lambda(_)
            | Expr::Map(_) => {
                bail!(ValidationError::UnsupportedFeature(expr.to_string()))
            }
        }
        Ok(())
    }

    fn pre_select_item(&mut self, p: &mut SelectItem) -> Result<()> {
        match p {
            SelectItem::Wildcard(w) => {
                ensure!(
                    w.opt_ilike.is_none(),
                    ValidationError::UnsupportedFeature("ILIKE".into())
                );
                ensure!(
                    w.opt_exclude.is_none(),
                    ValidationError::UnsupportedFeature("EXCLUDE".into())
                );
                ensure!(
                    w.opt_except.is_none(),
                    ValidationError::UnsupportedFeature("EXCEPT".into())
                );
                ensure!(
                    w.opt_replace.is_none(),
                    ValidationError::UnsupportedFeature("REPLACE".into())
                );
                ensure!(
                    w.opt_rename.is_none(),
                    ValidationError::UnsupportedFeature("RENAME".into())
                );
                Ok(())
            }
            SelectItem::QualifiedWildcard(_, _) => {
                bail!(ValidationError::UnsupportedFeature(p.to_string()))
            }
            _ => Ok(()),
        }
    }

    fn pre_table_factor(&mut self, j: &mut TableFactor) -> Result<()> {
        match j {
            TableFactor::Table { .. } => Ok(()),
            TableFactor::Derived { .. } => {
                // NOTE: when the time comes, let us be careful of LATERAL joins
                bail!(ValidationError::NestedSelect(j.to_string()));
            }
            TableFactor::TableFunction { .. }
            | TableFactor::Function { .. }
            | TableFactor::UNNEST { .. }
            | TableFactor::JsonTable { .. }
            | TableFactor::NestedJoin { .. }
            | TableFactor::Pivot { .. }
            | TableFactor::Unpivot { .. }
            | TableFactor::MatchRecognize { .. } => {
                bail!(ValidationError::UnsupportedJointure(format!("{j}:#?")))
            }
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
            | JoinOperator::AsOf { .. } => {
                bail!(ValidationError::NonStandardSql(format!("{j:#?}")))
            }
        }
    }

    fn pre_distinct(&mut self, distinct: &mut Distinct) -> Result<()> {
        match distinct {
            Distinct::Distinct => Ok(()),
            Distinct::On(_) => bail!(ValidationError::UnsupportedFeature("DISTINCT ON".into())),
        }
    }

    fn pre_offset(&mut self, offset: &mut Offset) -> Result<()> {
        match offset.rows {
            OffsetRows::None => Ok(()),
            OffsetRows::Row | OffsetRows::Rows => {
                bail!(ValidationError::UnsupportedFeature(offset.to_string()))
            }
        }
    }

    fn pre_select(&mut self, s: &mut Select) -> Result<()> {
        ensure!(
            s.top.is_none(),
            ValidationError::NonStandardSql("TOP".into())
        );
        ensure!(
            s.into.is_none(),
            ValidationError::UnsupportedFeature("SELECT ... INTO not supported".into())
        );
        ensure!(
            s.lateral_views.is_empty(),
            ValidationError::UnsupportedFeature("LATERAL VIEW".into())
        );
        match &s.group_by {
            GroupByExpr::All(_) => bail!(ValidationError::NonStandardSql(s.group_by.to_string())),
            GroupByExpr::Expressions(es, _) => ensure!(
                es.is_empty(),
                ValidationError::UnsupportedFeature("GROUP BY".into())
            ),
        };
        ensure!(
            s.cluster_by.is_empty(),
            ValidationError::UnsupportedFeature("CLUSTER BY".into())
        );
        ensure!(
            s.distribute_by.is_empty(),
            ValidationError::NonStandardSql("DISTRIBUTE BY".into())
        );
        ensure!(
            s.named_window.is_empty(),
            ValidationError::UnsupportedFeature("windows".into())
        );
        ensure!(
            s.qualify.is_none(),
            ValidationError::UnsupportedFeature("QUALIFY".into())
        );
        ensure!(
            s.value_table_mode.is_none(),
            ValidationError::NonStandardSql(s.value_table_mode.unwrap().to_string())
        );
        ensure!(
            s.connect_by.is_none(),
            ValidationError::NonStandardSql("STARTING WITH ... CONNECT BY".into())
        );
        Ok(())
    }

    fn pre_set_expr(&mut self, s: &mut SetExpr) -> Result<()> {
        match s {
            SetExpr::Select(_) => Ok(()),
            SetExpr::Query(_) => {
                bail!(ValidationError::NestedSelect(s.to_string()))
            }
            SetExpr::SetOperation { .. } => bail!(ValidationError::SetOperation(s.to_string())),
            SetExpr::Values(_) | SetExpr::Insert(_) | SetExpr::Update(_) | SetExpr::Table(_) => {
                bail!(ValidationError::MutableQueries(s.to_string()))
            }
        }
    }

    fn pre_order_by(&mut self, o: &mut OrderBy) -> Result<()> {
        ensure!(
            o.exprs.len() <= 2,
            ValidationError::OrderByArity(format!("{o:?}"), 2)
        );
        ensure!(
            o.interpolate.is_none(),
            ValidationError::NonStandardSql(format!("{:?}", o.interpolate.as_ref().unwrap()))
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
        ensure!(
            q.with.is_none(),
            ValidationError::UnsupportedFeature("CTEs".into())
        );
        ensure!(
            q.limit_by.is_empty(),
            ValidationError::UnsupportedFeature("LIMIT BY".into())
        );
        ensure!(
            q.locks.is_empty(),
            ValidationError::UnsupportedFeature("locks".into())
        );
        ensure!(
            q.for_clause.is_none(),
            ValidationError::NonStandardSql("FOR".into())
        );
        ensure!(
            q.fetch.is_none(),
            ValidationError::NonStandardSql("FETCH".into())
        );
        Ok(())
    }
}
/// Instantiate a new [`Validator`] and validate this query with it.
pub fn validate<C: ContextProvider>(settings: &ParsilSettings<C>, query: &mut Query) -> Result<()> {
    if let SetExpr::Select(ref mut select) = *query.body {
        ensure!(
            select.projection.iter().all(|s| matches!(
                s,
                SelectItem::UnnamedExpr(Expr::Function(_))
                    | SelectItem::ExprWithAlias {
                        expr: Expr::Function(_),
                        ..
                    }
            )),
            ValidationError::TabularQuery,
        );
    } else {
        bail!(ValidationError::NotASelect)
    }

    let mut validator = SqlValidator { settings };
    query.visit(&mut validator)
}
