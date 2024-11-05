use sqlparser::ast::{
    BinaryOperator, Distinct, Expr, FunctionArg, FunctionArgExpr, FunctionArguments, GroupByExpr,
    JoinOperator, Offset, OffsetRows, OrderBy, OrderByExpr, Query, Select, SelectItem, SetExpr,
    TableFactor, UnaryOperator, Value,
};

use crate::{
    errors::ValidationError,
    symbols::ContextProvider,
    utils::{str_to_u256, ParsilSettings},
    visitor::{AstVisitor, Visit},
};

macro_rules! ensure {
    ($cond:expr, $error:expr) => {
        if !$cond {
            return Err($error);
        }
    };
}

/// Ensure that a top-level [`Query`] is compatible with the currently
/// implemented subset of SQL.
pub struct SqlValidator<'a, C: ContextProvider> {
    settings: &'a ParsilSettings<C>,
}
impl<'a, C: ContextProvider> AstVisitor for SqlValidator<'a, C> {
    type Error = ValidationError;

    fn pre_unary_operator(&mut self, unary_operator: &UnaryOperator) -> Result<(), Self::Error> {
        match unary_operator {
            UnaryOperator::Plus | UnaryOperator::Not => Ok(()),
            _ => Err(ValidationError::UnsupportedUnaryOperator(*unary_operator)),
        }
    }

    fn pre_binary_operator(&mut self, op: &BinaryOperator) -> Result<(), ValidationError> {
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

            _ => Err(ValidationError::UnsupportedBinaryOperator(op.clone())),
        }
    }

    fn pre_expr(&mut self, expr: &Expr) -> Result<(), ValidationError> {
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

                if let FunctionArguments::List(arglist) = &funcall.args {
                    ensure!(
                        arglist.args.len() == 1,
                        ValidationError::InvalidArity(
                            funcall.name.to_string(),
                            1,
                            arglist.args.len()
                        )
                    );
                    match &arglist.args[0] {
                        FunctionArg::Unnamed(FunctionArgExpr::Expr(_)) => {}
                        _ => {
                            return Err(ValidationError::InvalidFunctionArgument(
                                arglist.args[0].to_string(),
                            ))
                        }
                    }
                } else {
                    return Err(ValidationError::InvalidFunctionArgument(format!(
                        "{}",
                        funcall.args
                    )));
                }
            }

            Expr::Value(v) => match v {
                Value::Number(_, _) | Value::Boolean(_) => {}
                Value::Placeholder(p) => {
                    self.settings
                        .placeholders
                        .resolve_placeholder(p)
                        .map_err(|_| ValidationError::UnknownPlaceholder(p.to_owned()))?;
                }
                Value::SingleQuotedString(s) => {
                    str_to_u256(s).map_err(|_| ValidationError::InvalidInteger(s.to_owned()))?;
                }
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
                | Value::Null => {
                    return Err(ValidationError::UnsupportedImmediateValue(v.to_string()))
                }
            },
            Expr::Subquery(s) => {
                return Err(ValidationError::NestedSelect(s.to_string()));
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
            | Expr::Map(_) => return Err(ValidationError::UnsupportedFeature(expr.to_string())),
        }
        Ok(())
    }

    fn pre_select_item(&mut self, p: &SelectItem) -> Result<(), ValidationError> {
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
                Err(ValidationError::UnsupportedFeature(p.to_string()))
            }
            _ => Ok(()),
        }
    }

    fn pre_table_factor(&mut self, j: &TableFactor) -> Result<(), ValidationError> {
        match j {
            TableFactor::Table { .. } => Ok(()),
            TableFactor::Derived { .. } => {
                // NOTE: when the time comes, let us be careful of LATERAL joins
                Err(ValidationError::NestedSelect(j.to_string()))
            }
            TableFactor::TableFunction { .. }
            | TableFactor::Function { .. }
            | TableFactor::UNNEST { .. }
            | TableFactor::JsonTable { .. }
            | TableFactor::NestedJoin { .. }
            | TableFactor::Pivot { .. }
            | TableFactor::Unpivot { .. }
            | TableFactor::MatchRecognize { .. } => {
                Err(ValidationError::UnsupportedJointure(format!("{j}:#?")))
            }
        }
    }

    fn pre_join_operator(&mut self, j: &JoinOperator) -> Result<(), ValidationError> {
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
            | JoinOperator::AsOf { .. } => Err(ValidationError::NonStandardSql(format!("{j:#?}"))),
        }
    }

    fn pre_distinct(&mut self, distinct: &Distinct) -> Result<(), ValidationError> {
        match distinct {
            Distinct::Distinct => Ok(()),
            Distinct::On(_) => Err(ValidationError::UnsupportedFeature("DISTINCT ON".into())),
        }
    }

    fn pre_offset(&mut self, offset: &Offset) -> Result<(), ValidationError> {
        match offset.rows {
            OffsetRows::None => Ok(()),
            OffsetRows::Row | OffsetRows::Rows => {
                Err(ValidationError::UnsupportedFeature(offset.to_string()))
            }
        }
    }

    fn pre_select(&mut self, s: &Select) -> Result<(), ValidationError> {
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
            GroupByExpr::All(_) => {
                return Err(ValidationError::NonStandardSql(s.group_by.to_string()))
            }
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

    fn pre_set_expr(&mut self, s: &SetExpr) -> Result<(), ValidationError> {
        match s {
            SetExpr::Select(_) => Ok(()),
            SetExpr::Query(_) => Err(ValidationError::NestedSelect(s.to_string())),
            SetExpr::SetOperation { .. } => Err(ValidationError::SetOperation(s.to_string())),
            SetExpr::Values(_) | SetExpr::Insert(_) | SetExpr::Update(_) | SetExpr::Table(_) => {
                Err(ValidationError::MutableQueries(s.to_string()))
            }
        }
    }

    fn pre_order_by(&mut self, o: &OrderBy) -> Result<(), ValidationError> {
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

    fn pre_order_by_expr(&mut self, o: &OrderByExpr) -> Result<(), ValidationError> {
        ensure!(
            o.nulls_first.is_none(),
            ValidationError::NullRelatedOrdering
        );
        Ok(())
    }

    fn pre_query(&mut self, q: &Query) -> Result<(), ValidationError> {
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
        ensure!(
            q.order_by.is_none(),
            ValidationError::UnsupportedFeature("ORDER BY".into())
        );
        Ok(())
    }
}

// Determine if the query does not aggregate values across different matching rows
pub(crate) fn is_query_with_no_aggregation(select: &Select) -> bool {
    select.projection.iter().all(|s| {
        !matches!(
            s,
            SelectItem::UnnamedExpr(Expr::Function(_))
                | SelectItem::ExprWithAlias {
                    expr: Expr::Function(_),
                    ..
                }
        )
    })
}
// Determine if the query does aggregates values across different matching rows
pub(crate) fn is_query_with_aggregation(select: &Select) -> bool {
    select.projection.iter().all(|s| {
        matches!(
            s,
            SelectItem::UnnamedExpr(Expr::Function(_))
                | SelectItem::ExprWithAlias {
                    expr: Expr::Function(_),
                    ..
                }
        )
    })
}

/// Instantiate a new [`Validator`] and validate this query with it.
pub fn validate<C: ContextProvider>(
    settings: &ParsilSettings<C>,
    query: &Query,
) -> Result<(), ValidationError> {
    if let SetExpr::Select(ref select) = *query.body {
        ensure!(
            is_query_with_aggregation(select) || is_query_with_no_aggregation(select),
            ValidationError::MixedQuery
        );
    } else {
        return Err(ValidationError::NotASelect);
    }

    let mut validator = SqlValidator { settings };
    query.visit(&mut validator)
}
