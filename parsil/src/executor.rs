//! The executor module converts a SQL query as provided by the user targeting a
//! virtual contract-storage table into a query executable against the ryhope
//! row tree tables.
use alloy::primitives::U256;
use anyhow::*;
use ryhope::{
    mapper_table_name, EPOCH, INCREMENTAL_EPOCH, KEY, PAYLOAD, USER_EPOCH, VALID_FROM, VALID_UNTIL,
};
use sqlparser::ast::{
    BinaryOperator, CastKind, DataType, Distinct, ExactNumberInfo, Expr, Function, FunctionArg,
    FunctionArgExpr, FunctionArgumentList, FunctionArguments, GroupByExpr, Ident, Join,
    JoinConstraint, JoinOperator, ObjectName, Query, Select, SelectItem, SetExpr, TableAlias,
    TableFactor, TableWithJoins, Value,
};
use std::collections::HashMap;
use verifiable_db::query::{
    computational_hash_ids::PlaceholderIdentifier,
    universal_circuit::universal_circuit_inputs::Placeholders,
};

use crate::{
    placeholders,
    symbols::{ColumnKind, ContextProvider, ZkTable},
    utils::str_to_u256,
    visitor::{AstMutator, VisitMut},
    ParsilSettings,
};

/// Safely wraps a [`Query`], ensuring its meaning and the status of its
/// placeholders.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SafeQuery {
    /// A query featuring placeholders as defined in a [`PlaceholderRegister`]
    ZkQuery(Query),
    /// A query featuring placeholders acceptable for PgSQL (i.e. only numeric
    /// ones)
    PgSqlQuery(Query),
    /// A query where all the placeholders have been replaced by their numeric
    /// values, as defined in a [`Placeholders`] structure.
    InterpolatedQuery(Query),
}
impl SafeQuery {
    /// Convert a safe query into a string ready to be executed by PgSQL.
    ///
    /// Panic if the query is not executable by PgSQL, i.e. if its
    /// zkPlaceholders have not been converted into a format usable by PgSQL.
    pub fn to_pgsql_string_with_placeholder(&self) -> String {
        match self {
            SafeQuery::ZkQuery(_) => panic!("ZkQuery can not be transmitted to PgSQL"),
            SafeQuery::PgSqlQuery(q) => q.to_string(),
            SafeQuery::InterpolatedQuery(_) => {
                panic!("Interpolated query can not be used in PgSQL with placeholders")
            }
        }
    }

    pub fn to_pgsql_string_no_placeholders(&self) -> String {
        match self {
            SafeQuery::ZkQuery(_) => panic!("ZkQuery can not be transmitted to PgSQL"),
            SafeQuery::PgSqlQuery(_) => {
                panic!("Query with placeholders can not be used in PgSQL without placeholders")
            }
            SafeQuery::InterpolatedQuery(q) => q.to_string(),
        }
    }

    /// Convert a safe query into a string.
    pub fn to_display(&self) -> String {
        match self {
            SafeQuery::ZkQuery(q) | SafeQuery::PgSqlQuery(q) | SafeQuery::InterpolatedQuery(q) => {
                q.to_string()
            }
        }
    }
}
impl AsRef<Query> for SafeQuery {
    fn as_ref(&self) -> &Query {
        match self {
            SafeQuery::ZkQuery(q) | SafeQuery::PgSqlQuery(q) | SafeQuery::InterpolatedQuery(q) => q,
        }
    }
}
impl AsMut<Query> for SafeQuery {
    fn as_mut(&mut self) -> &mut Query {
        match self {
            SafeQuery::ZkQuery(q) | SafeQuery::PgSqlQuery(q) | SafeQuery::InterpolatedQuery(q) => q,
        }
    }
}

/// A data structure wrapping a zkSQL query converted into a pgSQL able to be
/// executed on zkTables and its accompanying metadata.
#[derive(Debug, Clone)]
pub struct TranslatedQuery {
    /// The translated query, should be converted to string
    pub query: SafeQuery,
    /// Where each placeholder from the zkSQL query should be put in the array
    /// of PgSQL placeholder.
    pub placeholder_mapping: HashMap<PlaceholderIdentifier, usize>,
    /// A mapping from the named placeholders as defined in the settings to the
    /// string representation of numeric placeholders (e.g. from `$MIN_BLOCK` to
    /// `$4`).
    pub placeholder_name_mapping: HashMap<String, String>,
}
impl TranslatedQuery {
    pub fn make<C: ContextProvider>(
        mut query: SafeQuery,
        settings: &ParsilSettings<C>,
    ) -> Result<Self> {
        let used_placeholders = placeholders::gather_placeholders(settings, query.as_mut())?;
        let placeholder_mapping = std::iter::once(PlaceholderIdentifier::MinQueryOnIdx1)
            .chain(std::iter::once(PlaceholderIdentifier::MaxQueryOnIdx1))
            .chain(
                used_placeholders
                    .iter()
                    .map(|i| PlaceholderIdentifier::Generic(*i)),
            )
            .enumerate()
            .map(|(i, p)| (p, i))
            .collect();

        let placeholder_name_mapping =
            std::iter::once(settings.placeholders.min_block_placeholder.clone())
                .chain(std::iter::once(
                    settings.placeholders.max_block_placeholder.clone(),
                ))
                .chain(used_placeholders.iter().map(|i| format!("${i}")))
                .enumerate()
                .map(|(i, p)| (p, format!("${}", i + 1)))
                .collect();

        Ok(Self {
            query,
            placeholder_mapping,
            placeholder_name_mapping,
        })
    }

    /// Combine the encapsulated query and placeholder mappings to generate a
    /// SQL query with name placeholders replaced with the corresponding numeric
    /// placeholders.
    pub fn normalize_placeholder_names(&mut self) -> SafeQuery {
        assert!(matches!(self.query, SafeQuery::ZkQuery(_)));
        let mut r = self.query.as_ref().to_owned();
        r.visit_mut(self).unwrap();
        SafeQuery::PgSqlQuery(r)
    }

    /// How many PgSQL placeholders should be allocated
    pub fn placeholder_count(&self) -> usize {
        self.placeholder_mapping.len()
    }

    /// From the [`Placeholders`] generated for the circuit public inputs,
    /// generate a list of placeholders that can be used in a PgSQL query.
    pub fn convert_placeholders(&self, placeholders: &Placeholders) -> Vec<U256> {
        let mut r = vec![U256::default(); self.placeholder_mapping.len()];
        for (placeholder_id, positions) in self.placeholder_mapping.iter() {
            r[*positions] = placeholders.0[placeholder_id];
        }
        r
    }

    /// Replace the placeholders met in the query by the values they should
    /// take, as defined in the given [`Placeholder`].
    pub fn interpolate<C: ContextProvider>(
        &mut self,
        settings: &ParsilSettings<C>,
        placeholders: &Placeholders,
    ) -> Result<SafeQuery> {
        assert!(matches!(self.query, SafeQuery::ZkQuery(_)));
        let mut r = self.query.as_ref().to_owned();
        let mut interpolator = PlaceholderInterpolator {
            settings,
            placeholders,
        };
        r.visit_mut(&mut interpolator)?;
        Ok(SafeQuery::InterpolatedQuery(r))
    }
}

impl AstMutator for TranslatedQuery {
    type Error = anyhow::Error;
    fn post_expr(&mut self, expr: &mut Expr) -> Result<()> {
        if let Expr::Value(Value::Placeholder(name)) = expr {
            *name = self.placeholder_name_mapping[name].to_string();
        }
        Ok(())
    }
}

struct PlaceholderInterpolator<'a, C: ContextProvider> {
    settings: &'a ParsilSettings<C>,
    placeholders: &'a Placeholders,
}
impl<C: ContextProvider> AstMutator for PlaceholderInterpolator<'_, C> {
    type Error = anyhow::Error;

    fn post_expr(&mut self, expr: &mut Expr) -> Result<()> {
        if let Some(replacement) = if let Expr::Value(Value::Placeholder(name)) = expr {
            let value = self
                .placeholders
                .get(&self.settings.placeholders.resolve_placeholder(name)?)?;
            Some(Expr::Cast {
                kind: CastKind::DoubleColon,
                expr: Box::new(Expr::Value(Value::SingleQuotedString(format!("{value}")))),
                data_type: UINT256,
                format: None,
            })
        } else {
            None
        } {
            *expr = replacement;
        }

        Ok(())
    }
}

/// The SQL datatype to represent a UINT256
const UINT256: DataType = DataType::Numeric(ExactNumberInfo::None);

/// Generate an [`Expr`] encoding a call to the given function with the given
/// arguments.
fn funcall(fname: &str, args: Vec<Expr>) -> Expr {
    Expr::Function(Function {
        name: ObjectName(vec![Ident::new(fname)]),
        parameters: FunctionArguments::None,
        args: FunctionArguments::List(FunctionArgumentList {
            duplicate_treatment: None,
            args: args
                .into_iter()
                .map(|arg| FunctionArg::Unnamed(FunctionArgExpr::Expr(arg)))
                .collect(),
            clauses: vec![],
        }),
        filter: None,
        null_treatment: None,
        over: None,
        within_group: vec![],
    })
}

/// If the given expression is a string-encoded value, it is casted to a NUMERIC
/// in place.
pub fn convert_number_string(expr: &mut Expr) -> Result<()> {
    if let Some(replacement) = match expr {
        Expr::Value(v) => match v {
            Value::Number(_, _) => None,
            Value::SingleQuotedString(s) => Expr::Cast {
                kind: CastKind::DoubleColon,
                expr: Box::new(Expr::Value(Value::SingleQuotedString(format!(
                    "{}",
                    str_to_u256(s)?
                )))),
                data_type: UINT256,
                format: None,
            }
            .into(),
            _ => None,
        },
        _ => None,
    } {
        *expr = replacement;
    }
    Ok(())
}

/// When a function that may return a float is encountered, (i.e., AVG), it is replaced
/// with a call to integer division DIV.
fn convert_funcalls(expr: &mut Expr) -> Result<()> {
    if let Some(replacement) = match expr {
        Expr::Function(Function { name, .. }) => match name.to_string().to_uppercase().as_str() {
            "AVG" => {
                // Replace AVG(expr) with DIV(SUM(expr)/COUNT(expr))
                // replace AVG in `expr` with `SUM`
                let mut sum_expr = expr.clone();
                if let Expr::Function(Function { name, .. }) = &mut sum_expr {
                    *name = ObjectName(vec![Ident::from("SUM")]);
                }
                // replace AVG in `expr` with `COUNT`
                let mut count_expr = expr.clone();
                if let Expr::Function(Function { name, .. }) = &mut count_expr {
                    *name = ObjectName(vec![Ident::from("COUNT")]);
                }
                // Add DIV operation
                funcall("DIV", vec![sum_expr, count_expr]).into()
            }
            _ => None,
        },
        _ => None,
    } {
        *expr = replacement;
    }

    Ok(())
}

/// Build the subquery that will be used as the source of epochs and block numbers
/// in the internal queries  generated by the executor visitors implemented in this module.
/// More specifically, this method builds the following JOIN table:
/// {table} JOIN (
///      SELECT {USER_EPOCH}, {INCREMENTAL_EPOCH} FROM {mapper_table}
///      WHERE {USER_EPOCH} >= $min_block AND {USER_EPOCH} <= $max_block
/// ) ON {VALID_FROM} <= {INCREMENTAL_EPOCH} AND {VALID_UNTIL} >= {INCREMENTAL_EPOCH}
fn executor_range_table<C: ContextProvider>(
    settings: &ParsilSettings<C>,
    table: &ZkTable,
) -> TableWithJoins {
    let mapper_table_name = mapper_table_name(&table.zktable_name);
    TableWithJoins {
        relation: TableFactor::Table {
            name: ObjectName(vec![Ident::new(table.zktable_name.clone())]),
            alias: None,
            args: None,
            with_hints: vec![],
            version: None,
            with_ordinality: false,
            partitions: vec![],
        },
        joins: vec![Join {
            relation: TableFactor::Derived {
                lateral: false,
                subquery: Box::new(Query {
                    with: None,
                    body: Box::new(SetExpr::Select(Box::new(Select {
                        distinct: None,
                        top: None,
                        projection: vec![
                            SelectItem::UnnamedExpr(Expr::Identifier(Ident::new(USER_EPOCH))),
                            SelectItem::UnnamedExpr(Expr::Identifier(Ident::new(
                                INCREMENTAL_EPOCH,
                            ))),
                        ],
                        into: None,
                        from: vec![TableWithJoins {
                            relation: TableFactor::Table {
                                name: ObjectName(vec![Ident::new(mapper_table_name)]),
                                alias: None,
                                args: None,
                                with_hints: vec![],
                                version: None,
                                with_ordinality: false,
                                partitions: vec![],
                            },
                            joins: vec![],
                        }],
                        lateral_views: vec![],
                        prewhere: None,
                        selection: Some(Expr::BinaryOp {
                            left: Box::new(Expr::BinaryOp {
                                left: Box::new(Expr::Identifier(Ident::new(USER_EPOCH))),
                                op: BinaryOperator::GtEq,
                                right: Box::new(Expr::Value(Value::Placeholder(
                                    settings.placeholders.min_block_placeholder.to_owned(),
                                ))),
                            }),
                            op: BinaryOperator::And,
                            right: Box::new(Expr::BinaryOp {
                                left: Box::new(Expr::Identifier(Ident::new(USER_EPOCH))),
                                op: BinaryOperator::LtEq,
                                right: Box::new(Expr::Value(Value::Placeholder(
                                    settings.placeholders.max_block_placeholder.to_owned(),
                                ))),
                            }),
                        }),
                        group_by: GroupByExpr::Expressions(vec![], vec![]),
                        cluster_by: vec![],
                        distribute_by: vec![],
                        sort_by: vec![],
                        having: None,
                        named_window: vec![],
                        qualify: None,
                        window_before_qualify: false,
                        value_table_mode: None,
                        connect_by: None,
                    }))),
                    order_by: None,
                    limit: None,
                    limit_by: vec![],
                    offset: None,
                    fetch: None,
                    locks: vec![],
                    for_clause: None,
                    settings: None,
                    format_clause: None,
                }),
                // Subqueries *MUST* have an alias in PgSQL
                alias: Some(TableAlias {
                    name: Ident::new("_mapper"),
                    columns: vec![],
                }),
            },
            join_operator: JoinOperator::Inner(JoinConstraint::On(Expr::BinaryOp {
                left: Box::new(Expr::BinaryOp {
                    left: Box::new(Expr::Identifier(Ident::new(VALID_FROM))),
                    op: BinaryOperator::LtEq,
                    right: Box::new(Expr::Identifier(Ident::new(INCREMENTAL_EPOCH))),
                }),
                op: BinaryOperator::And,
                right: Box::new(Expr::BinaryOp {
                    left: Box::new(Expr::Identifier(Ident::new(VALID_UNTIL))),
                    op: BinaryOperator::GtEq,
                    right: Box::new(Expr::Identifier(Ident::new(INCREMENTAL_EPOCH))),
                }),
            })),
        }],
    }
}

/// Generate an [`Expr`] encoding for `PAYLOAD -> cells -> '{id}' -> value
fn fetch_from_payload(id: u64) -> Expr {
    Expr::Cast {
        kind: CastKind::DoubleColon,
        expr: Box::new(Expr::Nested(Box::new(Expr::BinaryOp {
            left: Box::new(Expr::Identifier(Ident::new(PAYLOAD))),
            op: BinaryOperator::Arrow,
            right: Box::new(Expr::BinaryOp {
                left: Box::new(Expr::Value(Value::SingleQuotedString("cells".into()))),
                op: BinaryOperator::Arrow,
                right: Box::new(Expr::BinaryOp {
                    left: Box::new(Expr::Value(Value::SingleQuotedString(id.to_string()))),
                    op: BinaryOperator::LongArrow,
                    right: Box::new(Expr::Value(Value::SingleQuotedString("value".into()))),
                }),
            }),
        }))),
        data_type: UINT256,
        format: None,
    }
}

/// The `KeyFetcher` gathers all `(row_key, epoch)` pairs generated by a
/// query, used then to generate the values public inputs for the query
/// circuits.
struct KeyFetcher<'a, C: ContextProvider> {
    settings: &'a ParsilSettings<C>,
}
impl<'a, C: ContextProvider> KeyFetcher<'a, C> {
    fn new(settings: &'a ParsilSettings<C>) -> Result<Self> {
        Ok(Self { settings })
    }

    fn process(&mut self, query: &mut Query) -> Result<()> {
        query.visit_mut(self)?;

        let r = Query {
            with: None,
            body: Box::new(SetExpr::Select(Box::new(Select {
                distinct: None,
                top: None,
                projection: vec![
                    SelectItem::UnnamedExpr(Expr::Identifier(Ident::new(KEY))),
                    SelectItem::UnnamedExpr(Expr::Identifier(Ident::new(EPOCH))),
                ],
                into: None,
                from: vec![TableWithJoins {
                    relation: TableFactor::Derived {
                        lateral: false,
                        subquery: Box::new(query.clone()),
                        alias: Some(TableAlias {
                            name: Ident::new("__inner"),
                            columns: vec![],
                        }),
                    },
                    joins: vec![],
                }],
                lateral_views: vec![],
                prewhere: None,
                selection: None,
                group_by: GroupByExpr::Expressions(vec![], vec![]),
                cluster_by: vec![],
                distribute_by: vec![],
                sort_by: vec![],
                having: None,
                named_window: vec![],
                qualify: None,
                window_before_qualify: false,
                value_table_mode: None,
                connect_by: None,
            }))),
            order_by: None,
            limit: None,
            limit_by: vec![],
            offset: None,
            fetch: None,
            locks: vec![],
            for_clause: None,
            settings: None,
            format_clause: None,
        };

        *query = r;

        Ok(())
    }

    const MIN_EPOCH_ALIAS: &'static str = "min_epoch";
    const MAX_EPOCH_ALIAS: &'static str = "max_epoch";

    fn expand_block_range() -> Expr {
        funcall(
            "generate_series",
            vec![
                funcall(
                    "GREATEST",
                    vec![
                        Expr::Identifier(Ident::new(VALID_FROM)),
                        Expr::Identifier(Ident::new(Self::MIN_EPOCH_ALIAS)),
                    ],
                ),
                funcall(
                    "LEAST",
                    vec![
                        Expr::Identifier(Ident::new(VALID_UNTIL)),
                        Expr::Identifier(Ident::new(Self::MAX_EPOCH_ALIAS)),
                    ],
                ),
            ],
        )
    }

    // Build the subquery that will be used as the source of epochs and block numbers
    // in the internal queries  generated by the executor visitors implemented in this module.
    // More specifically, this method builds the following JOIN table:
    // {table} JOIN (
    //      SELECT MIN{INCREMENTAL_EPOCH} as {MIN_EPOCH_ALIAS}, MAX{INCREMENTAL_EPOCH} as {MAX_EPOCH_ALIAS}
    //      FROM {mapper_table}
    //      WHERE {USER_EPOCH} >= $min_block AND {USER_EPOCH} <= $max_block
    // ) ON {VALID_FROM} <= {MAX_EPOCH_ALIAS} AND {VALID_UNTIL} >= {MIN_EPOCH_ALIAS}
    fn range_table(&self, table: &ZkTable) -> TableWithJoins {
        let mapper_table_name = mapper_table_name(&table.zktable_name);
        TableWithJoins {
            relation: TableFactor::Table {
                name: ObjectName(vec![Ident::new(table.zktable_name.clone())]),
                alias: None,
                args: None,
                with_hints: vec![],
                version: None,
                with_ordinality: false,
                partitions: vec![],
            },
            joins: vec![Join {
                relation: TableFactor::Derived {
                    lateral: false,
                    subquery: Box::new(Query {
                        with: None,
                        body: Box::new(SetExpr::Select(Box::new(Select {
                            distinct: None,
                            top: None,
                            projection: vec![
                                SelectItem::ExprWithAlias {
                                    expr: funcall(
                                        "MIN",
                                        vec![Expr::Identifier(Ident::new(INCREMENTAL_EPOCH))],
                                    ),
                                    alias: Ident::new(Self::MIN_EPOCH_ALIAS),
                                },
                                SelectItem::ExprWithAlias {
                                    expr: funcall(
                                        "MAX",
                                        vec![Expr::Identifier(Ident::new(INCREMENTAL_EPOCH))],
                                    ),
                                    alias: Ident::new(Self::MAX_EPOCH_ALIAS),
                                },
                            ],
                            into: None,
                            from: vec![TableWithJoins {
                                relation: TableFactor::Table {
                                    name: ObjectName(vec![Ident::new(mapper_table_name)]),
                                    alias: None,
                                    args: None,
                                    with_hints: vec![],
                                    version: None,
                                    with_ordinality: false,
                                    partitions: vec![],
                                },
                                joins: vec![],
                            }],
                            lateral_views: vec![],
                            prewhere: None,
                            selection: Some(Expr::BinaryOp {
                                left: Box::new(Expr::BinaryOp {
                                    left: Box::new(Expr::Identifier(Ident::new(USER_EPOCH))),
                                    op: BinaryOperator::GtEq,
                                    right: Box::new(Expr::Value(Value::Placeholder(
                                        self.settings.placeholders.min_block_placeholder.to_owned(),
                                    ))),
                                }),
                                op: BinaryOperator::And,
                                right: Box::new(Expr::BinaryOp {
                                    left: Box::new(Expr::Identifier(Ident::new(USER_EPOCH))),
                                    op: BinaryOperator::LtEq,
                                    right: Box::new(Expr::Value(Value::Placeholder(
                                        self.settings.placeholders.max_block_placeholder.to_owned(),
                                    ))),
                                }),
                            }),
                            group_by: GroupByExpr::Expressions(vec![], vec![]),
                            cluster_by: vec![],
                            distribute_by: vec![],
                            sort_by: vec![],
                            having: None,
                            named_window: vec![],
                            qualify: None,
                            window_before_qualify: false,
                            value_table_mode: None,
                            connect_by: None,
                        }))),
                        order_by: None,
                        limit: None,
                        limit_by: vec![],
                        offset: None,
                        fetch: None,
                        locks: vec![],
                        for_clause: None,
                        settings: None,
                        format_clause: None,
                    }),
                    // Subqueries *MUST* have an alias in PgSQL
                    alias: Some(TableAlias {
                        name: Ident::new("_mapper"),
                        columns: vec![],
                    }),
                },
                join_operator: JoinOperator::Inner(JoinConstraint::On(Expr::BinaryOp {
                    left: Box::new(Expr::BinaryOp {
                        left: Box::new(Expr::Identifier(Ident::new(VALID_FROM))),
                        op: BinaryOperator::LtEq,
                        right: Box::new(Expr::Identifier(Ident::new(Self::MAX_EPOCH_ALIAS))),
                    }),
                    op: BinaryOperator::And,
                    right: Box::new(Expr::BinaryOp {
                        left: Box::new(Expr::Identifier(Ident::new(VALID_UNTIL))),
                        op: BinaryOperator::GtEq,
                        right: Box::new(Expr::Identifier(Ident::new(Self::MIN_EPOCH_ALIAS))),
                    }),
                })),
            }],
        }
    }
}
impl<C: ContextProvider> AstMutator for KeyFetcher<'_, C> {
    type Error = anyhow::Error;

    fn post_select(&mut self, select: &mut Select) -> Result<()> {
        // When we meet a SELECT, insert a * to be sure to bubble up the key &
        // block number
        select.projection = vec![
            SelectItem::UnnamedExpr(Expr::Identifier(Ident::new(KEY))),
            SelectItem::UnnamedExpr(Expr::Identifier(Ident::new(EPOCH))),
        ];
        Ok(())
    }

    fn post_expr(&mut self, expr: &mut Expr) -> Result<()> {
        convert_number_string(expr)?;

        Ok(())
    }

    fn post_table_factor(&mut self, table_factor: &mut TableFactor) -> Result<()> {
        if let Some(replacement) = match table_factor {
            TableFactor::Table { name, alias, .. } => {
                // The vTable being referenced
                let user_facing_name = &name.0[0].value;

                // Fetch all the column declared in this table
                let table = self.settings.context.fetch_table(user_facing_name)?;
                let table_columns = &table.columns;

                // Extract the apparent table name (either the concrete one
                // or its alia), and, if they exist, the aliased column
                // names.
                let (apparent_table_name, column_aliases) = if let Some(table_alias) = alias {
                    (
                        table_alias.name.value.to_owned(),
                        if table_alias.columns.is_empty() {
                            None
                        } else {
                            table_alias.columns.clone().into()
                        },
                    )
                } else {
                    (user_facing_name.to_owned(), None)
                };

                let select_items =
                    // Insert the `key` column in the selected values...
                    std::iter::once(SelectItem::UnnamedExpr(Expr::Identifier(Ident::new(KEY))))
                    .chain(std::iter::once(
                        SelectItem::ExprWithAlias {
                            expr: Self::expand_block_range(),
                            alias: Ident::new(EPOCH)
                        }
                    ))
                    // then continue normally
                        .chain(table_columns.iter().enumerate().map(|(i, column)| {
                            let alias = Ident::new(
                                column_aliases
                                    .as_ref()
                                    .map(|a| a[i].value.as_str())
                                    .unwrap_or(column.name.as_str()),
                            );
                            match column.kind {
                                // primary index column := $MIN_BLOCK AS name. 
                                // We return a constant value as a trick to avoid extracting USER_EPOCH from
                                // epoch mapper table, which would require a costly JOIN. 
                                // Indeed, given that: 
                                // - The filtering over the primary index have already been applied in 
                                //   the epoch mapper table
                                // - This column is later ignored in the overall query 
                                // We just need to provide as block_number a column value that satisfies the 
                                // filtering over the primary index specified in the existing query,
                                // which is `block_number >= $MIN_BLOCK AND block_number <= $MAX_BLOCK`, as
                                // any other predicate is removed from the query by the isolator
                                // ToDo: remove this column once we merge the new version of the isolator,
                                // which will remove the block_number range filtering
                                ColumnKind::PrimaryIndex => SelectItem::ExprWithAlias {
                                    expr: Expr::Value(Value::Placeholder(
                                        self.settings.placeholders.min_block_placeholder.to_owned(),
                                    )),
                                    alias,
                                },
                                // other columns := payload->'cells'->'id'->'value' AS name
                                ColumnKind::SecondaryIndex | ColumnKind::Standard => {
                                    SelectItem::ExprWithAlias {
                                        expr: fetch_from_payload(column.id),
                                        alias,
                                    }
                                }
                            }
                        }))
                        .collect();

                TableFactor::Derived {
                    lateral: false,
                    subquery: Box::new(Query {
                        with: None,
                        body: Box::new(SetExpr::Select(Box::new(Select {
                            distinct: None,
                            top: None,
                            projection: select_items,
                            into: None,
                            from: vec![self.range_table(&table)],
                            lateral_views: vec![],
                            prewhere: None,
                            selection: None,
                            group_by: GroupByExpr::Expressions(vec![], vec![]),
                            cluster_by: vec![],
                            distribute_by: vec![],
                            sort_by: vec![],
                            having: None,
                            named_window: vec![],
                            qualify: None,
                            window_before_qualify: false,
                            value_table_mode: None,
                            connect_by: None,
                        }))),
                        order_by: None,
                        limit: None,
                        limit_by: vec![],
                        offset: None,
                        fetch: None,
                        locks: vec![],
                        for_clause: None,
                        settings: None,
                        format_clause: None,
                    }),
                    // Subqueries *MUST* have an alias in PgSQL
                    alias: Some(TableAlias {
                        name: Ident::new(apparent_table_name),
                        columns: vec![],
                    }),
                }
                .into()
            }
            _ => None,
        } {
            *table_factor = replacement;
        }
        Ok(())
    }
}

/// Implementation of `post_table_factor` shared both by `Executor` and by
/// `ExecutorWithKey`. If the flag `return_keys` is true, `key` and `epoch`
/// columns are returned as well as `SELECT` items in the constructed sub-query,
/// as required in the `ExecutorWithKey` implementation of `post_table_factor`
fn post_table_factor<C: ContextProvider>(
    settings: &ParsilSettings<C>,
    table_factor: &mut TableFactor,
    return_keys: bool,
) -> Result<()> {
    if let Some(replacement) = match &table_factor {
        TableFactor::Table {
            name, alias, args, ..
        } => {
            // In this case, we handle
            //
            // ... FROM table [AS alias [(col1, // col2, ...)]]
            //
            // so both the table name and its columns may be aliased.
            if args.is_some() {
                unreachable!()
            } else {
                // The actual table being referenced
                let concrete_table_name = &name.0[0].value;

                // Fetch all the column declared in this table
                let table = settings.context.fetch_table(concrete_table_name)?;
                let table_columns = &table.columns;

                // Extract the apparent table name (either the concrete one
                // or its alia), and, if they exist, the aliased column
                // names.
                let (apparent_table_name, column_aliases) = if let Some(table_alias) = alias {
                    (
                        table_alias.name.value.to_owned(),
                        if table_alias.columns.is_empty() {
                            None
                        } else {
                            table_alias.columns.clone().into()
                        },
                    )
                } else {
                    (concrete_table_name.to_owned(), None)
                };

                // Create one `SelectItem` for each column of the table, as they have to be returned
                // in `SELECT` in the constructed sub-query
                let current_columns_select_items =
                    table_columns.iter().enumerate().map(|(i, column)| {
                        let alias = Ident::new(
                            column_aliases
                                .as_ref()
                                .map(|a| a[i].value.as_str())
                                .unwrap_or(column.name.as_str()),
                        );
                        match column.kind {
                            // primary index column := USER_EPOCH AS name
                            ColumnKind::PrimaryIndex => SelectItem::ExprWithAlias {
                                expr: Expr::Identifier(Ident::new(USER_EPOCH)),
                                alias,
                            },
                            // other columns := PAYLOAD->'cells'->'id'->'value' AS name
                            ColumnKind::SecondaryIndex | ColumnKind::Standard => {
                                SelectItem::ExprWithAlias {
                                    expr: fetch_from_payload(column.id),
                                    alias,
                                }
                            }
                        }
                    });

                let select_items = if return_keys {
                    // Insert the `key` and `epoch` columns in the selected values...
                    std::iter::once(SelectItem::UnnamedExpr(Expr::Identifier(Ident::new(KEY))))
                        .chain(std::iter::once(SelectItem::ExprWithAlias {
                            expr: Expr::Identifier(Ident::new(USER_EPOCH)),
                            alias: Ident::new(EPOCH),
                        }))
                        .chain(current_columns_select_items)
                        .collect()
                } else {
                    current_columns_select_items.collect()
                };

                Some(TableFactor::Derived {
                    lateral: false,
                    subquery: Box::new(Query {
                        with: None,
                        body: Box::new(SetExpr::Select(Box::new(Select {
                            distinct: None,
                            top: None,
                            projection: select_items,
                            into: None,
                            from: vec![executor_range_table(settings, &table)],
                            lateral_views: vec![],
                            prewhere: None,
                            selection: None,
                            group_by: GroupByExpr::Expressions(vec![], vec![]),
                            cluster_by: vec![],
                            distribute_by: vec![],
                            sort_by: vec![],
                            having: None,
                            named_window: vec![],
                            qualify: None,
                            window_before_qualify: false,
                            value_table_mode: None,
                            connect_by: None,
                        }))),
                        order_by: None,
                        limit: None,
                        limit_by: vec![],
                        offset: None,
                        fetch: None,
                        locks: vec![],
                        for_clause: None,
                        settings: None,
                        format_clause: None,
                    }),
                    // Subqueries *MUST* have an alias in PgSQL
                    alias: Some(TableAlias {
                        name: Ident::new(apparent_table_name),
                        columns: vec![],
                    }),
                })
            }
        }
        TableFactor::Derived { .. } => None,
        TableFactor::TableFunction { .. } => todo!(),
        TableFactor::Function { .. } => todo!(),
        TableFactor::UNNEST { .. } => todo!(),
        TableFactor::JsonTable { .. } => todo!(),
        TableFactor::NestedJoin { .. } => todo!(),
        TableFactor::Pivot { .. } => todo!(),
        TableFactor::Unpivot { .. } => todo!(),
        TableFactor::MatchRecognize { .. } => todo!(),
    } {
        *table_factor = replacement;
    }

    Ok(())
}

struct Executor<'a, C: ContextProvider> {
    settings: &'a ParsilSettings<C>,
}
impl<'a, C: ContextProvider> Executor<'a, C> {
    fn new(settings: &'a ParsilSettings<C>) -> Result<Self> {
        Ok(Self { settings })
    }
}

impl<C: ContextProvider> AstMutator for Executor<'_, C> {
    type Error = anyhow::Error;

    fn post_expr(&mut self, expr: &mut Expr) -> Result<()> {
        convert_number_string(expr)?;
        convert_funcalls(expr)?;

        Ok(())
    }

    fn post_table_factor(&mut self, table_factor: &mut TableFactor) -> Result<()> {
        post_table_factor(self.settings, table_factor, false)
    }
}

/// Executor to prepare a query that returns both the results of a user query
/// and the matching rows, each identified by the pair (row_key, epoch)
struct ExecutorWithKey<'a, C: ContextProvider> {
    settings: &'a ParsilSettings<C>,
}

impl<'a, C: ContextProvider> ExecutorWithKey<'a, C> {
    fn new(settings: &'a ParsilSettings<C>) -> Self {
        Self { settings }
    }
}

impl<C: ContextProvider> AstMutator for ExecutorWithKey<'_, C> {
    type Error = anyhow::Error;

    fn post_expr(&mut self, expr: &mut Expr) -> Result<()> {
        let mut executor = Executor {
            settings: self.settings,
        };
        executor.post_expr(expr)
    }

    fn post_table_factor(&mut self, table_factor: &mut TableFactor) -> Result<()> {
        post_table_factor(self.settings, table_factor, true)
    }

    fn post_select(&mut self, select: &mut Select) -> Result<()> {
        let replace_wildcard = || {
            // we expand the Wildcard by replacing it will all the columns of the original table
            assert_eq!(select.from.len(), 1); // single table queries
            let table = &select.from.first().unwrap().relation;
            match table {
                TableFactor::Derived { subquery, .. } => {
                    subquery
                        .as_ref()
                        .body
                        .as_ref()
                        .as_select()
                        .unwrap()
                        .projection
                        .iter()
                        .filter_map(|item| {
                            let expr = match item {
                                SelectItem::ExprWithAlias { alias, .. } => {
                                    Expr::Identifier(alias.clone())
                                }
                                SelectItem::UnnamedExpr(expr) => expr.clone(),
                                _ => unreachable!(),
                            };
                            // we need to filter out KEY and EPOCH from the columns expanded by the Wildcard,
                            // as these ones are the columns over which we need to apply DISTINCT
                            match &expr {
                                Expr::Identifier(ident)
                                    if ident.value == EPOCH || ident.value == KEY =>
                                {
                                    None
                                }
                                _ => Some(expr),
                            }
                        })
                        .collect::<Vec<_>>()
                }
                _ => unreachable!(), // post_table_factor makes `TableFactor::Derived`
            }
        };
        // need to:
        // 1. add KEY and EPOCH to existing `SelectItem`s
        // 2. Ensure that, if there is DISTINCT keyword in the original query,
        //    the original `SelectItem`s are wrapped in `DISTINCT ON`, to
        //    ensure that we return only DISTINCT results
        // first, turn existing `SelectItem`s in a vector of Expressions
        if let Some(distinct) = select.distinct.as_mut() {
            let items = select
                .projection
                .iter()
                .flat_map(|item| {
                    match item {
                        SelectItem::UnnamedExpr(expr) => vec![expr.clone()],
                        SelectItem::ExprWithAlias { expr, .. } => vec![expr.clone()], // we don't care about alias here
                        SelectItem::QualifiedWildcard(_, _) => unreachable!(),
                        SelectItem::Wildcard(_) => replace_wildcard(),
                    }
                })
                .collect::<Vec<_>>();
            *distinct = Distinct::On(items)
        }
        // we add KEY and EPOCH to existing `SelectItem`s
        select.projection = vec![
            SelectItem::UnnamedExpr(Expr::Identifier(Ident::new(KEY))),
            SelectItem::UnnamedExpr(Expr::Identifier(Ident::new(EPOCH))),
        ]
        .into_iter()
        .chain(select.projection.iter().flat_map(|item| {
            match item {
                SelectItem::Wildcard(_) => replace_wildcard()
                    .into_iter()
                    .map(SelectItem::UnnamedExpr)
                    .collect(),
                _ => vec![item.clone()],
            }
        }))
        .collect();

        Ok(())
    }
}

pub fn generate_query_execution<C: ContextProvider>(
    query: &mut Query,
    settings: &ParsilSettings<C>,
) -> Result<TranslatedQuery> {
    let mut executor = Executor::new(settings)?;
    let mut query_execution = query.clone();
    query_execution.visit_mut(&mut executor)?;

    TranslatedQuery::make(SafeQuery::ZkQuery(query_execution), settings)
}

/// Build a statement to be executed in order to fetch the matching rows for
/// a query, each identified by a pair (row_key, epoch), altogether with the
/// results of the query corresponding to each matching row
pub fn generate_query_execution_with_keys<C: ContextProvider>(
    query: &mut Query,
    settings: &ParsilSettings<C>,
) -> Result<TranslatedQuery> {
    let mut executor = ExecutorWithKey::new(settings);
    let mut query_execution = query.clone();
    query_execution.visit_mut(&mut executor)?;

    TranslatedQuery::make(SafeQuery::ZkQuery(query_execution), settings)
}

pub fn generate_query_keys<C: ContextProvider>(
    query: &mut Query,
    settings: &ParsilSettings<C>,
) -> Result<TranslatedQuery> {
    let mut key_fetcher = KeyFetcher::new(settings)?;
    let mut key_query = query.clone();
    key_fetcher.process(&mut key_query)?;

    TranslatedQuery::make(SafeQuery::ZkQuery(key_query), settings)
}
