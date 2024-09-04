//! The executor module converts a SQL query as provided by the user targeting a
//! virtual contract-storage table into a query executable against the ryhope
//! row tree tables.
use alloy::primitives::U256;
use anyhow::*;
use log::*;
use ryhope::{EPOCH, KEY, PAYLOAD, VALID_FROM, VALID_UNTIL};
use sqlparser::ast::{
    BinaryOperator, CastKind, DataType, ExactNumberInfo, Expr, Function, FunctionArg,
    FunctionArgExpr, FunctionArgumentList, FunctionArguments, GroupByExpr, Ident, ObjectName,
    Query, Select, SelectItem, SetExpr, TableAlias, TableFactor, TableWithJoins, Value,
};
use std::collections::HashMap;
use verifiable_db::query::{
    computational_hash_ids::PlaceholderIdentifier,
    universal_circuit::universal_circuit_inputs::{PlaceholderId, Placeholders},
};

use crate::{
    placeholders,
    symbols::{ColumnKind, ContextProvider},
    utils::str_to_u256,
    visitor::{AstPass, Visit},
    ParsilSettings,
};

/// Safely wraps a [`Query`], ensuring its meaning and the status of its
/// placeholders.
#[derive(Debug, PartialEq, Eq)]
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
    pub fn to_pgsql_string(&self) -> String {
        match self {
            SafeQuery::ZkQuery(_) => panic!("ZkQuery can not be transmitted to PgSQL"),
            SafeQuery::PgSqlQuery(q) | SafeQuery::InterpolatedQuery(q) => q.to_string(),
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
#[derive(Debug)]
pub struct TranslatedQuery {
    /// The translated query, should be converted to string
    pub query: SafeQuery,
    /// Where each placeholder from the zkSQL query should be put in the array
    /// of PgSQL placeholder.
    pub placeholder_mapping: HashMap<PlaceholderId, usize>,
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
        let largest_placeholder = placeholders::validate(settings, query.as_mut())?;
        let placeholder_mapping = std::iter::once(PlaceholderId::MinQueryOnIdx1)
            .chain(std::iter::once(PlaceholderIdentifier::MaxQueryOnIdx1))
            .chain((1..=largest_placeholder).map(|i| PlaceholderId::Generic(i)))
            .enumerate()
            .map(|(i, p)| (p, i))
            .collect();

        let placeholder_name_mapping =
            std::iter::once(settings.placeholders.min_block_placeholder.clone())
                .chain(std::iter::once(
                    settings.placeholders.max_block_placeholder.clone(),
                ))
                .chain((1..=largest_placeholder).map(|i| format!("${i}")))
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
        r.visit(self).unwrap();
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
        r.visit(&mut interpolator)?;
        Ok(SafeQuery::InterpolatedQuery(r))
    }
}

impl AstPass for TranslatedQuery {
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
impl<'a, C: ContextProvider> AstPass for PlaceholderInterpolator<'a, C> {
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

/// When a function that may return a float is encountered, it is wrapped in a
/// call to `FLOOR`.
fn convert_funcalls(expr: &mut Expr) -> Result<()> {
    if let Some(replacement) = match expr {
        Expr::Function(Function { name, .. }) => match name.to_string().to_uppercase().as_str() {
            "AVG" => funcall("FLOOR", vec![expr.clone()]).into(),
            _ => None,
        },
        _ => None,
    } {
        *expr = replacement;
    }

    Ok(())
}

fn expand_block_range<C: ContextProvider>(settings: &ParsilSettings<C>) -> Expr {
    funcall(
        "generate_series",
        vec![
            funcall(
                "GREATEST",
                vec![
                    Expr::Identifier(Ident::new(VALID_FROM)),
                    Expr::Value(Value::Placeholder(
                        settings.placeholders.min_block_placeholder.to_owned(),
                    )),
                ],
            ),
            funcall(
                "LEAST",
                vec![
                    Expr::Identifier(Ident::new(VALID_UNTIL)),
                    Expr::Value(Value::Placeholder(
                        settings.placeholders.max_block_placeholder.to_owned(),
                    )),
                ],
            ),
        ],
    )
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
        query.visit(self)?;

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
}
impl<'a, C: ContextProvider> AstPass for KeyFetcher<'a, C> {
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
                // The actual table being referenced
                let concrete_table_name = &name.0[0].value;

                // Fetch all the column declared in this table
                let table = self.settings.context.fetch_table(&concrete_table_name)?;
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

                let select_items =
                    // Insert the `key` column in the selected values...
                    std::iter::once(SelectItem::UnnamedExpr(Expr::Identifier(Ident::new(KEY))))
                    .chain(std::iter::once(
                        SelectItem::ExprWithAlias {
                            expr: expand_block_range(self.settings),
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
                                // primary index column := generate_series(VALID_FROM, VALID_UNTIL) AS name
                                ColumnKind::PrimaryIndex => SelectItem::ExprWithAlias {
                                    expr: expand_block_range(self.settings),
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
                            from: vec![TableWithJoins {
                                relation: TableFactor::Table {
                                    name: ObjectName(vec![Ident::new(concrete_table_name)]),
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

struct Executor<'a, C: ContextProvider> {
    settings: &'a ParsilSettings<C>,
}
impl<'a, C: ContextProvider> Executor<'a, C> {
    fn new(settings: &'a ParsilSettings<C>) -> Result<Self> {
        Ok(Self { settings })
    }
}

impl<'a, C: ContextProvider> AstPass for Executor<'a, C> {
    fn post_expr(&mut self, expr: &mut Expr) -> Result<()> {
        convert_number_string(expr)?;
        convert_funcalls(expr)?;

        Ok(())
    }

    fn post_table_factor(&mut self, table_factor: &mut TableFactor) -> Result<()> {
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
                    let table = self.settings.context.fetch_table(&concrete_table_name)?;
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

                    let select_items = table_columns
                        .iter()
                        .enumerate()
                        .map(|(i, column)| {
                            let alias = Ident::new(
                                column_aliases
                                    .as_ref()
                                    .map(|a| a[i].value.as_str())
                                    .unwrap_or(column.name.as_str()),
                            );
                            match column.kind {
                                // primary index column := generate_series(VALID_FROM, VALID_UNTIL) AS name
                                ColumnKind::PrimaryIndex => SelectItem::ExprWithAlias {
                                    expr: expand_block_range(self.settings),
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
                        })
                        .collect();

                    Some(TableFactor::Derived {
                        lateral: false,
                        subquery: Box::new(Query {
                            with: None,
                            body: Box::new(SetExpr::Select(Box::new(Select {
                                distinct: None,
                                top: None,
                                projection: select_items,
                                into: None,
                                from: vec![TableWithJoins {
                                    relation: TableFactor::Table {
                                        name: ObjectName(vec![Ident::new(concrete_table_name)]),
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
}

pub fn generate_query_execution<C: ContextProvider>(
    query: &mut Query,
    settings: &ParsilSettings<C>,
) -> Result<TranslatedQuery> {
    let mut executor = Executor::new(settings)?;
    let mut query_execution = query.clone();
    query_execution.visit(&mut executor)?;

    TranslatedQuery::make(SafeQuery::ZkQuery(query_execution), settings)
}

pub fn generate_query_keys<C: ContextProvider>(
    query: &mut Query,
    settings: &ParsilSettings<C>,
) -> Result<TranslatedQuery> {
    let mut key_fetcher = KeyFetcher::new(settings)?;
    let mut key_query = query.clone();
    key_fetcher.process(&mut key_query)?;

    info!("PIs: {key_query}");
    TranslatedQuery::make(SafeQuery::ZkQuery(key_query), settings)
}

/// Return two queries, respectively returning the largest sec. ind. value
/// smaller than the given lower bound, and the smallest sec. ind. value larger
/// than the given higher bound.
///
/// If the lower or higher bound are the extrema of the U256 definition domain,
/// the associated query is `None`, reflecting the impossibility for a node
/// satisfying the condition to exist in the database.
pub fn bracket_secondary_index<C: ContextProvider>(
    table_name: &str,
    settings: &ParsilSettings<C>,
    block_number: i64,
    secondary_lo: U256,
    secondary_hi: U256,
) -> (Option<String>, Option<String>) {
    let sec_ind_column = settings
        .context
        .fetch_table(table_name)
        .unwrap()
        .secondary_index_column()
        .id;

    // A simple alias for the sec. ind. values
    let sec_index = format!("({PAYLOAD} -> 'cells' -> '{sec_ind_column}' ->> 'value')::NUMERIC");

    // Select the largest of all the sec. ind. values that remains smaller than
    // the provided sec. ind. lower bound if it is provided, -1 otherwise.
    let largest_below = if secondary_lo == U256::MIN {
        None
    } else {
        Some(format!("SELECT key FROM {table_name}
                           WHERE {sec_index} < '{secondary_lo}'::DECIMAL AND {VALID_FROM} <= {block_number} AND {VALID_UNTIL} >= {block_number}
                           ORDER BY {sec_index} DESC LIMIT 1"))
    };

    // Symmetric situation for the upper bound.
    let smallest_above = if secondary_hi == U256::MAX {
        None
    } else {
        Some(format!("SELECT key FROM {table_name}
                           WHERE {sec_index} > '{secondary_hi}'::DECIMAL AND {VALID_FROM} <= {block_number} AND {VALID_UNTIL} >= {block_number}
                           ORDER BY {sec_index} ASC LIMIT 1"))
    };

    (largest_below, smallest_above)
}
