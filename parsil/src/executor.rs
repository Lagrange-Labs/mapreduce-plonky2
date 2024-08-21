//! The executor module converts a SQL query as provided by the user targeting a
//! virtual contract-storage table into a query executable against the ryhope
//! row tree tables.
use alloy::primitives::U256;
use anyhow::*;
use log::*;
use sqlparser::ast::{
    BinaryOperator, CastKind, DataType, ExactNumberInfo, Expr, Function, FunctionArg,
    FunctionArgExpr, FunctionArgumentList, FunctionArguments, GroupByExpr, Ident, ObjectName,
    Query, Select, SelectItem, SetExpr, TableAlias, TableFactor, TableWithJoins, Value,
    WildcardAdditionalOptions,
};
use std::{collections::HashMap, str::FromStr};
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

/// A data structure wrapping a zkSQL query converted into a pgSQL able to be
/// executed on zkTables and its accompanying metadata.
#[derive(Debug)]
pub struct TranslatedQuery {
    /// The translated query, should be converted to string
    pub query: Query,
    /// Where each placeholder from the zkSQL query should be put in the array
    /// of PgSQL placeholder.
    pub placeholder_mapping: HashMap<PlaceholderId, usize>,
}
impl TranslatedQuery {
    /// How many PgSQL placeholders should be allocated
    pub fn placeholder_count(&self) -> usize {
        self.placeholder_mapping.len()
    }

    /// From the [`Placeholders`] generated for the circuit public inputs,
    /// generate a list of placeholders that can be used in a PgSQL query.
    pub fn convert_placeholders(&self, placeholders: &Placeholders) -> Vec<String> {
        let mut r = vec![String::new(); self.placeholder_count()];
        for (name, value) in placeholders.0.iter() {
            r[self.placeholder_mapping[name]] = format!("'{}'::NUMERIC", value);
        }
        r
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
fn convert_number_string(expr: &mut Expr) -> Result<()> {
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
            "AVG" => funcall("CEIL", vec![expr.clone()]).into(),
            _ => None,
        },
        _ => None,
    } {
        *expr = replacement;
    }

    Ok(())
}

/// Generate an [`Expr`] encoding `generate_series(__valid_from, __valid_until)`
fn expand_block_range() -> Expr {
    funcall(
        "generate_series",
        vec![
            Expr::Identifier(Ident::new("__valid_from")),
            Expr::Identifier(Ident::new("__valid_until")),
        ],
    )
}

/// Generate an [`Expr`] encoding for `payload -> cells -> '{id}' -> value
fn fetch_from_payload(id: u64) -> Expr {
    Expr::Cast {
        kind: CastKind::DoubleColon,
        expr: Box::new(Expr::Nested(Box::new(Expr::BinaryOp {
            left: Box::new(Expr::Identifier(Ident::new("payload"))),
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

/// The `RowFetcher` gathers all `(primary_index, row_key)` pairs generated by a
/// query, used then to generate the values public inputs for the query
/// circuits.
struct RowFetcher<'a, C: ContextProvider> {
    settings: &'a ParsilSettings<C>,
    largest_placeholder: usize,
}
impl<'a, C: ContextProvider> RowFetcher<'a, C> {
    fn new(query: &mut Query, settings: &'a ParsilSettings<C>) -> Result<Self> {
        let largest_placeholder = placeholders::validate(settings, query)?;
        Ok(Self {
            settings,
            largest_placeholder,
        })
    }

    fn process(&mut self, query: &mut Query) -> Result<()> {
        query.visit(self)?;

        if let SetExpr::Select(ref mut select) = *query.body {
            select.projection = vec![
                SelectItem::UnnamedExpr(Expr::Identifier(Ident::new("key"))),
                SelectItem::UnnamedExpr(Expr::Identifier(Ident::new("block"))),
            ];
        }

        Ok(())
    }
}
impl<'a, C: ContextProvider> AstPass for RowFetcher<'a, C> {
    fn post_select(&mut self, select: &mut Select) -> Result<()> {
        // When we meet a SELECT, insert a * to be sure to bubble up the key &
        // block number
        select
            .projection
            .push(SelectItem::Wildcard(WildcardAdditionalOptions {
                opt_ilike: None,
                opt_exclude: None,
                opt_except: None,
                opt_replace: None,
                opt_rename: None,
            }));
        Ok(())
    }

    fn post_expr(&mut self, expr: &mut Expr) -> Result<()> {
        convert_number_string(expr)?;
        convert_funcalls(expr)?;

        if let Expr::Value(Value::Placeholder(ref mut name)) = expr {
            match self.settings.placeholders.resolve_placeholder(name)? {
                PlaceholderIdentifier::MinQueryOnIdx1 => {
                    *name = format!("${}", self.largest_placeholder + 1);
                }
                PlaceholderIdentifier::MaxQueryOnIdx1 => {
                    *name = format!("${}", self.largest_placeholder + 2);
                }
                PlaceholderIdentifier::Generic(_) => {}
            }
        }
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
                    std::iter::once(SelectItem::UnnamedExpr(Expr::Identifier(Ident::new("key"))))
                    .chain(std::iter::once(
                        SelectItem::ExprWithAlias { expr: expand_block_range(), alias: Ident::new("block") }
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
                                // primary index column := generate_series(__valid_from, __valid_until) AS name
                                ColumnKind::PrimaryIndex => SelectItem::ExprWithAlias {
                                    expr: expand_block_range(),
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
    largest_placeholder: usize,
}
impl<'a, C: ContextProvider> Executor<'a, C> {
    fn new(query: &mut Query, settings: &'a ParsilSettings<C>) -> Result<Self> {
        let largest_placeholder = placeholders::validate(settings, query)?;
        Ok(Self {
            settings,
            largest_placeholder,
        })
    }
}

impl<'a, C: ContextProvider> AstPass for Executor<'a, C> {
    fn post_expr(&mut self, expr: &mut Expr) -> Result<()> {
        convert_number_string(expr)?;
        convert_funcalls(expr)?;

        if let Expr::Value(Value::Placeholder(ref mut name)) = expr {
            match self.settings.placeholders.resolve_placeholder(name)? {
                PlaceholderIdentifier::MinQueryOnIdx1 => {
                    *name = format!("${}", self.largest_placeholder + 1);
                }
                PlaceholderIdentifier::MaxQueryOnIdx1 => {
                    *name = format!("${}", self.largest_placeholder + 2);
                }
                PlaceholderIdentifier::Generic(_) => {}
            }
        }

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
                                // primary index column := generate_series(__valid_from, __valid_until) AS name
                                ColumnKind::PrimaryIndex => SelectItem::ExprWithAlias {
                                    expr: expand_block_range(),
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
    let mut executor = Executor::new(query, settings)?;
    let mut query_execution = query.clone();
    query_execution.visit(&mut executor)?;

    let placeholder_mapping = (1..=executor.largest_placeholder)
        .map(|i| PlaceholderId::Generic(i))
        .chain(std::iter::once(PlaceholderId::MinQueryOnIdx1))
        .chain(std::iter::once(PlaceholderIdentifier::MaxQueryOnIdx1))
        .enumerate()
        .map(|(i, p)| (p, i))
        .collect();

    Ok(TranslatedQuery {
        query: query_execution,
        placeholder_mapping,
    })
}

pub fn generate_query_keys<C: ContextProvider>(
    query: &mut Query,
    settings: &ParsilSettings<C>,
) -> Result<Query> {
    let mut pis = RowFetcher::new(query, settings)?;
    let mut query_pis = query.clone();
    pis.process(&mut query_pis)?;
    info!("PIs: {query_pis}");
    Ok(query_pis)
}

pub fn bracket_secondary_index<C: ContextProvider>(
    table_name: &str,
    settings: &ParsilSettings<C>,
    placeholders: &Placeholders,
    secondary_lo: Option<U256>,
    secondary_hi: Option<U256>,
) -> Result<Query> {
    let min_u256 = '0';
    let max_u256 =
        U256::from_str("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
            .unwrap();

    let sec_ind_column = settings
        .context
        .fetch_table(table_name)
        .unwrap()
        .secondary_index_column()
        .id;

    // A simple alias for the sec. ind. values
    let sec_index = format!("(payload -> 'cells' -> '{sec_ind_column}' ->> 'value')::NUMERIC");

    // Select the largest of all the sec. ind. values that remains smaller than:
    //  - if the sec. ind. lower bound is set, the min of the sec. ind. lower
    //  bound and the smallest sec. ind. value covered by the given prim. ind.
    //  range;
    //
    //  - otherwise, the smallest sec. ind. value covered by the given prim.
    //  ind. range.
    let lower_bound = secondary_lo
        .map(|lo| format!("LEAST('{lo}'::DECIMAL, inrange_sec_index.kmin)"))
        .unwrap_or("inrange_sec_index.kmin".into());
    let largest_below =
        format!("SELECT COALESCE(MAX(sec_index), {min_u256}) FROM all_sec_index, inrange_sec_index WHERE sec_index < {lower_bound}");

    // Symmetric situation for the upper bound.
    let higher_bound = secondary_hi
        .map(|hi| format!("GREATEST('{hi}'::DECIMAL, inrange_sec_index.kmax)"))
        .unwrap_or("inrange_sec_index.kmax".into());
    let smallest_above =
        format!("select COALESCE(MIN(sec_index), '{max_u256}'::DECIMAL) FROM all_sec_index, inrange_sec_index WHERE sec_index > {higher_bound}");

    // 1. Extract all the sec. ind. in the table;
    //
    // 2. Extract all the sec. ind. covered by the prim. ind. range;
    //
    // 3. Apply the above sub-queries to find the highest-just-below and
    // lowest-just-above values of the sec. ind.
    let query = format!("WITH
                           all_sec_index as (SELECT {sec_index} AS sec_index FROM {table_name}),
                           inrange_sec_index AS (SELECT
                                        MIN({sec_index}) AS kmin,
                                        MAX({sec_index}) AS kmax
                                      FROM {table_name} where __valid_until >= {min_primary_index} AND __valid_from <= {max_primary_index})
                         ({largest_below}) UNION ({smallest_above})",
                        min_primary_index = placeholders.0[&PlaceholderId::MinQueryOnIdx1],
                        max_primary_index = placeholders.0[&PlaceholderIdentifier::MaxQueryOnIdx1]);

    println!("{}", query);
    todo!()
}
