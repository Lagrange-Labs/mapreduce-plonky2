//! This module replaces the WHERE clause of a query with another one that contains
//! only predicates to apply the query bounds on primary and secondary index columns.
use alloy::primitives::U256;
use anyhow::*;
use log::warn;
use sqlparser::ast::{
    BinaryOperator, Expr, Ident, Query, Select, SelectItem, TableAlias, TableFactor, Value,
};
use verifiable_db::query::utils::QueryBounds;

use crate::{
    errors::ValidationError,
    symbols::{ColumnKind, ContextProvider, Handle, Kind, ScopeTable, Symbol},
    utils::{u256_to_expr, ParsilSettings},
    visitor::{AstMutator, VisitMut},
};

/// Define on which side(s) the secondary index is known to be bounded within a query.
#[derive(Clone, Copy)]
enum SecondaryIndexBounds {
    BothSides((U256, U256)),
    Low(U256),
    High(U256),
    None,
}

impl SecondaryIndexBounds {
    fn from_secondary_bounds(low: Option<U256>, high: Option<U256>) -> Self {
        match (low, high) {
            (None, None) => SecondaryIndexBounds::None,
            (None, Some(high)) => SecondaryIndexBounds::High(high),
            (Some(low), None) => SecondaryIndexBounds::Low(low),
            (Some(low), Some(high)) => SecondaryIndexBounds::BothSides((low, high)),
        }
    }
}

/// An `Isolator` recursively browse the `WHERE` clauses of a query and prune
/// all the sub-expressions irrelevant to evaluation of the known index bounds.
pub(crate) struct Isolator<'a, C: ContextProvider> {
    settings: &'a ParsilSettings<C>,
    /// The symbol table hierarchy for this query
    scopes: ScopeTable<(), Expr>,
    /// The isolation operation to perform on the secondary index.
    isolation: SecondaryIndexBounds,
}
impl<'a, C: ContextProvider> Isolator<'a, C> {
    /// Create a new empty [`Resolver`]
    fn new(settings: &'a ParsilSettings<C>, isolation: SecondaryIndexBounds) -> Self {
        Isolator {
            settings,
            scopes: ScopeTable::new(),
            isolation,
        }
    }

    fn exit_scope(&mut self) -> Result<()> {
        self.scopes.exit_scope().map(|_| ())
    }

    /// Return whether the given `Symbol` encodes the secondary index column.
    fn is_symbol_idx(s: &Symbol<Expr>, idx: ColumnKind) -> bool {
        match s {
            Symbol::Column { kind, .. } => *kind == idx,
            Symbol::Alias { to, .. } => Self::is_symbol_idx(to, idx),
            _ => false,
        }
    }

    fn isolate(&mut self) -> Result<Expr> {
        // first, get the identifiers of primary and secondary index columns
        let (primary, secondary) = self.scopes.currently_reachable()?.into_iter().fold(
            Ok((None, None)),
            |acc, symbol| {
                let (primary, secondary) = acc?;
                Ok((
                    if Self::is_symbol_idx(&symbol, ColumnKind::PrimaryIndex) {
                        ensure!(primary.is_none(), "Multiple primary index columns found");
                        let handle = symbol
                            .handle()
                            .ok_or(anyhow!("Cannot convert symbol {symbol} to handle"))?;
                        Some(format!("{handle}"))
                    } else {
                        primary
                    },
                    if Self::is_symbol_idx(&symbol, ColumnKind::SecondaryIndex) {
                        ensure!(
                            secondary.is_none(),
                            "Multiple secondary index columns found"
                        );
                        let handle = symbol
                            .handle()
                            .ok_or(anyhow!("Cannot convert symbol {symbol} to handle"))?;
                        Some(format!("{handle}"))
                    } else {
                        secondary
                    },
                ))
            },
        )?;

        let primary = primary.ok_or(anyhow!("No primary index column found in current scope"))?;
        let secondary =
            secondary.ok_or(anyhow!("No secondary index column found in current scope"))?;

        // now, add the predicate `primary >= $MIN_BLOCK AND primary <= $MAX_BLOCK`
        let expr_primary_index = Expr::BinaryOp {
            left: Box::new(Expr::BinaryOp {
                left: Box::new(Expr::Identifier(Ident::new(&primary))),
                op: BinaryOperator::GtEq,
                right: Box::new(Expr::Value(Value::Placeholder(
                    self.settings.placeholders.min_block_placeholder.to_owned(),
                ))),
            }),
            op: BinaryOperator::And,
            right: Box::new(Expr::BinaryOp {
                left: Box::new(Expr::Identifier(Ident::new(primary))),
                op: BinaryOperator::LtEq,
                right: Box::new(Expr::Value(Value::Placeholder(
                    self.settings.placeholders.max_block_placeholder.to_owned(),
                ))),
            }),
        };

        // Closure to build the predicate secondary >= value
        let build_secondary_index_lower_expr = |value| Expr::BinaryOp {
            left: Box::new(Expr::Identifier(Ident::new(&secondary))),
            op: BinaryOperator::GtEq,
            right: Box::new(u256_to_expr(value)),
        };

        // Closure to build the predicate secondary <= value
        let build_secondary_index_upper_expr = |value| Expr::BinaryOp {
            left: Box::new(Expr::Identifier(Ident::new(&secondary))),
            op: BinaryOperator::LtEq,
            right: Box::new(u256_to_expr(value)),
        };

        // Build the predicate to filter rows by secondary index values, depending on
        // the secondary index bounds specified in the query
        let secondary_index_expr = match self.isolation {
            SecondaryIndexBounds::BothSides((lower_value, upper_value)) => Some(Expr::BinaryOp {
                left: Box::new(build_secondary_index_lower_expr(lower_value)),
                op: BinaryOperator::And,
                right: Box::new(build_secondary_index_upper_expr(upper_value)),
            }),
            SecondaryIndexBounds::Low(lower_value) => {
                Some(build_secondary_index_lower_expr(lower_value))
            }
            SecondaryIndexBounds::High(upper_value) => {
                Some(build_secondary_index_upper_expr(upper_value))
            }
            SecondaryIndexBounds::None => None,
        };

        // Build an expression with both range predicates for primary and secondary index, if any
        Ok(if let Some(expr) = secondary_index_expr {
            Expr::BinaryOp {
                left: Box::new(expr_primary_index),
                op: BinaryOperator::And,
                right: Box::new(expr),
            }
        } else {
            expr_primary_index
        })
    }
}

impl<C: ContextProvider> AstMutator for Isolator<'_, C> {
    type Error = anyhow::Error;

    fn pre_table_factor(&mut self, table_factor: &mut TableFactor) -> Result<()> {
        match &table_factor {
            TableFactor::Table {
                name, alias, args, ..
            } => {
                // In this case, we handle
                //
                // ... FROM table [AS alias [(col1, // col2, ...)]]
                //
                // so both the table name and its columns may be aliased.
                self.scopes
                    .enter_scope(format!("TableFactor: {table_factor}"), Kind::Standard);
                if args.is_some() {
                    warn!("ignoring table-valued function {name}");
                } else {
                    ensure!(
                        name.0.len() == 1,
                        ValidationError::CompoundTableName(name.to_string())
                    );

                    // The actual table being referenced
                    let concrete_table_name = &name.0[0].value;

                    // Fetch all the column declared in this table
                    let table_columns = self
                        .settings
                        .context
                        .fetch_table(concrete_table_name)?
                        .columns;

                    // Extract the apparent table name (either the concrete one
                    // or its alia), and, if they exist, the aliased column
                    // names.
                    let (apparent_table_name, column_aliases) = if let Some(table_alias) = alias {
                        (
                            table_alias.name.value.to_owned(),
                            Some(&table_alias.columns),
                        )
                    } else {
                        (concrete_table_name.to_owned(), None)
                    };

                    // If columns are aliased, we must have as many aliases as
                    // we have columns.
                    if let Some(column_aliases) = column_aliases {
                        ensure!(column_aliases.len() == table_columns.len())
                    }

                    for (i, column) in table_columns.into_iter().enumerate() {
                        // The symbol refers to a concrete column
                        let symbol = Symbol::Column {
                            handle: Handle::Qualified {
                                table: apparent_table_name.clone(),
                                // If a column is not aliased, it keeps its real
                                // name
                                name: if let Some(column_aliases) = column_aliases {
                                    column_aliases[i].value.to_owned()
                                } else {
                                    column.name.clone()
                                },
                            },
                            // The column may be known under an alias instead of
                            // its real name
                            target: Handle::Qualified {
                                table: apparent_table_name.clone(),
                                name: column.name.clone(),
                            },
                            // TODO: ugly
                            payload: Expr::Wildcard,
                            kind: column.kind,
                        };

                        self.scopes.current_scope_mut().insert(symbol)?;
                    }
                }
            }
            TableFactor::Derived { alias, .. } => {
                // Here we handle
                //
                // (SELECT ...) [AS alias [(col1, col2, ...)]]
                //
                // Depending on the aliasing clause, the created context may be
                // transparent, only a table aliaser, or a full aliaser, of the
                // context that will be created for the `SELECT` underneath.
                let kind = if let Some(TableAlias { name, columns }) = alias {
                    if columns.is_empty() {
                        // Only a table name is defined in the AS clause, this
                        // is a table aliaser.
                        Kind::TableAliasing(name.value.clone())
                    } else {
                        // Both table and column names is defined in the AS
                        // clause, this is a full aliaser.
                        Kind::FullAliasing {
                            table: name.value.clone(),
                            columns: columns.iter().map(|c| c.value.clone()).collect(),
                        }
                    }
                } else {
                    // No AS clause are provided, this context is purely transparent.
                    Kind::Transparent
                };
                self.scopes.enter_scope(format!("{table_factor}"), kind);
            }
            TableFactor::TableFunction { .. } => todo!(),
            TableFactor::Function { .. } => todo!(),
            TableFactor::UNNEST { .. } => todo!(),
            TableFactor::JsonTable { .. } => todo!(),
            TableFactor::NestedJoin { .. } => todo!(),
            TableFactor::Pivot { .. } => todo!(),
            TableFactor::Unpivot { .. } => todo!(),
            TableFactor::MatchRecognize { .. } => todo!(),
        }
        Ok(())
    }

    fn post_table_factor(&mut self, _: &mut TableFactor) -> Result<()> {
        self.exit_scope()
    }

    /// SELECT always generate standard context, that will expose the SELECTed
    /// items to their parent while ensuring that they are actually contained in
    /// its providers.
    fn pre_select(&mut self, s: &mut Select) -> Result<()> {
        self.scopes
            .enter_scope(format!("Select: {s}"), Kind::Standard);
        Ok(())
    }

    fn post_select(&mut self, select: &mut Select) -> Result<()> {
        // Replace WHERE clause with the predicates filtering over primary and
        // secondary index query bounds
        select.selection = Some(self.isolate()?);
        self.exit_scope()
    }

    fn post_expr(&mut self, expr: &mut Expr) -> Result<()> {
        crate::executor::convert_number_string(expr)?;

        Ok(())
    }

    /// All the [`SelectItem`] in the SELECT clause are exposed to the current
    /// context parent.
    fn pre_select_item(&mut self, select_item: &mut SelectItem) -> Result<()> {
        let provided = match select_item {
            SelectItem::ExprWithAlias { expr, alias } => Symbol::NamedExpression {
                name: Handle::Simple(alias.value.clone()),
                payload: expr.clone(),
            },
            SelectItem::UnnamedExpr(e) => match e {
                Expr::Identifier(i) => self.scopes.resolve_freestanding(i)?,
                Expr::CompoundIdentifier(is) => self.scopes.resolve_compound(is)?,
                _ => Symbol::Expression(e.clone()),
            },
            SelectItem::Wildcard(_) => Symbol::Wildcard,
            SelectItem::QualifiedWildcard(_, _) => unreachable!(),
        };
        self.scopes.current_scope_mut().provides(provided);
        Ok(())
    }
}

/// Validate the given query, ensuring that it satisfies all the requirements of
/// the circuit.
pub fn isolate<C: ContextProvider>(
    query: &Query,
    settings: &ParsilSettings<C>,
    bounds: &QueryBounds,
) -> Result<Query> {
    let lower_bound = bounds.min_query_secondary();
    let upper_bound = bounds.max_query_secondary();
    isolate_with(
        query,
        settings,
        lower_bound.is_bounded_low().then_some(*lower_bound.value()),
        upper_bound
            .is_bounded_high()
            .then_some(*upper_bound.value()),
    )
}

pub(crate) fn isolate_with<C: ContextProvider>(
    query: &Query,
    settings: &ParsilSettings<C>,
    lower_bound: Option<U256>,
    upper_bound: Option<U256>,
) -> Result<Query> {
    let mut converted_query = query.clone();
    let mut insulator = Isolator::new(
        settings,
        SecondaryIndexBounds::from_secondary_bounds(lower_bound, upper_bound),
    );
    converted_query.visit_mut(&mut insulator)?;
    Ok(converted_query)
}
