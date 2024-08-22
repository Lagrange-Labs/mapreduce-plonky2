//! This module prunes a query from all its WHERE clauses that are not related
//! to either the primary index, or a well-defined bound on the secondary index.
use alloy::primitives::U256;
use anyhow::*;
use log::warn;
use mp2_common::{array::ToField, F};
use serde::{Deserialize, Serialize};
use sqlparser::ast::{
    BinaryOperator, Expr, FunctionArg, FunctionArgExpr, FunctionArguments, Query, Select,
    SelectItem, SetExpr, TableAlias, TableFactor, UnaryOperator, Value,
};
use verifiable_db::query::{
    aggregation::{QueryBoundSource, QueryBounds},
    computational_hash_ids::{AggregationOperation, Operation, PlaceholderIdentifier},
    universal_circuit::universal_circuit_inputs::{
        BasicOperation, InputOperand, OutputItem, Placeholders, ResultStructure,
    },
};

use crate::{
    errors::ValidationError,
    symbols::{ColumnKind, ContextProvider, Handle, Kind, ScopeTable, Symbol},
    utils::{str_to_u256, ParsilSettings},
    visitor::{AstPass, Visit},
};

/// An interval used to constraint the secondary index of a query.
#[derive(Debug, Default, Clone)]
struct Bounds {
    /// The higher bound, may be a constant or a static expression
    high: Option<QueryBoundSource>,
    /// The lower bound, may be a constant or a static expression
    low: Option<QueryBoundSource>,
}

pub(crate) struct Assembler<'a, C: ContextProvider> {
    settings: &'a ParsilSettings<C>,
    /// The symbol table hierarchy for this query
    scopes: ScopeTable<(), Expr>,
    secondary_index_bounds: Bounds,
}
impl<'a, C: ContextProvider> Assembler<'a, C> {
    /// Create a new empty [`Resolver`]
    fn new(settings: &'a ParsilSettings<C>) -> Self {
        Assembler {
            settings,
            scopes: ScopeTable::new(),
            secondary_index_bounds: Default::default(),
        }
    }

    fn exit_scope(&mut self) -> Result<()> {
        self.scopes.exit_scope().map(|_| ())
    }

    /// Return true if, within the current scope, the given symbol is
    /// computable as an expression of constants and placeholders.
    fn is_symbol_static(&self, s: &Symbol<Expr>) -> Result<bool> {
        match s {
            Symbol::Column { .. } => Ok(false),
            Symbol::Alias { to, .. } => self.is_symbol_static(to),
            Symbol::NamedExpression { payload, .. } => self.is_expr_static(&payload),
            Symbol::Expression(_) => todo!(),
            Symbol::Wildcard => Ok(false),
        }
    }

    /// Return true if, within the current scope, the given expression is
    /// computable as an expression of constants and placeholders.
    fn is_expr_static(&self, e: &Expr) -> Result<bool> {
        match e {
            Expr::Identifier(s) => self.is_symbol_static(&self.scopes.resolve_freestanding(s)?),
            Expr::CompoundIdentifier(c) => self.is_symbol_static(&self.scopes.resolve_compound(c)?),
            Expr::BinaryOp { left, right, .. } => {
                Ok(self.is_expr_static(left)? && self.is_expr_static(right)?)
            }
            Expr::UnaryOp { expr, .. } => self.is_expr_static(expr),
            Expr::Nested(e) => self.is_expr_static(e),
            Expr::Value(_) => Ok(true),

            _ => Ok(false),
        }
    }

    /// Return whether the given `Symbol` encodes the secondary index column.
    fn is_symbol_idx(&self, s: &Symbol<Expr>, idx: ColumnKind) -> bool {
        match s {
            Symbol::Column { kind, .. } => *kind == idx,
            Symbol::Alias { to, .. } => self.is_symbol_idx(to, idx),
            _ => false,
        }
    }

    /// Return whether, in the current scope, the given expression refers to the
    /// secondary index.
    fn contains_index(&self, expr: &Expr, idx: ColumnKind) -> Result<bool> {
        Ok(match expr {
            Expr::Identifier(s) => self.is_symbol_idx(&self.scopes.resolve_freestanding(s)?, idx),
            Expr::CompoundIdentifier(c) => {
                self.is_symbol_idx(&self.scopes.resolve_compound(c)?, idx)
            }
            Expr::UnaryOp { expr, .. } => self.contains_index(expr, idx)?,
            Expr::BinaryOp { left, right, .. } => {
                self.contains_index(left, idx)? || self.contains_index(right, idx)?
            }
            Expr::Nested(e) => self.contains_index(e, idx)?,
            _ => false,
        })
    }

    fn isolate(&mut self, expr: &mut Expr) -> Result<()> {
        fn should_keep(expr: &Expr) -> bool {
            true
        }

        if let Some(replacement) = match expr {
            Expr::Value(_) | Expr::Identifier(_) | Expr::CompoundIdentifier(_) => None,
            Expr::Nested(e) => {
                self.isolate(e)?;
                None
            }
            Expr::BinaryOp { left, op, right } => {
                // TODO:
                // if !left contains index left = None
                // if !right contains index right = None
                // if both self = None
                match (should_keep(left), should_keep(right)) {
                    (true, true) => {
                        self.isolate(left)?;
                        self.isolate(right)?;
                        None
                    }
                    (true, false) => Some(*left.to_owned()),
                    (false, true) => Some(*right.to_owned()),
                    // NOTE: this cannot be reached, as then expr would never be
                    // explored.
                    (false, false) => unreachable!(),
                }
            }
            Expr::UnaryOp { op, expr } => match op {
                UnaryOperator::Not => {
                    todo!()
                }
                _ => unreachable!(),
            },
            _ => None,
        } {
            *expr = replacement;
        }

        Ok(())
    }
}

impl<'a, C: ContextProvider> AstPass for Assembler<'a, C> {
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
                        .fetch_table(&concrete_table_name)?
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
        if let Some(where_clause) = select.selection.as_mut() {
            // As the expression are traversed depth-first, the top level
            // expression will mechnically find itself at the last position, as
            // required by the universal query circuit API.
            self.isolate(where_clause)?;
        }
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
pub fn validate<C: ContextProvider>(query: &Query, settings: &ParsilSettings<C>) -> Result<()> {
    let mut converted_query = query.clone();
    let mut resolver = Assembler::new(settings);
    converted_query.visit(&mut resolver)?;
    resolver.prepare_result().map(|_| ())
}
