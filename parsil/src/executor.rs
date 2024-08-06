use anyhow::*;
use log::*;
use sqlparser::ast::{Expr, Ident, Query, Select, TableAlias, TableFactor};

use crate::{
    symbols::{Handle, Kind, RootContextProvider, ScopeTable, Symbol},
    visitor::{AstPass, Visit},
};

struct Leafer<'a> {
    resolver: &'a ScopeTable<(), ()>,
    leafs: Vec<Symbol<()>>,
}
impl<'a> Leafer<'a> {
    fn new(resolver: &'a ScopeTable<(), ()>) -> Self {
        Self {
            resolver,
            leafs: Vec::new(),
        }
    }
}
impl<'a> AstPass for Leafer<'a> {
    fn pre_expr(&mut self, expr: &mut Expr) -> Result<()> {
        match expr {
            Expr::Identifier(e) => self.leafs.push(self.resolver.resolve_freestanding(e)?),
            Expr::CompoundIdentifier(c) => self.leafs.push(self.resolver.resolve_compound(c)?),
            _ => {}
        }
        Ok(())
    }
}

struct Executor<C: RootContextProvider> {
    scopes: ScopeTable<(), ()>,
    /// A handle to an object providing a register of the existing virtual
    /// tables and their columns.
    context: C,
}
impl<C: RootContextProvider> Executor<C> {
    fn new(context: C) -> Self {
        Self {
            scopes: ScopeTable::new(),
            context,
        }
    }
}
impl<C: RootContextProvider> AstPass for Executor<C> {
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
                        "compounded table names unsupported: `{}`",
                        name
                    );

                    // The actual table being referenced
                    let concrete_table_name = &name.0[0].value;

                    // Fetch all the column declared in this table
                    let table_columns = self.context.fetch_table(&concrete_table_name)?.columns;

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
                            payload: (),
                            is_primary_index: column.is_primary_index,
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
        self.scopes.exit_scope().map(|_| ())
    }

    fn pre_select(&mut self, s: &mut Select) -> Result<()> {
        self.scopes
            .enter_scope(format!("Select: {s}"), Kind::Standard);
        Ok(())
    }

    fn post_select(&mut self, select: &mut Select) -> Result<()> {
        self.scopes.exit_scope().map(|_| ())
    }

    fn post_expr(&mut self, e: &mut Expr) -> Result<()> {
        match e {
            // Identifier must be converted to JSON accesses into the ryhope tables.
            Expr::Identifier(symbol) => {
                if let Symbol::Column { target, .. } = self.scopes.resolve_freestanding(symbol)? {
                    *e = if let Handle::Qualified { table, name } = target {
                        Expr::BinaryOp {
                            left: Box::new(Expr::CompoundIdentifier(
                                [Ident::new(table), Ident::new("payload")].to_vec(),
                            )),
                            op: sqlparser::ast::BinaryOperator::Arrow,
                            right: Box::new(Expr::Identifier(Ident::with_quote('\'', name))),
                        }
                    } else {
                        unreachable!()
                    }
                }
            }
            // Qualified identifiers must be converted to JSON accesses into the ryhope tables.
            Expr::CompoundIdentifier(compound) => {
                if let Symbol::Column { target, .. } = self.scopes.resolve_compound(compound)? {
                    *e = if let Handle::Qualified { table, name } = target {
                        Expr::BinaryOp {
                            left: Box::new(Expr::CompoundIdentifier(
                                [Ident::new(table), Ident::new("payload")].to_vec(),
                            )),
                            op: sqlparser::ast::BinaryOperator::Arrow,
                            right: Box::new(Expr::Identifier(Ident::with_quote('\'', name))),
                        }
                    } else {
                        unreachable!()
                    }
                }
            }
            // Function call must be validated
            Expr::Function(f) => self.scopes.resolve_function(f)?,
            _ => {}
        }
        Ok(())
    }
}

pub(crate) fn execute<C: RootContextProvider>(mut query: Query, ctx: C) -> Result<Query> {
    let mut executor = Executor::new(ctx);
    println!("OLD QUERY:\n{query}");
    query.visit(&mut executor)?;
    println!("NEW QUERY:\n{query}");
    Ok(query)
}
