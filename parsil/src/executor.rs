use anyhow::*;
use log::*;
use sqlparser::ast::{BinaryOperator, Expr, Ident, Query, Select, TableAlias, TableFactor};

use crate::{
    symbols::{ContextProvider, Handle, Kind, ScopeTable, Symbol},
    visitor::{AstPass, Visit},
};

/// Describes what part of a query the visitor is currently traversing
enum Position {
    /// Root context of the query
    Root,
    /// Within an item of SELECT
    Select,
    /// Within an item of WHERE
    Where,
}

/// The Leafer extracts all the symbols occuring under a given node in the AST.
struct Leafer<'a> {
    /// A reference to a symbol resolver
    resolver: &'a ScopeTable<(), ()>,
    /// The collected symbol leaves
    leafs: Vec<Symbol<()>>,
}
impl<'a> Leafer<'a> {
    /// Initialize a new leafer from a symbol resolver
    fn new(resolver: &'a ScopeTable<(), ()>) -> Self {
        Self {
            resolver,
            leafs: Vec::new(),
        }
    }

    /// Instantiate a new Leafer, traverse an expression and return the result
    fn traverse(resolver: &'a ScopeTable<(), ()>, e: &mut Expr) -> Result<Self> {
        let mut leafer = Self::new(resolver);
        e.visit(&mut leafer)?;
        Ok(leafer)
    }

    /// Returns whether the Leafer has met a symbol mapping to a primary index.
    fn contains_primary_index(&self) -> bool {
        for l in self.leafs.iter() {
            if let Symbol::Column {
                is_primary_index: true,
                ..
            } = l
            {
                return true;
            }
        }
        false
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

/// Return true if this expression is an identifier
fn is_ident(e: &Expr) -> bool {
    matches!(e, Expr::Identifier(_) | Expr::CompoundIdentifier(_))
}

struct Executor<C: ContextProvider> {
    /// The stack representation of the query sections currently being traversed
    position: Vec<Position>,
    /// A symbol resolver without any metadata attached
    scopes: ScopeTable<(), ()>,
    /// A handle to an object providing a register of the existing virtual
    /// tables and their columns.
    context: C,
}
impl<C: ContextProvider> Executor<C> {
    fn new(context: C) -> Self {
        Self {
            scopes: ScopeTable::new(),
            position: vec![Position::Root],
            context,
        }
    }

    /// Convert PI < g into PI_0 < g
    ///
    /// Use inclusive comparison <= if `inclusive` is set
    fn expand_lt(&self, operand: &Expr, inclusive: bool) -> Expr {
        let op = if inclusive {
            BinaryOperator::LtEq
        } else {
            BinaryOperator::Lt
        };

        if let Result::Ok(Symbol::MetaColumn {
            handle:
                Handle::Qualified {
                    table,
                    name: valid_from,
                },
            ..
        }) = self.scopes.resolve_str("__valid_from")
        {
            Expr::BinaryOp {
                left: Box::new(Expr::CompoundIdentifier(vec![
                    Ident::new(table),
                    Ident::new(valid_from),
                ])),

                op,
                right: Box::new(operand.clone()),
            }
        } else {
            unreachable!()
        }
    }

    /// Convert PI > g into PI_1 > g
    ///
    /// Use inclusive comparison <= if `inclusive` is set
    fn expand_gt(&self, operand: &Expr, inclusive: bool) -> Expr {
        let op = if inclusive {
            BinaryOperator::GtEq
        } else {
            BinaryOperator::Gt
        };

        if let Result::Ok(Symbol::MetaColumn {
            handle:
                Handle::Qualified {
                    table,
                    name: valid_until,
                },
            ..
        }) = self.scopes.resolve_str("__valid_until")
        {
            Expr::BinaryOp {
                left: Box::new(Expr::CompoundIdentifier(vec![
                    Ident::new(table),
                    Ident::new(valid_until),
                ])),
                op,
                right: Box::new(operand.clone()),
            }
        } else {
            unreachable!()
        }
    }

    /// Convert PI = x into PI_0 <= x AND PI_1 >= x
    ///
    /// Use inclusive comparison <= if `inclusive` is set
    fn expand_eq(&self, target: &Expr) -> Expr {
        if let (
            Result::Ok(Symbol::MetaColumn {
                handle:
                    Handle::Qualified {
                        table,
                        name: valid_from,
                    },
                ..
            }),
            Result::Ok(Symbol::MetaColumn {
                handle:
                    Handle::Qualified {
                        name: valid_until, ..
                    },
                ..
            }),
        ) = (
            self.scopes.resolve_str("__valid_from"),
            self.scopes.resolve_str("__valid_until"),
        ) {
            Expr::Nested(Box::new(Expr::BinaryOp {
                left: Box::new(Expr::BinaryOp {
                    left: Box::new(Expr::CompoundIdentifier(vec![
                        Ident::new(table.clone()),
                        Ident::new(valid_from),
                    ])),
                    op: BinaryOperator::LtEq,
                    right: Box::new(target.clone()),
                }),
                op: BinaryOperator::And,
                right: Box::new(Expr::BinaryOp {
                    left: Box::new(target.clone()),
                    op: BinaryOperator::LtEq,
                    right: Box::new(Expr::CompoundIdentifier(vec![
                        Ident::new(table),
                        Ident::new(valid_until),
                    ])),
                }),
            }))
        } else {
            unreachable!()
        }
    }

    fn expand_condition(&mut self, e: &mut Expr) -> Result<()> {
        if let Some(new_e) = match e {
            Expr::BinaryOp { left, op, right } => {
                match op {
                    BinaryOperator::Lt | BinaryOperator::LtEq => {
                        let pi_left =
                            Leafer::traverse(&self.scopes, left)?.contains_primary_index();
                        let pi_right =
                            Leafer::traverse(&self.scopes, right)?.contains_primary_index();

                        match (pi_left, pi_right) {
                            // self-referencing comparisons on PI are forbidden
                            (true, true) => bail!(
                                "{e}: block number can not appear on both sides of comparison"
                            ),
                            // PI on the left
                            (true, false) => {
                                ensure!(
                                    is_ident(left),
                                    "{e}: block number must appear alone in comparisons"
                                );
                                Some(self.expand_lt(right, *op == BinaryOperator::LtEq))
                            }
                            // PI on the right
                            (false, true) => {
                                ensure!(
                                    is_ident(right),
                                    "{e}: block number must appear alone in comparisons"
                                );
                                Some(self.expand_gt(left, *op == BinaryOperator::LtEq))
                            }
                            // Nothing to do
                            (false, false) => None,
                        }
                    }
                    BinaryOperator::Gt | BinaryOperator::GtEq => {
                        let pi_left =
                            Leafer::traverse(&self.scopes, left)?.contains_primary_index();
                        let pi_right =
                            Leafer::traverse(&self.scopes, right)?.contains_primary_index();

                        match (pi_left, pi_right) {
                            // self-referencing comparisons on PI are forbidden
                            (true, true) => bail!(
                                "{e}: block number can not appear on both sides of comparison"
                            ),
                            // PI on the left
                            (true, false) => {
                                ensure!(
                                    is_ident(left),
                                    "{e}: block number must appear alone in comparisons"
                                );
                                Some(self.expand_gt(right, *op == BinaryOperator::GtEq))
                            }
                            // PI on the right
                            (false, true) => {
                                ensure!(
                                    is_ident(right),
                                    "{e}: block number must appear alone in comparisons"
                                );
                                Some(self.expand_lt(left, *op == BinaryOperator::GtEq))
                            }
                            // Nothing to do
                            (false, false) => None,
                        }
                    }
                    BinaryOperator::Eq => {
                        let pi_left =
                            Leafer::traverse(&self.scopes, left)?.contains_primary_index();
                        let pi_right =
                            Leafer::traverse(&self.scopes, right)?.contains_primary_index();

                        match (pi_left, pi_right) {
                            // self-referencing comparisons on PI are forbidden
                            (true, true) => bail!(
                                "{e}: block number can not appear on both sides of comparison"
                            ),
                            // PI on the left
                            (true, false) => {
                                ensure!(
                                    is_ident(left),
                                    "{e}: block number must appear alone in comparisons"
                                );
                                Some(self.expand_eq(right))
                            }
                            // PI on the right
                            (false, true) => {
                                ensure!(
                                    is_ident(right),
                                    "{e}: block number must appear alone in comparisons"
                                );
                                Some(self.expand_eq(left))
                            }
                            // Nothing to do
                            (false, false) => None,
                        }
                    }
                    BinaryOperator::NotEq => todo!(),
                    _ => None,
                }
            }
            _ => None,
        } {
            *e = new_e;
        }
        Ok(())
    }
}
impl<C: ContextProvider> AstPass for Executor<C> {
    fn pre_selection(&mut self) -> Result<()> {
        self.position.push(Position::Where);
        Ok(())
    }

    fn post_selection(&mut self) -> Result<()> {
        self.position.pop().expect("should never fail");
        Ok(())
    }

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
                    for special in ["__valid_from", "__valid_until"] {
                        self.scopes
                            .current_scope_mut()
                            .insert(Symbol::MetaColumn {
                                handle: Handle::Qualified {
                                    table: apparent_table_name.clone(),
                                    name: special.into(),
                                },
                                payload: (),
                            })
                            .unwrap();
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
        self.position.push(Position::Where);
        Ok(())
    }

    fn post_select(&mut self, _select: &mut Select) -> Result<()> {
        self.position.pop().expect("should never fail");
        self.scopes.exit_scope().map(|_| ())
    }

    // The pre_expr hooks triggers the conversion of the conditions related to
    // the primary index, that must be run before the symbol expansion would
    // break symbol resolution.
    fn pre_expr(&mut self, e: &mut Expr) -> Result<()> {
        // Only expand conditions in WHERE statements
        if matches!(self.position.last().unwrap(), Position::Where) {
            self.expand_condition(e)?;
        }
        Ok(())
    }

    // The post_expr hook runs the conversion from virtual column symbols to
    // JSON access into the zkTable payloads.
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

pub(crate) fn execute<C: ContextProvider>(mut query: Query, ctx: C) -> Result<Query> {
    let mut executor = Executor::new(ctx);
    println!("OLD QUERY:\n{query}");
    query.visit(&mut executor)?;
    println!("NEW QUERY:\n{query}");
    Ok(query)
}
