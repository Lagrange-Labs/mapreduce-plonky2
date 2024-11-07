//! This module prunes a query from all its WHERE clauses that are not related
//! to either the primary index, or a well-defined bound on the secondary index.
use anyhow::*;
use log::warn;
use sqlparser::ast::{BinaryOperator, Expr, Query, Select, SelectItem, TableAlias, TableFactor};
use verifiable_db::query::aggregation::QueryBounds;

use crate::{
    errors::ValidationError,
    symbols::{ColumnKind, ContextProvider, Handle, Kind, ScopeTable, Symbol},
    utils::ParsilSettings,
    visitor::{AstMutator, VisitMut},
};

/// Define on which side(s) the secondary index is known to be bounded within a query.
#[derive(Clone, Copy)]
enum SecondaryIndexBounds {
    BothSides,
    Low,
    High,
    None,
}
impl SecondaryIndexBounds {
    /// Instiantiate a [`SecondaryIndexBounds`] from a pair of booleans indicating whether
    /// the secondary index is bounded on the lower and higher ends.
    fn from_lo_hi(lo_sec: bool, hi_sec: bool) -> Self {
        match (lo_sec, hi_sec) {
            (true, true) => Self::BothSides,
            (true, false) => Self::Low,
            (false, true) => Self::High,
            (false, false) => Self::None,
        }
    }

    /// Generate a list of index and operator pattern to detect for a
    /// [`SecondaryIndexBounds`] instance.
    fn kinds(&self) -> &[(ColumnKind, RelevantFor)] {
        match self {
            SecondaryIndexBounds::BothSides => &[
                (ColumnKind::PrimaryIndex, RelevantFor::Either),
                (ColumnKind::SecondaryIndex, RelevantFor::Either),
            ],
            SecondaryIndexBounds::Low => &[
                (ColumnKind::PrimaryIndex, RelevantFor::Either),
                (ColumnKind::SecondaryIndex, RelevantFor::Gt),
            ],
            SecondaryIndexBounds::High => &[
                (ColumnKind::PrimaryIndex, RelevantFor::Either),
                (ColumnKind::SecondaryIndex, RelevantFor::Lt),
            ],
            SecondaryIndexBounds::None => &[(ColumnKind::PrimaryIndex, RelevantFor::Either)],
        }
    }
}

/// Describe whether an index is relevant when found on the left of a =, < or >
/// comparison.
#[derive(Clone, Copy)]
enum RelevantFor {
    Lt,
    Gt,
    Either,
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

    /// Return whether, in the current scope, the given expression refers to the
    /// secondary index.
    fn contains_index(&self, expr: &Expr, idx: ColumnKind, side: RelevantFor) -> Result<bool> {
        fn is_relevant_left(op: &BinaryOperator, side: RelevantFor) -> bool {
            match side {
                RelevantFor::Either => true,
                RelevantFor::Gt => {
                    matches!(op, BinaryOperator::Gt | BinaryOperator::GtEq)
                }
                RelevantFor::Lt => {
                    matches!(op, BinaryOperator::Lt | BinaryOperator::LtEq)
                }
            }
        }

        fn is_relevant_right(op: &BinaryOperator, side: RelevantFor) -> bool {
            match side {
                RelevantFor::Either => true,
                RelevantFor::Gt => {
                    matches!(op, BinaryOperator::Lt | BinaryOperator::LtEq)
                }
                RelevantFor::Lt => {
                    matches!(op, BinaryOperator::Gt | BinaryOperator::GtEq)
                }
            }
        }

        Ok(match expr {
            Expr::Identifier(s) => Self::is_symbol_idx(&self.scopes.resolve_freestanding(s)?, idx),
            Expr::CompoundIdentifier(c) => {
                Self::is_symbol_idx(&self.scopes.resolve_compound(c)?, idx)
            }
            Expr::UnaryOp { expr, .. } => self.contains_index(expr, idx, side)?,
            Expr::BinaryOp { left, right, op } => {
                (self.contains_index(left, idx, side)? && is_relevant_left(op, side))
                    || (self.contains_index(right, idx, side)? && is_relevant_right(op, side))
            }
            Expr::Nested(e) => self.contains_index(e, idx, side)?,
            _ => false,
        })
    }

    /// Depending on the secondary index predicates, determine whether this
    /// expression is relevant to index bounds or if it should be pruned.
    fn should_keep(&self, expr: &Expr) -> Result<bool> {
        let mut keep = false;
        for (idx, side) in self.isolation.kinds() {
            keep |= self.contains_index(expr, *idx, *side)?;
        }
        Ok(keep)
    }

    /// Recursively traverse an [`Expr`], pruning all sub-expresssions not
    /// related to index bounds.
    fn isolate(&mut self, expr: &mut Expr) -> Result<()> {
        if let Some(replacement) = match expr {
            Expr::Nested(e) => {
                self.isolate(e)?;
                None
            }
            Expr::BinaryOp {
                left,
                right,
                op: BinaryOperator::And | BinaryOperator::Or | BinaryOperator::Xor,
            } => {
                match (self.should_keep(left)?, self.should_keep(right)?) {
                    (true, true) => {
                        self.isolate(left)?;
                        self.isolate(right)?;
                        None
                    }
                    (true, false) => {
                        self.isolate(left)?;
                        Some(*left.to_owned())
                    }
                    (false, true) => {
                        self.isolate(right)?;
                        Some(*right.to_owned())
                    }
                    // NOTE: this cannot be reached, as then the expr
                    // would never have been explored in the first
                    // place.
                    (false, false) => unreachable!(),
                }
            }
            Expr::UnaryOp { expr, .. } => {
                self.isolate(expr)?;
                None
            }
            _ => None,
        } {
            *expr = replacement;
        }

        // Only recursively go down if we are within an `AND`
        if let Expr::BinaryOp {
            left,
            op: BinaryOperator::And,
            right,
        } = expr
        {
            self.isolate(left)?;
            self.isolate(right)?;
        }

        Ok(())
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
pub fn isolate<C: ContextProvider>(
    query: &Query,
    settings: &ParsilSettings<C>,
    bounds: &QueryBounds,
) -> Result<Query> {
    isolate_with(
        query,
        settings,
        bounds.min_query_secondary().is_bounded_low(),
        bounds.max_query_secondary().is_bounded_high(),
    )
}

pub fn isolate_with<C: ContextProvider>(
    query: &Query,
    settings: &ParsilSettings<C>,
    lo_sec: bool,
    hi_sec: bool,
) -> Result<Query> {
    let mut converted_query = query.clone();
    let mut insulator = Isolator::new(settings, SecondaryIndexBounds::from_lo_hi(lo_sec, hi_sec));
    converted_query.visit_mut(&mut insulator)?;
    Ok(converted_query)
}
