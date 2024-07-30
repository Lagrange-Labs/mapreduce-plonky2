//! This module converts a user-defined query into one that can directly be
//! executed on the ryhope table containing the related data. The main steps
//! are:
//!
//! 1. convert virtual columns accesses into JSON payload access;
//!
//! 2. wrap the original query into a CTE to expand CoW row spans into
//!    individual column for each covered block number.
use anyhow::*;
use log::warn;
use sqlparser::ast::{Expr, Function, Ident, Query, Select, SelectItem, TableAlias, TableFactor};

use crate::{
    symbols::{Handle, RootContextProvider},
    visitor::{AstPass, Visit},
};

/// A [`Symbol`] is anything that can be referenced from an SQL expression.
#[derive(Debug, Clone)]
pub enum Symbol {
    /// A column must be replaced by <table>.payload -> <column>
    ConcreteColumn {
        /// The name or alias this column is known under
        handle: Handle,
        /// The concrete column it targets
        target: Handle,
        /// Cryptographic ID of the column in the circuits
        id: u64,
    },
    /// An alias is validated as existing, but is not replaced; as substitution
    /// will take place in its own definition
    Alias { from: Handle, to: Box<Symbol> },
    /// A named expression is defined by `<expression> AS <name>`
    NamedExpression { name: Handle, e: Expr },
    /// A free-standing, anonymous, expression
    Expression(Expr),
    /// The wildcard selector: `*`
    Wildcard,
}
impl Symbol {
    /// Return, if any, the [`Handle`] under which a symbol is known in the
    /// current context.
    fn handle(&self) -> Option<&Handle> {
        match self {
            Symbol::ConcreteColumn { handle, .. } => Some(handle),
            Symbol::Alias { from, .. } => Some(from),
            Symbol::NamedExpression { name, .. } => Some(name),
            Symbol::Expression(_) => None,
            Symbol::Wildcard => None,
        }
    }

    /// Return whether this symbol could be referenced by `other`.
    fn matches(&self, other: &Handle) -> bool {
        self.handle().map(|h| h.matches(other)).unwrap_or(false)
    }
}
impl std::fmt::Display for Symbol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Symbol::ConcreteColumn { handle, target, .. } => write!(f, "{}: {}", handle, target),
            Symbol::Alias { from, to } => write!(f, "{}: {}", from, to),
            Symbol::NamedExpression { name, e } => write!(f, "{}: {}", name, e),
            Symbol::Expression(e) => write!(f, "{}", e),
            Symbol::Wildcard => write!(f, "*"),
        }
    }
}

/// The [`Kind`] of a [`Context`] defines how it behaves when being traversed.
#[derive(Debug)]
enum Kind {
    /// This context exposes symbols, and can not be traversed further.
    Standard,
    /// This context behaves transparently and delegates to its `providers`.
    Transparent,
    /// This context exposes the symbols it can reach, renaming their table
    /// name.
    TableAliasing(String),
    /// This context exposes the symbols it can reach under new names.
    FullAliasing { table: String, columns: Vec<String> },
}

/// A [`Context`] stores the symbols accessible at a given level in the AST, as
/// well as information to guide symbol retrieval.
///
/// A `Context` stores in `provides` the symbol that it exposes to its parent,
/// and in `providers` the sub-context it can leverage to resolve identifiers
/// living at its level.
///
/// For instance, for the following expression:
///
/// ```sql
/// SELECT a, b, FROM my_table
/// ```
///
/// the context at the `SELECT` level in the AST would **provide** the symbols
/// `a` and `b`, and have the `Context` matching `FROM my_table` as a provider.
/// Therefore, it could dip into the `FROM` [`Context`] to ensure that columns
/// `a` and `b` exists, and then hold them available for a putative parent
/// [`Context`] to use.
#[derive(Debug)]
struct Context {
    /// The name of this context - for debugging purpose.
    name: String,
    /// The kind of context, which drives traversal behavior.
    kind: Kind,
    /// The symbols exposed by this context.
    provides: Vec<Symbol>,
    /// The other contexts this ontext may call upon when resolving a symbol.
    providers: Vec<usize>,
}
impl Context {
    /// Create a new context with some space is pre-allocated for its
    /// variable-size members.
    fn new(name: String, kind: Kind) -> Self {
        Context {
            name,
            kind,
            provides: Vec::with_capacity(8),
            providers: Vec::with_capacity(2),
        }
    }

    /// Add a sub-context in which odentifier at this context level can be
    /// resolved.
    fn add_provider(&mut self, id: usize) {
        self.providers.push(id);
    }
}

impl Context {
    /// Insert a new symbol in the current context, ensuring it does not
    /// conflict with the existing ones.
    fn insert(&mut self, s: Symbol) -> Result<()> {
        for p in &self.provides {
            if p.matches(s.handle().unwrap()) {
                bail!("{} already known: {}", s, p)
            }
        }

        self.provides.push(s);
        Ok(())
    }
}

/// The `Resolver` is an AST pass, or visitor, that will ensure that all the
/// symbols in a query are valid and references known items.
struct Resolver<C: RootContextProvider> {
    /// A tree of [`Context`] mirroring the AST, whose nodes are the AST nodes
    /// introducing new contexts, i.e. `SELECT` and `FROM`.
    ///
    /// The tree topology is built through the `providers` links in the
    /// [`Context`].
    contexts: Vec<Context>,
    /// A handle to an object providing a register of the existing virtual
    /// tables and their columns.
    context: C,
    /// A stack of pointers to the currently active node in the context tree.
    /// The top of the stack points toward the currentlt active [`Context`]. New
    /// pointers are pushed when entering a new context, and popped when exiting
    /// it.
    pointer: Vec<usize>,
}
impl<C: RootContextProvider> Resolver<C> {
    /// Create a new empty [`Resolver`]
    fn new(context: C) -> Self {
        Resolver {
            contexts: vec![Context::new("<QUERY>".into(), Kind::Standard)],
            context,
            pointer: vec![0],
        }
    }

    fn rec_pretty(&self, i: usize, indent: usize) {
        let spacer = "  ".repeat(indent);
        let ctx = &self.contexts[i];
        println!("{}{}[{:?}]{}:", spacer, i, ctx.kind, ctx.name);
        for s in &ctx.provides {
            println!(
                "{} - {}",
                spacer,
                s.handle()
                    .map(|h| h.to_string())
                    .unwrap_or("unnamed symbol".into())
            )
        }
        println!();
        for n in &ctx.providers {
            self.rec_pretty(*n, indent + 1);
        }
    }
    /// Pretty-print the context tree.
    fn pretty(&self) {
        self.rec_pretty(0, 0);
    }

    /// Returns a list of all the symbols reachable from the [`Context`] `n`,
    /// i.e. that can be used for symbol resolution at its level.
    fn reachable(&self, n: usize) -> Result<Vec<Symbol>> {
        let ctx = &self.contexts[n];

        Ok(ctx
            .providers
            .iter()
            .map(|i| self.provided(*i))
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .flat_map(|x| x.into_iter())
            .collect())
    }

    /// Returns a list of all the symbols exposed by the [`Context`] `n` to its parent.
    fn provided(&self, n: usize) -> Result<Vec<Symbol>> {
        let ctx = &self.contexts[n];
        Ok(match &ctx.kind {
            // A standard context exposes the symbol it containts
            Kind::Standard => ctx.provides.clone(),
            // A transparent context delegates to its children
            Kind::Transparent => self.reachable(n)?,
            // A table aliaser rewrites the table name of the symbols it can reach
            Kind::TableAliasing(table) => {
                let mut accessibles = self.reachable(n)?;
                for s in accessibles.iter_mut() {
                    match s {
                        Symbol::ConcreteColumn { handle, .. } => {
                            handle.move_to_table(table);
                        }
                        Symbol::Alias { from, .. } => {
                            from.move_to_table(table);
                        }
                        Symbol::NamedExpression { name, .. } => {
                            name.move_to_table(table);
                        }
                        Symbol::Expression(_) => {}
                        Symbol::Wildcard => unreachable!(),
                    }
                }

                accessibles
            }
            // A full aliaser exposes the symbols it can reach, but renamed.
            Kind::FullAliasing { table, columns } => {
                let accessible = self.reachable(n)?;
                ensure!(columns.len() == accessible.len());
                columns
                    .iter()
                    .cloned()
                    .zip(accessible)
                    .map(|(alias, symbol)| Symbol::Alias {
                        from: Handle::Qualified {
                            table: table.clone(),
                            name: alias,
                        },
                        to: Box::new(symbol),
                    })
                    .collect()
            }
        })
    }

    /// Resolve a free-standing (non-qualified) identifier in the current
    /// context.
    fn resolve_freestanding(&self, symbol: &Ident) -> Result<Symbol> {
        self.resolve_handle(&Handle::Simple(symbol.value.clone()))
    }

    /// Resolve a qualified (e.g. `<table>.<name>`) identifier in the current
    /// context.
    fn resolve_compound(&self, compound: &[Ident]) -> Result<Symbol> {
        ensure!(
            compound.len() == 2,
            "`{compound:?}`: deeply coumpounded symbols are not supported"
        );

        self.resolve_handle(&Handle::Qualified {
            table: compound[0].value.clone(),
            name: compound[1].value.clone(),
        })
    }

    /// Find a unique symbol reachable from the current context matching the
    /// given [`Handle`].
    fn resolve_handle(&self, h: &Handle) -> Result<Symbol> {
        let pointer = *self.pointer.last().unwrap();

        let candidates = self
            .reachable(pointer)?
            .into_iter()
            .filter(|e| e.matches(h))
            .collect::<Vec<_>>();

        ensure!(
            !candidates.is_empty(),
            "symbol `{h}` not found in {}",
            self.contexts[pointer].name,
        );

        ensure!(
            candidates.len() <= 1,
            "symbol `{h}` ambiguous in {}",
            self.contexts[pointer].name
        );

        Ok(candidates[0].to_owned())
    }

    /// Ensure that the given function call is valid.
    fn resolve_function(&self, f: &Function) -> Result<()> {
        ensure!(f.name.0.len() == 1, "{}: unknown function `{}`", f, f.name);

        let fname = &f.name.0[0];

        match fname.value.as_str() {
            "AVG" | "SUM" | "COUNT" | "MIN" | "MAX" => Ok(()),
            _ => bail!("{}: unknown function `{}`", f, f.name),
        }
    }

    /// Enter a new context in the context tree, marking it as a provider to its
    /// parent.
    fn enter_context(&mut self, name: String, kind: Kind) {
        let new_id = self.contexts.len();
        self.contexts.push(Context::new(name, kind));
        self.contexts[*self.pointer.last().unwrap()].add_provider(new_id);
        self.pointer.push(new_id);
    }

    /// Exit the current context, moving the pointer back to its parent.
    fn exit_context(&mut self) {
        // Expand the wildcards that may be present in this context exposed
        // symbols.
        let pointer = *self.pointer.last().unwrap();
        let reached = self.reachable(pointer).unwrap();
        let new_provided = self.contexts[pointer]
            .provides
            .iter()
            .cloned()
            .flat_map(|s| {
                // If the symbol is normal, let it be; if it is a wildcard,
                // replace it by an integral copy of the symbols reachable from
                // this context.
                match s {
                    Symbol::Wildcard => reached.clone(),
                    _ => vec![s],
                }
                .into_iter()
            })
            .collect::<Vec<_>>();
        self.contexts[pointer].provides = new_provided;

        // Move back to the parent context.
        self.pointer.pop();
    }
}

impl<C: RootContextProvider> AstPass for Resolver<C> {
    fn post_expr(&mut self, e: &mut Expr) -> Result<()> {
        match e {
            // Identifier must be converted to JSON accesses into the ryhope tables.
            Expr::Identifier(symbol) => {
                if let Symbol::ConcreteColumn { target, .. } = self.resolve_freestanding(symbol)? {
                    *e = if let Handle::Qualified { table, name } = target {
                        Expr::BinaryOp {
                            left: Box::new(Expr::CompoundIdentifier(
                                [Ident::new(table), Ident::new("payload")].to_vec(),
                            )),
                            op: sqlparser::ast::BinaryOperator::Arrow,
                            right: Box::new(Expr::Identifier(Ident {
                                value: name.to_owned(),
                                quote_style: None,
                            })),
                        }
                    } else {
                        unreachable!()
                    }
                }
            }
            // Qualified identifiers must be converted to JSON accesses into the ryhope tables.
            Expr::CompoundIdentifier(compound) => {
                if let Symbol::ConcreteColumn { target, .. } = self.resolve_compound(compound)? {
                    *e = if let Handle::Qualified { table, name } = target {
                        Expr::BinaryOp {
                            left: Box::new(Expr::CompoundIdentifier(
                                [Ident::new(table), Ident::new("payload")].to_vec(),
                            )),
                            op: sqlparser::ast::BinaryOperator::Arrow,
                            right: Box::new(Expr::Identifier(Ident {
                                value: name.to_owned(),
                                quote_style: None,
                            })),
                        }
                    } else {
                        unreachable!()
                    }
                }
            }
            // Function call must be validated
            Expr::Function(f) => self.resolve_function(f)?,
            _ => {}
        }
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
                self.enter_context(format!("TableFactor: {table_factor}"), Kind::Standard);
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
                        let symbol = Symbol::ConcreteColumn {
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
                            id: column.id,
                        };

                        self.contexts
                            .last_mut()
                            .expect("never empty by construction")
                            .insert(symbol)?;
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
                self.enter_context(format!("{table_factor}"), kind);
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
        self.exit_context();
        Ok(())
    }

    /// SELECT always generate standard context, that will expose the SELECTed
    /// items to their parent while ensuring that they are actually contained in
    /// its providers.
    fn pre_select(&mut self, s: &mut Select) -> Result<()> {
        self.enter_context(format!("Select: {s}"), Kind::Standard);
        Ok(())
    }

    fn post_select(&mut self, _: &mut Select) -> Result<()> {
        self.exit_context();
        Ok(())
    }

    /// All the [`SelectItem`] in the SELECT clause are exposed to the current
    /// context parent.
    fn pre_select_item(&mut self, select_item: &mut SelectItem) -> Result<()> {
        self.contexts[*self.pointer.last().unwrap()]
            .provides
            .push(match select_item {
                SelectItem::ExprWithAlias { expr, alias } => Symbol::NamedExpression {
                    name: Handle::Simple(alias.value.clone()),
                    e: expr.clone(),
                },
                SelectItem::Wildcard(_) => Symbol::Wildcard,
                SelectItem::QualifiedWildcard(_, _) => unreachable!(),
                SelectItem::UnnamedExpr(e) => Symbol::Expression(e.clone()),
            });
        Ok(())
    }
}

/// Convert a query so that it can be executed on a ryhope-generated db.
pub fn resolve<C: RootContextProvider>(q: &Query, context: C) -> Result<Vec<Symbol>> {
    let mut converted_query = q.clone();
    let mut resolver = Resolver::new(context);
    converted_query.visit(&mut resolver)?;
    println!("Original query:\n>> {}", q);
    println!("Translated query:\n>> {}", converted_query);
    resolver.pretty();

    let exposed = resolver.reachable(0)?;
    println!("Exposed at the top level: {:?}", exposed);
    Ok(exposed)
}
