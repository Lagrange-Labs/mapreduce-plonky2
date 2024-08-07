use anyhow::*;
use mp2_common::F;
use serde::{Deserialize, Serialize};
use sqlparser::ast::{Function, Ident};
use std::{collections::HashMap, fmt::Debug};

/// A virtual table representing data extracted from a contract storage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkTable {
    /// The user-facing name of this table
    pub name: String,
    /// This table identifier in the circuits
    pub id: u64,
    /// Columns accessible from this table
    pub columns: Vec<ZkColumn>,
}

/// A scalar value accessible from a contract storage and exposed as a virtual
/// table column.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkColumn {
    /// The user-facing name of this column
    pub name: String,
    /// Whether this column is the cryptographic primary index
    pub is_primary_index: bool,
    /// The cryptographic ID of this column
    pub id: F,
}

/// A [`Handle`] defines an identifier in a SQL expression.
#[derive(PartialEq, Eq, Hash, Clone, Debug)]
pub enum Handle {
    /// A free-standing identifier, e.g. `price`
    Simple(String),
    /// A fully-qualified identifier, e.g. `contract2.price`
    Qualified { table: String, name: String },
}
impl Handle {
    /// Return whether two handles could refer to the same symbol.
    pub fn matches(&self, other: &Handle) -> bool {
        match (self, other) {
            (Handle::Simple(n1), Handle::Simple(n2)) => n1 == n2,
            (Handle::Simple(_), Handle::Qualified { .. }) => false,
            (Handle::Qualified { name, .. }, Handle::Simple(n)) => name == n,
            (
                Handle::Qualified { table, name },
                Handle::Qualified {
                    table: table2,
                    name: name2,
                },
            ) => table == table2 && name == name2,
        }
    }

    /// Rewrite this handle to make it refer to the given table name.
    pub fn move_to_table(&mut self, table: &str) {
        match self {
            Handle::Simple(name) => {
                *self = Handle::Qualified {
                    table: table.to_owned(),
                    name: name.clone(),
                }
            }
            Handle::Qualified { table, .. } => *table = table.clone(),
        }
    }
}
impl std::fmt::Display for Handle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Handle::Simple(name) => write!(f, "{}", name),
            Handle::Qualified { table, name } => write!(f, "{}.{}", table, name),
        }
    }
}

/// The `RootContextProvider` gives access to the root context for symbol
/// resolution in a query, i.e. the virtual columns representing the indexed
/// data from the contraact, and available in the JSON payload exposed by
/// Ryhope.
pub trait RootContextProvider {
    /// Return, if it exists, the structure of the given virtual table.
    fn fetch_table(&mut self, table_name: &str) -> Result<ZkTable>;

    /// Return the current block number
    fn current_block(&self) -> u64;
}

pub struct EmptyProvider;
impl RootContextProvider for EmptyProvider {
    fn fetch_table(&mut self, _table_name: &str) -> Result<ZkTable> {
        bail!("empty provider")
    }

    fn current_block(&self) -> u64 {
        0
    }
}

pub struct FileContextProvider {
    tables: HashMap<String, ZkTable>,
}
impl FileContextProvider {
    pub fn from_file(filename: &str) -> Result<Self> {
        let tables: Vec<ZkTable> = serde_json::from_reader(std::fs::File::open(filename)?)?;
        Ok(FileContextProvider {
            tables: tables.into_iter().map(|t| (t.name.clone(), t)).collect(),
        })
    }
}
impl RootContextProvider for FileContextProvider {
    fn fetch_table(&mut self, table_name: &str) -> Result<ZkTable> {
        self.tables
            .get(table_name)
            .cloned()
            .ok_or_else(|| anyhow!("table `{}` not found", table_name))
    }

    fn current_block(&self) -> u64 {
        2134
    }
}

pub struct PgsqlContextProvider {}
impl RootContextProvider for PgsqlContextProvider {
    fn fetch_table(&mut self, table_name: &str) -> Result<ZkTable> {
        todo!()
    }

    fn current_block(&self) -> u64 {
        todo!()
    }
}

/// The [`Kind`] of a [`Scope`] defines how it behaves when being traversed.
#[derive(Debug)]
pub enum Kind {
    /// This scope exposes symbols, and can not be traversed further.
    Standard,
    /// This scope behaves transparently and delegates to its `providers`.
    Transparent,
    /// This scope exposes the symbols it can reach, renaming their table
    /// name.
    TableAliasing(String),
    /// This scope exposes the symbols it can reach under new names.
    FullAliasing { table: String, columns: Vec<String> },
}

/// A [`Scope`] stores the symbols accessible at a given level in the AST, as
/// well as information to guide symbol retrieval.
///
/// A `Scope` stores in `provides` the symbol that it exposes to its parent,
/// and in `providers` the sub-scope it can leverage to resolve identifiers
/// living at its level.
///
/// For instance, for the following expression:
///
/// ```sql
/// SELECT a, b, FROM my_table
/// ```
///
/// the scope at the `SELECT` level in the AST would **provide** the symbols
/// `a` and `b`, and have the `Scope` matching `FROM my_table` as a provider.
/// Therefore, it could dip into the `FROM` [`Scope`] to ensure that columns
/// `a` and `b` exists, and then hold them available for a putative parent
/// [`Scope`] to use.
#[derive(Debug)]
pub struct Scope<M: Debug + Default, P: Debug + Clone> {
    /// The name of this scope - for debugging purpose.
    name: String,
    /// The kind of scope, which drives traversal behavior.
    kind: Kind,
    /// The symbols exposed by this scope.
    provides: Vec<Symbol<P>>,
    /// The other contexts this scope may call upon when resolving a symbol.
    providers: Vec<usize>,
    /// Metadata that may be attached to the scope by the caller
    metadata: M,
}
impl<M: Debug + Default, P: Debug + Clone> Scope<M, P> {
    /// Create a new scope with some space is pre-allocated for its
    /// variable-size members.
    fn new(name: String, kind: Kind) -> Self {
        Scope {
            name,
            kind,
            provides: Vec::with_capacity(8),
            providers: Vec::with_capacity(2),
            metadata: Default::default(),
        }
    }

    /// Add a sub-scope in which odentifier at this scope level can be
    /// resolved.
    pub fn add_provider(&mut self, id: usize) {
        self.providers.push(id);
    }

    /// Add a sub-scope in which odentifier at this scope level can be
    /// resolved.
    pub fn provides(&mut self, object: Symbol<P>) {
        self.provides.push(object);
    }

    /// Insert a new symbol in the current scope, ensuring it does not
    /// conflict with the existing ones.
    pub fn insert(&mut self, s: Symbol<P>) -> Result<()> {
        for p in &self.provides {
            if p.matches(s.handle().unwrap()) {
                bail!("{} already defined: {}", s, p)
            }
        }

        self.provides.push(s);
        Ok(())
    }

    pub fn metadata(&self) -> &M {
        &self.metadata
    }

    pub fn metadata_mut(&mut self) -> &mut M {
        &mut self.metadata
    }
}

/// A [`Symbol`] is anything that can be referenced from an SQL expression.
#[derive(Debug, Clone)]
pub enum Symbol<Payload: Debug + Clone> {
    /// A column directly handled by the SQL table that should not be changed, e.g. `valid_from`
    MetaColumn { handle: Handle, payload: Payload },
    /// A column must be replaced by <table>.payload -> <column>
    Column {
        /// The name or alias this column is known under
        handle: Handle,
        /// The concrete column it targets
        target: Handle,
        /// Index of the column
        payload: Payload,
        ///
        is_primary_index: bool,
    },
    /// An alias is validated as existing, but is not replaced, as substitution
    /// will take place in its own definition
    Alias {
        from: Handle,
        to: Box<Symbol<Payload>>,
    },
    /// A named expression is defined by `<expression> AS <name>`
    NamedExpression { name: Handle, payload: Payload },
    /// A free-standing, anonymous, expression
    Expression(Payload),
    /// The wildcard selector: `*`
    Wildcard,
}
impl<P: Debug + Clone> Symbol<P> {
    /// Return, if any, the [`Handle`] under which a symbol is known in the
    /// current scope.
    fn handle(&self) -> Option<&Handle> {
        match self {
            Symbol::MetaColumn { handle, .. } | Symbol::Column { handle, .. } => Some(handle),
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
impl<P: Debug + Clone> std::fmt::Display for Symbol<P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Symbol::MetaColumn { handle, .. } => write!(f, "__|{}|__", handle),
            Symbol::Column { handle, target, .. } => write!(f, "{}: {}", handle, target),
            Symbol::Alias { from, to } => write!(f, "{}: {}", from, to),
            Symbol::NamedExpression { name, payload: id } => write!(f, "{}: {:?}", name, id),
            Symbol::Expression(e) => write!(f, "{:?}", e),
            Symbol::Wildcard => write!(f, "*"),
        }
    }
}

/// A `ScopeTable` handles the hierarchy of symbols defining the symbol tables
/// of a query.
pub struct ScopeTable<M: Debug + Default, P: Debug + Clone> {
    /// A tree of [`Scope`] mirroring the AST, whose nodes are the AST nodes
    /// introducing new contexts, i.e. `SELECT` and `FROM`.
    ///
    /// The tree topology is built through the `providers` links in the
    /// [`Scope`].
    scopes: Vec<Scope<M, P>>,
    /// A stack of pointers to the currently active node in the context tree.
    /// The top of the stack points toward the currentlt active [`Scope`]. New
    /// pointers are pushed when entering a new context, and popped when exiting
    /// it.
    pointer: Vec<usize>,
}

impl<M: Debug + Default, P: Debug + Clone> ScopeTable<M, P> {
    pub fn new() -> Self {
        ScopeTable {
            scopes: vec![Scope::new("<QUERY>".into(), Kind::Standard)],
            pointer: vec![0],
        }
    }

    fn rec_pretty(&self, i: usize, indent: usize) {
        let spacer = "  ".repeat(indent);
        let ctx = &self.scopes[i];
        println!("{}{}[{:?}]{}:", spacer, i, ctx.kind, ctx.name);
        println!("{}Metadata: {:?}", spacer, ctx.metadata);
        for s in &ctx.provides {
            println!(
                "{} - {}",
                spacer,
                s.handle()
                    .map(|h| h.to_string())
                    .unwrap_or(format!("unnamed term: {}", s))
            )
        }
        println!();
        for n in &ctx.providers {
            self.rec_pretty(*n, indent + 1);
        }
    }

    /// Obtain a reference to the given scope.
    pub fn scope_at(&self, i: usize) -> &Scope<M, P> {
        &self.scopes[i]
    }

    /// Obtain a mutable reference to the given scope.
    pub fn scope_at_mut(&mut self, i: usize) -> &mut Scope<M, P> {
        &mut self.scopes[i]
    }

    /// Pretty-print the context tree.
    pub fn pretty(&self) {
        self.rec_pretty(0, 0);
    }

    /// Returns a list of all the symbols reachable from the [`Scope`] `n`,
    /// i.e. that can be used for symbol resolution at its level.
    pub fn reachable(&self, context_id: usize) -> Result<Vec<Symbol<P>>> {
        let ctx = &self.scopes[context_id];

        Ok(ctx
            .providers
            .iter()
            .map(|i| self.provided(*i))
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .flat_map(|x| x.into_iter())
            .collect())
    }

    /// Returns a list of all the symbols exposed by the [`Scope`] `n` to its parent.
    fn provided(&self, n: usize) -> Result<Vec<Symbol<P>>> {
        let ctx = &self.scopes[n];
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
                        Symbol::MetaColumn { .. } => {}
                        Symbol::Column { handle, .. } => {
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
    pub fn resolve_freestanding(&self, symbol: &Ident) -> Result<Symbol<P>> {
        self.resolve_handle(&Handle::Simple(symbol.value.clone()))
    }

    /// Resolve a string identifier in the current context.
    pub fn resolve_str(&self, symbol: &str) -> Result<Symbol<P>> {
        self.resolve_freestanding(&Ident::new(symbol))
    }

    /// Resolve a qualified (e.g. `<table>.<name>`) identifier in the current
    /// context.
    pub fn resolve_compound(&self, compound: &[Ident]) -> Result<Symbol<P>> {
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
    fn resolve_handle(&self, h: &Handle) -> Result<Symbol<P>> {
        let pointer = *self.pointer.last().unwrap();

        let candidates = self
            .reachable(pointer)?
            .into_iter()
            .filter(|e| e.matches(h))
            .collect::<Vec<_>>();

        ensure!(
            !candidates.is_empty(),
            "symbol `{h}` not found in {}",
            self.scopes[pointer].name,
        );

        ensure!(
            candidates.len() <= 1,
            "symbol `{h}` ambiguous in {}",
            self.scopes[pointer].name
        );

        Ok(candidates[0].to_owned())
    }

    /// Ensure that the given function call is valid.
    pub fn resolve_function(&self, f: &Function) -> Result<()> {
        ensure!(f.name.0.len() == 1, "{}: unknown function `{}`", f, f.name);

        let fname = &f.name.0[0];

        match fname.value.as_str() {
            "AVG" | "SUM" | "COUNT" | "MIN" | "MAX" => Ok(()),
            _ => bail!("{}: unknown function `{}`", f, f.name),
        }
    }

    /// Return a reference to the currently active scope.
    pub fn current_scope(&self) -> &Scope<M, P> {
        &self.scopes[*self.pointer.last().unwrap()]
    }

    /// Return a mutable reference to the currently active scope.
    pub fn current_scope_mut(&mut self) -> &mut Scope<M, P> {
        &mut self.scopes[*self.pointer.last().unwrap()]
    }

    /// Return a list of the symbols reachable from the current scope.
    pub fn currently_reachable(&self) -> Result<Vec<Symbol<P>>> {
        self.reachable(*self.pointer.last().unwrap())
    }

    /// Enter a new context in the context tree, marking it as a provider to its
    /// parent.
    pub fn enter_scope(&mut self, name: String, kind: Kind) {
        let new_id = self.scopes.len();
        self.scopes.push(Scope::new(name, kind));
        self.scopes[*self.pointer.last().unwrap()].add_provider(new_id);
        self.pointer.push(new_id);
    }

    /// Exit the current context, moving the pointer back to its parent.
    pub fn exit_scope(&mut self) -> Result<usize> {
        // Expand the wildcards that may be present in this context exposed
        // symbols.
        let pointer = *self.pointer.last().unwrap();
        let reached = self.currently_reachable().unwrap();
        let new_provided = self.scopes[pointer]
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
        self.scopes[pointer].provides = new_provided;

        // Jump back to the parent context.
        let previous = self.pointer.pop().unwrap();
        Ok(previous)
    }
}
