//! This module converts a user-defined query into one that can directly be
//! executed on the ryhope table containing the related data. The main steps
//! are:
//!
//! 1. convert virtual columns accesses into JSON payload access;
//!
//! 2. wrap the original query into a CTE to expand CoW row spans into
//!    individual column for each covered block number.
use std::{cell::OnceCell, default, thread::scope};

use alloy::primitives::U256;
use anyhow::*;
use log::warn;
use mp2_common::array::ToField;
use mp2_common::F;
use plonky2::field::types::Field;
use sqlparser::ast::{
    BinaryOperator, Expr, Function, FunctionArg, FunctionArgExpr, FunctionArguments, Ident, Query,
    Select, SelectItem, SetExpr, TableAlias, TableFactor, UnaryOperator, Value,
};
use verifiable_db::query::{
    computational_hash_ids::{AggregationOperation, Operation},
    universal_circuit::universal_circuit_inputs::{
        BasicOperation, InputOperand, OutputItem, ResultStructure,
    },
};

use crate::{
    symbols::{Handle, RootContextProvider},
    visitor::{AstPass, Visit},
};

// NOTE: not yet used
struct Leafer<'a, C: RootContextProvider> {
    resolver: &'a Resolver<C>,
    leafs: Vec<Symbol>,
}
impl<'a, C: RootContextProvider> Leafer<'a, C> {
    fn new(resolver: &'a Resolver<C>) -> Self {
        Self {
            resolver,
            leafs: Vec::new(),
        }
    }
}
impl<'a, C: RootContextProvider> AstPass for Leafer<'a, C> {
    fn pre_expr(&mut self, expr: &mut Expr) -> Result<()> {
        match expr {
            Expr::Identifier(e) => self.leafs.push(self.resolver.resolve_freestanding(e)?),
            Expr::CompoundIdentifier(c) => self.leafs.push(self.resolver.resolve_compound(c)?),
            _ => {}
        }
        Ok(())
    }
}

/// A Wire carry data that can be injected in universal query circuits. It
/// carries an index, whose sginification depends on the type of wire.
#[derive(Debug, Clone, PartialEq)]
enum Wire {
    /// A wire indexing an operation, either in the SELECT-sepcific or
    /// WHERE-specific operation storage.
    BasicOperation(usize),
    /// A wire carrying a column index.
    /// NOTE: this will have to be reworked when allowing JOINs.
    ColumnId(usize),
    /// A wire referring to the given constant in the constant storage.
    Constant(usize),
    /// A wire referring to a placeholder, carrying its natural index.
    PlaceHolder(usize),
    /// A wire associating an aggregation function to an existing wire
    Aggregation(AggregationOperation, Box<Wire>),
}
impl Wire {
    /// Extract the index carried by a wire.
    pub fn to_index(&self) -> usize {
        match self {
            Wire::BasicOperation(index)
            | Wire::Constant(index)
            | Wire::ColumnId(index)
            | Wire::PlaceHolder(index) => *index,
            Wire::Aggregation(_, _) => unreachable!(),
        }
    }
}

pub(crate) fn parse_placeholder(p: &str) -> Result<usize> {
    ensure!(p.starts_with("$"), "{p}: invalid placeholder");

    let number = p.trim_start_matches('$');
    number.parse().with_context(|| "failed to parse `{p}`")
}

/// A [`Symbol`] is anything that can be referenced from an SQL expression.
#[derive(Debug, Clone)]
enum Symbol {
    /// A column must be replaced by <table>.payload -> <column>
    Column {
        /// The name or alias this column is known under
        handle: Handle,
        /// The concrete column it targets
        target: Handle,
        /// Index of the column
        id: Wire,
        ///
        is_primary_index: bool,
    },
    /// An alias is validated as existing, but is not replaced, as substitution
    /// will take place in its own definition
    Alias { from: Handle, to: Box<Symbol> },
    /// A named expression is defined by `<expression> AS <name>`
    NamedExpression { name: Handle, id: Wire },
    /// A free-standing, anonymous, expression
    Expression(Wire),
    /// The wildcard selector: `*`
    Wildcard,
}
impl Symbol {
    /// Return, if any, the [`Handle`] under which a symbol is known in the
    /// current context.
    fn handle(&self) -> Option<&Handle> {
        match self {
            Symbol::Column { handle, .. } => Some(handle),
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

    fn to_wire_id(&self) -> Wire {
        match self {
            Symbol::NamedExpression { id, .. } | Symbol::Expression(id) => id.clone(),
            Symbol::Column { id, .. } => id.clone(),
            Symbol::Alias { from, to } => todo!(),
            Symbol::Wildcard => todo!(),
        }
    }
}
impl std::fmt::Display for Symbol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Symbol::Column { handle, target, .. } => write!(f, "{}: {}", handle, target),
            Symbol::Alias { from, to } => write!(f, "{}: {}", from, to),
            Symbol::NamedExpression { name, id } => write!(f, "{}: {:?}", name, id),
            Symbol::Expression(e) => write!(f, "{:?}", e),
            Symbol::Wildcard => write!(f, "*"),
        }
    }
}

/// The [`Kind`] of a [`Scope`] defines how it behaves when being traversed.
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

/// This struct aggregates the data from which the universal query circuit
/// public inputs will be built.
#[derive(Debug, Default)]
struct CircuitData {
    /// The SELECTed items
    outputs: Vec<OutputItem>,
    /// The aggregation operation to apply to the `outputs`
    aggregation: Vec<AggregationOperation>,
    /// The mutually-referencing operations composing the WHERE predicate; by
    /// convention, the root expression is at the last position.
    predicates: UniqueStorage<BasicOperation>,
}

/// During the compilation step, the resulting operations and wires may be
/// stored either as query operations if the apply to the SELECTed terms, or as
/// predicate operations if the make up the WHERE term.
#[derive(Clone, Copy)]
enum StorageTarget {
    /// Store the compilation object as SELECT-related
    Query,
    /// Store the compilation object as WHERE-related
    Predicate,
}

/// A light wrapper over a Vec that avoids inserting twice the same element,
/// while keeping the indexable propoerty of a vector.
#[derive(Debug, Clone)]
struct UniqueStorage<T: PartialEq> {
    ops: Vec<T>,
}
impl<T: PartialEq> Default for UniqueStorage<T> {
    fn default() -> Self {
        Self { ops: Vec::new() }
    }
}
impl<T: PartialEq> UniqueStorage<T> {
    /// Insert the given element into the storage, returning its index. If the
    /// operation already exist, its current index is returned; otherwise, it is
    /// inserted and its index is returned.
    fn insert(&mut self, op: T) -> usize {
        if let Some(existing) =
            self.ops
                .iter()
                .enumerate()
                .find_map(|(i, o)| if *o == op { Some(i) } else { None })
        {
            existing
        } else {
            let new_id = self.ops.len();
            self.ops.push(op);
            new_id
        }
    }

    fn get(&self, i: usize) -> &T {
        self.ops.get(i).unwrap()
    }
}

/// A [`Scope`] stores the symbols accessible at a given level in the AST, as
/// well as information to guide symbol retrieval.
///
/// A `Scope` stores in `provides` the symbol that it exposes to its parent,
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
/// `a` and `b`, and have the `Scope` matching `FROM my_table` as a provider.
/// Therefore, it could dip into the `FROM` [`Scope`] to ensure that columns
/// `a` and `b` exists, and then hold them available for a putative parent
/// [`Scope`] to use.
#[derive(Debug)]
struct Scope {
    /// The name of this context - for debugging purpose.
    name: String,
    /// The kind of context, which drives traversal behavior.
    kind: Kind,
    /// The symbols exposed by this context.
    provides: Vec<Symbol>,
    /// The other contexts this context may call upon when resolving a symbol.
    providers: Vec<usize>,
    circuit_data: CircuitData,
}
impl Scope {
    /// Create a new context with some space is pre-allocated for its
    /// variable-size members.
    fn new(name: String, kind: Kind) -> Self {
        Scope {
            name,
            kind,
            provides: Vec::with_capacity(8),
            providers: Vec::with_capacity(2),
            circuit_data: Default::default(),
        }
    }

    /// Add a sub-context in which odentifier at this context level can be
    /// resolved.
    fn add_provider(&mut self, id: usize) {
        self.providers.push(id);
    }
}

impl Scope {
    /// Insert a new symbol in the current context, ensuring it does not
    /// conflict with the existing ones.
    fn insert(&mut self, s: Symbol) -> Result<()> {
        for p in &self.provides {
            if p.matches(s.handle().unwrap()) {
                bail!("{} already defined: {}", s, p)
            }
        }

        self.provides.push(s);
        Ok(())
    }
}

/// The `Resolver` is an AST pass, or visitor, that will ensure that all the
/// symbols in a query are valid and references known items.
pub(crate) struct Resolver<C: RootContextProvider> {
    /// A tree of [`Scope`] mirroring the AST, whose nodes are the AST nodes
    /// introducing new contexts, i.e. `SELECT` and `FROM`.
    ///
    /// The tree topology is built through the `providers` links in the
    /// [`Scope`].
    scopes: Vec<Scope>,
    /// A handle to an object providing a register of the existing virtual
    /// tables and their columns.
    context: C,
    /// A stack of pointers to the currently active node in the context tree.
    /// The top of the stack points toward the currentlt active [`Scope`]. New
    /// pointers are pushed when entering a new context, and popped when exiting
    /// it.
    pointer: Vec<usize>,
    /// A storage for the SELECT-involved operations.
    query_ops: UniqueStorage<BasicOperation>,
    /// The query-global immediate values storage.
    constants: UniqueStorage<U256>,
}
impl<C: RootContextProvider> Resolver<C> {
    /// Create a new empty [`Resolver`]
    fn new(context: C) -> Self {
        Resolver {
            scopes: vec![Scope::new("<QUERY>".into(), Kind::Standard)],
            context,
            pointer: vec![0],
            query_ops: Default::default(),
            constants: Default::default(),
        }
    }

    fn rec_pretty(&self, i: usize, indent: usize) {
        let spacer = "  ".repeat(indent);
        let ctx = &self.scopes[i];
        println!("{}{}[{:?}]{}:", spacer, i, ctx.kind, ctx.name);
        println!("{}Predicates: {:?}", spacer, ctx.circuit_data.predicates);
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
    /// Pretty-print the context tree.
    fn pretty(&self) {
        self.rec_pretty(0, 0);
    }

    /// Returns a list of all the symbols reachable from the [`Scope`] `n`,
    /// i.e. that can be used for symbol resolution at its level.
    fn reachable(&self, context_id: usize) -> Result<Vec<Symbol>> {
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

    /// Insert, if needed, a new constant in the constant register and returns its index.
    fn new_constant(&mut self, value: U256) -> Wire {
        Wire::Constant(self.constants.insert(value))
    }

    /// Returns a list of all the symbols exposed by the [`Scope`] `n` to its parent.
    fn provided(&self, n: usize) -> Result<Vec<Symbol>> {
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
    fn resolve_function(&self, f: &Function) -> Result<()> {
        ensure!(f.name.0.len() == 1, "{}: unknown function `{}`", f, f.name);

        let fname = &f.name.0[0];

        match fname.value.as_str() {
            "AVG" | "SUM" | "COUNT" | "MIN" | "MAX" => Ok(()),
            _ => bail!("{}: unknown function `{}`", f, f.name),
        }
    }

    /// Return a reference to the currently active scope.
    fn current_scope(&self) -> &Scope {
        &self.scopes[*self.pointer.last().unwrap()]
    }

    /// Return a mutable reference to the currently active scope.
    fn current_scope_mut(&mut self) -> &mut Scope {
        &mut self.scopes[*self.pointer.last().unwrap()]
    }

    /// Return a list of the symbols reachable from the current scope.
    fn currently_reachable(&self) -> Result<Vec<Symbol>> {
        self.reachable(*self.pointer.last().unwrap())
    }

    /// Enter a new context in the context tree, marking it as a provider to its
    /// parent.
    fn enter_scope(&mut self, name: String, kind: Kind) {
        let new_id = self.scopes.len();
        self.scopes.push(Scope::new(name, kind));
        self.scopes[*self.pointer.last().unwrap()].add_provider(new_id);
        self.pointer.push(new_id);
    }

    /// Exit the current context, moving the pointer back to its parent.
    fn exit_scope(&mut self) -> Result<()> {
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

        // Prepare the data that will be used to generate the circuit PIs
        let mut output_items = Vec::new();
        let mut aggregations = Vec::new();
        for r in self.reachable(0)?.into_iter() {
            match r {
                Symbol::Column { id, .. }
                | Symbol::NamedExpression { id, .. }
                | Symbol::Expression(id) => {
                    let (aggregation, output_item) = self.to_output_expression(id, false)?;
                    output_items.push(output_item);
                    aggregations.push(aggregation);
                }
                Symbol::Alias { .. } => {}
                Symbol::Wildcard => unreachable!(),
            };
        }
        self.scopes[pointer].provides = new_provided;
        self.scopes[pointer].circuit_data.outputs = output_items;
        self.scopes[pointer].circuit_data.aggregation = aggregations;

        // Jump back to the parent context.
        self.pointer.pop();
        Ok(())
    }

    /// Recursively convert the given expression into an assembly of circuit PI
    /// objects.
    ///
    /// `storage_target` determines whether the circuit ojects should be stored
    /// in the SELECT-specific or the WHERE-specific storage target.
    fn compile(&mut self, expr: &mut Expr, storage_target: StorageTarget) -> Result<Symbol> {
        match expr {
            Expr::Value(v) => Ok(Symbol::Expression(match v {
                Value::Number(x, _) => self.new_constant(x.parse().unwrap()),
                Value::Placeholder(p) => Wire::PlaceHolder(parse_placeholder(p)?),
                _ => unreachable!(),
            })),
            Expr::Identifier(s) => Ok(Symbol::Expression(
                self.resolve_freestanding(s)?.to_wire_id(),
            )),
            Expr::Nested(e) => self.compile(e, storage_target),
            Expr::CompoundIdentifier(c) => self.resolve_compound(c),
            Expr::BinaryOp { left, op, right } => {
                let first_operand = self.compile(left, storage_target)?;
                let second_operand = self.compile(right, storage_target)?;
                let op = match op {
                    BinaryOperator::Plus => Operation::AddOp,
                    BinaryOperator::Minus => Operation::SubOp,
                    BinaryOperator::Multiply => Operation::MulOp,
                    BinaryOperator::Divide => Operation::DivOp,
                    BinaryOperator::Modulo => Operation::ModOp,
                    BinaryOperator::Eq => Operation::EqOp,
                    BinaryOperator::NotEq => Operation::NeOp,
                    BinaryOperator::Gt => Operation::GreaterThanOp,
                    BinaryOperator::Lt => Operation::LessThanOp,
                    BinaryOperator::GtEq => Operation::GreaterThanOrEqOp,
                    BinaryOperator::LtEq => Operation::LessThanOrEqOp,
                    BinaryOperator::And => Operation::AndOp,
                    BinaryOperator::Or => Operation::OrOp,
                    BinaryOperator::Xor => Operation::XorOp,
                    _ => unreachable!(),
                };
                let first_operand = self.to_operand(&first_operand);
                let second_operand = self.to_operand(&second_operand);
                let operation = BasicOperation {
                    first_operand,
                    second_operand: Some(second_operand),
                    op,
                };
                let new_id = Wire::BasicOperation(match storage_target {
                    StorageTarget::Query => self.query_ops.insert(operation),
                    StorageTarget::Predicate => self
                        .current_scope_mut()
                        .circuit_data
                        .predicates
                        .insert(operation),
                });

                Ok(Symbol::Expression(new_id))
            }
            Expr::UnaryOp { op, expr } => match op {
                UnaryOperator::Not => {
                    let first_operand = self.compile(expr, storage_target)?;
                    let first_operand = self.to_operand(&first_operand);
                    let operation = BasicOperation {
                        first_operand,
                        second_operand: None,
                        op: Operation::NotOp,
                    };
                    let new_id = Wire::BasicOperation(match storage_target {
                        StorageTarget::Query => self.query_ops.insert(operation),
                        StorageTarget::Predicate => self
                            .current_scope_mut()
                            .circuit_data
                            .predicates
                            .insert(operation),
                    });
                    Ok(Symbol::Expression(new_id))
                }
                _ => unreachable!(),
            },
            Expr::Function(funcall) => {
                let fname = &funcall.name.0[0];
                let agg = match fname.value.to_uppercase().as_str() {
                    "AVG" => AggregationOperation::AvgOp,
                    "SUM" => AggregationOperation::SumOp,
                    "MIN" => AggregationOperation::MinOp,
                    "MAX" => AggregationOperation::MaxOp,
                    "COUNT" => AggregationOperation::CountOp,
                    _ => unreachable!(),
                };

                if let FunctionArguments::List(arglist) = &mut funcall.args {
                    match &mut arglist.args[0] {
                        FunctionArg::Unnamed(FunctionArgExpr::Expr(e)) => {
                            let wire = self.compile(e, storage_target)?;
                            Ok(Symbol::Expression(Wire::Aggregation(
                                agg,
                                Box::new(wire.to_wire_id()),
                            )))
                        }
                        _ => unreachable!(),
                    }
                } else {
                    unreachable!()
                }
            }
            _ => unreachable!(),
        }
    }

    /// Create an operand from the given wire.
    fn to_operand(&self, s: &Symbol) -> InputOperand {
        match s {
            Symbol::Column { id, .. } => InputOperand::Column(id.to_index()),
            Symbol::NamedExpression { id, .. } | Symbol::Expression(id) => match id {
                Wire::BasicOperation(idx) => InputOperand::PreviousValue(*idx),
                Wire::ColumnId(idx) => InputOperand::Column(*idx),
                Wire::Constant(idx) => InputOperand::Constant(self.constants.get(*idx).clone()),
                Wire::PlaceHolder(idx) => InputOperand::Placeholder(F::from_canonical_usize(*idx)),
                Wire::Aggregation(_, _) => unreachable!("an aggregation can not be an operand"),
            },
            _ => unreachable!(),
        }
    }

    /// Create an output and its associated aggregation function from a wire.
    fn to_output_expression(
        &self,
        wire_id: Wire,
        in_aggregation: bool,
    ) -> Result<(AggregationOperation, OutputItem)> {
        match wire_id {
            Wire::BasicOperation(i) => {
                Ok((AggregationOperation::IdOp, OutputItem::ComputedValue(i)))
            }
            Wire::ColumnId(i) => Ok((AggregationOperation::IdOp, OutputItem::Column(i))),
            Wire::Aggregation(agg, sub_wire_id) => {
                ensure!(!in_aggregation, "recursive aggregation detected");
                Ok((agg, self.to_output_expression(*sub_wire_id, true)?.1))
            }
            Wire::Constant(_) => unreachable!("top-level immediate values are not supported"),
            Wire::PlaceHolder(_) => unreachable!("top-level placeholders are not supported"),
        }
    }

    /// Generate appropriate universal query circuit PIs from the root context
    /// of this Resolver.
    fn to_pis(&self) -> CircuitPis {
        let root_scope = &self.scopes[1];
        let result = ResultStructure::from((
            self.query_ops.ops.clone(),
            root_scope.circuit_data.outputs.clone(),
        ));

        CircuitPis {
            result,
            // TODO:
            column_ids: vec![],
            query_aggregations: root_scope
                .circuit_data
                .aggregation
                .iter()
                .map(|x| x.to_field())
                .collect(),
            predication_operations: root_scope.circuit_data.predicates.ops.clone(),
        }
    }
}

#[derive(Debug)]
struct CircuitPis {
    result: ResultStructure,
    query_aggregations: Vec<F>,
    column_ids: Vec<F>,
    predication_operations: Vec<BasicOperation>,
}

impl<C: RootContextProvider> AstPass for Resolver<C> {
    // NOTE: will be used later
    // fn post_expr(&mut self, e: &mut Expr) -> Result<()> {
    //     match e {
    //         // Identifier must be converted to JSON accesses into the ryhope tables.
    //         Expr::Identifier(symbol) => {
    //             if let Symbol::Column { target, .. } = self.resolve_freestanding(symbol)? {
    //                 *e = if let Handle::Qualified { table, name } = target {
    //                     Expr::BinaryOp {
    //                         left: Box::new(Expr::CompoundIdentifier(
    //                             [Ident::new(table), Ident::new("payload")].to_vec(),
    //                         )),
    //                         op: sqlparser::ast::BinaryOperator::Arrow,
    //                         right: Box::new(Expr::Identifier(Ident::with_quote('\'', name))),
    //                     }
    //                 } else {
    //                     unreachable!()
    //                 }
    //             }
    //         }
    //         // Qualified identifiers must be converted to JSON accesses into the ryhope tables.
    //         Expr::CompoundIdentifier(compound) => {
    //             if let Symbol::Column { target, .. } = self.resolve_compound(compound)? {
    //                 *e = if let Handle::Qualified { table, name } = target {
    //                     Expr::BinaryOp {
    //                         left: Box::new(Expr::CompoundIdentifier(
    //                             [Ident::new(table), Ident::new("payload")].to_vec(),
    //                         )),
    //                         op: sqlparser::ast::BinaryOperator::Arrow,
    //                         right: Box::new(Expr::Identifier(Ident::with_quote('\'', name))),
    //                     }
    //                 } else {
    //                     unreachable!()
    //                 }
    //             }
    //         }
    //         // Function call must be validated
    //         Expr::Function(f) => self.resolve_function(f)?,
    //         _ => {}
    //     }
    //     Ok(())
    // }

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
                self.enter_scope(format!("TableFactor: {table_factor}"), Kind::Standard);
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
                            id: Wire::ColumnId(i),
                            is_primary_index: column.is_primary_index,
                        };

                        self.scopes
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
                self.enter_scope(format!("{table_factor}"), kind);
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
        self.enter_scope(format!("Select: {s}"), Kind::Standard);
        Ok(())
    }

    fn post_select(&mut self, select: &mut Select) -> Result<()> {
        if let Some(predicate) = select.selection.as_mut() {
            // As the expression are traversed depth-first, the top level
            // expression will mechnically find itself at the last position, as
            // required by the universal query circuit API.
            self.compile(predicate, StorageTarget::Predicate)?;
        }
        self.exit_scope()
    }

    fn post_query(&mut self, query: &mut Query) -> Result<()> {
        if let SetExpr::Select(_) = *query.body {
            if let Some(order_by) = query.order_by.as_mut() {
                for order_by_expr in order_by.exprs.iter_mut() {
                    let wire_id = self
                        .compile(&mut order_by_expr.expr, StorageTarget::Query)?
                        .to_wire_id();
                    ensure!(
                        self.currently_reachable()?
                            .iter()
                            .map(|s| s.to_wire_id())
                            .any(|w| w == wire_id),
                        "ORDER BY criterions must be a subset of the SELECT expressions; `{}` not found",
                        order_by_expr
                    )
                }
            }
        }

        Ok(())
    }

    /// All the [`SelectItem`] in the SELECT clause are exposed to the current
    /// context parent.
    fn pre_select_item(&mut self, select_item: &mut SelectItem) -> Result<()> {
        let provided = match select_item {
            SelectItem::ExprWithAlias { expr, alias } => Symbol::NamedExpression {
                name: Handle::Simple(alias.value.clone()),
                id: self.compile(expr, StorageTarget::Query)?.to_wire_id(),
            },
            SelectItem::UnnamedExpr(e) => match e {
                Expr::Identifier(i) => self.resolve_freestanding(i)?,
                Expr::CompoundIdentifier(is) => self.resolve_compound(is)?,
                _ => Symbol::Expression(self.compile(e, StorageTarget::Query)?.to_wire_id()),
            },
            SelectItem::Wildcard(_) => Symbol::Wildcard,
            SelectItem::QualifiedWildcard(_, _) => unreachable!(),
        };
        self.scopes[*self.pointer.last().unwrap()]
            .provides
            .push(provided);
        Ok(())
    }
}

// NOTE: will be used later
// /// Wrap an existing query to demultiplicate and annotate each row with `block`
// /// ranging from `valid_from` to `valid_until`.
// fn expand_block_range(mut q: Query) -> Query {
//     // Save the original projection queried by the user
//     if let SetExpr::Select(ref mut select) = &mut *q.body {
//         // Filter out `block` if it has explicitely been selected by the user,
//         // it will be injected back later
//         select.projection.retain(|p| match p {
//             SelectItem::UnnamedExpr(e) => match e {
//                 Expr::Identifier(id) => id.value != "block",
//                 _ => true,
//             },
//             SelectItem::ExprWithAlias { expr, alias } => todo!(),
//             _ => true,
//         });
//         for additional_column in ["valid_from", "valid_until"] {
//             select
//                 .projection
//                 .push(SelectItem::UnnamedExpr(Expr::Identifier(Ident::new(
//                     additional_column,
//                 ))));
//         }
//     } else {
//         unreachable!()
//     };

//     Query {
//         with: None,
//         body: Box::new(SetExpr::Select(Box::new(Select {
//             distinct: None,
//             top: None,
//             projection: vec![
//                 SelectItem::Wildcard(WildcardAdditionalOptions::default()),
//                 SelectItem::ExprWithAlias {
//                     expr: Expr::Function(Function {
//                         name: ObjectName(vec![Ident::new("generate_series")]),
//                         parameters: FunctionArguments::None,
//                         args: FunctionArguments::List(FunctionArgumentList {
//                             duplicate_treatment: None,
//                             args: vec![
//                                 FunctionArg::Unnamed(FunctionArgExpr::Expr(Expr::Identifier(
//                                     Ident::new("valid_from"),
//                                 ))),
//                                 FunctionArg::Unnamed(FunctionArgExpr::Expr(Expr::Identifier(
//                                     Ident::new("valid_until"),
//                                 ))),
//                             ],
//                             clauses: vec![],
//                         }),
//                         filter: None,
//                         null_treatment: None,
//                         over: None,
//                         within_group: vec![],
//                     }),
//                     alias: Ident::new("block"),
//                 },
//             ],
//             into: None,
//             from: vec![TableWithJoins {
//                 relation: TableFactor::Derived {
//                     lateral: false,
//                     subquery: Box::new(q),
//                     alias: Some(TableAlias {
//                         name: Ident::new("user_query"),
//                         columns: vec![],
//                     }),
//                 },
//                 joins: vec![],
//             }],
//             lateral_views: vec![],
//             prewhere: None,
//             selection: None,
//             group_by: GroupByExpr::Expressions(vec![], vec![]),
//             cluster_by: vec![],
//             distribute_by: vec![],
//             sort_by: vec![],
//             having: None,
//             named_window: vec![],
//             qualify: None,
//             window_before_qualify: false,
//             value_table_mode: None,
//             connect_by: None,
//         }))),
//         order_by: None,
//         limit: None,
//         limit_by: vec![],
//         offset: None,
//         fetch: None,
//         locks: vec![],
//         for_clause: None,
//         settings: None,
//         format_clause: None,
//     }
// }

/// Convert a query so that it can be executed on a ryhope-generated db.
pub fn resolve<C: RootContextProvider>(q: &Query, context: C) -> Result<()> {
    let mut converted_query = q.clone();
    let mut resolver = Resolver::new(context);
    converted_query.visit(&mut resolver)?;
    println!("Original query:\n>> {}", q);
    println!("Translated query:\n>> {}", converted_query);

    resolver.pretty();

    println!("Query ops:");
    for (i, op) in resolver.query_ops.ops.iter().enumerate() {
        println!("     {i}: {op:?}");
    }

    println!("Sent to circuit:");
    println!("{:#?}", resolver.to_pis());

    Ok(())
}
