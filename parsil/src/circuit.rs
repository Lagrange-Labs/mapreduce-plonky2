//! This module converts a user-defined query into one that can directly be
//! executed on the ryhope table containing the related data. The main steps
//! are:
//!
//! 1. convert virtual columns accesses into JSON payload access;
//!
//! 2. wrap the original query into a CTE to expand CoW row spans into
//!    individual column for each covered block number.
use alloy::primitives::U256;
use anyhow::*;
use log::warn;
use mp2_common::{array::ToField, F};
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

/// A Wire carry data that can be injected in universal query circuits. It
/// carries an index, whose sginification depends on the type of wire.
#[derive(Debug, Clone, PartialEq)]
enum Wire {
    /// A wire indexing an operation, either in the SELECT-specific or
    /// WHERE-specific operation storage.
    BasicOperation(usize),
    /// A wire carrying a column index in the column register.
    /// NOTE: this will have to be reworked when allowing JOINs.
    ColumnId(usize),
    /// A wire referring to the given constant in the constant storage.
    Constant(usize),
    /// A wire referring to a placeholder, carrying its natural index.
    PlaceHolder(PlaceholderIdentifier),
    /// A wire associating an aggregation function to an existing wire
    Aggregation(AggregationOperation, Box<Wire>),
}
impl Wire {
    /// Extract the index carried by a wire.
    pub fn to_index(&self) -> usize {
        match self {
            Wire::BasicOperation(index) | Wire::Constant(index) | Wire::ColumnId(index) => *index,
            Wire::PlaceHolder(_) | Wire::Aggregation(_, _) => unreachable!(),
        }
    }
}

impl Symbol<Wire> {
    fn to_wire_id(&self) -> Wire {
        match self {
            Symbol::NamedExpression { payload, .. }
            | Symbol::Expression(payload)
            | Symbol::Column { payload, .. } => payload.clone(),
            Symbol::Alias { .. } => todo!(),
            Symbol::Wildcard => todo!(),
        }
    }
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
#[derive(Clone)]
enum StorageTarget {
    /// Store the compilation object as SELECT-related
    Query,
    /// Store the compilation object as WHERE-related
    Predicate,
    /// An immediately accumulating storage target
    Immediate(Vec<BasicOperation>),
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
    scopes: ScopeTable<CircuitData, Wire>,
    /// A storage for the SELECT-involved operations.
    query_ops: UniqueStorage<BasicOperation>,
    /// The query-global immediate value storage.
    constants: UniqueStorage<U256>,
    /// The query-global column storage, mapping a column index to a
    /// cryptographic column ID.
    columns: Vec<u64>,
    secondary_index_bounds: Bounds,
}
impl<'a, C: ContextProvider> Assembler<'a, C> {
    /// Create a new empty [`Resolver`]
    fn new(settings: &'a ParsilSettings<C>) -> Self {
        Assembler {
            settings,
            scopes: ScopeTable::<CircuitData, Wire>::new(),
            query_ops: Default::default(),
            constants: Default::default(),
            columns: Vec::new(),
            secondary_index_bounds: Default::default(),
        }
    }

    fn exit_scope(&mut self) -> Result<()> {
        let exited_scope = self.scopes.exit_scope()?;

        // Prepare the data that will be used to generate the circuit PIs
        let mut output_items = Vec::new();
        let mut aggregations = Vec::new();
        for r in self.scopes.currently_reachable()?.into_iter() {
            match r {
                Symbol::Column { payload: id, .. }
                | Symbol::NamedExpression { payload: id, .. }
                | Symbol::Expression(id) => {
                    let (aggregation, output_item) = self.to_output_expression(id, false)?;
                    output_items.push(output_item);
                    aggregations.push(aggregation);
                }
                Symbol::Alias { .. } => {}
                Symbol::Wildcard => unreachable!(),
            };
        }
        self.scopes
            .scope_at_mut(exited_scope)
            .metadata_mut()
            .outputs = output_items;
        self.scopes
            .scope_at_mut(exited_scope)
            .metadata_mut()
            .aggregation = aggregations;

        Ok(())
    }

    /// Insert, if needed, a new constant in the constant register and returns its index.
    fn new_constant(&mut self, value: U256) -> Wire {
        Wire::Constant(self.constants.insert(value))
    }

    /// Return whether an [`InputOperand`] is only function of constants and/or
    /// placeholders.
    fn is_operand_static(&self, operand: &InputOperand) -> bool {
        match operand {
            InputOperand::Placeholder(_) | InputOperand::Constant(_) => true,
            InputOperand::Column(_) => false,
            InputOperand::PreviousValue(idx) => self.is_operation_static(&self.query_ops.ops[*idx]),
        }
    }

    /// Return whether a [`BasicOperations`] is only function of constants and/or
    /// placeholders.
    fn is_operation_static(&self, op: &BasicOperation) -> bool {
        self.is_operand_static(&op.first_operand)
            && op
                .second_operand
                .map(|operand| self.is_operand_static(&operand))
                .unwrap_or(true)
    }

    /// Return whether a [`Wire`] is only function of constants and/or
    /// placeholders.
    fn is_wire_static(&self, wire: &Wire) -> bool {
        match wire {
            Wire::BasicOperation(idx) => self.is_operation_static(&self.query_ops.ops[*idx]),
            Wire::ColumnId(_) => false,
            Wire::Constant(_) => true,
            Wire::PlaceHolder(_) => true,
            Wire::Aggregation(_, _) => false,
        }
    }

    /// Return true if, within the current scope, the given symbol is
    /// computable as an expression of constants and placeholders.
    fn is_symbol_static(&self, s: &Symbol<Wire>) -> bool {
        match s {
            Symbol::Column { .. } => false,
            Symbol::Alias { to, .. } => self.is_symbol_static(to),
            Symbol::NamedExpression { payload, .. } => self.is_wire_static(&payload),
            Symbol::Expression(_) => todo!(),
            Symbol::Wildcard => false,
        }
    }

    /// Return true if, within the current scope, the given expression is
    /// computable as an expression of constants and placeholders.
    fn is_expr_static(&self, e: &Expr) -> Result<bool> {
        Ok(match e {
            Expr::Identifier(s) => self.is_symbol_static(&self.scopes.resolve_freestanding(s)?),
            Expr::CompoundIdentifier(c) => self.is_symbol_static(&self.scopes.resolve_compound(c)?),
            Expr::BinaryOp { left, right, .. } => {
                self.is_expr_static(left)? && self.is_expr_static(right)?
            }
            Expr::UnaryOp { expr, .. } => self.is_expr_static(expr)?,
            Expr::Nested(e) => self.is_expr_static(e)?,
            Expr::Value(_) => true,

            _ => false,
        })
    }

    /// Return the depth of the given expression, in terms of [`BasicOperation`] it will take to encode.
    fn depth(&self, e: &Expr) -> usize {
        match e {
            Expr::Identifier(_) | Expr::CompoundIdentifier(_) => 0,
            Expr::BinaryOp { left, right, .. } => 1 + self.depth(left).max(self.depth(right)),
            Expr::UnaryOp { expr, .. } => 1 + self.depth(expr),
            Expr::Nested(e) => self.depth(e),
            Expr::Value(_) => 0,
            _ => unreachable!(),
        }
    }

    /// Return whether the given `Symbol` encodes the secondary index column.
    fn is_symbol_secondary_idx(&self, s: &Symbol<Wire>) -> bool {
        match s {
            Symbol::Column { kind, .. } => *kind == ColumnKind::SecondaryIndex,
            Symbol::Alias { to, .. } => self.is_symbol_secondary_idx(to),
            _ => false,
        }
    }

    /// Return whether, in the current scope, the given expression refers to the
    /// secondary index.
    fn is_secondary_index(&self, expr: &Expr) -> Result<bool> {
        Ok(match expr {
            Expr::Identifier(s) => {
                self.is_symbol_secondary_idx(&self.scopes.resolve_freestanding(s)?)
            }
            Expr::CompoundIdentifier(c) => {
                self.is_symbol_secondary_idx(&self.scopes.resolve_compound(c)?)
            }

            _ => false,
        })
    }

    /// Convert the given [`Expr`] a [`QueryBoundSource`]. It is assumed that
    /// the input expression has already been checked for correctness for use as
    /// a SID bound, which means that it resolves correctly, that its depth is
    /// less than two, and that it is static.
    fn expression_to_boundary(&mut self, expr: &Expr) -> QueryBoundSource {
        // A SID can only be bound by only one BasicOperation, that must not be
        // stored along the query operations. Therefore we use an immediate
        // storage, whose length will later down checked to be less than two.
        let mut store = StorageTarget::Immediate(Vec::new());

        // Compile the voundary expression into this storage...
        let wire = self.compile(expr, &mut store).unwrap();
        if let StorageTarget::Immediate(ops) = store {
            assert!(ops.len() <= 1);

            // ...then convert the resulting Wire into a QueryBoundSource
            match wire {
                Symbol::Expression(e) => match e {
                    Wire::BasicOperation(id) => {
                        // Safety check
                        assert_eq!(id, 0);
                        QueryBoundSource::Operation(ops[0].clone())
                    }
                    Wire::Constant(id) => {
                        QueryBoundSource::Constant(self.constants.ops[id].clone())
                    }
                    Wire::PlaceHolder(ph) => QueryBoundSource::Placeholder(ph),
                    _ => unreachable!(),
                },
                _ => unreachable!(),
            }
        } else {
            unreachable!();
        }
    }

    /// Pattern matches the expression to find, it possible, a bound for the
    /// secondary index.
    ///
    /// For now, the only acceptable forms are:
    ///   - sid <[=] <placeholder>
    ///   - sid >[=] <placeholder>
    ///   - sid = <placeholder>
    fn maybe_set_secondary_index_boundary(&mut self, expr: &Expr) -> Result<()> {
        if let Expr::BinaryOp { left, op, right } = expr {
            if self.is_secondary_index(left)?
                // SID can only be computed from constants and placeholders
                && self.is_expr_static(right)?
                // SID can only be defined by up to one level of BasicOperation
                && self.depth(right) <= 1
            {
                let bound = Some(self.expression_to_boundary(right));
                match op {
                    // $sid > x
                    BinaryOperator::Gt | BinaryOperator::GtEq => {
                        if self.secondary_index_bounds.low.is_some() {
                            // impossible to say which is higher between two
                            // conflicting low bounds
                            self.secondary_index_bounds.low = None;
                        } else {
                            self.secondary_index_bounds.low = bound;
                        }
                    }
                    // $sid < x
                    BinaryOperator::Lt | BinaryOperator::LtEq => {
                        if self.secondary_index_bounds.high.is_some() {
                            // impossible to say which is lower between two
                            // conflicting high bounds
                            self.secondary_index_bounds.high = None;
                        } else {
                            self.secondary_index_bounds.high = bound;
                        }
                    }
                    // $sid = x
                    BinaryOperator::Eq => {
                        if self.secondary_index_bounds.low.is_some()
                            && self.secondary_index_bounds.high.is_some()
                        {
                            self.secondary_index_bounds.low = None;
                            self.secondary_index_bounds.high = None;
                        } else {
                            self.secondary_index_bounds.low = bound.clone();
                            self.secondary_index_bounds.high = bound;
                        }
                    }
                    _ => {}
                }
            } else if self.is_secondary_index(right)? && self.is_expr_static(left)? {
                let bound = Some(self.expression_to_boundary(left));
                match op {
                    // x > $sid
                    BinaryOperator::Gt | BinaryOperator::GtEq => {
                        if self.secondary_index_bounds.high.is_some() {
                            self.secondary_index_bounds.high = None;
                        } else {
                            self.secondary_index_bounds.high = bound;
                        }
                    }
                    // x < $sid
                    BinaryOperator::Lt | BinaryOperator::LtEq => {
                        if self.secondary_index_bounds.low.is_some() {
                            // impossible to say which is lower between two
                            // conflicting high bounds
                            self.secondary_index_bounds.low = None;
                        } else {
                            self.secondary_index_bounds.low = bound;
                        }
                    }
                    // x = $sid
                    BinaryOperator::Eq => {
                        if self.secondary_index_bounds.low.is_some()
                            && self.secondary_index_bounds.high.is_some()
                        {
                            self.secondary_index_bounds.low = None;
                            self.secondary_index_bounds.high = None;
                        } else {
                            self.secondary_index_bounds.low = bound.clone();
                            self.secondary_index_bounds.high = bound;
                        }
                    }
                    _ => {}
                }
            }
        }

        Ok(())
    }

    /// Recursively traverses the given expression (supposedly a WHERE clause)
    /// to extract putative bounds on the secondary index. Only `AND`
    /// combinators are traversed, as any other one would not statically
    /// guarantee the predominance of the bound.
    fn find_secondary_index_boundaries(&mut self, expr: &Expr) -> Result<()> {
        self.maybe_set_secondary_index_boundary(expr)?;
        match expr {
            Expr::BinaryOp { left, op, right } => match op {
                BinaryOperator::And => {
                    self.find_secondary_index_boundaries(left)?;
                    self.find_secondary_index_boundaries(right)?;
                    Ok(())
                }
                _ => Ok(()),
            },
            Expr::Nested(e) => self.find_secondary_index_boundaries(e),
            _ => Ok(()),
        }
    }

    /// Recursively convert the given expression into an assembly of circuit PI
    /// objects.
    ///
    /// `storage_target` determines whether the circuit ojects should be stored
    /// in the SELECT-specific or the WHERE-specific storage target.
    fn compile(&mut self, expr: &Expr, storage_target: &mut StorageTarget) -> Result<Symbol<Wire>> {
        match expr {
            Expr::Value(v) => Ok(Symbol::Expression(match v {
                Value::Number(x, _) => self.new_constant(x.parse().unwrap()),
                Value::SingleQuotedString(s) => self.new_constant(str_to_u256(s)?),
                Value::Placeholder(p) => {
                    Wire::PlaceHolder(self.settings.placeholders.resolve_placeholder(p)?)
                }
                _ => unreachable!(),
            })),
            Expr::Identifier(s) => Ok(Symbol::Expression(
                self.scopes.resolve_freestanding(s)?.to_wire_id(),
            )),
            Expr::Nested(e) => self.compile(e, storage_target),
            Expr::CompoundIdentifier(c) => self.scopes.resolve_compound(c),
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
                let operation =
                    BasicOperation::new_binary_operation(first_operand, second_operand, op);
                let new_id = Wire::BasicOperation(match storage_target {
                    StorageTarget::Query => self.query_ops.insert(operation),
                    StorageTarget::Predicate => self
                        .scopes
                        .current_scope_mut()
                        .metadata_mut()
                        .predicates
                        .insert(operation),
                    StorageTarget::Immediate(ops) => {
                        ops.push(operation);
                        ops.len() - 1
                    }
                });

                Ok(Symbol::Expression(new_id))
            }
            Expr::UnaryOp { op, expr } => match op {
                UnaryOperator::Not => {
                    let first_operand = self.compile(expr, storage_target)?;
                    let first_operand = self.to_operand(&first_operand);
                    let operation =
                        BasicOperation::new_unary_operation(first_operand, Operation::NotOp);
                    let new_id = Wire::BasicOperation(match storage_target {
                        StorageTarget::Query => self.query_ops.insert(operation),
                        StorageTarget::Predicate => self
                            .scopes
                            .current_scope_mut()
                            .metadata_mut()
                            .predicates
                            .insert(operation),
                        StorageTarget::Immediate(ops) => {
                            ops.push(operation);
                            ops.len() - 1
                        }
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

                if let FunctionArguments::List(arglist) = &funcall.args {
                    match &arglist.args[0] {
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
    fn to_operand(&self, s: &Symbol<Wire>) -> InputOperand {
        match s {
            Symbol::Column { payload: id, .. } => InputOperand::Column(id.to_index()),
            Symbol::NamedExpression { payload: id, .. } | Symbol::Expression(id) => match id {
                Wire::BasicOperation(idx) => InputOperand::PreviousValue(*idx),
                Wire::ColumnId(idx) => InputOperand::Column(*idx),
                Wire::Constant(idx) => InputOperand::Constant(self.constants.get(*idx).clone()),
                Wire::PlaceHolder(ph) => InputOperand::Placeholder(*ph),
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
            Wire::Constant(_) => bail!(ValidationError::UnsupportedFeature(
                "top-level immediate values".into()
            )),
            Wire::PlaceHolder(_) => bail!(ValidationError::UnsupportedFeature(
                "top-level placeholders".into()
            )),
        }
    }

    /// Generate a [`ResultStructure`] from the parsed query; fails if it does
    /// not satisfy the circuit requirements.
    fn prepare_result(&self) -> Result<ResultStructure> {
        let root_scope = &self.scopes.scope_at(1);

        Ok(
            if root_scope
                .metadata()
                .aggregation
                .iter()
                .all(|&a| a == AggregationOperation::IdOp)
            {
                ResultStructure::new_for_query_no_aggregation(
                    self.query_ops.ops.clone(),
                    root_scope.metadata().outputs.clone(),
                    vec![0; root_scope.metadata().outputs.len()],
                )
            } else if root_scope
                .metadata()
                .aggregation
                .iter()
                .all(|&a| a != AggregationOperation::IdOp)
            {
                ResultStructure::new_for_query_with_aggregation(
                    self.query_ops.ops.clone(),
                    root_scope.metadata().outputs.clone(),
                    root_scope
                        .metadata()
                        .aggregation
                        .iter()
                        .map(|x| x.to_id())
                        .collect(),
                )
            } else {
                unreachable!()
            },
        )
    }

    /// Generate appropriate universal query circuit PIs from the root context
    /// of this Resolver.
    fn to_pis(&self, placeholders: &Placeholders) -> Result<CircuitPis> {
        let result = self.prepare_result()?;
        let root_scope = &self.scopes.scope_at(1);

        Ok(CircuitPis {
            result,
            column_ids: self.columns.clone(),
            query_aggregations: root_scope
                .metadata()
                .aggregation
                .iter()
                .map(|x| x.to_field())
                .collect(),
            predication_operations: root_scope.metadata().predicates.ops.clone(),
            bounds: QueryBounds::new(
                placeholders,
                self.secondary_index_bounds.low.clone(),
                self.secondary_index_bounds.high.clone(),
            )
            .context("while setting query bounds")?,
        })
    }
}

/// This struct contains all the data required to build the public inputs of the
/// universal query circuit for a given query.
#[derive(Debug)]
pub struct CircuitPis {
    /// The [`ResultStructure`] taken as input by the universal query circuit
    pub result: ResultStructure,
    /// A list of [`AggregationOperation`] matching 1-1 the outputs in
    /// [`ResultStructure`]
    pub query_aggregations: Vec<F>,
    /// The list of crypto IDs of the column involved in the query. Their
    /// position in this list **MUST** match their index in the
    /// [`ResultStructure`] operations.
    pub column_ids: Vec<u64>,
    /// A list of mutually-referencing [`BasicOperation`] encoding the AST of
    /// the WHERE predicate, if any. By convention, the root of the AST **MUST**
    /// be the last one in this list.
    pub predication_operations: Vec<BasicOperation>,
    /// If any, the bounds for the secondary index
    pub bounds: QueryBounds,
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

                    let initial_offset = self.columns.len();
                    for (i, column) in table_columns.into_iter().enumerate() {
                        let i = i + initial_offset;
                        self.columns.push(column.id);
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
                            payload: Wire::ColumnId(i),
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
            self.find_secondary_index_boundaries(where_clause)?;
            self.compile(where_clause, &mut StorageTarget::Predicate)?;
        }
        self.exit_scope()
    }

    fn post_query(&mut self, query: &mut Query) -> Result<()> {
        if let SetExpr::Select(_) = *query.body {
            if let Some(order_by) = query.order_by.as_mut() {
                for order_by_expr in order_by.exprs.iter_mut() {
                    let wire_id = self
                        .compile(&mut order_by_expr.expr, &mut StorageTarget::Query)?
                        .to_wire_id();
                    ensure!(
                        self.scopes
                            .currently_reachable()?
                            .iter()
                            .map(|s| s.to_wire_id())
                            .any(|w| w == wire_id),
                        ValidationError::SpecialOrderBy(order_by_expr.to_string())
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
                payload: self.compile(expr, &mut StorageTarget::Query)?.to_wire_id(),
            },
            SelectItem::UnnamedExpr(e) => match e {
                Expr::Identifier(i) => self.scopes.resolve_freestanding(i)?,
                Expr::CompoundIdentifier(is) => self.scopes.resolve_compound(is)?,
                _ => Symbol::Expression(self.compile(e, &mut StorageTarget::Query)?.to_wire_id()),
            },
            SelectItem::Wildcard(_) => Symbol::Wildcard,
            SelectItem::QualifiedWildcard(_, _) => unreachable!(),
        };
        self.scopes.current_scope_mut().provides(provided);
        Ok(())
    }
}

pub fn validate<C: ContextProvider>(query: &Query, settings: &ParsilSettings<C>) -> Result<()> {
    let mut converted_query = query.clone();
    let mut resolver = Assembler::new(settings);
    converted_query.visit(&mut resolver)?;
    resolver.prepare_result()?;
    Ok(())
}

pub fn assemble<C: ContextProvider>(q: &Query, settings: &ParsilSettings<C>, placeholders: &Placeholders) -> Result<CircuitPis> {
    let mut converted_query = q.clone();
    let mut resolver = Assembler::new(settings);
    converted_query.visit(&mut resolver)?;
    println!("Original query:\n>> {}", q);
    println!("Translated query:\n>> {}", converted_query);

    resolver.scopes.pretty();

    println!("Query ops:");
    for (i, op) in resolver.query_ops.ops.iter().enumerate() {
        println!("     {i}: {op:?}");
    }

    let pis = resolver.to_pis(&placeholders)?;

    println!("Sent to circuit:");
    println!("{:#?}", pis);

    Ok(pis)
}
