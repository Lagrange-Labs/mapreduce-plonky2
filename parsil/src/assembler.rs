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
use serde::{Deserialize, Serialize};
use sqlparser::ast::{
    BinaryOperator, Expr, FunctionArg, FunctionArgExpr, FunctionArguments, Query, Select,
    SelectItem, SetExpr, TableAlias, TableFactor, UnaryOperator, Value,
};
use verifiable_db::query::{
    computational_hash_ids::{AggregationOperation, Operation, PlaceholderIdentifier},
    universal_circuit::universal_circuit_inputs::{
        BasicOperation, InputOperand, OutputItem, Placeholders, ResultStructure,
    },
    utils::{QueryBoundSource, QueryBounds},
};

use crate::{
    errors::ValidationError,
    symbols::{ColumnKind, ContextProvider, Handle, Kind, ScopeTable, Symbol},
    utils::{str_to_u256, ParsilSettings},
    visitor::{AstVisitor, Visit},
};

/// Replace `current` with `Some(other)` if (i) `current` is empty, or (ii)
/// `other` is smaller than the value in `current`.
fn maybe_replace_min<T: PartialOrd>(current: &mut Option<T>, other: T) {
    if current.as_ref().map(|x| other < *x).unwrap_or(false) || current.is_none() {
        *current = Some(other);
    }
}

/// Replace `current` with `Some(other)` if (i) `current` is empty, or (ii)
/// `other` is larger than the value in `current`.
fn maybe_replace_max<T: PartialOrd>(current: &mut Option<T>, other: T) {
    if current.as_ref().map(|x| other > *x).unwrap_or(false) || current.is_none() {
        *current = Some(other);
    }
}

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
    /// If any, the boundaries of the secondary index
    secondary_index_bounds: Bounds,
    /// Flag specifying whether DISTINCT keyword is employed in the query
    distinct: bool,
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
            distinct: false,
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
                    let (aggregation, output_item) = Self::to_output_expression(id, false)?;
                    output_items.push(output_item);
                    aggregations.push(aggregation);
                }
                Symbol::Alias { .. } => {}
                Symbol::Wildcard => unreachable!(),
            };
        }

        let exited_scope_metadata = self.scopes.scope_at_mut(exited_scope).metadata_mut();
        exited_scope_metadata.outputs = output_items;
        exited_scope_metadata.aggregation = aggregations;

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
            Symbol::NamedExpression { payload, .. } => self.is_wire_static(payload),
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
    fn depth(e: &Expr) -> usize {
        match e {
            Expr::Identifier(_) | Expr::CompoundIdentifier(_) => 0,
            Expr::BinaryOp { left, right, .. } => 1 + Self::depth(left).max(Self::depth(right)),
            Expr::UnaryOp { expr, .. } => 1 + Self::depth(expr),
            Expr::Nested(e) => Self::depth(e),
            Expr::Value(_) => 0,
            _ => unreachable!(),
        }
    }

    /// Return whether the given `Symbol` encodes the given kind of column.
    fn is_symbol_kind(s: &Symbol<Wire>, target: ColumnKind) -> bool {
        match s {
            Symbol::Column { kind, .. } => *kind == target,
            Symbol::Alias { to, .. } => Self::is_symbol_kind(to, target),
            _ => false,
        }
    }

    /// Return whether, in the current scope, the given expression refers to the
    /// primary index.
    fn is_primary_index(&self, expr: &Expr) -> Result<bool> {
        Ok(match expr {
            Expr::Identifier(s) => Self::is_symbol_kind(
                &self.scopes.resolve_freestanding(s)?,
                ColumnKind::PrimaryIndex,
            ),
            Expr::CompoundIdentifier(c) => {
                Self::is_symbol_kind(&self.scopes.resolve_compound(c)?, ColumnKind::PrimaryIndex)
            }

            _ => false,
        })
    }

    /// Return whether, in the current scope, the given expression refers to the
    /// secondary index.
    fn is_secondary_index(&self, expr: &Expr) -> Result<bool> {
        Ok(match expr {
            Expr::Identifier(s) => Self::is_symbol_kind(
                &self.scopes.resolve_freestanding(s)?,
                ColumnKind::SecondaryIndex,
            ),
            Expr::CompoundIdentifier(c) => Self::is_symbol_kind(
                &self.scopes.resolve_compound(c)?,
                ColumnKind::SecondaryIndex,
            ),

            _ => false,
        })
    }

    /// Convert the given [`Expr`] a [`QueryBoundSource`]. It is assumed that
    /// the input expression has already been checked for correctness for use as
    /// a SID bound, which means that it resolves correctly, that its depth is
    /// less than two, and that it is static.
    fn expression_to_boundary(&mut self, expr: &Expr) -> Result<QueryBoundSource> {
        // A SID can only be bound by only one BasicOperation, that must not be
        // stored along the query operations. Therefore we use an immediate
        // storage, whose length will later down checked to be less than two.
        let mut store = StorageTarget::Immediate(Vec::new());

        // Compile the boundary expression into this storage...
        let wire = self.compile(expr, &mut store).unwrap();
        if let StorageTarget::Immediate(ops) = store {
            ensure!(ops.len() <= 1, "{expr} is not a valid boundary expression");

            // ...then convert the resulting Wire into a QueryBoundSource
            Ok(match wire {
                Symbol::Expression(e) => match e {
                    Wire::BasicOperation(id) => {
                        // Safety check
                        assert_eq!(id, 0);
                        QueryBoundSource::Operation(ops[0])
                    }
                    Wire::Constant(id) => QueryBoundSource::Constant(self.constants.ops[id]),
                    Wire::PlaceHolder(ph) => QueryBoundSource::Placeholder(ph),
                    _ => unreachable!(),
                },
                _ => unreachable!(),
            })
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
    fn maybe_set_secondary_index_bounds(&mut self, expr: &Expr, bounds: &mut Bounds) -> Result<()> {
        fn plus_one(expr: &Expr) -> Expr {
            Expr::BinaryOp {
                left: Box::new(expr.clone()),
                op: BinaryOperator::Plus,
                right: Box::new(Expr::Value(Value::Number("1".into(), false))),
            }
        }

        fn minus_one(expr: &Expr) -> Expr {
            Expr::BinaryOp {
                left: Box::new(expr.clone()),
                op: BinaryOperator::Minus,
                right: Box::new(Expr::Value(Value::Number("1".into(), false))),
            }
        }

        if let Expr::BinaryOp { left, op, right } = expr {
            if self.is_secondary_index(left)?
                // SID can only be computed from constants and placeholders
                && self.is_expr_static(right)?
                // SID can only be defined by up to one level of BasicOperation
                && Self::depth(right) <= 1
            {
                match op {
                    // $sid > x
                    BinaryOperator::Gt | BinaryOperator::GtEq => {
                        let right = if *op == BinaryOperator::Gt {
                            &plus_one(right)
                        } else {
                            right
                        };
                        let bound = self.expression_to_boundary(right)?;

                        maybe_replace_max(&mut bounds.low, bound);
                    }
                    // $sid < x
                    BinaryOperator::Lt | BinaryOperator::LtEq => {
                        let right = if *op == BinaryOperator::Lt {
                            &minus_one(right)
                        } else {
                            right
                        };
                        let bound = self.expression_to_boundary(right)?;

                        maybe_replace_min(&mut bounds.high, bound);
                    }
                    // $sid = x
                    BinaryOperator::Eq => {
                        let bound = self.expression_to_boundary(right)?;
                        bounds.low = Some(bound.clone());
                        bounds.high = Some(bound);
                    }
                    _ => {}
                }
            } else if self.is_secondary_index(right)? && self.is_expr_static(left)? {
                match op {
                    // x > $sid
                    BinaryOperator::Gt | BinaryOperator::GtEq => {
                        let left = if *op == BinaryOperator::Gt {
                            &minus_one(left)
                        } else {
                            left
                        };
                        let bound = self.expression_to_boundary(left)?;

                        maybe_replace_min(&mut bounds.high, bound);
                    }
                    // x < $sid
                    BinaryOperator::Lt | BinaryOperator::LtEq => {
                        let left = if *op == BinaryOperator::Lt {
                            &plus_one(left)
                        } else {
                            left
                        };
                        let bound = self.expression_to_boundary(left)?;

                        maybe_replace_max(&mut bounds.low, bound);
                    }
                    // x = $sid
                    BinaryOperator::Eq => {
                        let bound = self.expression_to_boundary(left)?;
                        bounds.low = Some(bound.clone());
                        bounds.high = Some(bound);
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
    fn find_secondary_index_boundaries(&mut self, expr: &Expr, bounds: &mut Bounds) -> Result<()> {
        self.maybe_set_secondary_index_bounds(expr, bounds)?;
        match expr {
            Expr::BinaryOp {
                left,
                op: BinaryOperator::And,
                right,
            } => {
                self.find_secondary_index_boundaries(left, bounds)?;
                self.find_secondary_index_boundaries(right, bounds)?;
                Ok(())
            }
            Expr::Nested(e) => self.find_secondary_index_boundaries(e, bounds),
            _ => Ok(()),
        }
    }

    /// If `expr` defines a definite boundary on the primary index, update the
    /// adequate member of the `bounds` tuple.
    fn maybe_set_primary_index_bounds(
        &mut self,
        expr: &Expr,
        bounds: &mut (bool, bool),
    ) -> Result<()> {
        if let Expr::BinaryOp { left, op, right } = expr {
            if self.is_primary_index(left)?
                // SID can only be computed from constants and placeholders
                && self.is_expr_static(right)?
                // SID can only be defined by up to one level of BasicOperation
                && Self::depth(right) <= 1
            {
                match op {
                    // $PI > x
                    BinaryOperator::GtEq => {
                        let bound = self.expression_to_boundary(right)?;
                        if matches!(
                            bound,
                            QueryBoundSource::Placeholder(PlaceholderIdentifier::MinQueryOnIdx1)
                        ) {
                            bounds.0 = true;
                        }
                    }
                    // $PI < x
                    BinaryOperator::LtEq => {
                        let bound = self.expression_to_boundary(right)?;

                        if matches!(
                            bound,
                            QueryBoundSource::Placeholder(PlaceholderIdentifier::MaxQueryOnIdx1)
                        ) {
                            bounds.1 = true;
                        }
                    }
                    _ => {}
                }
            } else if self.is_primary_index(right)? && self.is_expr_static(left)? {
                match op {
                    // x > $PI
                    BinaryOperator::Gt | BinaryOperator::GtEq => {
                        let bound = self.expression_to_boundary(right)?;

                        if matches!(
                            bound,
                            QueryBoundSource::Placeholder(PlaceholderIdentifier::MaxQueryOnIdx1)
                        ) {
                            bounds.1 = true;
                        }
                    }
                    // x < $PI
                    BinaryOperator::Lt | BinaryOperator::LtEq => {
                        let bound = self.expression_to_boundary(right)?;
                        if matches!(
                            bound,
                            QueryBoundSource::Placeholder(PlaceholderIdentifier::MinQueryOnIdx1)
                        ) {
                            bounds.0 = true;
                        }
                    }
                    _ => {}
                }
            }
        }

        Ok(())
    }

    /// Recursively traverses the given expression (typically a WHERE clause) to
    /// ensure that the [MIN_BLOCK, MAX_BLOCK] boundaries are enforced on the
    /// primary index.
    ///   * `expr`: the [`Expr`] to traverse;
    ///   * `bound`: whether the (low, high) bound for the prim. ind. have been found.
    fn detect_primary_index_boundaries(
        &mut self,
        expr: &Expr,
        bounds: &mut (bool, bool),
    ) -> Result<()> {
        self.maybe_set_primary_index_bounds(expr, bounds)?;
        match expr {
            Expr::BinaryOp {
                left,
                op: BinaryOperator::And,
                right,
            } => {
                self.detect_primary_index_boundaries(left, bounds)?;
                self.detect_primary_index_boundaries(right, bounds)?;
                Ok(())
            }
            Expr::Nested(e) => self.detect_primary_index_boundaries(e, bounds),
            _ => Ok(()),
        }
    }

    /// Recursively convert the given expression into an assembly of circuit PI
    /// objects.
    ///
    /// `storage_target` determines whether the circuit ojects should be stored
    /// in the SELECT-specific or the WHERE-specific storage target.
    fn compile(&mut self, expr: &Expr, storage_target: &mut StorageTarget) -> Result<Symbol<Wire>> {
        let mut expr = expr.clone();
        crate::utils::const_reduce(&mut expr);

        match &expr {
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
                    // NOTE: we only accept funcalls with a single argument for now
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
            _ => unreachable!("trying to compile `{expr}`"),
        }
    }

    /// Create an operand from the given wire.
    fn to_operand(&self, s: &Symbol<Wire>) -> InputOperand {
        match s {
            Symbol::Column { payload: id, .. } => InputOperand::Column(id.to_index()),
            Symbol::NamedExpression { payload: id, .. } | Symbol::Expression(id) => match id {
                Wire::BasicOperation(idx) => InputOperand::PreviousValue(*idx),
                Wire::ColumnId(idx) => InputOperand::Column(*idx),
                Wire::Constant(idx) => InputOperand::Constant(*self.constants.get(*idx)),
                Wire::PlaceHolder(ph) => InputOperand::Placeholder(*ph),
                Wire::Aggregation(_, _) => unreachable!("an aggregation can not be an operand"),
            },
            _ => unreachable!(),
        }
    }

    /// Create an output and its associated aggregation function from a wire.
    fn to_output_expression(
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
                Ok((agg, Self::to_output_expression(*sub_wire_id, true)?.1))
            }
            Wire::Constant(_) => bail!(ValidationError::UnsupportedFeature(
                "top-level immediate values".into(),
            )),
            Wire::PlaceHolder(_) => bail!(ValidationError::UnsupportedFeature(
                "top-level placeholders".into(),
            )),
        }
    }

    /// Generate a [`ResultStructure`] from the parsed query; fails if it does
    /// not satisfy the circuit requirements.
    fn prepare_result(&self) -> Result<ResultStructure> {
        let root_scope = &self.scopes.scope_at(1);

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
                self.distinct,
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
        }
    }

    /// Generate appropriate universal query circuit PIs in static mode from the
    /// root context of this Resolver.
    fn to_static_inputs(&self) -> Result<CircuitPis<StaticQueryBounds>> {
        let result = self.prepare_result()?;
        let root_scope = &self.scopes.scope_at(1);

        let pis = CircuitPis {
            result,
            column_ids: self.columns.clone(),
            query_aggregations: root_scope.metadata().aggregation.to_vec(),
            predication_operations: root_scope.metadata().predicates.ops.clone(),
            bounds: StaticQueryBounds::without_values(
                self.secondary_index_bounds.low.clone(),
                self.secondary_index_bounds.high.clone(),
            ),
        };
        pis.validate::<C>()?;
        Ok(pis)
    }

    /// Generate appropriate universal query circuit PIs in runtime mode from
    /// the root context of this Resolver.
    fn to_dynamic_inputs(&self, placeholders: &Placeholders) -> Result<CircuitPis<QueryBounds>> {
        let result = self.prepare_result()?;
        let root_scope = &self.scopes.scope_at(1);

        let pis = CircuitPis {
            result,
            column_ids: self.columns.clone(),
            query_aggregations: root_scope.metadata().aggregation.to_vec(),
            predication_operations: root_scope.metadata().predicates.ops.clone(),
            bounds: QueryBounds::new(
                placeholders,
                self.secondary_index_bounds.low.clone(),
                self.secondary_index_bounds.high.clone(),
            )
            .context("while setting query bounds")?,
        };
        pis.validate::<C>()?;
        Ok(pis)
    }
}

/// A trait unifying [`StaticQueryBounds`] and [`QueryBounds`] construction to
/// place them in a [`CircuitPis`] that may be either build in static mode (i.e.
/// no reference to runtime value) at query registration time, or in dynamic
/// mode at query execution time.
pub trait BuildableBounds: Sized + Serialize {
    fn without_values(low: Option<QueryBoundSource>, high: Option<QueryBoundSource>) -> Self;

    fn with_values(
        placeholders: &Placeholders,
        low: Option<QueryBoundSource>,
        high: Option<QueryBoundSource>,
    ) -> Result<Self>;
}

/// Similar to [`QueryBounds`], but only containing the static expressions
/// defining the query bounds, without any reference to runtime values.
#[derive(Debug, Serialize)]
pub struct StaticQueryBounds {
    pub min_query_secondary: Option<QueryBoundSource>,
    pub max_query_secondary: Option<QueryBoundSource>,
}

impl BuildableBounds for StaticQueryBounds {
    fn without_values(low: Option<QueryBoundSource>, high: Option<QueryBoundSource>) -> Self {
        Self {
            min_query_secondary: low,
            max_query_secondary: high,
        }
    }

    fn with_values(
        _: &Placeholders,
        _: Option<QueryBoundSource>,
        _: Option<QueryBoundSource>,
    ) -> Result<Self> {
        unreachable!()
    }
}

impl BuildableBounds for QueryBounds {
    fn without_values(_: Option<QueryBoundSource>, _: Option<QueryBoundSource>) -> Self {
        unreachable!()
    }

    fn with_values(
        placeholders: &Placeholders,
        low: Option<QueryBoundSource>,
        high: Option<QueryBoundSource>,
    ) -> Result<Self> {
        QueryBounds::new(placeholders, low, high)
    }
}

/// This struct contains all the data required to build the public inputs of the
/// universal query circuit for a given query.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CircuitPis<T: BuildableBounds> {
    /// The [`ResultStructure`] taken as input by the universal query circuit
    pub result: ResultStructure,
    /// A list of [`AggregationOperation`] matching 1-1 the outputs in
    /// [`ResultStructure`]
    pub query_aggregations: Vec<AggregationOperation>,
    /// The list of crypto IDs of the column involved in the query. Their
    /// position in this list **MUST** match their index in the
    /// [`ResultStructure`] operations.
    pub column_ids: Vec<u64>,
    /// A list of mutually-referencing [`BasicOperation`] encoding the AST of
    /// the WHERE predicate, if any. By convention, the root of the AST **MUST**
    /// be the last one in this list.
    pub predication_operations: Vec<BasicOperation>,
    /// If any, the bounds for the secondary index
    pub bounds: T,
}

/// Circuit PIs in static mode, i.e. without reference to runtime placeholder
/// values.
pub type StaticCircuitPis = CircuitPis<StaticQueryBounds>;
/// Circuit PIs in dynamic mode, i.e. with the placeholder values set at query
/// runtime.
pub type DynamicCircuitPis = CircuitPis<QueryBounds>;

impl<T: BuildableBounds> CircuitPis<T> {
    fn validate<C: ContextProvider>(&self) -> Result<()> {
        ensure!(
            self.predication_operations.len() <= C::MAX_NUM_PREDICATE_OPS,
            format!(
                "too many basic operations found in WHERE clause: found {}, maximum allowed is {}",
                self.predication_operations.len(),
                C::MAX_NUM_PREDICATE_OPS,
            )
        );
        ensure!(
            self.column_ids.len() <= C::MAX_NUM_COLUMNS,
            format!(
                "too many columns found in the table: found {}, maximum allowed is {}",
                self.column_ids.len(),
                C::MAX_NUM_COLUMNS,
            )
        );
        self.result
            .validate(C::MAX_NUM_RESULT_OPS, C::MAX_NUM_ITEMS_PER_OUTPUT)
    }

    pub fn to_json(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap()
    }
}

impl<C: ContextProvider> AstVisitor for Assembler<'_, C> {
    type Error = anyhow::Error;

    fn pre_table_factor(&mut self, table_factor: &TableFactor) -> Result<(), Self::Error> {
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

    fn post_table_factor(&mut self, _: &TableFactor) -> Result<()> {
        self.exit_scope()
    }

    /// SELECT always generate standard context, that will expose the SELECTed
    /// items to their parent while ensuring that they are actually contained in
    /// its providers.
    fn pre_select(&mut self, s: &Select) -> Result<()> {
        self.scopes
            .enter_scope(format!("Select: {s}"), Kind::Standard);
        Ok(())
    }

    fn post_select(&mut self, select: &Select) -> Result<()> {
        self.distinct = select.distinct.is_some();
        if let Some(where_clause) = select.selection.as_ref() {
            // As the expression are traversed depth-first, the top level
            // expression will mechanically find itself at the last position, as
            // required by the universal query circuit API.
            let mut primary_index_bounded = (false, false);
            self.detect_primary_index_boundaries(where_clause, &mut primary_index_bounded)?;
            ensure!(
                primary_index_bounded.0,
                "min. bound not found for primary index"
            );
            ensure!(
                primary_index_bounded.1,
                "max. bound not found for primary index"
            );

            let mut secondary_index_bounds = Default::default();
            self.find_secondary_index_boundaries(where_clause, &mut secondary_index_bounds)?;
            self.secondary_index_bounds = secondary_index_bounds;
            self.compile(where_clause, &mut StorageTarget::Predicate)?;
        }
        self.exit_scope()
    }

    fn post_query(&mut self, query: &Query) -> Result<()> {
        if let SetExpr::Select(_) = *query.body {
            if let Some(order_by) = query.order_by.as_ref() {
                for order_by_expr in order_by.exprs.iter() {
                    let wire_id = self
                        .compile(&order_by_expr.expr, &mut StorageTarget::Query)?
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
    fn pre_select_item(&mut self, select_item: &SelectItem) -> Result<()> {
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

/// Validate the given query, ensuring that it satisfies all the requirements of
/// the circuit.
pub fn validate<C: ContextProvider>(query: &Query, settings: &ParsilSettings<C>) -> Result<()> {
    let mut resolver = Assembler::new(settings);
    query.visit(&mut resolver)?;
    resolver.to_static_inputs().map(|_| ())
}

/// Generate static circuit public inputs, i.e. without reference to runtime
/// placeholder values.
pub fn assemble_static<C: ContextProvider>(
    query: &Query,
    settings: &ParsilSettings<C>,
) -> Result<StaticCircuitPis> {
    let mut resolver = Assembler::new(settings);
    query.visit(&mut resolver)?;

    resolver.to_static_inputs()
}

/// Generate dynamic circuit public inputs, i.e. referencing runtime placeholder
/// values.
pub fn assemble_dynamic<C: ContextProvider>(
    query: &Query,
    settings: &ParsilSettings<C>,
    placeholders: &Placeholders,
) -> Result<DynamicCircuitPis> {
    let mut resolver = Assembler::new(settings);
    query.visit(&mut resolver)?;

    resolver.to_dynamic_inputs(placeholders)
}
