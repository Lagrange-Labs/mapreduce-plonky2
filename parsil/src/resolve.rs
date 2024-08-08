//! This module converts a user-defined query into one that can directly be
//! executed on the ryhope table containing the related data. The main steps
//! are:
//!
//! 1. convert virtual columns accesses into JSON payload access;
//!
//! 2. wrap the original query into a CTE to expand CoW row spans into
//!    individual column for each covered block number.
use std::fmt::Debug;

use alloy::primitives::U256;
use anyhow::*;
use log::warn;
use mp2_common::array::ToField;
use mp2_common::F;
use plonky2::field::types::Field;
use sqlparser::ast::{
    BinaryOperator, Expr, FunctionArg, FunctionArgExpr, FunctionArguments, Query, Select,
    SelectItem, SetExpr, TableAlias, TableFactor, UnaryOperator, Value,
};
use verifiable_db::query::{
    computational_hash_ids::{AggregationOperation, Operation, Output},
    universal_circuit::universal_circuit_inputs::{
        BasicOperation, InputOperand, OutputItem, ResultStructure,
    },
};

use crate::{
    symbols::{ContextProvider, Handle, Kind, ScopeTable, Symbol},
    utils::parse_string,
    visitor::{AstPass, Visit},
};

/// A Wire carry data that can be injected in universal query circuits. It
/// carries an index, whose sginification depends on the type of wire.
#[derive(Debug, Clone, PartialEq)]
enum Wire {
    /// A wire indexing an operation, either in the SELECT-sepcific or
    /// WHERE-specific operation storage.
    BasicOperation(usize),
    /// A wire carrying a column index in the column register.
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

impl Symbol<Wire> {
    fn to_wire_id(&self) -> Wire {
        match self {
            Symbol::NamedExpression { payload, .. }
            | Symbol::Expression(payload)
            | Symbol::MetaColumn { payload, .. }
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

pub(crate) struct Resolver<C: ContextProvider> {
    /// A storage for the SELECT-involved operations.
    query_ops: UniqueStorage<BasicOperation>,
    /// The query-global immediate value storage.
    constants: UniqueStorage<U256>,
    /// The query-global column storage, mapping a column index to a
    /// cryptographic column ID.
    columns: Vec<F>,
    /// The symbol table hierarchy for this query
    scopes: ScopeTable<CircuitData, Wire>,
    /// A handle to an object providing a register of the existing virtual
    /// tables and their columns.
    context: C,
}
impl<C: ContextProvider> Resolver<C> {
    /// Create a new empty [`Resolver`]
    fn new(context: C) -> Self {
        Resolver {
            scopes: ScopeTable::<CircuitData, Wire>::new(),
            query_ops: Default::default(),
            constants: Default::default(),
            columns: Vec::new(),
            context,
        }
    }

    fn exit_scope(&mut self) -> Result<()> {
        let exited_scope = self.scopes.exit_scope()?;

        // Prepare the data that will be used to generate the circuit PIs
        let mut output_items = Vec::new();
        let mut aggregations = Vec::new();
        for r in self.scopes.currently_reachable()?.into_iter() {
            match r {
                Symbol::MetaColumn { payload: id, .. }
                | Symbol::Column { payload: id, .. }
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

    /// Recursively convert the given expression into an assembly of circuit PI
    /// objects.
    ///
    /// `storage_target` determines whether the circuit ojects should be stored
    /// in the SELECT-specific or the WHERE-specific storage target.
    fn compile(&mut self, expr: &mut Expr, storage_target: StorageTarget) -> Result<Symbol<Wire>> {
        match expr {
            Expr::Value(v) => Ok(Symbol::Expression(match v {
                Value::Number(x, _) => self.new_constant(x.parse().unwrap()),
                Value::SingleQuotedString(s) => self.new_constant(parse_string(s)?),
                Value::Placeholder(p) => Wire::PlaceHolder(parse_placeholder(p)?),
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
                let operation = BasicOperation {
                    first_operand,
                    second_operand: Some(second_operand),
                    op,
                };
                let new_id = Wire::BasicOperation(match storage_target {
                    StorageTarget::Query => self.query_ops.insert(operation),
                    StorageTarget::Predicate => self
                        .scopes
                        .current_scope_mut()
                        .metadata_mut()
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
                            .scopes
                            .current_scope_mut()
                            .metadata_mut()
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
    fn to_operand(&self, s: &Symbol<Wire>) -> InputOperand {
        match s {
            Symbol::Column { payload: id, .. } => InputOperand::Column(id.to_index()),
            Symbol::NamedExpression { payload: id, .. } | Symbol::Expression(id) => match id {
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
            Wire::Constant(_) => bail!("top-level immediate values are not supported"),
            Wire::PlaceHolder(_) => bail!("top-level placeholders are not supported"),
        }
    }

    /// Generate appropriate universal query circuit PIs from the root context
    /// of this Resolver.
    fn to_pis(&self) -> Result<CircuitPis> {
        let root_scope = &self.scopes.scope_at(1);

        let aggregation = if root_scope
            .metadata()
            .aggregation
            .iter()
            .all(|&a| a == AggregationOperation::IdOp)
        {
            Output::NoAggregation
        } else if root_scope
            .metadata()
            .aggregation
            .iter()
            .all(|&a| a != AggregationOperation::IdOp)
        {
            Output::Aggregation
        } else {
            unreachable!()
        };

        let result = ResultStructure {
            result_operations: self.query_ops.ops.clone(),
            output_items: root_scope.metadata().outputs.clone(),
            // TODO: to fetch from the context
            output_ids: vec![F::from_canonical_u8(0); root_scope.metadata().outputs.len()],
            output_variant: aggregation,
        };

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
    pub column_ids: Vec<F>,
    /// A list of mutually-referencing [`BasicOperation`] encoding the AST of
    /// the WHERE predicate, if any. By convention, the root of the AST **MUST**
    /// be the last one in this list.
    pub predication_operations: Vec<BasicOperation>,
}

impl<C: ContextProvider> AstPass for Resolver<C> {
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
                        self.scopes.currently_reachable()?
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
                payload: self.compile(expr, StorageTarget::Query)?.to_wire_id(),
            },
            SelectItem::UnnamedExpr(e) => match e {
                Expr::Identifier(i) => self.scopes.resolve_freestanding(i)?,
                Expr::CompoundIdentifier(is) => self.scopes.resolve_compound(is)?,
                _ => Symbol::Expression(self.compile(e, StorageTarget::Query)?.to_wire_id()),
            },
            SelectItem::Wildcard(_) => Symbol::Wildcard,
            SelectItem::QualifiedWildcard(_, _) => unreachable!(),
        };
        self.scopes.current_scope_mut().provides(provided);
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
pub fn resolve<C: ContextProvider>(q: &Query, context: C) -> Result<CircuitPis> {
    let mut converted_query = q.clone();
    let mut resolver = Resolver::new(context);
    converted_query.visit(&mut resolver)?;
    println!("Original query:\n>> {}", q);
    println!("Translated query:\n>> {}", converted_query);

    resolver.scopes.pretty();

    println!("Query ops:");
    for (i, op) in resolver.query_ops.ops.iter().enumerate() {
        println!("     {i}: {op:?}");
    }

    println!("Sent to circuit:");
    println!("{:#?}", resolver.to_pis()?);

    resolver.to_pis()
}
