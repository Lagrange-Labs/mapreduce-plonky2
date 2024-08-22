use alloy::primitives::U256;
use anyhow::*;
use sqlparser::ast::Expr;
use verifiable_db::query::computational_hash_ids::{Operation, PlaceholderIdentifier};

use crate::{
    symbols::{ColumnKind, ContextProvider, ScopeTable, Symbol, ZkColumn},
    visitor::AstPass,
    ParsilSettings,
};

struct ExprAstBuilder<'a, C: ContextProvider> {
    settings: &'a ParsilSettings<C>,
    scopes: ScopeTable<(), ()>,
}
impl<'a, C: ContextProvider> ExprAstBuilder<'a, C> {
    fn new(settings: &'a ParsilSettings<C>) -> Self {
        Self {
            settings,
            scopes: ScopeTable::new(),
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
                    let (_, output_item) = self.to_output_expression(id, false)?;
                    output_items.push(output_item);
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
}

enum Node {
    UnaryOperation(Operation, Box<Node>),
    BinaryOperation(Operation, Box<Node>, Box<Node>),
    Nested(Box<Node>),
    Constant(U256),
    Column {
        column: ZkColumn,
        alias: Option<String>,
    },
    Placeholder(PlaceholderIdentifier),
}
impl Node {
    fn from_expr(e: &Expr) {}
}

struct Program {}

struct If(Select, Action);
impl AstPass for If {
    fn post_expr(&mut self, expr: &mut Expr) -> anyhow::Result<()> {
        Ok(())
    }
}

enum Select {
    ContainsName(String),
    ContainsKind(ColumnKind),
}
impl Select {
    fn apply(&self, expr: &Expr) -> bool {
        match self {
            Select::ContainsName(String) => todo!(),
            Select::ContainsKind(ColumnKind) => todo!(),
        }
    }
}

enum Action {
    NeutralizeInParent,
}

struct Interpreter<C: ContextProvider> {
    settings: ParsilSettings<C>,
}
impl<C: ContextProvider> AstPass for Interpreter<C> {}
