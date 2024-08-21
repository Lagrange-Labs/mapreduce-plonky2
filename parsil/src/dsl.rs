use alloy::primitives::U256;
use sqlparser::ast::Expr;
use verifiable_db::query::computational_hash_ids::{Operation, PlaceholderIdentifier};

use crate::{
    symbols::{ColumnKind, ContextProvider, ZkColumn},
    visitor::AstPass,
    ParsilSettings,
};

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
