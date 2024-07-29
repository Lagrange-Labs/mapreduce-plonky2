use anyhow::*;
use serde::{Deserialize, Serialize};
use sqlparser::ast::{Expr, Ident, TableFactor};
use std::collections::{HashMap, HashSet};

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
    /// This column identifier in the circuits
    pub id: u64,
}

/// A [`TableSymbols`] stores the symbols accessible in a table
pub enum TableSymbols {
    Normal(String, HashSet<String>),
    Alias {
        alias_name: String,
        real_name: String,
        columns: HashSet<String>,
    },
}

impl TableSymbols {
    pub fn resolve(&self, symbol: &str) -> Option<(String, String)> {
        match self {
            TableSymbols::Normal(me, columns) => {
                columns.get(symbol).map(|s| (me.clone(), s.to_owned()))
            }
            TableSymbols::Alias {
                real_name, columns, ..
            } => columns
                .get(symbol)
                .map(|s| (real_name.clone(), s.to_owned())),
        }
    }

    pub fn resolve_qualified(&self, table: &str, symbol: &str) -> Option<(String, String)> {
        match self {
            TableSymbols::Normal(me, columns) => {
                if me == table {
                    columns.get(symbol).map(|s| (me.clone(), s.to_owned()))
                } else {
                    None
                }
            }
            TableSymbols::Alias {
                alias_name,
                real_name,
                columns,
            } => {
                if alias_name == table {
                    columns
                        .get(symbol)
                        .map(|s| (real_name.clone(), s.to_owned()))
                } else {
                    None
                }
            }
        }
    }
}

/// The `RootContextProvider` gives access to the root context for symbol
/// resolution in a query, i.e. the virtual columns representing the indexed
/// data from the contraact, and available in the JSON payload exposed by
/// Ryhope.
pub trait RootContextProvider {
    fn fetch_table(&mut self, table_name: &str) -> Result<ZkTable>;

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
