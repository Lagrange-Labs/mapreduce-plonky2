use anyhow::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

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
    fn fetch_table(&self, table_name: &str) -> Result<ZkTable>;

    /// Return the current block number
    fn current_block(&self) -> u64;
}

pub struct EmptyProvider;
impl RootContextProvider for EmptyProvider {
    fn fetch_table(&self, _table_name: &str) -> Result<ZkTable> {
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
    fn fetch_table(&self, table_name: &str) -> Result<ZkTable> {
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
    fn fetch_table(&self, table_name: &str) -> Result<ZkTable> {
        todo!()
    }

    fn current_block(&self) -> u64 {
        todo!()
    }
}
