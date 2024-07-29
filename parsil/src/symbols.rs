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
    /// This column identifier in the circuits
    pub id: u64,
}

pub trait ContextProvider {
    fn fetch_table(&mut self, table_name: &str) -> Result<ZkTable>;

    fn current_block(&self) -> u64;
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
impl ContextProvider for FileContextProvider {
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
