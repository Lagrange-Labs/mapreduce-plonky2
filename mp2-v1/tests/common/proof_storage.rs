use super::{CellTreeKey, ProofKey, RowTreeKey};
use anyhow::{Context, Result};
use hashbrown::HashMap;

pub trait ProofStorage {
    fn store_proof(&mut self, key: ProofKey, proof: Vec<u8>) -> Result<()>;
    fn get_proof(&self, key: &ProofKey) -> Result<Vec<u8>>;
}

#[derive(Default)]
pub struct MemoryProofStorage {
    // right now unused but will be when we do multiple tables over multiple blocks
    namespace: String,
    cells: HashMap<CellTreeKey, Vec<u8>>,
    rows: HashMap<RowTreeKey, Vec<u8>>,
}

impl MemoryProofStorage {
    pub fn namespaced_from(s: String) -> Self {
        Self {
            namespace: s,
            ..Default::default()
        }
    }
}

impl ProofStorage for MemoryProofStorage {
    fn store_proof(&mut self, key: ProofKey, proof: Vec<u8>) -> Result<()> {
        match key {
            ProofKey::Cell(k) => self.cells.insert(k, proof),
            ProofKey::Row(k) => self.rows.insert(k, proof),
        };
        Ok(())
    }

    fn get_proof(&self, key: &ProofKey) -> Result<Vec<u8>> {
        match key {
            ProofKey::Cell(k) => self.cells.get(k),
            ProofKey::Row(k) => self.rows.get(k),
        }
        .context("unable to get proof from storage")
        .cloned()
    }
}
