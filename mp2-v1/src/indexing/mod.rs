use crate::indexing::{index::IndexNode, row::RowPayload};
use alloy::primitives::U256;
use mp2_common::{poseidon::empty_poseidon_hash, types::HashOutput};

pub mod block;
pub mod cell;
pub mod index;
pub mod row;

pub type ColumnID = u64;

// NOTE this might be good to have on public API ?
// cc/ @andrus
pub trait LagrangeNode {
    fn value(&self) -> U256;
    fn hash(&self) -> HashOutput;
    fn min(&self) -> U256;
    fn max(&self) -> U256;
    fn embedded_hash(&self) -> HashOutput;
}

impl<T: Eq + Default + std::fmt::Debug + Clone> LagrangeNode for RowPayload<T> {
    fn value(&self) -> U256 {
        self.secondary_index_value()
    }

    fn hash(&self) -> HashOutput {
        self.hash
    }

    fn min(&self) -> U256 {
        self.min
    }

    fn max(&self) -> U256 {
        self.max
    }

    fn embedded_hash(&self) -> HashOutput {
        self.cell_root_hash
            .unwrap_or(HashOutput::from(*empty_poseidon_hash()))
    }
}

impl<T> LagrangeNode for IndexNode<T> {
    fn value(&self) -> U256 {
        self.value.0
    }

    fn hash(&self) -> HashOutput {
        self.node_hash
    }

    fn min(&self) -> U256 {
        self.min
    }

    fn max(&self) -> U256 {
        self.max
    }

    fn embedded_hash(&self) -> HashOutput {
        self.row_tree_hash
    }
}
