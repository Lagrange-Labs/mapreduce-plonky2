use anyhow::Result;

use crate::indexing::{index::IndexNode, row::RowPayload};
use alloy::primitives::U256;
use block::MerkleIndexTree;
use mp2_common::{poseidon::empty_poseidon_hash, types::HashOutput};
use row::MerkleRowTree;
use ryhope::{
    storage::pgsql::{SqlServerConnection, SqlStorageSettings},
    tree::scapegoat,
    InitSettings, UserEpoch,
};

pub mod block;
pub mod cell;
pub mod index;
pub mod row;

pub type ColumnID = u64;

/// Build `MerkleIndexTree` and `MerkleRowTree` trees from tables
/// `index_table_name` and `row_table_name` in the DB with URL `db_url`.
pub async fn load_trees(
    db_url: &str,
    index_table_name: String,
    row_table_name: String,
) -> Result<(MerkleIndexTree, MerkleRowTree)> {
    let index_tree = MerkleIndexTree::new(
        InitSettings::MustExist,
        SqlStorageSettings::new(
            &index_table_name,
            SqlServerConnection::NewConnection(db_url.to_string()),
        )?,
    )
    .await?;
    let row_tree = MerkleRowTree::new(
        InitSettings::MustExist,
        SqlStorageSettings::new_with_mapper(
            &row_table_name,
            SqlServerConnection::NewConnection(db_url.to_string()),
            index_table_name,
        )?,
    )
    .await?;

    Ok((index_tree, row_tree))
}

/// Build `MerkleIndexTree` and `MerkleRowTree` trees starting from
/// `genesis_block`. The tables employed in the DB with URL `db_url`
/// to store the trees are `index_table_name` and `row_table_name`,
/// respectively. The following additional parameters are required:
/// - `alpha`: Parameter of the Scapegoat tree employed for the `MerkleRowTree`
/// - `reset_if_exist`: if true, an existing tree would be deleted
pub async fn build_trees(
    db_url: &str,
    index_table_name: String,
    row_table_name: String,
    genesis_block: UserEpoch,
    alpha: scapegoat::Alpha,
    max_depth: usize,
    reset_if_exist: bool,
) -> Result<(MerkleIndexTree, MerkleRowTree)> {
    let db_settings_index = SqlStorageSettings::new(
        &index_table_name,
        SqlServerConnection::NewConnection(db_url.to_string()),
    )?;
    let db_settings_row = SqlStorageSettings::new_with_mapper(
        &row_table_name,
        SqlServerConnection::NewConnection(db_url.to_string()),
        index_table_name,
    )?;

    let index_tree = ryhope::new_index_tree(
        genesis_block as UserEpoch,
        db_settings_index,
        reset_if_exist,
    )
    .await?;
    let row_tree = ryhope::new_row_tree(
        genesis_block as UserEpoch,
        alpha,
        max_depth,
        db_settings_row,
        reset_if_exist,
    )
    .await?;

    Ok((index_tree, row_tree))
}

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
