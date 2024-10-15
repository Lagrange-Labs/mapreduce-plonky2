//! Define test cases

use crate::common::StorageSlotInfo;
use alloy::primitives::{Address, U256};
use contract::Contract;
use indexing::{TableRowUpdate, TableRowValues};
use log::debug;
use mp2_common::eth::StorageSlot;
use mp2_v1::{
    indexing::{
        block::BlockPrimaryIndex,
        cell::Cell,
        row::{RowTreeKey, ToNonce},
        ColumnID,
    },
    values_extraction::{
        identifier_for_mapping_key_column, identifier_for_mapping_value_column,
        identifier_single_var_column,
    },
};
use serde::{Deserialize, Serialize};
use table_source::{ContractExtractionArgs, TableSource};

use super::{
    rowtree::SecondaryIndexCell,
    table::{CellsUpdate, Table},
    TableInfo,
};

pub mod contract;
pub mod indexing;
pub mod planner;
pub mod query;
pub mod table_source;

/// Test case definition
pub(crate) struct TableIndexing {
    pub(crate) table: Table,
    pub(crate) contract: Contract,
    pub(crate) contract_extraction: ContractExtractionArgs,
    pub(crate) source: TableSource,
    // the column over which we can do queries like ` y > 64`. It is not the address column that we
    // assume it the secondary index always.
    pub(crate) value_column: String,
}
