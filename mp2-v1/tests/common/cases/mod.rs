//! Define test cases

use alloy::primitives::{Address, U256};
use contract::Contract;
use indexing::TableRowValues;
use log::debug;
use mp2_common::eth::StorageSlot;
use mp2_v1::{
    indexing::{
        block::BlockPrimaryIndex,
        cell::Cell,
        row::{RowTreeKey, ToNonce},
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
}
