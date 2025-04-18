//! Define test cases

use contract::Contract;
use mp2_v1::values_extraction::identifier_for_mapping_key_column;
use table_source::{ContractExtractionArgs, TableSource};

use super::table::Table;

pub mod contract;
pub mod indexing;
pub mod query;
pub mod slot_info;
pub mod table_source;

/// Test case definition
pub(crate) struct TableIndexing {
    pub(crate) table: Table,
    pub(crate) contract: Option<Contract>, // might be meaningless for off-chain data
    pub(crate) contract_extraction: Option<ContractExtractionArgs>, // might be meaningless for off-chain data
    pub(crate) source: TableSource,
    // the column over which we can do queries like ` y > 64`. It is not the address column that we
    // assume it the secondary index always.
    pub(crate) value_column: String,
}
