use alloy::primitives::U256;
use verifiable_db::query::aggregation::QueryBounds;

use crate::{symbols::ContextProvider, ParsilSettings};

/// Return two queries, respectively returning the largest sec. ind. value/// smaller than the given lower bound, and the smallest sec. ind. value larger
/// than the given higher bound.
///
/// If the lower or higher bound are the extrema of the U256 definition domain,
/// the associated query is `None`, reflecting the impossibility for a node
/// satisfying the condition to exist in the database.
pub fn bracket_secondary_index<C: ContextProvider>(
    table_name: &str,
    settings: &ParsilSettings<C>,
    block_number: i64,
    bounds: &QueryBounds,
) -> (Option<String>, Option<String>) {
    let secondary_lo = bounds.min_query_secondary().value();
    let secondary_hi = bounds.max_query_secondary().value();
    _bracket_secondary_index(
        table_name,
        settings,
        block_number,
        secondary_lo,
        secondary_hi,
    )
}

pub(crate) fn _bracket_secondary_index<C: ContextProvider>(
    table_name: &str,
    settings: &ParsilSettings<C>,
    block_number: i64,
    secondary_lo: &U256,
    secondary_hi: &U256,
) -> (Option<String>, Option<String>) {
    let sec_ind_column = settings
        .context
        .fetch_table(table_name)
        .unwrap()
        .secondary_index_column()
        .id;

    // A simple alias for the sec. ind. values
    let sec_index = format!("(payload -> 'cells' -> '{sec_ind_column}' ->> 'value')::NUMERIC");

    // Select the largest of all the sec. ind. values that remains smaller than
    // the provided sec. ind. lower bound if it is provided, -1 otherwise.
    let largest_below = if *secondary_lo == U256::ZERO {
        None
    } else {
        Some(format!("SELECT key FROM {table_name}
                           WHERE {sec_index} < '{secondary_lo}'::DECIMAL AND __valid_from <= {block_number} AND __valid_until >= {block_number}
                           ORDER BY {sec_index} DESC LIMIT 1"))
    };

    // Symmetric situation for the upper bound.
    let smallest_above = if *secondary_hi == U256::MAX {
        None
    } else {
        Some(format!("SELECT key FROM {table_name}
                           WHERE {sec_index} > '{secondary_hi}'::DECIMAL AND __valid_from <= {block_number} AND __valid_until >= {block_number}
                           ORDER BY {sec_index} ASC LIMIT 1"))
    };

    (largest_below, smallest_above)
}