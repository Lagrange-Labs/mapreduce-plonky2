use alloy::primitives::U256;
use ryhope::{
    mapper_table_name, INCREMENTAL_EPOCH, KEY, PAYLOAD, USER_EPOCH, VALID_FROM, VALID_UNTIL,
};
use verifiable_db::query::utils::QueryBounds;

use crate::{symbols::ContextProvider, ParsilSettings};

/// Return two queries, respectively returning the largest sec. ind. value smaller than the
/// given lower bound, and the smallest sec. ind. value larger than the given higher bound.
///
/// The method returns also a preliminary query to be run in order to compute the value of
/// the epoch parameter to be provided to the two queries. Such a parameter is the actual
/// epoch in the DB that corresponds to the `block_number` provided as an argument to this
/// method. Note that the epoch parameter is the same for both queries, so the preliminary
/// query can be just run once and the result used for either of the two queries.
///
/// If the lower or higher bound are the extrema of the U256 definition domain,
/// the associated query is `None`, reflecting the impossibility for a node
/// satisfying the condition to exist in the database.
pub fn bracket_secondary_index<C: ContextProvider>(
    table_name: &str,
    settings: &ParsilSettings<C>,
    block_number: i64,
    bounds: &QueryBounds,
) -> (String, Option<String>, Option<String>) {
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
) -> (String, Option<String>, Option<String>) {
    let zk_table = settings.context.fetch_table(table_name).unwrap();
    let zktable_name = &zk_table.zktable_name;
    let mapper_table_name = mapper_table_name(zktable_name);
    let sec_ind_column = zk_table.secondary_index_column().id;

    let preliminary_query = format!("
        SELECT {INCREMENTAL_EPOCH} as epoch FROM {mapper_table_name} WHERE {USER_EPOCH} = {block_number} LIMIT 1;
        "
    );

    // A simple alias for the sec. ind. values
    let sec_index = format!("({PAYLOAD} -> 'cells' -> '{sec_ind_column}' ->> 'value')::NUMERIC");

    // Select the largest of all the sec. ind. values that remains smaller than
    // the provided sec. ind. lower bound if it is provided, -1 otherwise.
    let largest_below = if *secondary_lo == U256::ZERO {
        None
    } else {
        Some(format!(
            "SELECT {KEY} FROM 
            {zktable_name} 
            WHERE {VALID_FROM} <= $1 AND {VALID_UNTIL} >= $1
                AND {sec_index} < '{secondary_lo}'::DECIMAL
                ORDER BY {sec_index} DESC LIMIT 1"
        ))
    };

    // Symmetric situation for the upper bound.
    let smallest_above = if *secondary_hi == U256::MAX {
        None
    } else {
        Some(format!(
            "SELECT {KEY} FROM 
            {zktable_name} 
            WHERE {VALID_FROM} <= $1 AND {VALID_UNTIL} >= $1
                AND {sec_index} > '{secondary_hi}'::DECIMAL
                ORDER BY {sec_index} ASC LIMIT 1"
        ))
    };

    (preliminary_query, largest_below, smallest_above)
}
