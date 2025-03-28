

pub const ROW_TREE_MAX_DEPTH: usize = 25;
pub const INDEX_TREE_MAX_DEPTH: usize = 26;
pub const MAX_NUM_RESULT_OPS: usize = 20;
pub const MAX_NUM_RESULTS: usize = 10;
pub const MAX_NUM_OUTPUTS: usize = 5;
pub const MAX_NUM_ITEMS_PER_OUTPUT: usize = 5;
pub const MAX_NUM_PLACEHOLDERS: usize = 5;
pub const MAX_NUM_COLUMNS: usize = 20;
pub const MAX_NUM_PREDICATE_OPS: usize = 20;
/// Maximum number of chunks that can be aggregated in a single proof of batching query
/// We must use the same value of this constant for both DQ and Worker.
pub const NUM_CHUNKS: usize = 66;
/// Maximum number of rows that can be proven in a single proof of batching query
/// We must use the same value of this constant for both DQ and Worker.
pub const NUM_ROWS: usize = 100;

/// Filenames for parameters
 
/// The filename of params checksum hashes
pub const PARAMS_CHECKSUM_FILENAME: &str = "public_params.hash";

pub const GROTH16_ASSETS_PREFIX: &str = "groth16_assets";
pub const PP_BIN_KEY: &str = "preprocessing_params.bin";
pub const QP_BIN_KEY: &str = "query_params.bin";