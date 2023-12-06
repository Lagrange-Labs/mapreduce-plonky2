mod header;
mod mpt;
mod proof;
#[cfg(test)]
mod prover;

/// Length of a hash in bytes.
const HASH_LEN: usize = 32;
/// Length of a hash in U32
const PACKED_HASH_LEN: usize = 8;
