use plonky2::{field::goldilocks_field::GoldilocksField, iop::target::Target};

pub mod aggregation;
mod revelation;
#[cfg(test)]
mod tests;

// An EWord (EVM Word) is a 256-bits/8×32B integer
pub const EWORD_LEN: usize = 8;
// Targets for an EVM word
type EWordTarget = [Target; EWORD_LEN];
// 8 Goldilocks encoding an EVM words
type EWord = [GoldilocksField; EWORD_LEN];
