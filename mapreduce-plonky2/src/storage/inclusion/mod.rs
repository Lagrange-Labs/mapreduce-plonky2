mod inner_node;
mod leaf;
mod public_inputs;
#[cfg(test)]
mod tests;

use plonky2::field::{goldilocks_field::GoldilocksField, types::Field};
pub use public_inputs::PublicInputs;

#[allow(non_snake_case)]
fn LEAF_MARKER() -> GoldilocksField {
    GoldilocksField::from_canonical_u32(u32::from_be_bytes(*b"LEAF"))
}

#[allow(non_snake_case)]
fn NODE_MARKER() -> GoldilocksField {
    GoldilocksField::from_canonical_u32(u32::from_be_bytes(*b"NODE"))
}
