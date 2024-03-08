use super::BlockLinkingPublicInputs;
use plonky2::{
    field::extension::Extendable,
    hash::{
        hash_types::{HashOut, RichField, NUM_HASH_OUT_ELTS},
        hashing::hash_n_to_hash_no_pad,
        poseidon::{PoseidonHash, PoseidonPermutation},
    },
    iop::target::Target,
    plonk::circuit_builder::CircuitBuilder,
};

pub struct LeafPublicInputs<T> {
    inner: [T; LeafPublicInputs::<()>::TOTAL_LEN],
}

impl<T> LeafPublicInputs<T> {
    pub const C_LEN: usize = NUM_HASH_OUT_ELTS;
    pub const H_LEN: usize = BlockLinkingPublicInputs::<()>::H_LEN;
    pub const N_LEN: usize = BlockLinkingPublicInputs::<()>::N_LEN;
    pub const PREV_H_LEN: usize = BlockLinkingPublicInputs::<()>::PREV_H_LEN;
    pub const TOTAL_LEN: usize = Self::C_LEN + Self::H_LEN + Self::N_LEN + Self::PREV_H_LEN;

    pub const C_IDX: usize = 0;
    pub const H_IDX: usize = Self::C_IDX + Self::C_LEN;
    pub const N_IDX: usize = Self::H_IDX + Self::H_LEN;
    pub const PREV_H_IDX: usize = Self::N_IDX + Self::N_LEN;

    /// Creates a new instance of the leaf public inputs.
    ///
    /// # Arguments
    ///
    /// - `root` will correspond to the hash output of the node contents.
    /// - `block_linking_pi` will correspond to the public inputs of the [BlockLinkingPublicInputs]
    /// structure.
    ///
    /// # Panics
    ///
    /// This function will panic if:
    /// - The length of `root` is different than [Self::C_LEN].
    /// - The length of `block_linking_pi` is different than [BlockLinkingPublicInputs::TOTAL_LEN].
    pub fn new(root: &[T], block_linking_pi: &[T]) -> Self
    where
        T: Default + Copy,
    {
        let c = root;
        let h = &block_linking_pi[BlockLinkingPublicInputs::<()>::H_IDX
            ..BlockLinkingPublicInputs::<()>::H_IDX + BlockLinkingPublicInputs::<()>::H_LEN];
        let n = &block_linking_pi[BlockLinkingPublicInputs::<()>::N_IDX
            ..BlockLinkingPublicInputs::<()>::N_IDX + BlockLinkingPublicInputs::<()>::N_LEN];
        let prev_h = &block_linking_pi[BlockLinkingPublicInputs::<()>::PREV_H_IDX
            ..BlockLinkingPublicInputs::<()>::PREV_H_IDX
                + BlockLinkingPublicInputs::<()>::PREV_H_LEN];

        let mut inner = [T::default(); LeafPublicInputs::<()>::TOTAL_LEN];

        inner[Self::C_IDX..Self::C_IDX + Self::C_LEN].copy_from_slice(c);
        inner[Self::H_IDX..Self::H_IDX + Self::H_LEN].copy_from_slice(h);
        inner[Self::N_IDX..Self::N_IDX + Self::N_LEN].copy_from_slice(n);
        inner[Self::PREV_H_IDX..Self::PREV_H_IDX + Self::PREV_H_LEN].copy_from_slice(prev_h);

        Self { inner }
    }

    pub fn inner(&self) -> &[T] {
        &self.inner
    }

    pub fn root(s: &[T]) -> &[T] {
        &s[Self::C_IDX..Self::C_IDX + Self::C_LEN]
    }

    pub fn block_header(s: &[T]) -> &[T] {
        &s[Self::H_IDX..Self::H_IDX + Self::H_LEN]
    }

    pub fn block_index(s: &[T]) -> &[T] {
        &s[Self::N_IDX..Self::N_IDX + Self::N_LEN]
    }

    pub fn parent_block_header(s: &[T]) -> &[T] {
        &s[Self::PREV_H_IDX..Self::PREV_H_IDX + Self::PREV_H_LEN]
    }
}
