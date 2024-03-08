use plonky2::{
    field::extension::Extendable,
    hash::{
        hash_types::{RichField, NUM_HASH_OUT_ELTS},
        hashing::hash_n_to_hash_no_pad,
        poseidon::PoseidonPermutation,
    },
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::circuit_builder::CircuitBuilder,
};

use super::BlockLinkingPublicInputs;

pub struct LeafWires<T> {
    inner: [T; LeafWires::<()>::TOTAL_LEN],
}

impl<T> LeafWires<T> {
    pub const ROOT_F_LEN: usize = 1;
    pub const ROOT_A_LEN: usize = BlockLinkingPublicInputs::<()>::A_LEN;
    pub const ROOT_C_LEN: usize = BlockLinkingPublicInputs::<()>::C_LEN;
    pub const ROOT_S_LEN: usize = BlockLinkingPublicInputs::<()>::S_LEN;
    pub const ROOT_M_LEN: usize = BlockLinkingPublicInputs::<()>::M_LEN;
    pub const C_LEN: usize = NUM_HASH_OUT_ELTS;
    pub const H_LEN: usize = BlockLinkingPublicInputs::<()>::H_LEN;
    pub const N_LEN: usize = BlockLinkingPublicInputs::<()>::N_LEN;
    pub const PREV_H_LEN: usize = BlockLinkingPublicInputs::<()>::PREV_H_LEN;
    pub const TOTAL_LEN: usize = Self::ROOT_F_LEN
        + Self::ROOT_A_LEN
        + Self::ROOT_C_LEN
        + Self::ROOT_S_LEN
        + Self::ROOT_M_LEN
        + Self::C_LEN
        + Self::H_LEN
        + Self::N_LEN
        + Self::PREV_H_LEN;

    pub const ROOT_F_IDX: usize = 0;
    pub const ROOT_A_IDX: usize = Self::ROOT_F_IDX + Self::ROOT_F_LEN;
    pub const ROOT_C_IDX: usize = Self::ROOT_A_IDX + Self::ROOT_A_LEN;
    pub const ROOT_S_IDX: usize = Self::ROOT_C_IDX + Self::ROOT_C_LEN;
    pub const ROOT_M_IDX: usize = Self::ROOT_S_IDX + Self::ROOT_S_LEN;
    pub const C_IDX: usize = Self::C_IDX + Self::C_LEN;
    pub const H_IDX: usize = Self::H_IDX + Self::H_LEN;
    pub const N_IDX: usize = Self::N_IDX + Self::N_LEN;
    pub const PREV_H_IDX: usize = Self::PREV_H_IDX + Self::PREV_H_LEN;

    pub fn root_a(&self) -> &[T] {
        &self.inner[Self::ROOT_A_IDX..Self::ROOT_A_IDX + Self::ROOT_A_LEN]
    }

    pub fn root_c(&self) -> &[T] {
        &self.inner[Self::ROOT_C_IDX..Self::ROOT_C_IDX + Self::ROOT_C_LEN]
    }

    pub fn root_s(&self) -> &[T] {
        &self.inner[Self::ROOT_S_IDX..Self::ROOT_S_IDX + Self::ROOT_S_LEN]
    }

    pub fn root_m(&self) -> &[T] {
        &self.inner[Self::ROOT_M_IDX..Self::ROOT_M_IDX + Self::ROOT_M_LEN]
    }

    pub fn c(&self) -> &[T] {
        &self.inner[Self::C_IDX..Self::C_IDX + Self::C_LEN]
    }

    pub fn h(&self) -> &[T] {
        &self.inner[Self::H_IDX..Self::H_IDX + Self::H_LEN]
    }

    pub fn n(&self) -> &[T] {
        &self.inner[Self::N_IDX..Self::N_IDX + Self::N_LEN]
    }

    pub fn prev_h(&self) -> &[T] {
        &self.inner[Self::PREV_H_IDX..Self::PREV_H_IDX + Self::PREV_H_LEN]
    }

    pub fn node(&self) -> &[T] {
        &self.inner[..Self::C_LEN]
    }
}

impl LeafWires<Target> {
    pub fn build<F, const D: usize>(b: &mut CircuitBuilder<F, D>) -> Self
    where
        F: RichField + Extendable<D>,
    {
        Self {
            inner: b.add_virtual_target_arr(),
        }
    }

    pub fn assign<F: RichField>(&self, p: &mut PartialWitness<F>, block_linking_pi: &[F]) {
        let f = F::ZERO; // "LEAF"
        let a = BlockLinkingPublicInputs::a(block_linking_pi);
        let c = BlockLinkingPublicInputs::merkle_root(block_linking_pi);
        let s = BlockLinkingPublicInputs::s(block_linking_pi);
        let m = BlockLinkingPublicInputs::m(block_linking_pi);

        let len = 1 + a.len() + c.len() + s.len() + m.len();
        let mut node = Vec::with_capacity(len);
        node.push(f);
        node.extend_from_slice(a);
        node.extend_from_slice(c);
        node.extend_from_slice(s);
        node.extend_from_slice(m);
        let root = hash_n_to_hash_no_pad::<F, PoseidonPermutation<F>>(&node);

        p.set_target(self.inner[Self::ROOT_F_IDX], f);

        let targets = self
            .root_a()
            .iter()
            .chain(self.root_c().iter())
            .chain(self.root_s().iter())
            .chain(self.root_m().iter())
            .chain(self.c().iter())
            .chain(self.h().iter())
            .chain(self.n().iter())
            .chain(self.prev_h().iter());

        let witnesses = a
            .iter()
            .chain(c.iter())
            .chain(s.iter())
            .chain(m.iter())
            .chain(root.elements.iter())
            .chain(BlockLinkingPublicInputs::block_hash(block_linking_pi).iter())
            .chain(BlockLinkingPublicInputs::block_number(block_linking_pi).iter())
            .chain(BlockLinkingPublicInputs::prev_block_hash(block_linking_pi).iter());

        targets
            .zip(witnesses)
            .for_each(|(t, w)| p.set_target(*t, *w));
    }
}
