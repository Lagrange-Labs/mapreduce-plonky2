mod public_inputs;
mod wire;

/*
use plonky2::{
    field::extension::Extendable,
    hash::{hash_types::RichField, poseidon::PoseidonHash},
    iop::target::Target,
    plonk::circuit_builder::CircuitBuilder,
};

use super::BlockLinkingPublicInputs;
use crate::circuit::ProofOrDummyTarget;

pub use public_inputs::LeafPublicInputs;
pub use wire::LeafWires;

pub struct LeafCircuit;

impl LeafCircuit {
    pub const ARITY: usize = 1;

    pub fn build_recursive<F, const D: usize>(
        b: &mut CircuitBuilder<F, D>,
        p: &[ProofOrDummyTarget<D>; Self::ARITY],
    ) -> LeafWires<Target>
    where
        F: RichField + Extendable<D>,
    {
        let block_linking_pi = &p[0].p.public_inputs;
        let wires = LeafWires::build(b);
        let node = wires.node();
        let hash = b.hash_n_to_hash_no_pad::<PoseidonHash>(node.to_vec());

        node.iter()
            .zip(hash.elements.iter())
            .for_each(|(n, h)| b.connect(*n, *h));

        wires
    }
}
*/
