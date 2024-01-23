//! MPT Digest Implementation

use crate::{
    circuit::{PCDCircuit, ProofOrDummyTarget, UserCircuit},
    utils::less_than,
};
use plonky2::{
    field::extension::Extendable,
    hash::{
        hash_types::{HashOutTarget, RichField},
        hashing::hash_n_to_hash_no_pad,
        poseidon::{PoseidonHash, PoseidonPermutation},
    },
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::circuit_builder::CircuitBuilder,
};

/// MPT Digest Wires
#[derive(Clone, Debug)]
pub struct DigestWires<const ARITY: usize> {
    inputs: [Target; ARITY],
    real_len: Target,
    output: HashOutTarget,
}

/// MPT Digest Circuit
/// This is a simple version of MPT digest circuit with aggregation, and set
/// ARITY to 16 as default.
#[derive(Clone, Debug)]
pub struct DigestCircuit<F, const D: usize, const ARITY: usize = { 16 }> {
    inputs: [F; ARITY],
    real_len: usize,
}

impl<F, const D: usize, const ARITY: usize> DigestCircuit<F, D, ARITY>
where
    F: RichField + Extendable<D>,
{
    pub fn new(mut inputs: Vec<F>) -> Self {
        let real_len = inputs.len();
        assert!(real_len <= ARITY);

        inputs.resize(ARITY, F::ZERO);
        let inputs = inputs.try_into().unwrap();

        Self { inputs, real_len }
    }
}

impl<F, const D: usize, const ARITY: usize> UserCircuit<F, D> for DigestCircuit<F, D, ARITY>
where
    F: RichField + Extendable<D>,
{
    type Wires = DigestWires<ARITY>;

    fn build(b: &mut CircuitBuilder<F, D>) -> Self::Wires {
        let real_len = b.add_virtual_target();
        let inputs = b.add_virtual_target_arr::<ARITY>();

        let padding = b.constant(F::ZERO);
        let padded_inputs = inputs
            .iter()
            .enumerate()
            .map(|(i, data)| {
                let i = b.constant(F::from_canonical_usize(i));

                // Condition for real data if real_len < ARITY, otherwise it's
                // padding.
                let is_data = less_than(b, i, real_len, ARITY);
                let is_padding = b.not(is_data);

                // Construct the input item.
                let data = b.mul(is_data.target, *data);
                let padding = b.mul(is_padding.target, padding);

                b.add(data, padding)
            })
            .collect();

        // TODO: cannot confirm if hash output is right with padding zeros.
        let output = b.hash_n_to_hash_no_pad::<PoseidonHash>(padded_inputs);

        Self::Wires {
            inputs,
            real_len,
            output,
        }
    }

    fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
        pw.set_target_arr(&wires.inputs, &self.inputs);
        pw.set_target(wires.real_len, F::from_canonical_usize(self.real_len));

        // TODO: should pass into `self.inputs[..self.real_len]`?
        let output = hash_n_to_hash_no_pad::<F, PoseidonPermutation<F>>(&self.inputs);
        pw.set_hash_target(wires.output, output);
    }
}

impl<F, const D: usize, const ARITY: usize> PCDCircuit<F, D, ARITY> for DigestCircuit<F, D, ARITY>
where
    F: RichField + Extendable<D>,
{
    fn build_recursive(
        b: &mut CircuitBuilder<F, D>,
        p: &[ProofOrDummyTarget<D>; ARITY],
    ) -> Self::Wires {
        // TODO: sorry, cannot confirm if below code is right:
        // - register wires-inputs as public inputs.
        // - invoke `proof.conditionally_true` for valid inputs.

        let wires = <Self as UserCircuit<F, D>>::build(b);
        b.register_public_inputs(&wires.inputs);

        p.iter().enumerate().for_each(|(i, proof)| {
            let i = b.constant(F::from_canonical_usize(i));
            let is_data = less_than(b, i, wires.real_len, ARITY);

            proof.conditionally_true(b, is_data);
        });

        wires
    }

    fn base_inputs(&self) -> Vec<F> {
        F::rand_vec(ARITY)
    }

    fn num_io() -> usize {
        ARITY
    }
}
