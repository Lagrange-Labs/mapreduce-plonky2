//! Digest circuit implemention used to prove Poseidon hash of Merkle tree nodes
//! recursively.

use crate::{
    circuit::{PCDCircuit, ProofOrDummyTarget, UserCircuit},
    utils::less_than,
};
use plonky2::{
    field::extension::Extendable,
    hash::{
        hash_types::{HashOutTarget, RichField, NUM_HASH_OUT_ELTS},
        hashing::{hash_n_to_hash_no_pad, PlonkyPermutation},
        poseidon::{PoseidonHash, PoseidonPermutation, SPONGE_RATE},
    },
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::circuit_builder::CircuitBuilder,
};
use std::iter;

/// Digest circuit wires including input and output targets
#[derive(Clone, Debug)]
pub struct DigestWires<const ARITY: usize>
where
    [(); ARITY * 4]:,
{
    /// Input targets
    /// Each Merkle tree branch has ARITY child nodes at maximum, and each node
    /// has the value of type `[F; 4]` (which could be an U256 or hash value).
    inputs: [Target; ARITY * 4],
    /// Real input length
    /// The inputs are padded with dummy values to the length of `ARITY * 4`.
    real_len: Target,
    /// Output hash target
    output: HashOutTarget,
}

/// Digest circuit used to prove Poseidon hash
/// This circuit could be used to prove Merkle tree recursively. Each Merkle
/// tree branch has maximum ARITY children, and it's set to `16` as default.
#[derive(Clone, Debug)]
pub struct DigestCircuit<F, const D: usize, const ARITY: usize = { 16 }>
where
    [(); ARITY * 4]:,
{
    /// Input values
    inputs: [F; ARITY * 4],
    /// Real input length
    real_len: usize,
}

impl<F, const D: usize, const ARITY: usize> DigestCircuit<F, D, ARITY>
where
    [(); ARITY * 4]:,
    F: RichField + Extendable<D>,
{
    /// Create the digest circuit.
    /// The `inputs` argument must be flattened and `ARITY * 4` at maximum.
    pub fn new(mut inputs: Vec<F>) -> Self {
        let real_len = inputs.len();
        assert!(real_len <= ARITY * 4);

        inputs.resize(ARITY * 4, F::ZERO);
        let inputs = inputs.try_into().unwrap();

        Self { inputs, real_len }
    }
}

impl<F, const D: usize, const ARITY: usize> UserCircuit<F, D> for DigestCircuit<F, D, ARITY>
where
    [(); ARITY * 4]:,
    F: RichField + Extendable<D>,
{
    type Wires = DigestWires<ARITY>;

    /// Build the digest circuit.
    fn build(b: &mut CircuitBuilder<F, D>) -> Self::Wires {
        let real_len = b.add_virtual_target();
        let inputs = b.add_virtual_target_arr::<{ ARITY * 4 }>();

        // Generate the hash ouput by standard Poseidon.
        let output = build_standard_poseidon(b, &inputs, real_len);

        Self::Wires {
            inputs,
            real_len,
            output,
        }
    }

    /// Prove the digest circuit, connect values and targets.
    fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
        pw.set_target_arr(&wires.inputs, &self.inputs);
        pw.set_target(wires.real_len, F::from_canonical_usize(self.real_len));

        let output =
            hash_n_to_hash_no_pad::<F, PoseidonPermutation<F>>(&self.inputs[..self.real_len]);
        pw.set_hash_target(wires.output, output);
    }
}

impl<F, const D: usize, const ARITY: usize> PCDCircuit<F, D, ARITY> for DigestCircuit<F, D, ARITY>
where
    [(); ARITY * 4]:,
    F: RichField + Extendable<D>,
{
    fn build_recursive(
        b: &mut CircuitBuilder<F, D>,
        _: &[ProofOrDummyTarget<D>; ARITY],
    ) -> Self::Wires {
        let wires = <Self as UserCircuit<F, D>>::build(b);
        b.register_public_inputs(&wires.output.elements);

        // TODO: check the proof public inputs match what is expected.

        wires
    }

    fn base_inputs(&self) -> Vec<F> {
        // Poseidon hash always has NUM_HASH_OUT_ELTS outputs.
        F::rand_vec(NUM_HASH_OUT_ELTS)
    }

    fn num_io() -> usize {
        // Poseidon hash always has NUM_HASH_OUT_ELTS outputs.
        NUM_HASH_OUT_ELTS
    }
}

/// Build the standard Poseidon hash, pass into the inputs and real length
/// targets, and generate the hash ouput target.
/// This function references `hash_n_to_m_no_pad` function in plonky.
/// <https://github.com/nikkolasg/plonky2/blob/b53b079a2d6caabf317bc65aec2939aa5c72aaf0/plonky2/src/hash/hashing.rs#L30>
fn build_standard_poseidon<F, const D: usize>(
    b: &mut CircuitBuilder<F, D>,
    inputs: &[Target],
    real_len: Target,
) -> HashOutTarget
where
    F: RichField + Extendable<D>,
{
    // Initialize the poseison state to zeros.
    let zero = b.zero();
    let mut state =
        <PoseidonPermutation<Target> as PlonkyPermutation<Target>>::new(iter::repeat(zero));

    // Absorb all input chunks with a rate, and update the state.
    inputs
        .chunks(SPONGE_RATE)
        .enumerate()
        .for_each(|(i, chunks)| {
            let chunk_start = SPONGE_RATE * i;

            chunks.iter().enumerate().for_each(|(i, elt)| {
                // Set the element to state if it's a real data by comparing
                // with real length.
                let elt_offset = b.constant(F::from_canonical_usize(chunk_start + i));
                let is_elt = less_than(b, elt_offset, real_len, 8);

                let elt = b.select(is_elt, *elt, state.as_ref()[i]);
                state.set_elt(elt, i);
            });

            // Update to new state if the chunk start position (which is
            // `SPONGE_RATE * i`, and i starts from 0) is less than the real
            // data length. If so, the data of
            // `[chunk_start..chunk_start + SPONGE_RATE]` should be permuted
            // to the new state and the real data length must satisfies one
            // of the below conditions:
            // . real_len > chunk_start + SPONGE_RATE
            // . real_len > chunk_start && real_len <= chunk_start + SPONGE_RATE
            let new_state = b.permute::<PoseidonHash>(state);
            let chunk_start = b.constant(F::from_canonical_usize(chunk_start));
            let is_new_state = less_than(b, chunk_start, real_len, 8);

            let elts: Vec<_> = state
                .as_ref()
                .iter()
                .zip(new_state.as_ref())
                .map(|(elt, new_elt)| b.select(is_new_state, *new_elt, *elt))
                .collect();

            elts.into_iter()
                .enumerate()
                .for_each(|(i, elt)| state.set_elt(elt, i));
        });

    // Squeeze outputs from the state.
    let output = state.squeeze()[..NUM_HASH_OUT_ELTS].to_vec();

    HashOutTarget::from_vec(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;
    use plonky2::{
        field::types::{Field, Sample},
        plonk::{
            circuit_builder::CircuitBuilder,
            circuit_data::CircuitConfig,
            config::{GenericConfig, PoseidonGoldilocksConfig},
        },
    };
    use rand::{thread_rng, Rng};

    const ARITY: usize = 16;
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    /// Test standard Poseidon hash function `build_standard_poseidon` which
    /// could be used in circuit.
    #[test]
    fn test_standard_poseidon() -> Result<()> {
        let config = CircuitConfig::standard_recursion_config();
        let mut b = CircuitBuilder::<F, D>::new(config);

        // Initialize the input and real length targets.
        let real_len_target = b.add_virtual_target();
        let input_targets = b.add_virtual_target_arr::<ARITY>();

        // Build the Poseidon hash and generate hash output target.
        let output_target = build_standard_poseidon(&mut b, &input_targets, real_len_target);

        // Register public inputs.
        b.register_public_input(real_len_target);
        b.register_public_inputs(&input_targets);
        b.register_public_inputs(&output_target.elements);

        // Generate random input and real length values.
        let input_values = F::rand_vec(ARITY);
        let real_len_value = F::from_canonical_usize(rand::thread_rng().gen_range(1..ARITY));

        // Set the values to targets for witness.
        let mut pw = PartialWitness::new();
        pw.set_target_arr(&input_targets, &input_values);
        pw.set_target(real_len_target, real_len_value);

        // Prove and verify.
        let data = b.build::<C>();
        let proof = data.prove(pw)?;
        data.verify(proof)
    }
}
