//! Backup arity circuit implemention for proving Merkle tree nodes recursively.

use super::DigestTreeCircuit;
use crate::{
    circuit::{PCDCircuit, ProofOrDummyTarget, UserCircuit},
    utils::{convert_u8_targets_to_u32, convert_u8_values_to_u32, less_than},
};
use plonky2::{
    field::extension::Extendable,
    hash::{
        hash_types::{HashOut, HashOutTarget, RichField, NUM_HASH_OUT_ELTS},
        hashing::{hash_n_to_hash_no_pad, PlonkyPermutation},
        poseidon::{PoseidonHash, PoseidonPermutation, SPONGE_RATE},
    },
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::circuit_builder::CircuitBuilder,
};
use std::{array, iter};

/// Arity circuit wires including input and output targets
#[derive(Clone, Debug)]
pub struct DigestArityWires<const ARITY: usize>
where
    [(); ARITY * 4 + 28]:,
{
    /// Input targets
    /// The inputs have a constant length of 32 for a Merkle tree leaf, and
    /// `ARITY * 4` for a branch. This length is at least 32 since `ARITY >= 1`.
    inputs: [Target; ARITY * 4 + 28],
    /// Child input length
    /// This child length is zero if it's a leaf, otherwise it specifies the
    /// flattened input length of a branch. It's also used to identify if the
    /// current node is a leaf or branch, since branch have non-empty children.
    child_input_len: Target,
    /// Output hash target for a leaf or branch
    output: HashOutTarget,
}

/// Arity circuit used to prove Merkle tree
/// This circuit could be used to prove Merkle tree recursively. Each Merkle
/// tree branch has maximum ARITY children (`ARITY >= 1`).
#[derive(Clone, Debug)]
pub struct DigestArityCircuit<F, const D: usize, const ARITY: usize>
where
    [(); ARITY * 4 + 28]:,
{
    /// Input values
    /// The inputs have a constant length of 32 for a Merkle tree leaf, and
    /// `ARITY * 4` for a branch. This length is at least 32 since `ARITY >= 1`.
    inputs: [F; ARITY * 4 + 28],
    /// Child input length
    /// This child length is zero if it's a leaf, otherwise it specifies the
    /// flattened input length of a branch.
    child_input_len: usize,
}

impl<F, const D: usize, const ARITY: usize> DigestTreeCircuit<HashOut<F>>
    for DigestArityCircuit<F, D, ARITY>
where
    [(); ARITY * 4 + 28]:,
    F: RichField + Extendable<D>,
{
    /// Create a circuit instance for a leaf of Merkle tree.
    fn new_leaf(value: [u8; 32]) -> Self {
        let inputs: [F; ARITY * 4 + 28] = array::from_fn(|i| {
            if i < 32 {
                F::from_canonical_u8(value[i])
            } else {
                F::ZERO
            }
        });

        // Set the child input length to zero for identifying it's a leaf.
        Self {
            inputs,
            child_input_len: 0,
        }
    }

    /// Create a circuit instance for a branch of Merkle tree.
    fn new_branch(children: Vec<HashOut<F>>) -> Self {
        let child_len = children.len();
        assert!(child_len > 0 && child_len <= ARITY);

        // Flatten the child hash values and construct inputs.
        let children: Vec<_> = children.into_iter().flat_map(|c| c.elements).collect();
        let inputs = array::from_fn(|i| children.get(i).cloned().unwrap_or(F::ZERO));

        Self {
            inputs,
            child_input_len: inputs.len(),
        }
    }
}

impl<F, const D: usize, const ARITY: usize> UserCircuit<F, D> for DigestArityCircuit<F, D, ARITY>
where
    [(); ARITY * 4 + 28]:,
    F: RichField + Extendable<D>,
{
    type Wires = DigestArityWires<ARITY>;

    /// Build the digest circuit.
    fn build(b: &mut CircuitBuilder<F, D>) -> Self::Wires {
        let child_input_len = b.add_virtual_target();
        let inputs = b.add_virtual_target_arr::<{ ARITY * 4 + 28 }>();

        // Generate the hash outputs for both leaf and branch.
        let leaf_output = build_leaf(b, &inputs);
        let branch_output = build_branch(b, &inputs, child_input_len);

        // It's a leaf of Merkle tree if the child length is zero.
        let zero = b.zero();
        let is_leaf = b.is_equal(child_input_len, zero);

        // Construct the hash output with checking if it's a leaf or branch.
        let output = leaf_output
            .elements
            .into_iter()
            .zip(branch_output.elements)
            .map(|(leaf_target, branch_target)| b.select(is_leaf, leaf_target, branch_target))
            .collect();
        let output = HashOutTarget::from_vec(output);

        Self::Wires {
            inputs,
            child_input_len,
            output,
        }
    }

    /// Prove the digest circuit, connect values and targets.
    fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
        pw.set_target_arr(&wires.inputs, &self.inputs);
        pw.set_target(
            wires.child_input_len,
            F::from_canonical_usize(self.child_input_len),
        );

        // It's a leaf of Merkle tree if the child length is zero.
        let output = if self.child_input_len == 0 {
            // Convert the values from u8 array to u32.
            let inputs: Vec<_> = convert_u8_values_to_u32(&self.inputs[..32]);
            hash_n_to_hash_no_pad::<F, PoseidonPermutation<F>>(&inputs)
        } else {
            hash_n_to_hash_no_pad::<F, PoseidonPermutation<F>>(&self.inputs[..self.child_input_len])
        };

        pw.set_hash_target(wires.output, output);
    }
}

impl<F, const D: usize, const ARITY: usize> PCDCircuit<F, D, ARITY>
    for DigestArityCircuit<F, D, ARITY>
where
    [(); ARITY * 4 + 28]:,
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

/// Build the Poseidon hash for a leaf of Merkle tree.
fn build_leaf<F, const D: usize>(b: &mut CircuitBuilder<F, D>, inputs: &[Target]) -> HashOutTarget
where
    F: RichField + Extendable<D>,
{
    // Convert the u8 target array to u32 target array.
    let leaf_inputs: Vec<_> = convert_u8_targets_to_u32(b, &inputs[..32])
        .into_iter()
        .map(|u32_target| u32_target.0)
        .collect();

    // The leaf value should be `[U32Target; 8]` after conversion.
    let leaf_value_len = b.constant(F::from_canonical_usize(8));

    build_standard_poseidon(b, &leaf_inputs, leaf_value_len)
}

/// Build the Poseidon hash for a branch of Merkle tree.
fn build_branch<F, const D: usize>(
    b: &mut CircuitBuilder<F, D>,
    inputs: &[Target],
    child_input_len: Target,
) -> HashOutTarget
where
    F: RichField + Extendable<D>,
{
    build_standard_poseidon(b, &inputs, child_input_len)
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
