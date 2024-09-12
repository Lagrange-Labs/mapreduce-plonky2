//! Module handling the intermediate node with 1 child inside a cells tree

use super::{accumulate_proof_digest, decide_digest_section, public_inputs::PublicInputs};
use alloy::primitives::U256;
use anyhow::Result;
use mp2_common::{
    group_hashing::CircuitBuilderGroupHashing,
    poseidon::empty_poseidon_hash,
    public_inputs::PublicInputCommon,
    types::CBuilder,
    u256::{CircuitBuilderU256, UInt256Target, WitnessWriteU256},
    utils::ToTargets,
    CHasher, D, F,
};
use plonky2::{
    iop::{
        target::{BoolTarget, Target},
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::proof::ProofWithPublicInputsTarget,
};
use plonky2_ecgfp5::gadgets::curve::CircuitBuilderEcGFp5;
use recursion_framework::circuit_builder::CircuitLogicWires;
use serde::{Deserialize, Serialize};
use std::iter;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PartialNodeWires {
    identifier: Target,
    value: UInt256Target,
    #[serde(serialize_with = "serialize", deserialize_with = "deserialize")]
    is_multiplier: BoolTarget,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PartialNodeCircuit {
    /// The same identifier derived from the MPT extraction
    pub(crate) identifier: F,
    /// Uint256 value
    pub(crate) value: U256,
    /// Multiplier means that the digest goes into the multiplier public input, otherwise goes as
    /// usual in the individual digest (status quo)
    pub(crate) is_multiplier: bool,
}

impl PartialNodeCircuit {
    pub fn build(b: &mut CBuilder, child_proof: PublicInputs<Target>) -> PartialNodeWires {
        let identifier = b.add_virtual_target();
        let value = b.add_virtual_u256();
        let is_multiplier = b.add_virtual_bool_target_safe();

        // h = Poseidon(p.H || Poseidon("") || identifier || value)
        let child_hash = child_proof.node_hash();
        let empty_hash = empty_poseidon_hash();
        let empty_hash = b.constant_hash(*empty_hash);
        let inputs: Vec<_> = child_hash
            .elements
            .iter()
            .cloned()
            .chain(empty_hash.elements)
            .chain(iter::once(identifier))
            .chain(value.to_targets())
            .collect();
        let h = b.hash_n_to_hash_no_pad::<CHasher>(inputs).elements;

        // digest_cell = p.digest_cell + D(identifier || value)
        let inputs: Vec<_> = iter::once(identifier).chain(value.to_targets()).collect();
        let dc = b.map_to_curve_point(&inputs);
        let (digest_ind, digest_mult) = decide_digest_section(b, dc, is_multiplier);

        /// aggregate the digest of the child proof in the right digest
        let (digest_ind, digest_mul) =
            accumulate_proof_digest(b, digest_ind, digest_mult, child_proof);

        // Register the public inputs.
        PublicInputs::new(&h, &digest_ind, digest_mult).register(b);

        PartialNodeWires {
            identifier,
            value,
            is_multiplier,
        }
    }

    /// Assign the wires.
    fn assign(&self, pw: &mut PartialWitness<F>, wires: &PartialNodeWires) {
        pw.set_target(wires.identifier, self.identifier);
        pw.set_u256_target(&wires.value, self.value);
        pw.set_bool_target(wires.is_multiplier, self.is_multiplier);
    }
}

/// Num of children = 1
impl CircuitLogicWires<F, D, 1> for PartialNodeWires {
    type CircuitBuilderParams = ();

    type Inputs = PartialNodeCircuit;

    const NUM_PUBLIC_INPUTS: usize = PublicInputs::<F>::TOTAL_LEN;

    fn circuit_logic(
        builder: &mut CBuilder,
        verified_proofs: [&ProofWithPublicInputsTarget<D>; 1],
        _: Self::CircuitBuilderParams,
    ) -> Self {
        let child_proof = PublicInputs::from_slice(&verified_proofs[0].public_inputs);
        PartialNodeCircuit::build(builder, child_proof)
    }

    fn assign_input(&self, inputs: Self::Inputs, pw: &mut PartialWitness<F>) -> Result<()> {
        inputs.assign(pw, self);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mp2_common::{
        group_hashing::{add_curve_point, map_to_curve_point},
        poseidon::H,
        utils::{Fieldable, ToFields},
        C,
    };
    use mp2_test::{
        circuit::{run_circuit, UserCircuit},
        utils::random_vector,
    };
    use plonky2::{
        field::types::Sample, hash::hash_types::NUM_HASH_OUT_ELTS, iop::witness::WitnessWrite,
        plonk::config::Hasher,
    };
    use plonky2_ecgfp5::curve::curve::Point;
    use rand::{thread_rng, Rng};

    #[derive(Clone, Debug)]
    struct TestPartialNodeCircuit<'a> {
        c: PartialNodeCircuit,
        child_pi: &'a [F],
    }

    impl<'a> UserCircuit<F, D> for TestPartialNodeCircuit<'a> {
        // Partial node wires + child public inputs
        type Wires = (PartialNodeWires, Vec<Target>);

        fn build(b: &mut CBuilder) -> Self::Wires {
            let child_pi = b.add_virtual_targets(PublicInputs::<Target>::TOTAL_LEN);

            let wires = PartialNodeCircuit::build(b, PublicInputs::from_slice(&child_pi));

            (wires, child_pi)
        }

        fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
            self.c.assign(pw, &wires.0);
            pw.set_target_arr(&wires.1, self.child_pi);
        }
    }

    #[test]
    fn test_cells_tree_partial_node_circuit() {
        let mut rng = thread_rng();

        let identifier = rng.gen::<u32>().to_field();
        let value = U256::from_limbs(rng.gen::<[u64; 4]>());
        let value_fields = value.to_fields();

        // Create the child public inputs.
        let child_hash = random_vector::<u32>(NUM_HASH_OUT_ELTS).to_fields();
        let child_digest = Point::sample(&mut rng);
        let dc = &child_digest.to_weierstrass().to_fields();
        let neutral = Point::NEUTRAL.to_fields();
        let child_pi = &PublicInputs {
            h: &child_hash,
            ind: dc,
            mul: &neutral,
        }
        .to_vec();

        let test_circuit = TestPartialNodeCircuit {
            c: PartialNodeCircuit { identifier, value },
            child_pi,
        };
        let proof = run_circuit::<F, D, C, _>(test_circuit);
        let pi = PublicInputs::from_slice(&proof.public_inputs);
        // Check the node Poseidon hash
        {
            let empty_hash = empty_poseidon_hash();
            let inputs: Vec<_> = child_hash
                .into_iter()
                .chain(empty_hash.elements)
                .chain(iter::once(identifier))
                .chain(value_fields.clone())
                .collect();
            let exp_hash = H::hash_no_pad(&inputs);

            assert_eq!(pi.h, exp_hash.elements);
        }
        // Check the cells digest
        {
            let inputs: Vec<_> = iter::once(identifier).chain(value_fields).collect();
            let exp_digest = map_to_curve_point(&inputs);
            let exp_digest = add_curve_point(&[exp_digest, child_digest]).to_weierstrass();

            assert_eq!(pi.individual_digest_point(), exp_digest);
        }
    }
}
