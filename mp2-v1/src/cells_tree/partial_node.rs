//! Module handling the intermediate node with 1 child inside a cells tree

use super::public_inputs::PublicInputs;
use anyhow::Result;
use mp2_common::{
    array::Array, group_hashing::CircuitBuilderGroupHashing, poseidon::empty_poseidon_hash,
    public_inputs::PublicInputCommon, types::CBuilder, u256, D, F,
};
use plonky2::{
    hash::poseidon::PoseidonHash,
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::proof::ProofWithPublicInputsTarget,
};
use recursion_framework::circuit_builder::CircuitLogicWires;
use serde::{Deserialize, Serialize};
use std::iter;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PartialNodeWires {
    identifier: Target,
    packed_value: Array<Target, { u256::NUM_LIMBS }>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PartialNodeCircuit {
    /// The same identifier derived from the MPT extraction
    pub(crate) identifier: F,
    /// Packed Uint256 value
    pub(crate) packed_value: [F; u256::NUM_LIMBS],
}

impl PartialNodeCircuit {
    pub fn build(b: &mut CBuilder, child_proof: PublicInputs<Target>) -> PartialNodeWires {
        let identifier = b.add_virtual_target();
        let packed_value = Array::new(b);

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
            .chain(packed_value.arr)
            .collect();
        let h = b.hash_n_to_hash_no_pad::<PoseidonHash>(inputs).elements;

        // dc = p.DC + D(identifier || value)
        let inputs: Vec<_> = iter::once(identifier).chain(packed_value.arr).collect();
        let dc = b.map_to_curve_point(&inputs);
        let child_digest = child_proof.cells_target();
        let dc = b.add_curve_point(&[child_digest, dc]);

        // Register the public inputs.
        PublicInputs::new(&h, &dc).register(b);

        PartialNodeWires {
            identifier,
            packed_value,
        }
    }

    /// Assign the wires.
    fn assign(&self, pw: &mut PartialWitness<F>, wires: &PartialNodeWires) {
        pw.set_target(wires.identifier, self.identifier);
        wires.packed_value.assign(pw, &self.packed_value);
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
        utils::{Fieldable, Packer, ToFields},
        C,
    };
    use mp2_test::{
        circuit::{run_circuit, UserCircuit},
        utils::random_vector,
    };
    use plonky2::{
        field::types::{Field, Sample},
        hash::hash_types::NUM_HASH_OUT_ELTS,
        iop::witness::WitnessWrite,
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
            pw.set_target_arr(&wires.1, &self.child_pi);
        }
    }

    #[test]
    fn test_cells_tree_partial_node_circuit() {
        let mut rng = thread_rng();

        let identifier = thread_rng().gen::<u32>().to_field();
        let packed_value: [_; u256::NUM_LIMBS] = random_vector::<u32>(u256::NUM_LIMBS)
            .to_fields()
            .try_into()
            .unwrap();

        // Create the child public inputs.
        let child_hash = random_vector::<u32>(NUM_HASH_OUT_ELTS).to_fields();
        let child_digest = Point::sample(&mut rng);
        let dc = child_digest.to_weierstrass();
        let dc_is_inf = if dc.is_inf { F::ONE } else { F::ZERO };
        let dc = (dc.x.0.as_slice(), dc.y.0.as_slice(), &dc_is_inf);
        let child_pi = &PublicInputs { h: &child_hash, dc }.to_vec();

        let test_circuit = TestPartialNodeCircuit {
            c: PartialNodeCircuit {
                identifier,
                packed_value,
            },
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
                .chain(packed_value.clone())
                .collect();
            let exp_hash = PoseidonHash::hash_no_pad(&inputs);

            assert_eq!(pi.h, exp_hash.elements);
        }
        // Check the cells digest
        {
            let inputs: Vec<_> = iter::once(identifier).chain(packed_value).collect();
            let exp_digest = map_to_curve_point(&inputs);
            let exp_digest = add_curve_point(&[exp_digest, child_digest]).to_weierstrass();

            assert_eq!(pi.cells_point(), exp_digest);
        }
    }
}
