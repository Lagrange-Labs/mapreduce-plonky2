//! Module handling the intermediate node with 2 children inside a cells tree

use super::public_inputs::PublicInputs;
use anyhow::Result;
use ethers::prelude::U256;
use mp2_common::{
    group_hashing::CircuitBuilderGroupHashing,
    public_inputs::PublicInputCommon,
    types::CBuilder,
    u256::{CircuitBuilderU256, UInt256Target, WitnessWriteU256},
    utils::ToTargets,
    D, F,
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
use std::{array, iter};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FullNodeWires {
    identifier: Target,
    value: UInt256Target,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FullNodeCircuit {
    /// The same identifier derived from the MPT extraction
    pub(crate) identifier: F,
    /// Uint256 value
    pub(crate) value: U256,
}

impl FullNodeCircuit {
    pub fn build(b: &mut CBuilder, child_proofs: [PublicInputs<Target>; 2]) -> FullNodeWires {
        let identifier = b.add_virtual_target();
        let value = b.add_virtual_u256();

        // h = Poseidon(p1.H || p2.H || identifier || value)
        let [p1_hash, p2_hash] = [0, 1].map(|i| child_proofs[i].node_hash());
        let inputs: Vec<_> = p1_hash
            .elements
            .iter()
            .cloned()
            .chain(p2_hash.elements)
            .chain(iter::once(identifier))
            .chain(value.to_targets())
            .collect();
        let h = b.hash_n_to_hash_no_pad::<PoseidonHash>(inputs).elements;

        // dc = p1.DC + p2.DC + D(identifier || value)
        let inputs: Vec<_> = iter::once(identifier).chain(value.to_targets()).collect();
        let dc = b.map_to_curve_point(&inputs);
        let [p1_dc, p2_dc] = [0, 1].map(|i| child_proofs[i].cells_target());
        let dc = b.add_curve_point(&[p1_dc, p2_dc, dc]);

        // Register the public inputs.
        PublicInputs::new(&h, &dc).register(b);

        FullNodeWires { identifier, value }
    }

    /// Assign the wires.
    fn assign(&self, pw: &mut PartialWitness<F>, wires: &FullNodeWires) {
        pw.set_target(wires.identifier, self.identifier);
        pw.set_u256_target(&wires.value, self.value);
    }
}

/// Num of children = 2
impl CircuitLogicWires<F, D, 2> for FullNodeWires {
    type CircuitBuilderParams = ();

    type Inputs = FullNodeCircuit;

    const NUM_PUBLIC_INPUTS: usize = PublicInputs::<F>::TOTAL_LEN;

    fn circuit_logic(
        builder: &mut CBuilder,
        verified_proofs: [&ProofWithPublicInputsTarget<D>; 2],
        _: Self::CircuitBuilderParams,
    ) -> Self {
        let child_proofs: [PublicInputs<Target>; 2] =
            array::from_fn(|i| PublicInputs::from_slice(&verified_proofs[i].public_inputs));
        FullNodeCircuit::build(builder, child_proofs)
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
    struct TestFullNodeCircuit<'a> {
        c: FullNodeCircuit,
        child_pis: &'a [Vec<F>; 2],
    }

    impl<'a> UserCircuit<F, D> for TestFullNodeCircuit<'a> {
        // Full node wires + child public inputs
        type Wires = (FullNodeWires, [Vec<Target>; 2]);

        fn build(b: &mut CBuilder) -> Self::Wires {
            let child_pis =
                [0; 2].map(|_| b.add_virtual_targets(PublicInputs::<Target>::TOTAL_LEN));

            let wires = FullNodeCircuit::build(
                b,
                array::from_fn(|i| PublicInputs::from_slice(&child_pis[i])),
            );

            (wires, child_pis)
        }

        fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
            self.c.assign(pw, &wires.0);

            assert_eq!(self.child_pis.len(), wires.1.len());
            for i in 0..2 {
                pw.set_target_arr(&wires.1[i], &self.child_pis[i]);
            }
        }
    }

    #[test]
    fn test_cells_tree_full_node_circuit() {
        let mut rng = thread_rng();

        let identifier = rng.gen::<u32>().to_field();
        let value = U256(rng.gen::<[u64; 4]>());
        let value_fields = value.to_fields();

        // Create the child public inputs.
        let child_hashs = [0; 2].map(|_| random_vector::<u32>(NUM_HASH_OUT_ELTS).to_fields());
        let child_digests = [0; 2].map(|_| Point::sample(&mut rng));
        let child_pis = &array::from_fn(|i| {
            let h = &child_hashs[i];

            let dc = child_digests[i].to_weierstrass();
            let dc_is_inf = if dc.is_inf { F::ONE } else { F::ZERO };
            let dc = (dc.x.0.as_slice(), dc.y.0.as_slice(), &dc_is_inf);

            PublicInputs { h, dc }.to_vec()
        });

        let test_circuit = TestFullNodeCircuit {
            c: FullNodeCircuit { identifier, value },
            child_pis,
        };
        let proof = run_circuit::<F, D, C, _>(test_circuit);
        let pi = PublicInputs::from_slice(&proof.public_inputs);
        // Check the node Poseidon hash
        {
            let inputs: Vec<_> = child_hashs[0]
                .clone()
                .into_iter()
                .chain(child_hashs[1].clone())
                .chain(iter::once(identifier))
                .chain(value_fields.clone())
                .collect();
            let exp_hash = PoseidonHash::hash_no_pad(&inputs);

            assert_eq!(pi.h, exp_hash.elements);
        }
        // Check the cells digest
        {
            let inputs: Vec<_> = iter::once(identifier).chain(value_fields).collect();
            let exp_digest = map_to_curve_point(&inputs);
            let exp_digest =
                add_curve_point(&[exp_digest, child_digests[0], child_digests[1]]).to_weierstrass();

            assert_eq!(pi.cells_point(), exp_digest);
        }
    }
}
