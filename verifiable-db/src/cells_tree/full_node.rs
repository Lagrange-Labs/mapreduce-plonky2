//! Module handling the intermediate node with 2 children inside a cells tree

use super::{public_inputs::PublicInputs, Cell, CellWire};
use anyhow::Result;
use derive_more::{From, Into};
use mp2_common::{
    poseidon::H, public_inputs::PublicInputCommon, types::CBuilder, utils::ToTargets, D, F,
};
use plonky2::{
    iop::{target::Target, witness::PartialWitness},
    plonk::proof::ProofWithPublicInputsTarget,
};
use recursion_framework::circuit_builder::CircuitLogicWires;
use serde::{Deserialize, Serialize};
use std::{array, iter::once};

#[derive(Clone, Debug, Serialize, Deserialize, Into, From)]
pub struct FullNodeWires(CellWire);

#[derive(Clone, Debug, Serialize, Deserialize, From, Into)]
pub struct FullNodeCircuit(Cell);

impl FullNodeCircuit {
    pub fn build(b: &mut CBuilder, child_proofs: [PublicInputs<Target>; 2]) -> FullNodeWires {
        let [p1, p2] = child_proofs;

        let cell = CellWire::new(b);
        let metadata_digests = cell.split_metadata_digest(b);
        let values_digests = cell.split_values_digest(b);

        let metadata_digests = metadata_digests.accumulate(b, &p1.split_metadata_digest_target());
        let metadata_digests = metadata_digests.accumulate(b, &p2.split_metadata_digest_target());

        let values_digests = values_digests.accumulate(b, &p1.split_values_digest_target());
        let values_digests = values_digests.accumulate(b, &p2.split_values_digest_target());

        // H(p1.H || p2.H || identifier || value)
        let inputs = p1
            .node_hash_target()
            .into_iter()
            .chain(p2.node_hash_target())
            .chain(once(cell.identifier))
            .chain(cell.value.to_targets())
            .collect();
        let h = b.hash_n_to_hash_no_pad::<H>(inputs);

        // Register the public inputs.
        PublicInputs::new(
            &h.to_targets(),
            &values_digests.individual.to_targets(),
            &values_digests.multiplier.to_targets(),
            &metadata_digests.individual.to_targets(),
            &metadata_digests.multiplier.to_targets(),
        )
        .register(b);

        cell.into()
    }

    /// Assign the wires.
    fn assign(&self, pw: &mut PartialWitness<F>, wires: &FullNodeWires) {
        self.0.assign_wires(pw, &wires.0);
    }
}

/// Num of children = 2
impl CircuitLogicWires<F, D, 2> for FullNodeWires {
    type CircuitBuilderParams = ();

    type Inputs = FullNodeCircuit;

    const NUM_PUBLIC_INPUTS: usize = PublicInputs::<F>::total_len();

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

/*
#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::U256;
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
        let value = U256::from_limbs(rng.gen::<[u64; 4]>());
        let value_fields = value.to_fields();

        // Create the child public inputs.
        let child_hashs = [0; 2].map(|_| random_vector::<u32>(NUM_HASH_OUT_ELTS).to_fields());
        let child_digests = [0; 2].map(|_| Point::sample(&mut rng));
        let child_pis = &array::from_fn(|i| {
            let h = &child_hashs[i];
            let ind = &child_digests[i].to_weierstrass().to_fields();
            let neutral = Point::NEUTRAL.to_fields();

            PublicInputs {
                h,
                ind,
                mul: &neutral,
            }
            .to_vec()
        });

        let test_circuit = TestFullNodeCircuit {
            c: Cell {
                identifier,
                value,
                is_multiplier: false,
            }
            .into(),
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
            let exp_hash = H::hash_no_pad(&inputs);

            assert_eq!(pi.h, exp_hash.elements);
        }
        // Check the cells digest
        {
            let inputs: Vec<_> = iter::once(identifier).chain(value_fields).collect();
            let exp_digest = map_to_curve_point(&inputs);
            let exp_digest =
                add_curve_point(&[exp_digest, child_digests[0], child_digests[1]]).to_weierstrass();

            assert_eq!(pi.individual_digest_point(), exp_digest);
        }
    }
}
*/
