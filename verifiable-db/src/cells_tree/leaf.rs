//! Module handling the leaf node inside a cells tree

use super::{public_inputs::PublicInputs, Cell, CellWire};
use derive_more::{From, Into};
use mp2_common::{
    poseidon::{empty_poseidon_hash, H},
    public_inputs::PublicInputCommon,
    types::CBuilder,
    utils::ToTargets,
    D, F,
};
use plonky2::{
    iop::witness::PartialWitness,
    plonk::{circuit_builder::CircuitBuilder, proof::ProofWithPublicInputsTarget},
};
use recursion_framework::circuit_builder::CircuitLogicWires;
use serde::{Deserialize, Serialize};
use std::iter::once;

#[derive(Clone, Debug, Serialize, Deserialize, From, Into)]
pub struct LeafWires(CellWire);

#[derive(Clone, Debug, Serialize, Deserialize, From, Into)]
pub struct LeafCircuit(Cell);

impl LeafCircuit {
    fn build(b: &mut CBuilder) -> LeafWires {
        let cell = CellWire::new(b);
        let metadata_digests = cell.split_metadata_digest(b);
        let values_digests = cell.split_values_digest(b);

        // H(H("") || H("") || identifier || pack_u32(value))
        let empty_hash = b.constant_hash(*empty_poseidon_hash()).to_targets();
        let inputs = empty_hash
            .clone()
            .into_iter()
            .chain(empty_hash)
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
    fn assign(&self, pw: &mut PartialWitness<F>, wires: &LeafWires) {
        self.0.assign_wires(pw, &wires.0);
    }
}

/// Num of children = 0
impl CircuitLogicWires<F, D, 0> for LeafWires {
    type CircuitBuilderParams = ();

    type Inputs = LeafCircuit;

    const NUM_PUBLIC_INPUTS: usize = PublicInputs::<F>::total_len();

    fn circuit_logic(
        builder: &mut CircuitBuilder<F, D>,
        _verified_proofs: [&ProofWithPublicInputsTarget<D>; 0],
        _builder_parameters: Self::CircuitBuilderParams,
    ) -> Self {
        LeafCircuit::build(builder)
    }

    fn assign_input(&self, inputs: Self::Inputs, pw: &mut PartialWitness<F>) -> anyhow::Result<()> {
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
        group_hashing::map_to_curve_point,
        poseidon::H,
        utils::{Fieldable, ToFields},
        C,
    };
    use mp2_test::circuit::{run_circuit, UserCircuit};
    use plonky2::plonk::config::Hasher;
    use rand::{thread_rng, Rng};

    impl UserCircuit<F, D> for LeafCircuit {
        type Wires = LeafWires;

        fn build(b: &mut CBuilder) -> Self::Wires {
            LeafCircuit::build(b)
        }

        fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
            self.assign(pw, wires);
        }
    }

    #[test]
    fn test_cells_tree_leaf_circuit() {
        test_cells_tree_leaf_multiplier(true);
        test_cells_tree_leaf_multiplier(false);
    }

    fn test_cells_tree_leaf_multiplier(is_multiplier: bool) {
        let mut rng = thread_rng();

        let identifier = rng.gen::<u32>().to_field();
        let value = U256::from_limbs(rng.gen::<[u64; 4]>());
        let value_fields = value.to_fields();

        let test_circuit: LeafCircuit = Cell {
            identifier,
            value,
            is_multiplier,
        }
        .into();

        let proof = run_circuit::<F, D, C, _>(test_circuit);
        let pi = PublicInputs::from_slice(&proof.public_inputs);
        // Check the node Poseidon hash
        {
            let empty_hash = empty_poseidon_hash();
            let inputs: Vec<_> = empty_hash
                .elements
                .iter()
                .cloned()
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
            let exp_digest = map_to_curve_point(&inputs).to_weierstrass();
            match is_multiplier {
                true => assert_eq!(pi.multiplier_digest_point(), exp_digest),
                false => assert_eq!(pi.individual_digest_point(), exp_digest),
            }
        }
    }
}
*/
