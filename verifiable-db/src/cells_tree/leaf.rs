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
        let values_digests = cell.split_values_digest(b);
        let individual_cnt = cell.is_individual(b).target;
        let multiplier_cnt = cell.is_multiplier().target;

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
            &individual_cnt,
            &multiplier_cnt,
        )
        .register(b);

        cell.into()
    }

    /// Assign the wires.
    fn assign(&self, pw: &mut PartialWitness<F>, wires: &LeafWires) {
        self.0.assign(pw, &wires.0);
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

#[cfg(test)]
mod tests {
    use super::*;
    use itertools::Itertools;
    use mp2_common::{poseidon::H, utils::ToFields, C};
    use mp2_test::circuit::{run_circuit, UserCircuit};
    use plonky2::{field::types::Field, plonk::config::Hasher};

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
        let cell = Cell::sample(is_multiplier);
        let id = cell.identifier;
        let value = cell.value;
        let values_digests = cell.split_values_digest();

        let test_circuit: LeafCircuit = cell.into();
        let proof = run_circuit::<F, D, C, _>(test_circuit);
        let pi = PublicInputs::from_slice(&proof.public_inputs);

        // Check the node hash
        {
            let empty_hash = empty_poseidon_hash();
            let inputs = empty_hash
                .elements
                .iter()
                .cloned()
                .chain(empty_hash.elements)
                .chain(once(id))
                .chain(value.to_fields())
                .collect_vec();
            let exp_hash = H::hash_no_pad(&inputs);

            assert_eq!(pi.h, exp_hash.elements);
        }
        // Check individual values digest
        assert_eq!(
            pi.individual_values_digest_point(),
            values_digests.individual.to_weierstrass(),
        );
        // Check multiplier values digest
        assert_eq!(
            pi.multiplier_values_digest_point(),
            values_digests.multiplier.to_weierstrass(),
        );
        // Check individual counter
        let individual_cnt = if is_multiplier { F::ZERO } else { F::ONE };
        assert_eq!(pi.individual_counter(), individual_cnt);
        // Check multiplier counter
        assert_eq!(pi.multiplier_counter(), F::ONE - individual_cnt);
    }
}
