//! Module handling the leaf node inside a cells tree

use super::public_inputs::PublicInputs;
use ethers::prelude::U256;
use mp2_common::{
    group_hashing::CircuitBuilderGroupHashing,
    poseidon::empty_poseidon_hash,
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
    plonk::{circuit_builder::CircuitBuilder, proof::ProofWithPublicInputsTarget},
};
use recursion_framework::circuit_builder::CircuitLogicWires;
use serde::{Deserialize, Serialize};
use std::iter;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct LeafWires {
    identifier: Target,
    value: UInt256Target,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct LeafCircuit {
    /// The same identifier derived from the MPT extraction
    pub(crate) identifier: F,
    /// Uint256 value
    pub(crate) value: U256,
}

impl LeafCircuit {
    fn build(b: &mut CBuilder) -> LeafWires {
        let identifier = b.add_virtual_target();
        let value = b.add_virtual_u256();

        // h = Poseidon(Poseidon("") || Poseidon("") || identifier || value)
        let empty_hash = empty_poseidon_hash();
        let empty_hash = b.constant_hash(*empty_hash);
        let inputs: Vec<_> = empty_hash
            .elements
            .iter()
            .cloned()
            .chain(empty_hash.elements)
            .chain(iter::once(identifier))
            .chain(value.to_targets())
            .collect();
        let h = b.hash_n_to_hash_no_pad::<PoseidonHash>(inputs).elements;

        // dc = D(identifier || value)
        let inputs: Vec<_> = iter::once(identifier).chain(value.to_targets()).collect();
        let dc = b.map_to_curve_point(&inputs).to_targets();

        // Register the public inputs.
        PublicInputs::new(&h, &dc).register(b);

        LeafWires { identifier, value }
    }

    /// Assign the wires.
    fn assign(&self, pw: &mut PartialWitness<F>, wires: &LeafWires) {
        pw.set_target(wires.identifier, self.identifier);
        pw.set_u256_target(&wires.value, self.value);
    }
}

/// Num of children = 0
impl CircuitLogicWires<F, D, 0> for LeafWires {
    type CircuitBuilderParams = ();

    type Inputs = LeafCircuit;

    const NUM_PUBLIC_INPUTS: usize = PublicInputs::<F>::TOTAL_LEN;

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
    use mp2_common::{
        group_hashing::map_to_curve_point,
        utils::{Fieldable, Packer, ToFields},
        C,
    };
    use mp2_test::{
        circuit::{run_circuit, UserCircuit},
        utils::random_vector,
    };
    use plonky2::{field::types::Field, plonk::config::Hasher};
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
        let mut rng = thread_rng();

        let identifier = rng.gen::<u32>().to_field();
        let value = U256(rng.gen::<[u64; 4]>());
        let value_fields = value.to_fields();

        let test_circuit = LeafCircuit { identifier, value };

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
            let exp_hash = PoseidonHash::hash_no_pad(&inputs);

            assert_eq!(pi.h, exp_hash.elements);
        }
        // Check the cells digest
        {
            let inputs: Vec<_> = iter::once(identifier).chain(value_fields).collect();
            let exp_digest = map_to_curve_point(&inputs).to_weierstrass();

            assert_eq!(pi.digest_point(), exp_digest);
        }
    }
}
