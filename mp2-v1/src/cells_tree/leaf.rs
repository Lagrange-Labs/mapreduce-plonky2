//! Module handling the leaf node inside a cells tree

use super::public_inputs::PublicInputs;
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
    plonk::{circuit_builder::CircuitBuilder, proof::ProofWithPublicInputsTarget},
};
use recursion_framework::circuit_builder::CircuitLogicWires;
use serde::{Deserialize, Serialize};
use std::iter;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct LeafWires {
    identifier: Target,
    packed_value: Array<Target, { u256::NUM_LIMBS }>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct LeafCircuit {
    /// The same identifier derived from the MPT extraction
    pub(crate) identifier: F,
    /// Packed Uint256 value
    pub(crate) packed_value: [F; u256::NUM_LIMBS],
}

impl LeafCircuit {
    fn build(b: &mut CBuilder) -> LeafWires {
        let identifier = b.add_virtual_target();
        let packed_value = Array::new(b);

        // h = Poseidon(Poseidon("") || Poseidon("") || identifier || packed_value)
        let empty_hash = empty_poseidon_hash();
        let empty_hash = b.constant_hash(*empty_hash);
        let inputs: Vec<_> = empty_hash
            .elements
            .iter()
            .cloned()
            .chain(empty_hash.elements)
            .chain(iter::once(identifier))
            .chain(packed_value.arr)
            .collect();
        let h = b.hash_n_to_hash_no_pad::<PoseidonHash>(inputs).elements;

        // dc = D(identifier || packed_value)
        let inputs: Vec<_> = iter::once(identifier).chain(packed_value.arr).collect();
        let dc = b.map_to_curve_point(&inputs);

        // Register the public inputs.
        PublicInputs::new(&h, &dc).register(b);

        LeafWires {
            identifier,
            packed_value,
        }
    }

    /// Assign the wires.
    fn assign(&self, pw: &mut PartialWitness<F>, wires: &LeafWires) {
        pw.set_target(wires.identifier, self.identifier);
        wires.packed_value.assign(pw, &self.packed_value);
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
        let identifier = thread_rng().gen::<u32>().to_field();
        let packed_value: [_; u256::NUM_LIMBS] = random_vector::<u32>(u256::NUM_LIMBS)
            .to_fields()
            .try_into()
            .unwrap();

        let test_circuit = LeafCircuit {
            identifier,
            packed_value,
        };

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
                .chain(packed_value.clone())
                .collect();
            let exp_hash = PoseidonHash::hash_no_pad(&inputs);

            assert_eq!(pi.h, exp_hash.elements);
        }
        // Check the cells digest
        {
            let inputs: Vec<_> = iter::once(identifier).chain(packed_value).collect();
            let exp_digest = map_to_curve_point(&inputs).to_weierstrass();

            assert_eq!(pi.cells_point(), exp_digest);
        }
    }
}
