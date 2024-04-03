use plonky2::{
    field::goldilocks_field::GoldilocksField,
    hash::{hash_types::NUM_HASH_OUT_ELTS, poseidon::PoseidonHash},
    iop::{target::Target, witness::PartialWitness},
    plonk::circuit_builder::CircuitBuilder,
};
use recursion_framework::circuit_builder::CircuitLogicWires;
use serde::{Deserialize, Serialize};

use crate::{array::Array, group_hashing::CircuitBuilderGroupHashing};

use super::public_inputs::PublicInputs;

#[derive(Serialize, Deserialize)]
pub struct FullInnerNodeWires {}

#[derive(Clone, Debug)]
pub struct FullInnerNodeCircuit {}

impl FullInnerNodeCircuit {
    pub fn build(
        b: &mut CircuitBuilder<GoldilocksField, 2>,
        inputs: [PublicInputs<Target>; 2],
    ) -> FullInnerNodeWires {
        // Compute the new root hash
        let to_hash = Array::<Target, { 2 * NUM_HASH_OUT_ELTS }>::try_from(
            inputs[0]
                .root()
                .elements
                .iter()
                .copied()
                .chain(inputs[1].root().elements.iter().copied())
                .collect::<Vec<_>>(),
        )
        .unwrap();
        let root = b.hash_n_to_hash_no_pad::<PoseidonHash>(Vec::from(to_hash.arr));

        // Assert that both children owners are equal
        inputs[0].owner().enforce_equal(b, &inputs[1].owner());

        // Compute the new digest
        let digest = b.add_curve_point(&[inputs[0].digest(), inputs[1].digest()]);

        PublicInputs::<GoldilocksField>::register(b, &root, &digest, &inputs[0].owner());
        FullInnerNodeWires {}
    }

    pub fn assign(&self, _pw: &mut PartialWitness<GoldilocksField>, _wires: &FullInnerNodeWires) {}
}

impl CircuitLogicWires<GoldilocksField, 2, 2> for FullInnerNodeWires {
    type CircuitBuilderParams = ();

    type Inputs = FullInnerNodeCircuit;

    const NUM_PUBLIC_INPUTS: usize = PublicInputs::<GoldilocksField>::TOTAL_LEN;

    fn circuit_logic(
        builder: &mut CircuitBuilder<GoldilocksField, 2>,
        verified_proofs: [&plonky2::plonk::proof::ProofWithPublicInputsTarget<2>; 2],
        _builder_parameters: Self::CircuitBuilderParams,
    ) -> Self {
        let inputs = std::array::from_fn(|i| {
            PublicInputs::from_slice(Self::public_input_targets(verified_proofs[i]))
        });
        FullInnerNodeCircuit::build(builder, inputs)
    }

    fn assign_input(
        &self,
        inputs: Self::Inputs,
        pw: &mut PartialWitness<GoldilocksField>,
    ) -> anyhow::Result<()> {
        inputs.assign(pw, self);
        Ok(())
    }
}
