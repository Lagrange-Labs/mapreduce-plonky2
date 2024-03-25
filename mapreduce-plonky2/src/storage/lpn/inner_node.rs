use plonky2::{
    field::{goldilocks_field::GoldilocksField, types::Field},
    hash::{hash_types::NUM_HASH_OUT_ELTS, poseidon::PoseidonHash},
    iop::{target::Target, witness::PartialWitness},
    plonk::circuit_builder::CircuitBuilder,
};
use recursion_framework::circuit_builder::CircuitLogicWires;
use serde::{Deserialize, Serialize};

use crate::{array::Array, group_hashing::CircuitBuilderGroupHashing};

use super::PublicInputs;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct NodeWires {}

#[derive(Clone, Debug)]
pub struct NodeCircuit {}

impl NodeCircuit {
    pub fn build(
        b: &mut CircuitBuilder<GoldilocksField, 2>,
        inputs: [PublicInputs<Target>; 2],
    ) -> NodeWires {
        let (left_child, right_child) = (&inputs[0], &inputs[1]);

        let digest = b.add_curve_point(&[left_child.digest(), right_child.digest()]);
        let to_hash = Array::<Target, { 2 * NUM_HASH_OUT_ELTS }>::try_from(
            left_child
                .root_raw()
                .iter()
                .chain(right_child.root_raw())
                .copied()
                .collect::<Vec<_>>(),
        )
        .unwrap();
        let root = b.hash_n_to_hash_no_pad::<PoseidonHash>(Vec::from(to_hash.arr));

        PublicInputs::<GoldilocksField>::register(b, &root, &digest);

        NodeWires {}
    }

    pub fn assign(&self, _: &mut PartialWitness<GoldilocksField>, _: &NodeWires) {}
}

impl CircuitLogicWires<GoldilocksField, 2, 2> for NodeWires {
    type CircuitBuilderParams = ();

    type Inputs = NodeCircuit;

    const NUM_PUBLIC_INPUTS: usize = PublicInputs::<GoldilocksField>::TOTAL_LEN;

    fn circuit_logic(
        builder: &mut CircuitBuilder<GoldilocksField, 2>,
        verified_proofs: [&plonky2::plonk::proof::ProofWithPublicInputsTarget<2>; 2],
        _builder_parameters: Self::CircuitBuilderParams,
    ) -> Self {
        let inputs = [
            PublicInputs::from(Self::public_input_targets(&verified_proofs[0])),
            PublicInputs::from(Self::public_input_targets(verified_proofs[1])),
        ];
        NodeCircuit::build(builder, inputs)
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
