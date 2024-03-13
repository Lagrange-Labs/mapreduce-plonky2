use plonky2::{
    field::goldilocks_field::GoldilocksField,
    hash::{hash_types::NUM_HASH_OUT_ELTS, poseidon::PoseidonHash},
    iop::{target::Target, witness::PartialWitness},
    plonk::circuit_builder::CircuitBuilder,
};

use crate::{array::Array, group_hashing::CircuitBuilderGroupHashing, storage::NODE_MARKER};

use super::public_inputs::PublicInputs;

pub struct FullInnerNodeWires {}

#[derive(Clone)]
pub(crate) struct FullInnerNodeCircuit {}

impl FullInnerNodeCircuit {
    pub fn build(
        b: &mut CircuitBuilder<GoldilocksField, 2>,
        inputs: [PublicInputs<Target>; 2],
    ) -> FullInnerNodeWires {
        // Compute the new root hash
        let to_hash = Array::<Target, { 1 + 2 * NUM_HASH_OUT_ELTS }>::try_from(
            std::iter::once(b.constant(NODE_MARKER()))
                .chain(inputs[0].root().elements.iter().copied())
                .chain(inputs[1].root().elements.iter().copied())
                .collect::<Vec<_>>(),
        )
        .unwrap();
        let root = b.hash_n_to_hash_no_pad::<PoseidonHash>(Vec::from(to_hash.arr));

        // Assert that both children owners are equal
        inputs[0]
            .owner()
            .arr
            .iter()
            .zip(inputs[1].owner().arr.iter())
            .for_each(|(l, r)| {
                let sub = b.sub(*l, *r);
                b.assert_zero(sub);
            });

        // Compute the new digest
        let digest = b.add_curve_point(&[inputs[0].digest(), inputs[1].digest()]);

        PublicInputs::<GoldilocksField>::register(b, &root, &digest, &inputs[0].owner());
        FullInnerNodeWires {}
    }

    pub fn assign(&self, pw: &mut PartialWitness<GoldilocksField>, wires: &FullInnerNodeWires) {}
}
