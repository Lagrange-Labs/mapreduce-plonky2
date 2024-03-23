use plonky2::{
    field::goldilocks_field::GoldilocksField,
    hash::{hash_types::NUM_HASH_OUT_ELTS, poseidon::PoseidonHash},
    iop::{target::Target, witness::PartialWitness},
    plonk::circuit_builder::CircuitBuilder,
};

use crate::{array::Array, group_hashing::CircuitBuilderGroupHashing};

use super::AggregationPublicInputs;

pub struct FullNodeWires {}
#[derive(Clone, Debug)]
pub struct FullNodeCircuit {}
impl FullNodeCircuit {
    pub fn build(
        b: &mut CircuitBuilder<GoldilocksField, 2>,
        inputs: [AggregationPublicInputs<Target>; 2],
    ) -> FullNodeWires {
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

        // X[0] == X[1]
        inputs[0]
            .user_address()
            .equals(b, &inputs[1].user_address());
        // M[0] == M[1]
        b.connect(inputs[0].mapping_slot(), inputs[1].mapping_slot());
        // A[0] == A[1]
        inputs[0]
            .smart_contract_address()
            .equals(b, &inputs[1].smart_contract_address());
        // S[0] == S[1]
        b.connect(
            inputs[0].mapping_slot_length(),
            inputs[1].mapping_slot_length(),
        );

        let root = b.hash_n_to_hash_no_pad::<PoseidonHash>(Vec::from(to_hash.arr));
        let new_range_min = b.sub(inputs[0].block_number(), inputs[0].range());
        let new_range_max = inputs[1].block_number();
        let new_range = b.sub(new_range_max, new_range_min);
        let digest = b.add_curve_point(&[inputs[0].digest(), inputs[1].digest()]);

        AggregationPublicInputs::<Target>::register(
            b,
            new_range_max,
            new_range,
            &root,
            &inputs[0].smart_contract_address(),
            &inputs[0].user_address(),
            inputs[0].mapping_slot(),
            inputs[0].mapping_slot_length(),
            digest,
        );

        FullNodeWires {}
    }

    pub fn assign(&self, _: &mut PartialWitness<GoldilocksField>, _: &FullNodeWires) {}
}
