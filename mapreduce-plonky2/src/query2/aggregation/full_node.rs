use plonky2::{
    field::goldilocks_field::GoldilocksField,
    hash::{
        hash_types::{RichField, NUM_HASH_OUT_ELTS},
        poseidon::PoseidonHash,
    },
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::circuit_builder::CircuitBuilder,
};

use crate::{array::Array, group_hashing::CircuitBuilderGroupHashing};

use super::AggregationPublicInputs;

pub struct FullNodeWires {
    children: [Vec<Target>; 2],
}

#[derive(Clone, Debug)]
pub struct FullNodeCircuit<F: RichField, const L: usize> {
    pub(crate) children: [Vec<F>; 2],
}
impl<F: RichField, const L: usize> FullNodeCircuit<F, L> {
    pub fn build(b: &mut CircuitBuilder<GoldilocksField, 2>) -> FullNodeWires {
        let inputs_io = [
            b.add_virtual_targets(AggregationPublicInputs::<Target, L>::total_len()),
            b.add_virtual_targets(AggregationPublicInputs::<Target, L>::total_len()),
        ];

        let inputs = [
            AggregationPublicInputs::<Target, L>::from(inputs_io[0].as_slice()),
            AggregationPublicInputs::<Target, L>::from(inputs_io[1].as_slice()),
        ];

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

        AggregationPublicInputs::<Target, L>::register(
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

        FullNodeWires {
            children: inputs_io.to_owned(),
        }
    }

    pub fn assign(&self, pw: &mut PartialWitness<F>, wires: &FullNodeWires) {
        pw.set_target_arr(&wires.children[0], &self.children[0]);
        pw.set_target_arr(&wires.children[1], &self.children[1]);
    }
}
