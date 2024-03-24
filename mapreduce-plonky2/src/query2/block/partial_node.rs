use plonky2::{
    field::goldilocks_field::GoldilocksField,
    hash::hash_types::HashOutTarget,
    iop::{
        target::{BoolTarget, Target},
        witness::PartialWitness,
    },
    plonk::circuit_builder::CircuitBuilder,
};

use crate::poseidon::hash_maybe_swap;

use super::BlockPublicInputs;

pub struct PartialNodeWires {}

#[derive(Clone, Debug)]
pub struct PartialNodeCircuit {}
impl PartialNodeCircuit {
    pub fn build(
        b: &mut CircuitBuilder<GoldilocksField, 2>,
        proved: &BlockPublicInputs<Target>,
        unproved: HashOutTarget,
        proved_is_right: BoolTarget,
    ) -> PartialNodeWires {
        let root = hash_maybe_swap(
            b,
            &[proved.root().elements, unproved.elements],
            proved_is_right,
        );

        BlockPublicInputs::<Target>::register(
            b,
            proved.block_number(),
            proved.range(),
            &root,
            &proved.smart_contract_address(),
            &proved.user_address(),
            proved.mapping_slot(),
            proved.mapping_slot_length(),
            proved.digest(),
        );

        PartialNodeWires {}
    }

    pub fn assign(&self, _: &mut PartialWitness<GoldilocksField>, _: &PartialNodeWires) {}
}
