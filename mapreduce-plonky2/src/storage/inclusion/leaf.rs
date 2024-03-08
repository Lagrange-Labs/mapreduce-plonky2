use plonky2::{
    field::goldilocks_field::GoldilocksField, gates::poseidon::PoseidonGate, iop::target::Target,
    plonk::circuit_builder::CircuitBuilder,
};

use crate::array::{Array, VectorWire};

pub struct LeafCircuit {
    value: [u8; 32],
}

struct LeafWires {
    root: Array<Target, POSEIDON_HASH_LEN>,
    value: VectorWire<Target, 32>,
}

impl LeafCircuit {
    pub fn build(b: &mut CircuitBuilder<GoldilocksField, 2>) -> LeafWires {
        let gate_type = PoseidonGate::<GoldilocksField, 2>::new();
        let gate = b.add_gate(gate_type, vec![]);

        let swap_wire = PoseidonGate::<GoldilocksField, 2>::WIRE_SWAP;
        let swap_wire = Target::wire(gate, swap_wire);
        b.connect(b.zero(), swap_wire);

        let inputs = ;
    }
}
