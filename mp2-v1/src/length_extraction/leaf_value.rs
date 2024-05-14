//! Database length extraction circuit for a single/simple slot value.

use mp2_common::{
    group_hashing::CircuitBuilderGroupHashing,
    mpt_sequential::{
        Circuit as MPTCircuit, InputWires as MPTInputWires, OutputWires as MPTOutputWires, PAD_LEN,
    },
    public_inputs::PublicInputCommon,
    storage_key::{SimpleSlot, SimpleSlotWires},
    types::{CBuilder, GFp},
    utils::less_than,
    D,
};

use plonky2::{
    field::types::Field,
    iop::{
        target::{BoolTarget, Target},
        witness::{PartialWitness, WitnessWrite},
    },
};

use super::{build_length_slot, public_inputs::PublicInputs};

/// The wires structure for the leaf length extraction of a single/simple value.
#[derive(Clone, Debug)]
pub struct LeafValueLengthWires<const DEPTH: usize, const NODE_LEN: usize>
where
    [(); PAD_LEN(NODE_LEN)]:,
    [(); DEPTH - 1]:,
{
    variable_slot: SimpleSlotWires,
    length_slot: SimpleSlotWires,
    is_rlp_encoded: BoolTarget,
    mpt_input: MPTInputWires<DEPTH, NODE_LEN>,
    mpt_output: MPTOutputWires<DEPTH, NODE_LEN>,
}

/// The circuit definition for the leaf length extraction of a single/simple value.
#[derive(Clone, Debug)]
pub struct LeafValueLengthCircuit<const DEPTH: usize, const NODE_LEN: usize> {
    length_slot: SimpleSlot,
    variable_slot: SimpleSlot,
    is_rlp_encoded: bool,
    mpt_circuit: MPTCircuit<DEPTH, NODE_LEN>,
}

impl<const DEPTH: usize, const NODE_LEN: usize> LeafValueLengthCircuit<DEPTH, NODE_LEN>
where
    [(); PAD_LEN(NODE_LEN)]:,
    [(); DEPTH - 1]:,
{
    /// Creates a new instance of the circuit.
    pub fn new(
        length_slot: u8,
        variable_slot: u8,
        is_rlp_encoded: bool,
        nodes: Vec<Vec<u8>>,
    ) -> Self {
        let length_slot = SimpleSlot::new(length_slot);
        let variable_slot = SimpleSlot::new(variable_slot);
        let mpt_circuit = MPTCircuit::new(length_slot.0.mpt_key(), nodes);

        Self {
            length_slot,
            variable_slot,
            is_rlp_encoded,
            mpt_circuit,
        }
    }

    /// Build the circuit, assigning the public inputs and returning the internal wires.
    pub fn build(cb: &mut CBuilder) -> LeafValueLengthWires<DEPTH, NODE_LEN> {
        let zero = cb.zero();
        let one = cb.one();

        let length_slot = SimpleSlot::build(cb);
        let variable_slot = SimpleSlot::build(cb);
        let is_rlp_encoded = cb.add_virtual_bool_target_safe();
        let (mpt_input, mpt_output, rlp_length) = build_length_slot(cb, &length_slot);

        let dm =
            cb.map_to_curve_point(&[length_slot.slot, variable_slot.slot, is_rlp_encoded.target]);
        let dm = (&dm.0 .0[0].0[..], &dm.0 .0[1].0[..], &dm.0 .1.target);
        let k = &mpt_input.key.key.arr;
        let t = &mpt_input.key.pointer;
        let n = &rlp_length.0;
        let h: Vec<_> = mpt_output.root.arr.iter().map(|t| t.0).collect();

        PublicInputs::new(&h, dm, k, t, n).register(cb);

        LeafValueLengthWires {
            variable_slot,
            length_slot,
            is_rlp_encoded,
            mpt_input,
            mpt_output,
        }
    }

    /// Assigns the values of this instance into the provided partial witness, using the generated
    /// circuit wires.
    pub fn assign(
        &self,
        pw: &mut PartialWitness<GFp>,
        wires: &LeafValueLengthWires<DEPTH, NODE_LEN>,
    ) -> anyhow::Result<()> {
        pw.set_target(
            wires.is_rlp_encoded.target,
            GFp::from_bool(self.is_rlp_encoded),
        );

        self.length_slot.assign(pw, &wires.length_slot);
        self.variable_slot.assign(pw, &wires.variable_slot);

        self.mpt_circuit
            .assign_wires::<_, D>(pw, &wires.mpt_input, &wires.mpt_output)?;

        Ok(())
    }
}
