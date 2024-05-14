use core::iter;

use mp2_common::{
    group_hashing::CircuitBuilderGroupHashing,
    mpt_sequential::{
        Circuit as MPTCircuit, InputWires as MPTInputWires, OutputWires as MPTOutputWires, PAD_LEN,
    },
    public_inputs::PublicInputCommon,
    storage_key::{MappingSlot, MappingSlotWires, SimpleSlot, SimpleSlotWires},
    types::{CBuilder, CBuilderD, GFp},
    utils::less_than,
};
use plonky2::{
    field::types::Field,
    iop::{target::BoolTarget, witness::PartialWitness},
};

use super::{build_length_slot, public_inputs::PublicInputs};

/// The wires structure for the leaf length extraction
#[derive(Clone, Debug)]
pub struct LeafMappingLengthWires<const DEPTH: usize, const NODE_LEN: usize>
where
    [(); PAD_LEN(NODE_LEN)]:,
    [(); DEPTH - 1]:,
{
    variable_slot: MappingSlotWires,
    length_slot: SimpleSlotWires,
    mpt_input: MPTInputWires<DEPTH, NODE_LEN>,
    mpt_output: MPTOutputWires<DEPTH, NODE_LEN>,
}

/// The circuit definition for the leaf length extraction.
#[derive(Clone, Debug)]
pub struct LeafMappingLengthCircuit<const DEPTH: usize, const NODE_LEN: usize> {
    length_slot: SimpleSlot,
    variable_slot: MappingSlot,
    mpt_circuit: MPTCircuit<DEPTH, NODE_LEN>,
}

impl<const DEPTH: usize, const NODE_LEN: usize> LeafMappingLengthCircuit<DEPTH, NODE_LEN>
where
    [(); PAD_LEN(NODE_LEN)]:,
    [(); DEPTH - 1]:,
{
    /// Creates a new instance of the circuit.
    pub fn new(
        length_slot: u8,
        variable_slot: u8,
        variable_key: Vec<u8>,
        nodes: Vec<Vec<u8>>,
    ) -> Self {
        let length_slot = SimpleSlot::new(length_slot);
        let variable_slot = MappingSlot::new(variable_slot, variable_key);
        let mpt_circuit = MPTCircuit::new(length_slot.0.mpt_key(), nodes);

        Self {
            length_slot,
            variable_slot,
            mpt_circuit,
        }
    }

    /// Build the circuit, assigning the public inputs and returning the internal wires.
    pub fn build(cb: &mut CBuilder) -> LeafMappingLengthWires<DEPTH, NODE_LEN> {
        let zero = cb.zero();
        let one = cb.one();

        let length_slot = SimpleSlot::build(cb);
        let variable_slot = MappingSlot::mpt_key(cb);
        let (mpt_input, mpt_output, rlp_length) = build_length_slot(cb, &length_slot);

        // mapping slot isn't RLP encoded
        let is_rlp_encoded = zero;

        // NOTE: we diverge from the simple value slot metadata commitment as we add the mapping
        // key as part of the point
        let dm = cb.map_to_curve_point(
            &iter::once(length_slot.slot)
                .chain(iter::once(variable_slot.mapping_slot))
                .chain(variable_slot.mapping_key.arr.iter().copied())
                .chain(iter::once(is_rlp_encoded))
                .collect::<Vec<_>>(),
        );

        let dm = (&dm.0 .0[0].0[..], &dm.0 .0[1].0[..], &dm.0 .1.target);
        let k = &mpt_input.key.key.arr;
        let t = &mpt_input.key.pointer;
        let n = &rlp_length.0;
        let h: Vec<_> = mpt_output.root.arr.iter().map(|t| t.0).collect();

        PublicInputs::new(&h, dm, k, t, n).register(cb);

        LeafMappingLengthWires {
            variable_slot,
            length_slot,
            mpt_input,
            mpt_output,
        }
    }

    /// Assigns the values of this instance into the provided partial witness, using the generated
    /// circuit wires.
    pub fn assign(
        &self,
        pw: &mut PartialWitness<GFp>,
        wires: &LeafMappingLengthWires<DEPTH, NODE_LEN>,
    ) -> anyhow::Result<()> {
        self.length_slot.assign(pw, &wires.length_slot);
        self.variable_slot.assign(pw, &wires.variable_slot);

        self.mpt_circuit
            .assign_wires::<_, CBuilderD>(pw, &wires.mpt_input, &wires.mpt_output)?;

        Ok(())
    }
}
