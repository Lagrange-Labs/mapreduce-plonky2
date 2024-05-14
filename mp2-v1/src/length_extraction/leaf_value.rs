use mp2_common::{
    group_hashing::CircuitBuilderGroupHashing,
    mpt_sequential::{
        Circuit as MPTCircuit, InputWires as MPTInputWires, OutputWires as MPTOutputWires, PAD_LEN,
    },
    public_inputs::PublicInputCommon,
    storage_key::{SimpleSlot, SimpleSlotWires},
    types::{CBuilder, CBuilderD, GFp},
    utils::less_than,
};

use plonky2::{
    field::types::Field,
    iop::{
        target::{BoolTarget, Target},
        witness::{PartialWitness, WitnessWrite},
    },
};

use super::public_inputs::PublicInputs;

/// The wires structure for the leaf length extraction
#[derive(Clone, Debug)]
pub struct LeafValueLengthWires<const DEPTH: usize, const NODE_LEN: usize>
where
    [(); PAD_LEN(NODE_LEN)]:,
    [(); DEPTH - 1]:,
{
    variable_slot: Target,
    length_slot: SimpleSlotWires,
    mpt_input: MPTInputWires<DEPTH, NODE_LEN>,
    mpt_output: MPTOutputWires<DEPTH, NODE_LEN>,
}

/// The circuit definition for the leaf length extraction.
#[derive(Clone, Debug)]
pub struct LeafValueLengthCircuit<const DEPTH: usize, const NODE_LEN: usize> {
    length_slot: SimpleSlot,
    variable_slot: GFp,
    mpt_circuit: MPTCircuit<DEPTH, NODE_LEN>,
}

impl<const DEPTH: usize, const NODE_LEN: usize> LeafValueLengthCircuit<DEPTH, NODE_LEN>
where
    [(); PAD_LEN(NODE_LEN)]:,
    [(); DEPTH - 1]:,
{
    /// Creates a new instance of the circuit.
    pub fn new(length_slot: u8, variable_slot: u8, nodes: Vec<Vec<u8>>) -> Self {
        let length_slot = SimpleSlot::new(length_slot);
        let variable_slot = GFp::from_canonical_u8(variable_slot);
        let mpt_circuit = MPTCircuit::new(length_slot.0.mpt_key(), nodes);

        Self {
            length_slot,
            variable_slot,
            mpt_circuit,
        }
    }

    /// Build the circuit, assigning the public inputs and returning the internal wires.
    pub fn build(cb: &mut CBuilder) -> LeafValueLengthWires<DEPTH, NODE_LEN> {
        let zero = cb.zero();
        let one = cb.one();

        // we assume the variable slot to be already proven, as it might be either simple or
        // mapping and is part of the public inputs
        let variable_slot = cb.add_virtual_target();
        let length_slot = SimpleSlot::build(cb);

        // storage value is RLP encoded
        let is_rlp_encoded = one;

        // we don't check the range of length & variable because they define the public input DM;
        // hence, they are guaranteed by the verifier to be correct

        let mpt_input = MPTCircuit::create_input_wires(cb, Some(length_slot.mpt_key.clone()));
        let mpt_output = MPTCircuit::verify_mpt_proof(cb, &mpt_input);

        mpt_input.nodes.iter().for_each(|n| n.assert_bytes(cb));

        // extract the recursive length prefix element from the output
        let prefix = mpt_output.leaf.arr[0];

        // constant used to extract the RLP header, if present
        let x80 = cb.constant(GFp::from_canonical_usize(0x80));
        let is_single_byte = less_than(cb, prefix, x80, 8);
        let len_x80 = cb.sub(prefix, x80);

        // extract the length, depending on the prefix header
        let value = cb.select(is_single_byte, one, x80);
        let offset = cb.select(is_single_byte, zero, one);
        let rlp_length = mpt_output
            .leaf
            .extract_array::<_, CBuilderD, 4>(cb, offset)
            .into_vec(value)
            .arr
            .reverse()
            .convert_u8_to_u32(cb)[0];

        let dm = cb.map_to_curve_point(&[length_slot.slot, variable_slot, is_rlp_encoded]);
        let dm = (&dm.0 .0[0].0[..], &dm.0 .0[1].0[..], &dm.0 .1.target);
        let k = &mpt_input.key.key.arr;
        let t = &mpt_input.key.pointer;
        let n = &rlp_length.0;
        let h: Vec<_> = mpt_output.root.arr.iter().map(|t| t.0).collect();

        PublicInputs::new(&h, dm, k, t, n).register(cb);

        LeafValueLengthWires {
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
        wires: &LeafValueLengthWires<DEPTH, NODE_LEN>,
    ) -> anyhow::Result<()> {
        pw.set_target(wires.variable_slot, self.variable_slot);
        self.length_slot.assign(pw, &wires.length_slot);

        self.mpt_circuit
            .assign_wires::<_, CBuilderD>(pw, &wires.mpt_input, &wires.mpt_output)?;

        Ok(())
    }
}
