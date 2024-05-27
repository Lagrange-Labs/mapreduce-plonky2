//! Database length extraction circuits

use core::array;

use mp2_common::{
    array::Vector,
    group_hashing::CircuitBuilderGroupHashing,
    keccak::PACKED_HASH_LEN,
    mpt_sequential::{
        MPTLeafOrExtensionNode, MPTLeafOrExtensionWires, MAX_LEAF_VALUE_LEN, PAD_LEN,
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
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
};

use super::PublicInputs;

/// The wires structure for the leaf length extraction.
#[derive(Clone, Debug)]
pub struct LeafLengthWires<const NODE_LEN: usize>
where
    [(); PAD_LEN(NODE_LEN)]:,
{
    pub length_slot: SimpleSlotWires,
    pub length_mpt: MPTLeafOrExtensionWires<NODE_LEN, MAX_LEAF_VALUE_LEN>,
    pub variable_slot: Target,
}

/// The circuit definition for the leaf length extraction.
#[derive(Clone, Debug)]
pub struct LeafLengthCircuit<const NODE_LEN: usize>
where
    [(); PAD_LEN(NODE_LEN)]:,
{
    pub length_slot: SimpleSlot,
    pub length_node: Vector<u8, { PAD_LEN(NODE_LEN) }>,
    pub variable_slot: u8,
}

impl<const NODE_LEN: usize> LeafLengthCircuit<NODE_LEN>
where
    [(); PAD_LEN(NODE_LEN)]:,
{
    /// Creates a new instance of the circuit.
    pub fn new(length_slot: u8, length_node: &[u8], variable_slot: u8) -> anyhow::Result<Self> {
        Ok(Self {
            length_slot: SimpleSlot::new(length_slot),
            length_node: Vector::from_vec(length_node)?,
            variable_slot,
        })
    }

    /// Build the circuit, assigning the public inputs and returning the internal wires.
    pub fn build(cb: &mut CBuilder) -> LeafLengthWires<NODE_LEN> {
        let zero = cb.zero();
        let one = cb.one();

        // we don't range check the variable and length slots as they are part of the DM public
        // commitment
        let variable_slot = cb.add_virtual_target();
        let length_slot = SimpleSlot::build(cb);

        let length_mpt =
            MPTLeafOrExtensionNode::build_and_advance_key::<_, D, NODE_LEN, MAX_LEAF_VALUE_LEN>(
                cb,
                &length_slot.mpt_key,
            );

        // extract the rlp encoded value
        let prefix = length_mpt.value[0];
        let x80 = cb.constant(GFp::from_canonical_usize(128));
        let is_single_byte = less_than(cb, prefix, x80, 8);
        let rlp_value_x80 = cb.sub(prefix, x80);
        let rlp_value = cb.select(is_single_byte, one, rlp_value_x80);
        let offset = cb.select(is_single_byte, zero, one);
        let length_rlp_encoded = length_mpt
            .value
            .extract_array::<GFp, D, 4>(cb, offset)
            .into_vec(rlp_value)
            .normalize_left::<GFp, D, 4>(cb)
            .reverse()
            .convert_u8_to_u32(cb)[0];

        let dm = &cb.map_to_curve_point(&[length_slot.slot, variable_slot]);
        let h = &array::from_fn::<_, PACKED_HASH_LEN, _>(|i| length_mpt.root.output_array.arr[i].0);
        let k = &length_mpt.key.key.arr;
        let t = &length_mpt.key.pointer;
        let n = &length_rlp_encoded.0;

        PublicInputs::new(h, dm, k, t, n).register(cb);

        LeafLengthWires {
            length_slot,
            length_mpt,
            variable_slot,
        }
    }

    /// Assigns the values of this instance into the provided partial witness, using the generated
    /// circuit wires.
    pub fn assign(&self, pw: &mut PartialWitness<GFp>, wires: &LeafLengthWires<NODE_LEN>) {
        pw.set_target(
            wires.variable_slot,
            GFp::from_canonical_u8(self.variable_slot),
        );

        self.length_slot.assign(pw, &wires.length_slot);
        wires.length_mpt.assign(pw, &self.length_node);
    }
}
