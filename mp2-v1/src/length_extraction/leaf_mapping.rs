//! Database length extraction circuit for a mapping slot value.

use core::array;

use mp2_common::{
    array::Vector,
    group_hashing::CircuitBuilderGroupHashing,
    keccak::PACKED_HASH_LEN,
    mpt_sequential::{
        MPTLeafOrExtensionNode, MPTLeafOrExtensionWires, MAX_LEAF_VALUE_LEN, PAD_LEN,
    },
    public_inputs::PublicInputCommon,
    storage_key::{MappingSlot, MappingSlotWires, SimpleSlot, SimpleSlotWires},
    types::{CBuilder, GFp},
    D,
};
use plonky2::{
    field::types::Field,
    iop::{
        target::BoolTarget,
        witness::{PartialWitness, WitnessWrite},
    },
};

use super::public_inputs::PublicInputs;

/// The wires structure for the leaf length extraction of a mapping value.
#[derive(Clone, Debug)]
pub struct LeafLengthWires<const NODE_LEN: usize>
where
    [(); PAD_LEN(NODE_LEN)]:,
{
    pub is_rlp_encoded: BoolTarget,
    pub length_slot: SimpleSlotWires,
    pub length_mpt: MPTLeafOrExtensionWires<NODE_LEN, MAX_LEAF_VALUE_LEN>,
    pub variable_slot: MappingSlotWires,
    pub variable_mpt: MPTLeafOrExtensionWires<NODE_LEN, MAX_LEAF_VALUE_LEN>,
}

/// The circuit definition for the leaf length extraction of a mapping value.
#[derive(Clone, Debug)]
pub struct LeafLengthCircuit<const NODE_LEN: usize>
where
    [(); PAD_LEN(NODE_LEN)]:,
{
    pub is_rlp_encoded: bool,
    pub length_slot: SimpleSlot,
    pub length_node: Vector<u8, { PAD_LEN(NODE_LEN) }>,
    pub variable_slot: MappingSlot,
    pub variable_node: Vector<u8, { PAD_LEN(NODE_LEN) }>,
}

impl<const NODE_LEN: usize> LeafLengthCircuit<NODE_LEN>
where
    [(); PAD_LEN(NODE_LEN)]:,
{
    /// Creates a new instance of the circuit.
    pub fn new(
        is_rlp_encoded: bool,
        length_slot: u8,
        length_node: &[u8],
        variable_slot: u8,
        variable_key: Vec<u8>,
        variable_node: &[u8],
    ) -> anyhow::Result<Self> {
        Ok(Self {
            is_rlp_encoded,
            length_slot: SimpleSlot::new(length_slot),
            length_node: Vector::from_vec(length_node)?,
            variable_slot: MappingSlot::new(variable_slot, variable_key),
            variable_node: Vector::from_vec(variable_node)?,
        })
    }

    /// Build the circuit, assigning the public inputs and returning the internal wires.
    pub fn build(cb: &mut CBuilder) -> LeafLengthWires<NODE_LEN> {
        let t_p = cb.constant(GFp::from_canonical_u32(64));
        let is_rlp_encoded = cb.add_virtual_bool_target_safe();

        let length_slot = SimpleSlot::build(cb);
        let length_mpt =
            MPTLeafOrExtensionNode::build_and_advance_key::<_, D, NODE_LEN, MAX_LEAF_VALUE_LEN>(
                cb,
                &length_slot.mpt_key,
            );

        let variable_slot = MappingSlot::mpt_key(cb);
        let variable_mpt =
            MPTLeafOrExtensionNode::build_and_advance_key::<_, D, NODE_LEN, MAX_LEAF_VALUE_LEN>(
                cb,
                &variable_slot.keccak_mpt.mpt_key,
            );

        let length = length_slot.slot;
        let variable = variable_slot.mapping_slot;

        let dm = cb.map_to_curve_point(&[length, variable, is_rlp_encoded.target]);
        let dm = (&dm.0 .0[0].0[..], &dm.0 .0[1].0[..], &dm.0 .1.target);

        let h =
            array::from_fn::<_, PACKED_HASH_LEN, _>(|i| variable_mpt.root.output_array.arr[i].0);
        let k = &variable_mpt.key.key.arr;
        let t = cb.sub(t_p, variable_mpt.key.pointer);
        let n = cb.select(
            is_rlp_encoded,
            variable_mpt.rlp_headers.len[0],
            length_mpt.value[0],
        );

        PublicInputs::new(&h, dm, k, &t, &n).register(cb);

        LeafLengthWires {
            is_rlp_encoded,
            length_slot,
            length_mpt,
            variable_slot,
            variable_mpt,
        }
    }

    /// Assigns the values of this instance into the provided partial witness, using the generated
    /// circuit wires.
    pub fn assign(&self, pw: &mut PartialWitness<GFp>, wires: &LeafLengthWires<NODE_LEN>) {
        pw.set_target(
            wires.is_rlp_encoded.target,
            GFp::from_bool(self.is_rlp_encoded),
        );

        self.length_slot.assign(pw, &wires.length_slot);
        wires.length_mpt.assign(pw, &self.length_node);
        self.variable_slot.assign(pw, &wires.variable_slot);
        wires.variable_mpt.assign(pw, &self.variable_node);
    }
}
