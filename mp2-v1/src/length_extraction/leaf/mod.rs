//! Database length extraction circuits

use core::array;

use mp2_common::{
    array::{Array, Vector},
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
        target::{BoolTarget, Target},
        witness::{PartialWitness, WitnessWrite},
    },
};

use super::PublicInputs;

#[cfg(test)]
mod tests;

/// The wires structure for the leaf length extraction of a mapping value.
#[derive(Clone, Debug)]
pub struct LeafLengthWires<const NODE_LEN: usize>
where
    [(); PAD_LEN(NODE_LEN)]:,
{
    pub is_rlp_encoded: BoolTarget,
    pub length_slot: SimpleSlotWires,
    pub length_mpt: MPTLeafOrExtensionWires<NODE_LEN, MAX_LEAF_VALUE_LEN>,
    pub variable_slot: Target,
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
    pub variable_slot: u8,
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
    ) -> anyhow::Result<Self> {
        Ok(Self {
            is_rlp_encoded,
            length_slot: SimpleSlot::new(length_slot),
            length_node: Vector::from_vec(length_node)?,
            variable_slot,
        })
    }

    /// Build the circuit, assigning the public inputs and returning the internal wires.
    pub fn build(cb: &mut CBuilder) -> LeafLengthWires<NODE_LEN> {
        let zero = cb.zero();
        let one = cb.one();

        // we don't range check the variable slot as it is part of the DM public commitment
        let t_p = cb.constant(GFp::from_canonical_u32(64));
        let variable_slot = cb.add_virtual_target();
        let is_rlp_encoded = cb.add_virtual_bool_target_safe();

        let length_slot = SimpleSlot::build(cb);
        let length_mpt =
            MPTLeafOrExtensionNode::build_and_advance_key::<_, D, NODE_LEN, MAX_LEAF_VALUE_LEN>(
                cb,
                &length_slot.mpt_key,
            );

        let length_raw = Array {
            arr: array::from_fn::<_, 4, _>(|i| length_mpt.value[3 - i]),
        }
        .convert_u8_to_u32(cb)[0];

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

        let dm = cb.map_to_curve_point(&[length_slot.slot, variable_slot, is_rlp_encoded.target]);
        let h = array::from_fn::<_, PACKED_HASH_LEN, _>(|i| length_mpt.root.output_array.arr[i].0);
        let k = &length_mpt.key.key.arr;
        let t = cb.sub(t_p, length_mpt.key.pointer);
        let n = cb.select(is_rlp_encoded, length_rlp_encoded.0, length_raw.0);

        PublicInputs::new(&h, &dm, k, &t, &n).register(cb);

        LeafLengthWires {
            is_rlp_encoded,
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
        pw.set_target(
            wires.is_rlp_encoded.target,
            GFp::from_bool(self.is_rlp_encoded),
        );

        self.length_slot.assign(pw, &wires.length_slot);
        wires.length_mpt.assign(pw, &self.length_node);
    }
}
