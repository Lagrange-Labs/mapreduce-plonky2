//! MPT leaf or extension node gadget

use super::{Circuit as MPTCircuit, MPTKeyWire, PAD_LEN};
use crate::{
    array::{Array, Vector, VectorWire},
    keccak::{InputData, KeccakCircuit, KeccakWires},
    rlp::decode_fixed_list,
    types::GFp,
};
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::{target::Target, witness::PartialWitness},
    plonk::circuit_builder::CircuitBuilder,
};

/// Wrapped wires for a MPT leaf or extension node
#[derive(Clone, Debug)]
pub struct MPTLeafOrExtensionWires<const NODE_LEN: usize, const VALUE_LEN: usize>
where
    [(); PAD_LEN(NODE_LEN)]:,
{
    /// MPT node
    pub node: VectorWire<Target, { PAD_LEN(NODE_LEN) }>,
    /// MPT root
    pub root: KeccakWires<{ PAD_LEN(NODE_LEN) }>,
    /// New MPT key after advancing the current key
    pub key: MPTKeyWire,
    /// New MPT value
    pub value: Array<Target, VALUE_LEN>,
}

impl<const NODE_LEN: usize, const VALUE_LEN: usize> MPTLeafOrExtensionWires<NODE_LEN, VALUE_LEN>
where
    [(); PAD_LEN(NODE_LEN)]:,
{
    pub fn assign(&self, pw: &mut PartialWitness<GFp>, node: &Vector<u8, { PAD_LEN(NODE_LEN) }>) {
        self.node.assign(pw, node);
        KeccakCircuit::assign(pw, &self.root, &InputData::Assigned(node));
    }
}

/// MPT leaf or extension node gadget
pub struct MPTLeafOrExtensionNode;

impl MPTLeafOrExtensionNode {
    /// Build the MPT node and advance the current key.
    pub fn build_and_advance_key<
        F: RichField + Extendable<D>,
        const D: usize,
        const NODE_LEN: usize,
        const VALUE_LEN: usize,
    >(
        b: &mut CircuitBuilder<F, D>,
        current_key: &MPTKeyWire,
    ) -> MPTLeafOrExtensionWires<NODE_LEN, VALUE_LEN>
    where
        [(); PAD_LEN(NODE_LEN)]:,
    {
        let zero = b.zero();
        let tru = b._true();

        // Build the node and ensure it only includes bytes.
        let node = VectorWire::<Target, { PAD_LEN(NODE_LEN) }>::new(b);
        node.assert_bytes(b);

        // Expose the keccak root of this subtree starting at this node.
        let root = KeccakCircuit::<{ PAD_LEN(NODE_LEN) }>::hash_vector(b, &node);

        // Advance the key and extract the value (only decode two headers in the case of leaf).
        let rlp_headers = decode_fixed_list::<_, D, 2>(b, &node.arr.arr, zero);
        let (key, value, valid) = MPTCircuit::<1, NODE_LEN>::advance_key_leaf_or_extension::<
            F,
            D,
            2,
            VALUE_LEN,
        >(b, &node.arr, current_key, &rlp_headers);
        b.connect(tru.target, valid.target);

        MPTLeafOrExtensionWires {
            node,
            root,
            key,
            value,
        }
    }
}
