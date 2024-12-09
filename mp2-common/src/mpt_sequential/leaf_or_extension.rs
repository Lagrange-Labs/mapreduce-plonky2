//! MPT leaf or extension node gadget

use super::{
    advance_key_leaf_or_extension, advance_key_receipt_leaf, key::MPTKeyWireGeneric, PAD_LEN,
};
use crate::{
    array::{Array, Vector, VectorWire},
    keccak::{InputData, KeccakCircuit, KeccakWires},
    rlp::{decode_fixed_list, MAX_KEY_NIBBLE_LEN},
    types::GFp,
};
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::{target::Target, witness::PartialWitness},
    plonk::circuit_builder::CircuitBuilder,
};
use serde::{Deserialize, Serialize};

pub type MPTLeafOrExtensionWires<const NODE_LEN: usize, const VALUE_LEN: usize> =
    MPTLeafOrExtensionWiresGeneric<NODE_LEN, VALUE_LEN, MAX_KEY_NIBBLE_LEN>;

/// Wrapped wires for a MPT leaf or extension node
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MPTLeafOrExtensionWiresGeneric<
    const NODE_LEN: usize,
    const VALUE_LEN: usize,
    const KEY_LEN: usize,
> where
    [(); PAD_LEN(NODE_LEN)]:,
{
    /// MPT node
    pub node: VectorWire<Target, { PAD_LEN(NODE_LEN) }>,
    /// MPT root
    pub root: KeccakWires<{ PAD_LEN(NODE_LEN) }>,
    /// New MPT key after advancing the current key
    pub key: MPTKeyWireGeneric<KEY_LEN>,
    /// New MPT value
    pub value: Array<Target, VALUE_LEN>,
}

impl<const NODE_LEN: usize, const VALUE_LEN: usize, const KEY_LEN: usize>
    MPTLeafOrExtensionWiresGeneric<NODE_LEN, VALUE_LEN, KEY_LEN>
where
    [(); PAD_LEN(NODE_LEN)]:,
{
    pub fn assign(&self, pw: &mut PartialWitness<GFp>, node: &Vector<u8, { PAD_LEN(NODE_LEN) }>) {
        self.node.assign(pw, node);
        KeccakCircuit::assign(pw, &self.root, &InputData::Assigned(node));
    }
}

pub type MPTLeafOrExtensionNode = MPTLeafOrExtensionNodeGeneric<MAX_KEY_NIBBLE_LEN>;

/// MPT leaf or extension node gadget
pub struct MPTLeafOrExtensionNodeGeneric<const KEY_LEN: usize>;

impl<const KEY_LEN: usize> MPTLeafOrExtensionNodeGeneric<KEY_LEN> {
    /// Build the MPT node and advance the current key.
    pub fn build_and_advance_key<
        F: RichField + Extendable<D>,
        const D: usize,
        const NODE_LEN: usize,
        const VALUE_LEN: usize,
    >(
        b: &mut CircuitBuilder<F, D>,
        current_key: &MPTKeyWireGeneric<KEY_LEN>,
    ) -> MPTLeafOrExtensionWiresGeneric<NODE_LEN, VALUE_LEN, KEY_LEN>
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
        let (key, value, valid) =
            advance_key_leaf_or_extension::<F, D, 2, VALUE_LEN, NODE_LEN, KEY_LEN>(
                b,
                &node.arr,
                current_key,
                &rlp_headers,
            );
        b.connect(tru.target, valid.target);

        MPTLeafOrExtensionWiresGeneric {
            node,
            root,
            key,
            value,
        }
    }
}

/// Wrapped wires for a MPT receipt leaf
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MPTReceiptLeafWiresGeneric<const NODE_LEN: usize, const KEY_LEN: usize>
where
    [(); PAD_LEN(NODE_LEN)]:,
{
    /// MPT node
    pub node: VectorWire<Target, { PAD_LEN(NODE_LEN) }>,
    /// MPT root
    pub root: KeccakWires<{ PAD_LEN(NODE_LEN) }>,
    /// New MPT key after advancing the current key
    pub key: MPTKeyWireGeneric<KEY_LEN>,
}

/// Receipt leaf node as we have to do things differently for efficiency reasons.
pub struct MPTReceiptLeafNode<const KEY_LEN: usize>;

impl<const KEY_LEN: usize> MPTReceiptLeafNode<KEY_LEN> {
    /// Build the MPT node and advance the current key.
    pub fn build_and_advance_key<
        F: RichField + Extendable<D>,
        const D: usize,
        const NODE_LEN: usize,
    >(
        b: &mut CircuitBuilder<F, D>,
        current_key: &MPTKeyWireGeneric<KEY_LEN>,
    ) -> MPTReceiptLeafWiresGeneric<NODE_LEN, KEY_LEN>
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

        // We know that the rlp encoding of the compact encoding of the key is going to be in roughly the first 10 bytes of
        // the node since the node is list byte, 2 bytes for list length (maybe 3), key length byte (1), key compact encoding (4 max)
        // so we take 10 bytes to be safe since this won't effect the number of random access gates we use.
        let rlp_headers = decode_fixed_list::<_, D, 1>(b, &node.arr.arr[..10], zero);

        let (key, valid) = advance_key_receipt_leaf::<F, D, NODE_LEN, KEY_LEN>(
            b,
            &node,
            current_key,
            &rlp_headers,
        );
        b.connect(tru.target, valid.target);

        MPTReceiptLeafWiresGeneric { node, root, key }
    }
}
