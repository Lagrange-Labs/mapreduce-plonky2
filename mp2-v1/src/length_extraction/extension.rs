//! Database length extraction circuits for extension node

use core::array;

use mp2_common::{
    array::{Targetable, Vector, VectorWire},
    keccak::{InputData, KeccakCircuit, KeccakWires, HASH_LEN, PACKED_HASH_LEN},
    mpt_sequential::{MPTLeafOrExtensionNode, PAD_LEN},
    public_inputs::PublicInputCommon,
    types::{CBuilder, GFp},
    D,
};
use plonky2::iop::{target::Target, witness::PartialWitness};

use crate::values_extraction::MAX_EXTENSION_NODE_LEN;

use super::PublicInputs;

const PADDED_LEN: usize = PAD_LEN(MAX_EXTENSION_NODE_LEN);

/// The wires structure for the extension extension extraction.
#[derive(Clone, Debug)]
pub struct ExtensionLengthWires {
    node: VectorWire<Target, PADDED_LEN>,
    root: KeccakWires<PADDED_LEN>,
}

/// The circuit definition for the extension length extraction.
#[derive(Clone, Debug)]
pub struct ExtensionLengthCircuit {
    node: Vec<u8>,
}

impl ExtensionLengthCircuit {
    /// Creates a new instance of the circuit.
    pub fn new(node: Vec<u8>) -> Self {
        Self { node }
    }

    /// Build the circuit, assigning the public inputs and returning the internal wires.
    pub fn build(cb: &mut CBuilder, child_proof: PublicInputs<Target>) -> ExtensionLengthWires {
        let one = cb.one();

        let key = child_proof.mpt_key_wire();
        let mpt = MPTLeafOrExtensionNode::build_and_advance_key::<
            _,
            D,
            MAX_EXTENSION_NODE_LEN,
            HASH_LEN,
        >(cb, &key);

        mpt.value
            .convert_u8_to_u32(cb)
            .arr
            .iter()
            .zip(child_proof.root_hash().iter())
            .for_each(|(v, p)| cb.connect(v.to_target(), *p));

        let PublicInputs { dm, k, n, .. } = child_proof;
        let t = &cb.add(*child_proof.mpt_key_pointer(), one);
        let h = &array::from_fn::<_, PACKED_HASH_LEN, _>(|i| mpt.root.output_array.arr[i].0);
        PublicInputs { h, dm, k, t, n }.register(cb);

        ExtensionLengthWires {
            node: mpt.node,
            root: mpt.root,
        }
    }

    /// Assigns the values of this instance into the provided partial witness, using the generated
    /// circuit wires.
    pub fn assign(&self, pw: &mut PartialWitness<GFp>, wires: &ExtensionLengthWires) {
        let node = Vector::<u8, PADDED_LEN>::from_vec(&self.node).unwrap();

        wires.node.assign(pw, &node);

        KeccakCircuit::<PADDED_LEN>::assign(pw, &wires.root, &InputData::Assigned(&node));
    }
}
