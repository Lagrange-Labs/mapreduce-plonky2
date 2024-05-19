//! Database branch length extraction circuits

use core::array;

use mp2_common::{
    array::{Vector, VectorWire},
    keccak::{InputData, KeccakCircuit, KeccakWires, PACKED_HASH_LEN},
    mpt_sequential::{Circuit as MPTCircuit, PAD_LEN},
    public_inputs::PublicInputCommon,
    rlp::{decode_fixed_list, MAX_ITEMS_IN_LIST},
    types::{CBuilder, GFp},
    utils::convert_u8_targets_to_u32,
    D,
};
use plonky2::iop::{target::Target, witness::PartialWitness};

use super::PublicInputs;

/// The wires structure for the branch length extraction.
#[derive(Clone, Debug)]
pub struct BranchLengthWires<const NODE_LEN: usize>
where
    [(); PAD_LEN(NODE_LEN)]:,
{
    node: VectorWire<Target, { PAD_LEN(NODE_LEN) }>,
    root: KeccakWires<{ PAD_LEN(NODE_LEN) }>,
}

/// The circuit definition for the branch length extraction.
#[derive(Clone, Debug)]
pub struct BranchLengthCircuit<const NODE_LEN: usize>
where
    [(); PAD_LEN(NODE_LEN)]:,
{
    node: Vector<u8, { PAD_LEN(NODE_LEN) }>,
}

impl<const NODE_LEN: usize> BranchLengthCircuit<NODE_LEN>
where
    [(); PAD_LEN(NODE_LEN)]:,
{
    /// Creates a new instance of the circuit.
    pub fn new(node: &[u8]) -> anyhow::Result<Self> {
        Ok(Self {
            node: Vector::from_vec(node)?,
        })
    }

    /// Build the circuit, assigning the public inputs and returning the internal wires.
    pub fn build(
        cb: &mut CBuilder,
        child_proof: PublicInputs<Target>,
    ) -> BranchLengthWires<NODE_LEN> {
        let zero = cb.zero();

        let key = child_proof.mpt_key_wire();
        let node = VectorWire::<Target, { PAD_LEN(NODE_LEN) }>::new(cb);
        let headers = decode_fixed_list::<_, D, MAX_ITEMS_IN_LIST>(cb, &node.arr.arr, zero);

        let (k_p, hash, _, _) =
            MPTCircuit::<1, NODE_LEN>::advance_key_branch(cb, &node.arr, &key, &headers);

        for (i, h) in convert_u8_targets_to_u32(cb, &hash.arr)
            .into_iter()
            .enumerate()
        {
            cb.connect(h.0, child_proof.root_hash()[i]);
        }

        let root = KeccakCircuit::<{ PAD_LEN(NODE_LEN) }>::hash_vector(cb, &node);
        let h = &array::from_fn::<_, PACKED_HASH_LEN, _>(|i| root.output_array.arr[i].0);
        let t = &k_p.pointer;

        let PublicInputs { dm, k, n, .. } = child_proof;
        PublicInputs { h, dm, k, t, n }.register(cb);

        BranchLengthWires { node, root }
    }

    /// Assigns the values of this instance into the provided partial witness, using the generated
    /// circuit wires.
    pub fn assign(&self, pw: &mut PartialWitness<GFp>, wires: &BranchLengthWires<NODE_LEN>) {
        wires.node.assign(pw, &self.node);

        KeccakCircuit::<{ PAD_LEN(NODE_LEN) }>::assign(
            pw,
            &wires.root,
            &InputData::Assigned(&self.node),
        );
    }
}
