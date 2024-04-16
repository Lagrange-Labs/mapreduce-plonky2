use plonky2::{
    iop::{target::Target, witness::PartialWitness},
    plonk::{circuit_builder::CircuitBuilder, proof::ProofWithPublicInputsTarget},
};
use plonky2_crypto::u32::arithmetic_u32::U32Target;
use recursion_framework::circuit_builder::{public_input_targets, CircuitLogicWires};
use serde::{Deserialize, Serialize};

use crate::{
    array::{Array, Vector, VectorWire, L32},
    keccak::{InputData, KeccakCircuit, KeccakWires, HASH_LEN},
    mpt_sequential::{Circuit as MPTCircuit, PAD_LEN},
    rlp::{decode_fixed_list, MAX_ITEMS_IN_LIST},
    utils::convert_u8_targets_to_u32,
};

use super::public_inputs::PublicInputs;
use anyhow::Result;

pub(crate) struct BranchCircuit<const NODE_LEN: usize>(Vec<u8>);

#[derive(Serialize, Deserialize)]
pub(super) struct BranchWires<const NODE_LEN: usize>
where
    [(); PAD_LEN(NODE_LEN)]:,
{
    /// input node - right now only branch
    node: VectorWire<Target, { PAD_LEN(NODE_LEN) }>,
    keccak: KeccakWires<{ PAD_LEN(NODE_LEN) }>,
}

type F = super::F;
const D: usize = super::D;

// Branch circuit needs to verify the proof for the child node in the MPT path being verified,
// so the number of verifiers for `CircuitLogicWires` is 1
impl<const NODE_LEN: usize> BranchCircuit<NODE_LEN>
where
    [(); PAD_LEN(NODE_LEN)]:,
{
    pub(crate) fn new(node: Vec<u8>) -> Self {
        Self(node)
    }

    pub(crate) fn build(cb: &mut CircuitBuilder<F, D>, child_pi: &[Target]) -> BranchWires<NODE_LEN>
    where
        [(); L32(HASH_LEN)]:,
    {
        let node = VectorWire::<Target, { PAD_LEN(NODE_LEN) }>::new(cb);
        // always ensure the node is bytes at the beginning
        node.assert_bytes(cb);

        let zero = cb.zero();
        let tru = cb._true();
        // First expose the keccak root of this subtree starting at this node
        let root = KeccakCircuit::<{ PAD_LEN(NODE_LEN) }>::hash_vector(cb, &node);

        // we already decode the rlp headers here since we need it to verify
        // the validity of the hash exposed by the proofs
        let headers = decode_fixed_list::<_, _, MAX_ITEMS_IN_LIST>(cb, &node.arr.arr, zero);

        // look at the key from the children proof and move its pointer according to this node
        let child_pi = PublicInputs::from(&child_pi);
        let child_mpt_key = child_pi.mpt_key();
        let (new_key, hash, is_valid, _nibble) =
            MPTCircuit::<1, NODE_LEN>::advance_key_branch(cb, &node.arr, &child_mpt_key, &headers);
        // enforce it's a branch node
        cb.connect(is_valid.target, tru.target);

        // make sure the extracted hash is the one exposed by the proof
        let packed_child_hash: Array<U32Target, { L32(HASH_LEN) }> =
            convert_u8_targets_to_u32(cb, &hash.arr).try_into().unwrap();
        let given_child_hash = child_pi.root_hash();
        packed_child_hash.enforce_equal(cb, &given_child_hash);

        PublicInputs::register(
            cb,
            &new_key,
            &child_pi.contract_address(),
            child_pi.mapping_slot(),
            child_pi.length_slot(),
            &root.output_array,
            &child_pi.digest(),
            &child_pi.lpn_root(),
        );

        BranchWires { node, keccak: root }
    }

    pub(crate) fn assign(
        &self,
        pw: &mut PartialWitness<F>,
        wires: &BranchWires<NODE_LEN>,
    ) -> Result<()> {
        let pad_node = Vector::<u8, { PAD_LEN(NODE_LEN) }>::from_vec(&self.0).unwrap();
        wires.node.assign(pw, &pad_node);

        KeccakCircuit::<{ PAD_LEN(NODE_LEN) }>::assign(
            pw,
            &wires.keccak,
            &InputData::Assigned(&pad_node),
        );

        Ok(())
    }
}

const NUM_IO: usize = PublicInputs::<Target>::TOTAL_LEN;
impl<const NODE_LEN: usize> CircuitLogicWires<F, D, 1> for BranchWires<NODE_LEN>
where
    [(); PAD_LEN(NODE_LEN)]:,
{
    type CircuitBuilderParams = ();

    type Inputs = BranchCircuit<NODE_LEN>;

    const NUM_PUBLIC_INPUTS: usize = NUM_IO;

    fn circuit_logic(
        builder: &mut CircuitBuilder<F, D>,
        verified_proofs: [&ProofWithPublicInputsTarget<D>; 1],
        _: Self::CircuitBuilderParams,
    ) -> Self {
        BranchCircuit::build(
            builder,
            public_input_targets::<F, D, NUM_IO>(verified_proofs[0]),
        )
    }

    fn assign_input(&self, inputs: Self::Inputs, pw: &mut PartialWitness<F>) -> Result<()> {
        inputs.assign(pw, &self)
    }
}
