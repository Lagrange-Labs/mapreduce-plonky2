//! Module handling the branch node inside a storage trie

use super::public_inputs::PublicInputs;
use anyhow::Result;
use mp2_common::{
    array::{Array, Vector, VectorWire},
    keccak::{InputData, KeccakCircuit, KeccakWires, HASH_LEN, PACKED_HASH_LEN},
    mpt_sequential::{Circuit as MPTCircuit, MPTKeyWire, PAD_LEN},
    rlp::{decode_fixed_list, MAX_ITEMS_IN_LIST},
    types::{CBuilder, GFp},
    utils::{convert_u8_targets_to_u32, less_than},
};
use plonky2::{
    field::types::Field,
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::proof::ProofWithPublicInputsTarget,
};
use plonky2_crypto::u32::arithmetic_u32::U32Target;
use plonky2_ecgfp5::gadgets::curve::CircuitBuilderEcGFp5;
use recursion_framework::circuit_builder::CircuitLogicWires;
use serde::{Deserialize, Serialize};
use std::array::from_fn;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BranchWires<const NODE_LEN: usize>
where
    [(); PAD_LEN(NODE_LEN)]:,
{
    /// Key provided by prover as a point of reference to verify all children proofs's exposed keys
    common_prefix: MPTKeyWire,
    node: VectorWire<Target, { PAD_LEN(NODE_LEN) }>,
    root: KeccakWires<{ PAD_LEN(NODE_LEN) }>,
    n_proof_valid: Target,
    /// It's true for `simple` aggregation type, otherwise it's `multiple` type.
    is_simple_aggregation: Target,
}

#[derive(Clone, Debug)]
pub struct BranchCircuit<const NODE_LEN: usize, const N_CHILDREN: usize> {
    node: Vec<u8>,
    common_prefix: Vec<u8>,
    expected_pointer: usize,
    n_proof_valid: usize,
    is_simple_aggregation: bool,
}

impl<const NODE_LEN: usize, const N_CHILDREN: usize> BranchCircuit<NODE_LEN, N_CHILDREN>
where
    [(); PAD_LEN(NODE_LEN)]:,
    [(); HASH_LEN / 4]:,
    [(); HASH_LEN]:,
{
    pub fn build(
        b: &mut CBuilder,
        inputs: &[PublicInputs<Target>; N_CHILDREN],
    ) -> BranchWires<NODE_LEN> {
        let zero = b.zero();
        let one = b.one();
        let ttrue = b._true();
        let ffalse = b._false();

        let n_proof_valid = b.add_virtual_target();
        let is_simple_aggregation = b.add_virtual_bool_target_safe();

        // Build the node and ensure it only includes bytes.
        let node = VectorWire::<Target, { PAD_LEN(NODE_LEN) }>::new(b);
        node.assert_bytes(b);

        // Key is exposed as common prefix, need to make sure all child proofs shared the same common prefix.
        let common_prefix = MPTKeyWire::new(b);

        // Expose the keccak root of this subtree starting at this node.
        let root = KeccakCircuit::<{ PAD_LEN(NODE_LEN) }>::hash_vector(b, &node);

        // N is the total number of entries recursively verified.
        let mut n = b.zero();

        // Accumulate for each child proof, the result is the addition of all children.
        let mut metadata_digest = inputs[0].metadata_digest();
        let mut values_digest = b.curve_zero();

        // we already decode the RLP headers here since we need it to verify the validity of the hash exposed by the proofs.
        let headers = decode_fixed_list::<_, 2, MAX_ITEMS_IN_LIST>(b, &node.arr.arr, zero);

        let zero_point = b.curve_zero();
        let mut seen_nibbles = vec![];
        for (i, proof_inputs) in inputs.iter().enumerate() {
            let it = b.constant(GFp::from_canonical_usize(i));
            let should_process = less_than(b, it, n_proof_valid, 4);

            let child_m_digest = proof_inputs.metadata_digest();
            let child_v_digest = proof_inputs.values_digest();

            // Accumulate the metadata digest.
            let maybe_m_digest = b.curve_select(is_simple_aggregation, child_m_digest, zero_point);
            metadata_digest = b.curve_add(metadata_digest, maybe_m_digest);

            // Accumulate the values digest.
            let maybe_v_digest = b.curve_select(should_process, child_v_digest, zero_point);
            values_digest = b.curve_add(values_digest, maybe_v_digest);

            // Add the number of leaves this proof has processed.
            let maybe_n = b.select(should_process, proof_inputs.n(), zero);
            n = b.add(n, maybe_n);
            let child_key = proof_inputs.mpt_key();
            let (_, hash, is_valid, nibble) =
                MPTCircuit::<1, NODE_LEN>::advance_key_branch(b, &node.arr, &child_key, &headers);

            // We always enforce it's a branch node, i.e. that it has 17 entries.
            let node_maybe_valid = b.select(should_process, is_valid.target, ttrue.target);
            b.connect(node_maybe_valid, ttrue.target);

            // Make sure we don't process twice the same proof for same nibble.
            seen_nibbles.iter().for_each(|sn| {
                let is_equal = b.is_equal(*sn, nibble);
                let should_be_false = b.select(should_process, is_equal.target, ffalse.target);
                b.connect(should_be_false, ffalse.target);
            });
            seen_nibbles.push(nibble);

            // We check the hash is the one exposed by the proof, first convert the extracted hash to packed one to compare.
            let packed_hash = Array::<U32Target, PACKED_HASH_LEN> {
                arr: convert_u8_targets_to_u32(b, &hash.arr).try_into().unwrap(),
            };
            let child_hash = proof_inputs.root_hash();
            let hash_equals = packed_hash.equals(b, &child_hash);
            let hash_maybe_equal = b.select(should_process, hash_equals.target, ttrue.target);
            b.connect(hash_maybe_equal, ttrue.target);

            // We now check that the MPT key at this point is equal to the one given by the prover. Reason why it is secure is because this circuit only cares that _all_ keys share the _same_ prefix, so if they're all equal to `common_prefix`, they're all equal.
            let is_equal = common_prefix.is_prefix_equal(b, &child_key);
            let prefix_maybe_equal = b.select(should_process, is_equal.target, ttrue.target);
            b.connect(prefix_maybe_equal, ttrue.target);
        }

        // We've compared the pointers _before_ advancing the key for each leaf, so now we can advance the pointer to move to the next node if any.
        let new_prefix = common_prefix.advance_by(b, one);

        // We now extract the public input to register for the proofs.
        PublicInputs::register(
            b,
            &root.output_array,
            &new_prefix,
            values_digest,
            metadata_digest,
            n,
        );

        BranchWires {
            node,
            common_prefix,
            root,
            n_proof_valid,
            is_simple_aggregation: is_simple_aggregation.target,
        }
    }

    fn assign(&self, pw: &mut PartialWitness<GFp>, wires: &BranchWires<NODE_LEN>) {
        let node = Vector::<u8, { PAD_LEN(NODE_LEN) }>::from_vec(&self.node).unwrap();
        wires.node.assign(pw, &node);
        wires.common_prefix.assign(
            pw,
            &self.common_prefix.clone().try_into().unwrap(),
            self.expected_pointer,
        );
        KeccakCircuit::<{ PAD_LEN(NODE_LEN) }>::assign(
            pw,
            &wires.root,
            &InputData::Assigned(&node),
        );
        pw.set_target(
            wires.n_proof_valid,
            GFp::from_canonical_usize(self.n_proof_valid),
        );
        pw.set_target(
            wires.is_simple_aggregation,
            GFp::from_bool(self.is_simple_aggregation),
        );
    }
}

/// D = 2,
/// Num of children = 0
impl<const NODE_LEN: usize, const N_CHILDREN: usize> CircuitLogicWires<GFp, 2, N_CHILDREN>
    for BranchWires<NODE_LEN>
where
    [(); PAD_LEN(NODE_LEN)]:,
{
    type CircuitBuilderParams = ();

    type Inputs = BranchCircuit<NODE_LEN, N_CHILDREN>;

    const NUM_PUBLIC_INPUTS: usize = PublicInputs::<GFp>::TOTAL_LEN;

    fn circuit_logic(
        builder: &mut CBuilder,
        verified_proofs: [&ProofWithPublicInputsTarget<2>; N_CHILDREN],
        _: Self::CircuitBuilderParams,
    ) -> Self {
        let inputs: [PublicInputs<Target>; N_CHILDREN] =
            from_fn(|i| PublicInputs::from(&verified_proofs[i].public_inputs));
        BranchCircuit::build(builder, &inputs)
    }

    fn assign_input(&self, inputs: Self::Inputs, pw: &mut PartialWitness<GFp>) -> Result<()> {
        inputs.assign(pw, self);
        Ok(())
    }
}
