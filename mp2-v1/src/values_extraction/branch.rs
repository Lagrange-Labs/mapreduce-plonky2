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
    D,
};
use plonky2::{
    field::types::Field,
    iop::{
        target::{BoolTarget, Target},
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::proof::ProofWithPublicInputsTarget,
};
use plonky2_crypto::u32::arithmetic_u32::U32Target;
use plonky2_ecgfp5::gadgets::curve::CircuitBuilderEcGFp5;
use recursion_framework::{
    circuit_builder::CircuitLogicWires,
    serialization::{deserialize, serialize},
};
use serde::{Deserialize, Serialize};
use std::array;

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
    /// The flag is true for `simple` aggregation type, and false for `multiple` type.
    #[serde(serialize_with = "serialize", deserialize_with = "deserialize")]
    is_simple_aggregation: BoolTarget,
}

#[derive(Clone, Debug)]
pub struct BranchCircuit<const NODE_LEN: usize, const N_CHILDREN: usize> {
    pub(crate) node: Vec<u8>,
    pub(crate) common_prefix: Vec<u8>,
    pub(crate) expected_pointer: usize,
    pub(crate) n_proof_valid: usize,
    pub(crate) is_simple_aggregation: bool,
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

        // Key is exposed as common prefix, need to make sure all child proofs
        // shared the same common prefix.
        let common_prefix = MPTKeyWire::new(b);

        // Expose the keccak root of this subtree starting at this node.
        let root = KeccakCircuit::<{ PAD_LEN(NODE_LEN) }>::hash_vector(b, &node);

        // N is the total number of entries recursively verified.
        let mut n = b.zero();

        // Accumulate the value digests for each child proof, the result is the
        // addition of all children.
        let mut values_digest = b.curve_zero();

        // Accumulate the metadata digests of each child proof for `simple`
        // aggregation type, or the digests of each child proof are same for
        // `multiple` type.
        let mut metadata_digest = b.curve_zero();

        // we already decode the RLP headers here since we need it to verify the
        // validity of the hash exposed by the proofs.
        let headers = decode_fixed_list::<_, D, MAX_ITEMS_IN_LIST>(b, &node.arr.arr, zero);

        let zero_point = b.curve_zero();
        let mut seen_nibbles = vec![];
        for (i, proof_inputs) in inputs.iter().enumerate() {
            let it = b.constant(GFp::from_canonical_usize(i));
            let should_process = less_than(b, it, n_proof_valid, 4);

            // Accumulate the values digest.
            let child_digest = proof_inputs.values_digest();
            let child_digest = b.curve_select(should_process, child_digest, zero_point);
            values_digest = b.curve_add(values_digest, child_digest);

            let child_digest = proof_inputs.metadata_digest();
            if i > 0 {
                // Check if the metadata digests are same for `multiple` aggregation type.
                let is_equal = b.curve_eq(metadata_digest, child_digest);
                let should_check = b.not(is_simple_aggregation);
                let should_check = b.and(should_process, should_check);
                let should_check = b.or(is_equal, should_check);
                b.connect(is_equal.target, should_check.target);

                // Accumulate the metadata digests for `simple` aggregation type.
                let should_acc = b.and(should_process, is_simple_aggregation);
                let child_digest = b.curve_select(should_acc, child_digest, zero_point);
                metadata_digest = b.curve_add(metadata_digest, child_digest);
            } else {
                metadata_digest = child_digest;
            }

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

            // We check the hash is the one exposed by the proof, first convert
            // the extracted hash to packed one to compare.
            let packed_hash = Array::<U32Target, PACKED_HASH_LEN> {
                arr: convert_u8_targets_to_u32(b, &hash.arr).try_into().unwrap(),
            };
            let child_hash = proof_inputs.root_hash();
            packed_hash.enforce_equal(b, &child_hash);

            // We now check that the MPT key at this point is equal to the one
            // given by the prover. Reason why it is secure is because this
            // circuit only cares that _all_ keys share the _same_ prefix, so if
            // they're all equal to `common_prefix`, they're all equal.
            common_prefix.enforce_prefix_equal(b, &child_key);
        }

        // We've compared the pointers _before_ advancing the key for each leaf,
        // so now we can advance the pointer to move to the next node if any.
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
            is_simple_aggregation,
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
        pw.set_bool_target(wires.is_simple_aggregation, self.is_simple_aggregation);
    }
}

impl<const NODE_LEN: usize, const N_CHILDREN: usize> CircuitLogicWires<GFp, D, N_CHILDREN>
    for BranchWires<NODE_LEN>
where
    [(); PAD_LEN(NODE_LEN)]:,
{
    type CircuitBuilderParams = ();

    type Inputs = BranchCircuit<NODE_LEN, N_CHILDREN>;

    const NUM_PUBLIC_INPUTS: usize = PublicInputs::<GFp>::TOTAL_LEN;

    fn circuit_logic(
        builder: &mut CBuilder,
        verified_proofs: [&ProofWithPublicInputsTarget<D>; N_CHILDREN],
        _: Self::CircuitBuilderParams,
    ) -> Self {
        let inputs: [PublicInputs<Target>; N_CHILDREN] =
            array::from_fn(|i| PublicInputs::new(&verified_proofs[i].public_inputs));
        BranchCircuit::build(builder, &inputs)
    }

    fn assign_input(&self, inputs: Self::Inputs, pw: &mut PartialWitness<GFp>) -> Result<()> {
        inputs.assign(pw, self);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{super::public_inputs::tests::new_extraction_public_inputs, *};
    use eth_trie::{EthTrie, MemoryDB, Nibbles, Trie};
    use mp2_common::{
        group_hashing::map_to_curve_point,
        mpt_sequential::utils::bytes_to_nibbles,
        rlp::MAX_KEY_NIBBLE_LEN,
        utils::{convert_u8_to_u32_slice, keccak256},
        C, D, F,
    };
    use mp2_test::{
        circuit::{run_circuit, UserCircuit},
        utils::random_vector,
    };
    use plonky2::{
        field::{goldilocks_field::GoldilocksField, types::Field},
        iop::{target::Target, witness::WitnessWrite},
        plonk::config::{GenericConfig, PoseidonGoldilocksConfig},
    };
    use rand::{thread_rng, Rng};
    use std::sync::Arc;

    #[derive(Clone, Debug)]
    struct TestBranchCircuit<'a, const NODE_LEN: usize, const N_CHILDREN: usize> {
        c: BranchCircuit<NODE_LEN, N_CHILDREN>,
        exp_pis: [PublicInputs<'a, F>; N_CHILDREN],
    }

    impl<'a, const NODE_LEN: usize, const N_CHILDREN: usize> UserCircuit<F, D>
        for TestBranchCircuit<'a, NODE_LEN, N_CHILDREN>
    where
        [(); PAD_LEN(NODE_LEN)]:,
    {
        type Wires = (BranchWires<NODE_LEN>, [Vec<Target>; N_CHILDREN]);

        fn build(c: &mut CBuilder) -> Self::Wires {
            let inputs: Vec<_> = (0..N_CHILDREN)
                .map(|_| c.add_virtual_targets(PublicInputs::<Target>::TOTAL_LEN))
                .collect();
            let exp_pis = array::from_fn(|i| PublicInputs::new(&inputs[i]));

            let branch_wires = BranchCircuit::<NODE_LEN, N_CHILDREN>::build(c, &exp_pis);

            (branch_wires, inputs.try_into().unwrap())
        }

        fn prove(&self, pw: &mut PartialWitness<GFp>, wires: &Self::Wires) {
            self.c.assign(pw, &wires.0);

            assert_eq!(self.exp_pis.len(), wires.1.len());
            for i in 0..N_CHILDREN {
                assert_eq!(self.exp_pis[i].proof_inputs.len(), wires.1[i].len());
                pw.set_target_arr(&wires.1[i], self.exp_pis[i].proof_inputs);
            }
        }
    }

    #[test]
    fn test_values_extraction_branch_circuit_simple_type() {
        test_branch_circuit(true);
    }

    #[test]
    fn test_values_extraction_branch_circuit_multiple_type() {
        test_branch_circuit(false);
    }

    fn test_branch_circuit(is_simple_aggregation: bool) {
        const NODE_LEN: usize = 100;
        const N_CHILDREN: usize = 2;

        // We need to create a trie that for sure contains an branch node:
        // We insert two values under two keys which only differ by their last nibble/byte
        // Normally, the trie should look like :
        // root = extension node
        // branch = point of different between the two keys
        // two leaves
        let memdb = Arc::new(MemoryDB::new(true));
        let mut trie = EthTrie::new(Arc::clone(&memdb));
        let key1 = random_vector(32);
        let mut key2 = key1.clone();
        key2[31] = thread_rng().gen();
        let value1 = random_vector(32);
        let value2 = random_vector(32);
        trie.insert(&key1, &value1).unwrap();
        trie.insert(&key2, &value2).unwrap();
        trie.root_hash().unwrap();
        let proof1 = trie.get_proof(&key1).unwrap();
        let proof2 = trie.get_proof(&key2).unwrap();
        assert!(proof1.len() == 3);
        assert_eq!(proof1[1], proof2[1]);
        let node = proof1[1].clone();
        let leaf1 = proof1.last().unwrap();
        let leaf2 = proof2.last().unwrap();
        let compute_key_ptr = |leaf: &[u8]| {
            let tuple: Vec<Vec<u8>> = rlp::decode_list(leaf);
            let partial_nibbles = Nibbles::from_compact(&tuple[0]);
            let partial_key_len = partial_nibbles.nibbles().len();
            MAX_KEY_NIBBLE_LEN - 1 - partial_key_len
        };
        let ptr1 = compute_key_ptr(leaf1);
        let ptr2 = compute_key_ptr(leaf2);
        assert_eq!(ptr1, ptr2);

        // Create the two public inputs.
        let compute_digest = |arr: Vec<u8>| {
            map_to_curve_point(
                &arr.into_iter()
                    .map(F::from_canonical_u8)
                    .collect::<Vec<_>>(),
            )
        };
        let compute_pi = |key: &[u8], value: &[u8], leaf: &[u8], metadata: &[u8]| {
            let h = convert_u8_to_u32_slice(&keccak256(leaf));
            let [values_digest, metadata_digest] =
                [value, metadata].map(|arr| compute_digest(arr.to_vec()).to_weierstrass());

            // Both ptr should be the same and set 1 for leaf.
            new_extraction_public_inputs(
                &h,
                &bytes_to_nibbles(key),
                ptr1,
                &values_digest,
                &metadata_digest,
                1,
            )
        };
        let metadata1 = random_vector(20);
        let child_pi1 = compute_pi(&key1, &value1, leaf1, &metadata1);
        let metadata2 = if is_simple_aggregation {
            random_vector(20)
        } else {
            // Set the same metadata digests for `multiple` aggregation type.
            metadata1.clone()
        };
        let child_pi2 = compute_pi(&key2, &value2, leaf2, &metadata2);
        assert_eq!(child_pi1.len(), PublicInputs::<F>::TOTAL_LEN);
        assert_eq!(child_pi2.len(), PublicInputs::<F>::TOTAL_LEN);

        let c = BranchCircuit::<NODE_LEN, N_CHILDREN> {
            node: node.clone(),
            // Any of the two keys should work since we only care about the common prefix.
            common_prefix: bytes_to_nibbles(&key1),
            expected_pointer: ptr1,
            n_proof_valid: 2,
            is_simple_aggregation,
        };
        let circuit = TestBranchCircuit {
            c,
            exp_pis: [&child_pi1, &child_pi2].map(|pi| PublicInputs::new(pi)),
        };
        let proof = run_circuit::<F, D, C, _>(circuit);
        let pi = PublicInputs::<F>::new(&proof.public_inputs);

        {
            let exp_hash = keccak256(&node);
            let exp_hash = convert_u8_to_u32_slice(&exp_hash);
            assert_eq!(pi.root_hash(), exp_hash);
        }
        {
            let (key, ptr) = pi.mpt_key_info();
            let exp_key: Vec<_> = bytes_to_nibbles(&key1)
                .into_iter()
                .map(F::from_canonical_u8)
                .collect();
            assert_eq!(key, exp_key);

            // -1 because branch circuit exposes the new pointer.
            let exp_ptr = F::from_canonical_usize(ptr1 - 1);
            assert_eq!(ptr, exp_ptr);
        }
        // Check values digest
        {
            let acc1 = compute_digest(value1);
            let acc2 = compute_digest(value2);
            let branch_acc = acc1 + acc2;

            assert_eq!(pi.values_digest(), branch_acc.to_weierstrass());
        }
        // Check metadata digest
        {
            let acc1 = compute_digest(metadata1);
            let acc2 = compute_digest(metadata2);
            let branch_acc = if is_simple_aggregation {
                acc1 + acc2
            } else {
                assert_eq!(acc1, acc2);
                acc1
            };

            assert_eq!(pi.metadata_digest(), branch_acc.to_weierstrass());
        }
        assert_eq!(pi.n(), F::from_canonical_usize(N_CHILDREN));
    }
}
