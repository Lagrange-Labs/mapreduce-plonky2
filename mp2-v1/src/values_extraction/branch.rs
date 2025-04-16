//! Module handling the branch node inside a storage trie

use super::public_inputs::{PublicInputs, PublicInputsArgs};
use anyhow::Result;
use mp2_common::{
    array::{Array, Vector, VectorWire},
    group_hashing::CircuitBuilderGroupHashing,
    keccak::{InputData, KeccakCircuit, KeccakWires, HASH_LEN, PACKED_HASH_LEN},
    mpt_sequential::{Circuit as MPTCircuit, MPTKeyWire, PAD_LEN},
    public_inputs::PublicInputCommon,
    rlp::{decode_fixed_list, MAX_ITEMS_IN_LIST},
    types::{CBuilder, GFp},
    utils::{less_than, Endianness, PackerTarget},
    D,
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
}

#[derive(Clone, Debug)]
pub struct BranchCircuit<const NODE_LEN: usize, const N_CHILDREN: usize> {
    pub(crate) node: Vec<u8>,
    pub(crate) common_prefix: Vec<u8>,
    pub(crate) expected_pointer: usize,
    pub(crate) n_proof_valid: usize,
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

        // Initialize the metadata digest.
        let mut metadata_digest = b.curve_zero();

        // we already decode the RLP headers here since we need it to verify the
        // validity of the hash exposed by the proofs.
        let headers = decode_fixed_list::<_, D, MAX_ITEMS_IN_LIST>(b, &node.arr.arr, zero);

        let zero_point = b.curve_zero();
        let mut seen_nibbles = vec![];
        for (i, proof_inputs) in inputs.iter().enumerate() {
            let it = b.constant(GFp::from_canonical_usize(i));
            let should_process = less_than(b, it, n_proof_valid, 5);

            // Accumulate the values digest.
            let child_digest = proof_inputs.values_digest_target();
            let child_digest = b.curve_select(should_process, child_digest, zero_point);
            values_digest = b.curve_add(values_digest, child_digest);

            let child_digest = proof_inputs.metadata_digest_target();
            if i > 0 {
                // Ensure the metadata digests of all child proofs are same.
                b.connect_curve_points(metadata_digest, child_digest);
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
            b.connect(is_valid.target, ttrue.target);

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
                arr: hash.arr.pack(b, Endianness::Little).try_into().unwrap(),
            };
            let child_hash = proof_inputs.root_hash_target();
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
        PublicInputsArgs {
            h: &root.output_array,
            k: &new_prefix,
            dv: values_digest,
            dm: metadata_digest,
            n,
        }
        .register(b);

        BranchWires {
            node,
            common_prefix,
            root,
            n_proof_valid,
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
        utils::{keccak256, Endianness, Packer},
        C, D, F,
    };
    use mp2_test::{
        circuit::{run_circuit, UserCircuit},
        utils::random_vector,
    };
    use plonky2::{
        field::types::Field,
        iop::{target::Target, witness::WitnessWrite},
    };
    use plonky2_ecgfp5::curve::curve::Point;
    use std::{array, iter, sync::Arc};

    #[derive(Clone, Debug, Default)]
    struct TestChildData {
        ptr: usize,
        key: Vec<u8>,
        value: Vec<u8>,
        leaf: Vec<u8>,
        metadata: Vec<u8>,
        proof: Vec<Vec<u8>>,
        pi: Vec<GFp>,
    }

    #[derive(Clone, Debug)]
    struct TestBranchCircuit<'a, const NODE_LEN: usize, const N_CHILDREN: usize> {
        c: BranchCircuit<NODE_LEN, N_CHILDREN>,
        child_pis: [PublicInputs<'a, F>; N_CHILDREN],
    }

    impl<const NODE_LEN: usize, const N_CHILDREN: usize> UserCircuit<F, D>
        for TestBranchCircuit<'_, NODE_LEN, N_CHILDREN>
    where
        [(); PAD_LEN(NODE_LEN)]:,
    {
        type Wires = (BranchWires<NODE_LEN>, [Vec<Target>; N_CHILDREN]);

        fn build(c: &mut CBuilder) -> Self::Wires {
            let inputs: Vec<_> = (0..N_CHILDREN)
                .map(|_| c.add_virtual_targets(PublicInputs::<Target>::TOTAL_LEN))
                .collect();
            let child_pis = array::from_fn(|i| PublicInputs::new(&inputs[i]));

            let branch_wires = BranchCircuit::<NODE_LEN, N_CHILDREN>::build(c, &child_pis);

            (branch_wires, inputs.try_into().unwrap())
        }

        fn prove(&self, pw: &mut PartialWitness<GFp>, wires: &Self::Wires) {
            self.c.assign(pw, &wires.0);

            assert_eq!(self.child_pis.len(), wires.1.len());
            for i in 0..N_CHILDREN {
                assert_eq!(self.child_pis[i].proof_inputs.len(), wires.1[i].len());
                pw.set_target_arr(&wires.1[i], self.child_pis[i].proof_inputs);
            }
        }
    }

    #[test]
    fn test_values_extraction_branch_circuit_without_padding() {
        const NODE_LEN: usize = 100;
        const N_REAL: usize = 2;
        const N_PADDING: usize = 0;

        test_branch_circuit::<NODE_LEN, N_REAL, N_PADDING>();
    }

    #[test]
    fn test_values_extraction_branch_circuit_with_padding() {
        const NODE_LEN: usize = 100;
        const N_REAL: usize = 2;
        const N_PADDING: usize = 1;

        test_branch_circuit::<NODE_LEN, N_REAL, N_PADDING>();
    }

    fn test_branch_circuit<const NODE_LEN: usize, const N_REAL: usize, const N_PADDING: usize>()
    where
        [(); PAD_LEN(NODE_LEN)]:,
        [(); N_REAL + N_PADDING]:,
    {
        let compute_key_ptr = |leaf: &[u8]| {
            let tuple: Vec<Vec<u8>> = rlp::decode_list(leaf);
            let partial_nibbles = Nibbles::from_compact(&tuple[0]);
            let partial_key_len = partial_nibbles.nibbles().len();
            MAX_KEY_NIBBLE_LEN - 1 - partial_key_len
        };
        let compute_digest = |arr: Vec<u8>| {
            map_to_curve_point(
                &arr.into_iter()
                    .map(F::from_canonical_u8)
                    .collect::<Vec<_>>(),
            )
        };
        let compute_pi = |ptr: usize, key: &[u8], value: &[u8], leaf: &[u8], metadata: &[u8]| {
            let h = keccak256(leaf).pack(Endianness::Little);
            let [values_digest, metadata_digest] =
                [value, metadata].map(|arr| compute_digest(arr.to_vec()).to_weierstrass());

            // Both ptr should be the same and set 1 for leaf.
            new_extraction_public_inputs(
                &h,
                &bytes_to_nibbles(key),
                ptr,
                &values_digest,
                &metadata_digest,
                1,
            )
        };

        let mut children: [TestChildData; N_REAL] = array::from_fn(|_| TestChildData::default());

        // We need to create a trie that for sure contains a branch node:
        // We insert N_REAL values under keys which only differ by their last nibble/byte
        // Normally, the trie should look like:
        // root = extension node
        // branch = point of different between the keys
        // N_REAL leaves
        let memdb = Arc::new(MemoryDB::new(true));
        let mut trie = EthTrie::new(Arc::clone(&memdb));

        let key: Vec<u8> = random_vector(32);
        for (i, child) in children.iter_mut().enumerate().take(N_REAL) {
            let mut key = key.clone();
            key[31] = key[31].wrapping_add(i as u8);
            let value = random_vector(32);
            trie.insert(&key, &value).unwrap();

            child.key = key;
            child.value = value;
        }
        trie.root_hash().unwrap();

        let metadata = random_vector(20);
        for (_, child) in children.iter_mut().enumerate().take(N_REAL) {
            let proof = trie.get_proof(&child.key).unwrap();
            assert!(proof.len() == 3);
            let leaf = proof.last().unwrap();
            let ptr = compute_key_ptr(leaf);

            let pi = compute_pi(ptr, &child.key, &child.value, leaf, &metadata);
            assert_eq!(pi.len(), PublicInputs::<F>::TOTAL_LEN);

            child.proof = proof.clone();
            child.leaf = leaf.clone();
            child.ptr = ptr;
            child.metadata = metadata.clone();
            child.pi = pi;
        }
        let node = children[0].proof[1].clone();

        let c = BranchCircuit::<NODE_LEN, { N_REAL + N_PADDING }> {
            node: node.clone(),
            // Any of the two keys should work since we only care about the common prefix.
            common_prefix: bytes_to_nibbles(&children[0].key),
            expected_pointer: children[0].ptr,
            n_proof_valid: N_REAL,
        };

        // Extend the children public inputs by repeatedly copying the last real one as paddings.
        let mut child_pis: Vec<_> = children.iter().map(|child| child.pi.clone()).collect();
        let last_pi = child_pis.last().unwrap().clone();
        child_pis.extend(iter::repeat(last_pi).take(N_PADDING));
        let child_pis: Vec<_> = child_pis.iter().map(|pi| PublicInputs::new(pi)).collect();

        let circuit = TestBranchCircuit::<NODE_LEN, { N_REAL + N_PADDING }> {
            c,
            child_pis: child_pis.try_into().unwrap(),
        };
        let proof =
            run_circuit::<F, D, C, TestBranchCircuit<NODE_LEN, { N_REAL + N_PADDING }>>(circuit);
        let pi = PublicInputs::<F>::new(&proof.public_inputs);

        {
            let exp_hash = keccak256(&node).pack(Endianness::Little);
            assert_eq!(pi.root_hash(), exp_hash);
        }
        {
            let (key, ptr) = pi.mpt_key_info();
            let exp_key: Vec<_> = bytes_to_nibbles(&children[0].key)
                .into_iter()
                .map(F::from_canonical_u8)
                .collect();
            assert_eq!(key, exp_key);

            // -1 because branch circuit exposes the new pointer.
            let exp_ptr = F::from_canonical_usize(children[0].ptr - 1);
            assert_eq!(ptr, exp_ptr);
        }
        // Check values digest
        {
            let branch_acc = children
                .iter()
                .take(N_REAL)
                .map(|child| compute_digest(child.value.clone()))
                .fold(Point::NEUTRAL, |acc, digest| acc + digest);

            assert_eq!(pi.values_digest(), branch_acc.to_weierstrass());
        }
        // Check metadata digest
        {
            let branch_acc = compute_digest(children[0].metadata.clone());
            children[1..].iter().for_each(|child| {
                let child_acc = compute_digest(child.metadata.clone());
                assert_eq!(child_acc, branch_acc);
            });

            assert_eq!(pi.metadata_digest(), branch_acc.to_weierstrass());
        }
        assert_eq!(pi.n(), F::from_canonical_usize(N_REAL));
    }
}
