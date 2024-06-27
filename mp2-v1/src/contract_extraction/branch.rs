//! Module handling the branch node inside a state trie

use super::public_inputs::PublicInputs;
use anyhow::Result;
use mp2_common::{
    array::{Array, Vector, VectorWire},
    keccak::{InputData, KeccakCircuit, KeccakWires, PACKED_HASH_LEN},
    mpt_sequential::{Circuit as MPTCircuit, PAD_LEN},
    public_inputs::PublicInputCommon,
    rlp::{decode_fixed_list, MAX_ITEMS_IN_LIST},
    types::{CBuilder, GFp},
    utils::{Endianness, PackerTarget},
    D, F,
};
use plonky2::{
    iop::{target::Target, witness::PartialWitness},
    plonk::proof::ProofWithPublicInputsTarget,
};
use plonky2_crypto::u32::arithmetic_u32::U32Target;
use recursion_framework::circuit_builder::CircuitLogicWires;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BranchWires<const NODE_LEN: usize>
where
    [(); PAD_LEN(NODE_LEN)]:,
{
    node: VectorWire<Target, { PAD_LEN(NODE_LEN) }>,
    root: KeccakWires<{ PAD_LEN(NODE_LEN) }>,
}

#[derive(Clone, Debug)]
pub struct BranchCircuit<const NODE_LEN: usize> {
    pub(crate) node: Vec<u8>,
}

impl<const NODE_LEN: usize> BranchCircuit<NODE_LEN>
where
    [(); PAD_LEN(NODE_LEN)]:,
{
    /// Build the branch circuit. Only have one single child proof, since we prove one contract at a time.
    pub fn build(b: &mut CBuilder, child_proof: PublicInputs<Target>) -> BranchWires<NODE_LEN> {
        let zero = b.zero();
        let ttrue = b._true();

        // Build the node and ensure it only includes bytes.
        let node = VectorWire::<Target, { PAD_LEN(NODE_LEN) }>::new(b);
        node.assert_bytes(b);

        // Expose the keccak root of this subtree starting at this node.
        let root = KeccakCircuit::<{ PAD_LEN(NODE_LEN) }>::hash_vector(b, &node);

        // We already decode the RLP headers here since we need it to verify the
        // validity of the hash exposed by the proofs.
        let headers = decode_fixed_list::<_, D, MAX_ITEMS_IN_LIST>(b, &node.arr.arr, zero);

        let (new_mpt_key, hash, is_valid, _) = MPTCircuit::<1, NODE_LEN>::advance_key_branch(
            b,
            &node.arr,
            &child_proof.mpt_key(),
            &headers,
        );

        // We always enforce it's a branch node, i.e. that it has 17 entries.
        b.connect(is_valid.target, ttrue.target);

        // We check the hash is the one exposed by the proof, first convert
        // the extracted hash to packed one to compare.
        let packed_hash = Array::<U32Target, PACKED_HASH_LEN> {
            arr: hash.arr.pack(b, Endianness::Little).try_into().unwrap(),
        };
        let child_hash = child_proof.root_hash();
        packed_hash.enforce_equal(b, &child_hash);

        // Register the public inputs.
        let PublicInputs { dm, s, .. } = child_proof;
        let h = &root.output_array.to_targets().arr;
        let k = &new_mpt_key.key.arr;
        let t = &new_mpt_key.pointer;
        PublicInputs { h, dm, k, t, s }.register(b);

        BranchWires { node, root }
    }

    fn assign(&self, pw: &mut PartialWitness<GFp>, wires: &BranchWires<NODE_LEN>) {
        let node = Vector::<u8, { PAD_LEN(NODE_LEN) }>::from_vec(&self.node).unwrap();
        wires.node.assign(pw, &node);

        KeccakCircuit::<{ PAD_LEN(NODE_LEN) }>::assign(
            pw,
            &wires.root,
            &InputData::Assigned(&node),
        );
    }
}

/// Num of children = 1
impl<const NODE_LEN: usize> CircuitLogicWires<F, D, 1> for BranchWires<NODE_LEN>
where
    [(); PAD_LEN(NODE_LEN)]:,
{
    type CircuitBuilderParams = ();

    type Inputs = BranchCircuit<NODE_LEN>;

    const NUM_PUBLIC_INPUTS: usize = PublicInputs::<F>::TOTAL_LEN;

    fn circuit_logic(
        builder: &mut CBuilder,
        verified_proofs: [&ProofWithPublicInputsTarget<D>; 1],
        _builder_parameters: Self::CircuitBuilderParams,
    ) -> Self {
        let inputs = PublicInputs::from_slice(&verified_proofs[0].public_inputs);
        BranchCircuit::build(builder, inputs)
    }

    fn assign_input(&self, inputs: Self::Inputs, pw: &mut PartialWitness<GFp>) -> Result<()> {
        inputs.assign(pw, self);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use eth_trie::{EthTrie, MemoryDB, Trie};
    use mp2_common::{
        array::ToField,
        group_hashing::map_to_curve_point,
        keccak::PACKED_HASH_LEN,
        mpt_sequential::{mpt_key_ptr, utils::bytes_to_nibbles},
        types::PACKED_ADDRESS_LEN,
        utils::{keccak256, Endianness, Packer, ToFields},
        C,
    };
    use mp2_test::{
        circuit::{run_circuit, UserCircuit},
        utils::random_vector,
    };
    use plonky2::{field::types::Field, iop::witness::WitnessWrite};
    use rand::{thread_rng, Rng};
    use std::sync::Arc;

    #[derive(Clone, Debug)]
    struct TestBranchCircuit<'a, const NODE_LEN: usize> {
        c: BranchCircuit<NODE_LEN>,
        child_pi: &'a [F],
    }

    impl<'a, const NODE_LEN: usize> UserCircuit<F, D> for TestBranchCircuit<'a, NODE_LEN>
    where
        [(); PAD_LEN(NODE_LEN)]:,
    {
        // Branch node wires + child public inputs
        type Wires = (BranchWires<NODE_LEN>, Vec<Target>);

        fn build(b: &mut CBuilder) -> Self::Wires {
            let child_pi = b.add_virtual_targets(PublicInputs::<Target>::TOTAL_LEN);
            let branch_wires = BranchCircuit::build(b, PublicInputs::from_slice(&child_pi));

            (branch_wires, child_pi)
        }

        fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
            self.c.assign(pw, &wires.0);

            assert_eq!(wires.1.len(), PublicInputs::<Target>::TOTAL_LEN);
            pw.set_target_arr(&wires.1, self.child_pi);
        }
    }

    #[test]
    fn test_contract_extraction_branch_circuit() {
        const NODE_LEN: usize = 100;

        // We need to create a trie that for sure contains a branch node:
        // We insert two values under two keys which only differ by their last nibble/byte
        // Normally, the trie should look like:
        // root = extension node
        // branch = point of different between the two keys
        // two leaves (we only prove one at a time)
        let memdb = Arc::new(MemoryDB::new(true));
        let mut trie = EthTrie::new(Arc::clone(&memdb));
        let key1 = random_vector::<u8>(32);
        let mut key2 = key1.clone();
        key2[31] = key2[31]
            .checked_sub(thread_rng().gen_range(1..10))
            .unwrap_or_default();
        assert!(key1 != key2);
        let value1 = random_vector(32);
        let value2 = random_vector(32);
        trie.insert(&key1, &value1).unwrap();
        trie.insert(&key2, &value2).unwrap();
        trie.root_hash().unwrap();
        let nodes = trie.get_proof(&key2).unwrap();
        assert_eq!(nodes.len(), 3);
        let leaf = nodes.last().unwrap();
        let tuple: Vec<Vec<u8>> = rlp::decode_list(leaf);
        let ptr = mpt_key_ptr(&tuple[0]);
        let branch = nodes[1].clone();
        assert!(rlp::decode_list::<Vec<u8>>(&branch).len() == 17);

        // Prepare the public inputs for the branch node circuit.
        let h = &keccak256(leaf).pack(Endianness::Little).to_fields();
        let dm = &map_to_curve_point(&random_vector::<u32>(PACKED_ADDRESS_LEN).to_fields())
            .to_weierstrass()
            .to_fields();
        let k = &bytes_to_nibbles(&key2).to_fields();
        let t = &ptr.to_field();
        let s = &random_vector::<u32>(PACKED_HASH_LEN).to_fields();
        let child_pi = PublicInputs { h, dm, k, t, s };

        let c = BranchCircuit::<NODE_LEN> {
            node: branch.clone(),
        };
        let test_circuit = TestBranchCircuit {
            c,
            child_pi: &child_pi.to_vec(),
        };
        let proof = run_circuit::<F, D, C, _>(test_circuit);
        let pi = PublicInputs::<F>::from_slice(&proof.public_inputs);

        // Check packed block hash
        {
            let hash = keccak256(&branch).pack(Endianness::Little).to_fields();
            assert_eq!(pi.h, hash);
        }
        // Check metadata digest
        assert_eq!(pi.dm, child_pi.dm);
        // Check MPT key and pointer
        {
            assert_eq!(pi.k, child_pi.k);

            // -1 because branch circuit exposes the new pointer.
            assert_eq!(*pi.t, *child_pi.t - F::ONE);
        }
        // Check packed storage root hash
        assert_eq!(pi.s, child_pi.s);
    }
}
