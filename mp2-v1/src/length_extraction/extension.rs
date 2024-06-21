//! Database length extraction circuits for extension node

use core::array;

use mp2_common::{
    array::{Targetable, Vector, VectorWire},
    keccak::{InputData, KeccakCircuit, KeccakWires, HASH_LEN, PACKED_HASH_LEN},
    mpt_sequential::MPTLeafOrExtensionNode,
    public_inputs::PublicInputCommon,
    types::{CBuilder, GFp},
    D,
};
use plonky2::{
    iop::{target::Target, witness::PartialWitness},
    plonk::proof::ProofWithPublicInputsTarget,
};
use recursion_framework::circuit_builder::CircuitLogicWires;
use serde::{Deserialize, Serialize};

use crate::{MAX_EXTENSION_NODE_LEN, MAX_EXTENSION_NODE_LEN_PADDED};

use super::PublicInputs;

/// The wires structure for the extension extension extraction.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExtensionLengthWires {
    node: VectorWire<Target, MAX_EXTENSION_NODE_LEN_PADDED>,
    root: KeccakWires<MAX_EXTENSION_NODE_LEN_PADDED>,
}

impl CircuitLogicWires<GFp, D, 1> for ExtensionLengthWires {
    type CircuitBuilderParams = ();
    type Inputs = ExtensionLengthCircuit;
    const NUM_PUBLIC_INPUTS: usize = PublicInputs::<GFp>::TOTAL_LEN;

    fn circuit_logic(
        cb: &mut CBuilder,
        verified_proofs: [&ProofWithPublicInputsTarget<D>; 1],
        _builder_parameters: Self::CircuitBuilderParams,
    ) -> Self {
        let pis = &verified_proofs[0].public_inputs[..PublicInputs::<GFp>::TOTAL_LEN];
        let pis = PublicInputs::from_slice(pis);

        ExtensionLengthCircuit::build(cb, pis)
    }

    fn assign_input(
        &self,
        inputs: Self::Inputs,
        pw: &mut PartialWitness<GFp>,
    ) -> anyhow::Result<()> {
        inputs.assign(pw, self);
        Ok(())
    }
}

/// The circuit definition for the extension length extraction.
#[derive(Clone, Debug, Serialize, Deserialize)]
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
            .zip(child_proof.root_hash_raw().iter())
            .for_each(|(v, p)| cb.connect(v.to_target(), *p));

        let PublicInputs { dm, k, n, .. } = child_proof;
        let t = &mpt.key.pointer;
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
        let node = Vector::<u8, MAX_EXTENSION_NODE_LEN_PADDED>::from_vec(&self.node).unwrap();

        wires.node.assign(pw, &node);

        KeccakCircuit::<MAX_EXTENSION_NODE_LEN_PADDED>::assign(
            pw,
            &wires.root,
            &InputData::Assigned(&node),
        );
    }
}

#[cfg(test)]
pub mod tests {
    use std::sync::Arc;

    use eth_trie::{EthTrie, MemoryDB, Nibbles, Trie};
    use mp2_common::{
        eth::StorageSlot,
        group_hashing::map_to_curve_point,
        rlp::MAX_KEY_NIBBLE_LEN,
        types::{CBuilder, GFp},
        utils::{convert_u8_to_u32_slice, keccak256},
        D,
    };
    use mp2_test::circuit::{run_circuit, UserCircuit};
    use plonky2::{
        field::types::Field,
        iop::{
            target::Target,
            witness::{PartialWitness, WitnessWrite},
        },
        plonk::config::PoseidonGoldilocksConfig,
    };
    use rand::{rngs::StdRng, Rng, RngCore, SeedableRng};

    use crate::length_extraction::{
        branch::tests::BranchTestCircuit, BranchLengthCircuit, LeafLengthCircuit, PublicInputs,
    };

    use super::{ExtensionLengthCircuit, ExtensionLengthWires};

    #[test]
    fn prove_and_verify_length_extraction_extension_circuit() {
        let rng = &mut StdRng::seed_from_u64(0xffff);
        let memdb = Arc::new(MemoryDB::new(true));
        let mut trie = EthTrie::new(Arc::clone(&memdb));

        let length_slot = rng.gen::<u8>();
        let variable_slot = rng.gen::<u8>();
        let storage_slot = StorageSlot::Simple(length_slot as usize);

        let key1 = storage_slot.mpt_key_vec();
        let mut key2 = storage_slot.mpt_key_vec();

        while key2[31] == key1[31] {
            key2[31] = rng.gen();
        }

        let value1 = rng.next_u32();
        let value2 = rng.next_u32();

        let mut bytes1 = rlp::encode(&value1);
        let mut bytes2 = rlp::encode(&value2);

        // padding is required for a consistent EthTrie path
        // check https://github.com/Lagrange-Labs/mapreduce-plonky2/pull/212
        bytes1.resize(32, 0);
        bytes2.resize(32, 0);

        trie.insert(&key1, &bytes1).unwrap();
        trie.insert(&key2, &bytes2).unwrap();
        trie.root_hash().unwrap();

        let mut proof = trie.get_proof(&key1).unwrap();

        let node = proof.first().unwrap().clone();
        let root_rlp: Vec<Vec<u8>> = rlp::decode_list(&node);
        assert_eq!(root_rlp.len(), 2);

        let mut key = Vec::with_capacity(64);
        for k in key1 {
            key.push(GFp::from_canonical_u8(k >> 4));
            key.push(GFp::from_canonical_u8(k & 0b00001111));
        }

        let length = GFp::from_canonical_u32(value1);
        let dm = map_to_curve_point(&[
            GFp::from_canonical_u8(length_slot),
            GFp::from_canonical_u8(variable_slot),
        ])
        .to_weierstrass();

        // Leaf extraction

        let node = proof.pop().unwrap();
        let leaf_circuit = LeafLengthCircuit::new(length_slot, node.clone(), variable_slot);
        let leaf_proof = run_circuit::<_, D, PoseidonGoldilocksConfig, _>(leaf_circuit);
        let leaf_pi = PublicInputs::<GFp>::from_slice(&leaf_proof.public_inputs);

        let root: Vec<_> = convert_u8_to_u32_slice(&keccak256(&node))
            .into_iter()
            .map(GFp::from_canonical_u32)
            .collect();

        let rlp_headers: Vec<Vec<u8>> = rlp::decode_list(&node);
        let rlp_nibbles = Nibbles::from_compact(&rlp_headers[0]);
        let t = GFp::from_canonical_usize(MAX_KEY_NIBBLE_LEN - 1)
            - GFp::from_canonical_usize(rlp_nibbles.nibbles().len());

        assert_eq!(leaf_pi.length(), &length);
        assert_eq!(leaf_pi.root_hash_raw(), &root);
        assert_eq!(leaf_pi.mpt_key(), &key);
        assert_eq!(leaf_pi.metadata_point(), dm);
        assert_eq!(leaf_pi.mpt_key_pointer(), &t);

        // Branch extraction

        let node = proof.pop().unwrap();
        let branch_circuit = BranchTestCircuit {
            base: BranchLengthCircuit::new(node.clone()),
            pi: &leaf_pi.to_vec(),
        };
        let branch_proof = run_circuit::<_, D, PoseidonGoldilocksConfig, _>(branch_circuit);
        let branch_pi = PublicInputs::<GFp>::from_slice(&branch_proof.public_inputs);

        let t = t - GFp::ONE;
        let root: Vec<_> = convert_u8_to_u32_slice(&keccak256(&node))
            .into_iter()
            .map(GFp::from_canonical_u32)
            .collect();

        assert_eq!(branch_pi.length(), &length);
        assert_eq!(branch_pi.root_hash_raw(), &root);
        assert_eq!(branch_pi.mpt_key(), &key);
        assert_eq!(branch_pi.metadata_point(), dm);
        assert_eq!(branch_pi.mpt_key_pointer(), &t);

        // Extension extraction

        let node = proof.pop().unwrap();
        let ext_circuit = ExtensionTestCircuit {
            base: ExtensionLengthCircuit::new(node.clone()),
            pi: &branch_pi.to_vec(),
        };
        let ext_proof = run_circuit::<_, D, PoseidonGoldilocksConfig, _>(ext_circuit);
        let ext_pi = PublicInputs::<GFp>::from_slice(&ext_proof.public_inputs);

        let t = GFp::ZERO - GFp::ONE;
        let root: Vec<_> = convert_u8_to_u32_slice(&keccak256(&node))
            .into_iter()
            .map(GFp::from_canonical_u32)
            .collect();

        assert_eq!(ext_pi.length(), &length);
        assert_eq!(ext_pi.root_hash_raw(), &root);
        assert_eq!(ext_pi.mpt_key(), &key);
        assert_eq!(ext_pi.metadata_point(), dm);
        assert_eq!(ext_pi.mpt_key_pointer(), &t);
    }

    #[derive(Debug, Clone)]
    pub struct ExtensionTestWires {
        pub base: ExtensionLengthWires,
        pub pi: Vec<Target>,
    }

    #[derive(Debug, Clone)]
    pub struct ExtensionTestCircuit<'a> {
        pub base: ExtensionLengthCircuit,
        pub pi: &'a [GFp],
    }

    impl<'a> UserCircuit<GFp, D> for ExtensionTestCircuit<'a> {
        type Wires = ExtensionTestWires;

        fn build(cb: &mut CBuilder) -> Self::Wires {
            let pi = cb.add_virtual_targets(PublicInputs::<Target>::TOTAL_LEN);
            let base = ExtensionLengthCircuit::build(cb, PublicInputs::from_slice(&pi));

            ExtensionTestWires { base, pi }
        }

        fn prove(&self, pw: &mut PartialWitness<GFp>, wires: &Self::Wires) {
            pw.set_target_arr(&wires.pi, self.pi);
            self.base.assign(pw, &wires.base);
        }
    }
}
