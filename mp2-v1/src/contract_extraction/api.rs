//! Contract extraction APIs

use super::{
    branch::{self, BranchCircuit},
    extension::{ExtensionCircuit, ExtensionWires},
    leaf::{self, LeafCircuit},
    public_inputs::PublicInputs,
};
use crate::{api::InputNode, C, D, F, MAX_BRANCH_NODE_LEN, MAX_LEAF_NODE_LEN};
use alloy::primitives::Address;
use anyhow::Result;
use mp2_common::{
    default_config,
    proof::{ProofInputSerialized, ProofWithVK},
    utils::find_index_subvector,
};
use recursion_framework::{
    circuit_builder::{CircuitWithUniversalVerifier, CircuitWithUniversalVerifierBuilder},
    framework::{RecursiveCircuitInfo, RecursiveCircuits},
};
use serde::{Deserialize, Serialize};

type LeafWires = leaf::LeafWires<MAX_LEAF_NODE_LEN>;
type BranchWires = branch::BranchWires<MAX_BRANCH_NODE_LEN>;

type LeafInput = LeafCircuit<MAX_LEAF_NODE_LEN>;
type ChildInput = ProofInputSerialized<InputNode>;

/// CircuitInput is a wrapper around the different specialized circuits that can
/// be used to prove a MPT node recursively.
#[derive(Serialize, Deserialize)]
pub enum CircuitInput {
    Leaf(LeafInput),
    Extension(ChildInput),
    Branch(ChildInput),
}

impl CircuitInput {
    /// Create a circuit input for proving a MPT leaf node.
    pub fn new_leaf(node: Vec<u8>, storage_root: &[u8], contract_address: Address) -> Self {
        let storage_root_offset = find_index_subvector(&node, storage_root)
            .expect("Failed to find the storage root in the state leaf node");

        CircuitInput::Leaf(LeafCircuit {
            contract_address,
            storage_root_offset,
            node,
        })
    }

    /// Create a circuit input for proving an extension MPT node.
    pub fn new_extension(node: Vec<u8>, child_proof: Vec<u8>) -> Self {
        CircuitInput::Extension(new_child_input(node, child_proof))
    }

    /// Create a circuit input for proving a branch MPT node.
    pub fn new_branch(node: Vec<u8>, child_proof: Vec<u8>) -> Self {
        CircuitInput::Branch(new_child_input(node, child_proof))
    }
}

/// Create a new child input.
fn new_child_input(node: Vec<u8>, child_proof: Vec<u8>) -> ChildInput {
    ChildInput {
        input: InputNode { node },
        serialized_child_proofs: vec![child_proof],
    }
}

/// Main struct holding the different circuit parameters for each of the MPT
/// circuits defined here.
#[derive(Eq, PartialEq, Serialize, Deserialize)]
pub struct PublicParameters {
    leaf: CircuitWithUniversalVerifier<F, C, D, 0, LeafWires>,
    extension: CircuitWithUniversalVerifier<F, C, D, 1, ExtensionWires>,
    branch: CircuitWithUniversalVerifier<F, C, D, 1, BranchWires>,
    set: RecursiveCircuits<F, C, D>,
}

/// Public API employed to build the MPT circuits, which are returned in
/// serialized form.
pub fn build_circuits_params() -> PublicParameters {
    PublicParameters::build()
}

/// Public API employed to generate a proof for the circuit specified by
/// `CircuitInput`, employing the `circuit_params` generated with the
/// `build_circuits_params` API.
pub fn generate_proof(params: &PublicParameters, input: CircuitInput) -> Result<Vec<u8>> {
    params.generate_proof(input)?.serialize()
}

const NUM_IO: usize = PublicInputs::<F>::TOTAL_LEN;

/// Number of circuits in the set
/// 1 branch circuit + 1 extension + 1 leaf
const CIRCUIT_SET_SIZE: usize = 3;

impl PublicParameters {
    /// Generates the circuit parameters for the MPT circuits.
    fn build() -> Self {
        let config = default_config();
        let circuit_builder =
            CircuitWithUniversalVerifierBuilder::<F, D, NUM_IO>::new::<C>(config, CIRCUIT_SET_SIZE);

        let leaf = circuit_builder.build_circuit(());
        let extension = circuit_builder.build_circuit(());
        let branch = circuit_builder.build_circuit(());

        let set = RecursiveCircuits::new_from_circuit_digests(vec![
            leaf.get_verifier_data().circuit_digest,
            extension.get_verifier_data().circuit_digest,
            branch.get_verifier_data().circuit_digest,
        ]);

        PublicParameters {
            leaf,
            extension,
            branch,
            set,
        }
    }

    fn generate_proof(&self, circuit_type: CircuitInput) -> Result<ProofWithVK> {
        let set = &self.set;

        match circuit_type {
            CircuitInput::Leaf(leaf) => set
                .generate_proof(&self.leaf, [], [], leaf)
                .map(|p| (p, self.leaf.get_verifier_data().clone()).into()),
            CircuitInput::Extension(ext) => {
                let mut child_proofs = ext.get_child_proofs()?;
                assert_eq!(
                    child_proofs.len(),
                    1,
                    "Must have one child proof in this extension node input"
                );
                let (child_proof, child_vk) = child_proofs.pop().unwrap().into();
                set.generate_proof(
                    &self.extension,
                    [child_proof],
                    [&child_vk],
                    ExtensionCircuit {
                        node: ext.input.node,
                    },
                )
                .map(|p| (p, self.extension.get_verifier_data().clone()).into())
            }
            CircuitInput::Branch(branch) => {
                let mut child_proofs = branch.get_child_proofs()?;
                assert_eq!(
                    child_proofs.len(),
                    1,
                    "Must have one child proof in this branch node input"
                );
                let (child_proof, child_vk) = child_proofs.pop().unwrap().into();
                set.generate_proof(
                    &self.branch,
                    [child_proof],
                    [&child_vk],
                    BranchCircuit {
                        node: branch.input.node,
                    },
                )
                .map(|p| (p, self.branch.get_verifier_data().clone()).into())
            }
        }
    }

    pub fn get_circuit_set(&self) -> &RecursiveCircuits<F, C, D> {
        &self.set
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contract_extraction::compute_metadata_digest;
    use alloy::{
        eips::BlockNumberOrTag,
        providers::{Provider, ProviderBuilder},
    };
    use eth_trie::Nibbles;
    use mp2_common::{
        eth::ProofQuery,
        mpt_sequential::{
            mpt_key_ptr, utils::bytes_to_nibbles, MPT_BRANCH_RLP_SIZE, MPT_EXTENSION_RLP_SIZE,
        },
        utils::{keccak256, Endianness, Packer, ToFields},
    };
    use mp2_test::eth::get_mainnet_url;
    use plonky2::field::types::Field;
    use rlp::{Prototype, Rlp};
    use serial_test::serial;
    use std::str::FromStr;

    /// Pudgy Penguins contract address for testing
    const PUDGY_PENGUINS_ADDRESS: &str = "0xbd3531da5cf5857e7cfaa92426877b022e612cf8";

    #[tokio::test]
    #[serial]
    async fn test_contract_extraction_api() -> Result<()> {
        // Query the MPT proof from RPC.
        let rpc_url = get_mainnet_url();
        let provider = ProviderBuilder::new().connect_http(rpc_url.parse().unwrap());
        let contract_address = Address::from_str(PUDGY_PENGUINS_ADDRESS)?;
        let query = ProofQuery::new_simple_slot(contract_address, 0);
        let res = query
            .query_mpt_proof(provider.root(), BlockNumberOrTag::Latest)
            .await?;

        // Get the storage root, it should be same with `keccak(storage_root)`,
        // but we don't prove the storage root here.
        let storage_root = res.storage_hash.0;

        // Get the state nodes, and reverse to get the sequence from leaf to root.
        let mut nodes = res.account_proof;
        nodes.reverse();

        // Build the parameters.
        let params = build_circuits_params();

        // Generate a proof from leaf node.
        let node = nodes[0].to_vec();
        let input = CircuitInput::new_leaf(node.clone(), &storage_root, contract_address);
        let leaf_proof = generate_proof(&params, input)?;

        // Check the leaf public inputs.
        let pi = ProofWithVK::deserialize(&leaf_proof)?.proof.public_inputs;
        let pi = PublicInputs::from_slice(&pi);
        // Check packed block hash
        {
            let exp_block_hash = keccak256(&node).pack(Endianness::Little).to_fields();
            assert_eq!(pi.h, exp_block_hash);
        }
        // Check metadata digest
        {
            let exp_digest = compute_metadata_digest(&contract_address);
            assert_eq!(pi.metadata_point(), exp_digest.to_weierstrass());
        }
        // Check MPT key and pointer
        {
            let key = pi.k;
            let ptr = pi.t;

            let mpt_key = keccak256(contract_address.as_slice());
            let exp_key: Vec<_> = bytes_to_nibbles(&mpt_key)
                .into_iter()
                .map(F::from_canonical_u8)
                .collect();
            assert_eq!(key, exp_key);

            let leaf_key: Vec<Vec<u8>> = rlp::decode_list(&node);
            let exp_ptr = F::from_canonical_usize(mpt_key_ptr(&leaf_key[0]));
            assert_eq!(exp_ptr, *ptr);
        }
        // Check packed storage root hash
        {
            let exp_storage_root_hash: Vec<_> = storage_root.pack(Endianness::Little).to_fields();
            assert_eq!(pi.s, exp_storage_root_hash);
        }

        // We only prove 2 branch or extension nodes here to make unit test fast,
        // should prove the all nodes in the integration test. We may miss to
        // test proving branch or extension node here, but it should be tested in
        // integration test.
        let max_test_len = nodes.len().min(3);
        let mut child_proof = leaf_proof;
        for node in &nodes[1..max_test_len] {
            let rlp = Rlp::new(node);
            match rlp.prototype().unwrap() {
                Prototype::List(MPT_EXTENSION_RLP_SIZE) => {
                    let input = CircuitInput::new_extension(node.to_vec(), child_proof.clone());
                    let ext_proof = generate_proof(&params, input)?;

                    // Check the extension public inputs.
                    let pi = ProofWithVK::deserialize(&ext_proof)?.proof.public_inputs;
                    let pi = PublicInputs::from_slice(&pi);
                    let child_pi = ProofWithVK::deserialize(&child_proof)?.proof.public_inputs;
                    let child_pi = PublicInputs::from_slice(&child_pi);
                    // Check packed block hash
                    {
                        let hash = keccak256(node).pack(Endianness::Little).to_fields();
                        assert_eq!(pi.h, hash);
                    }
                    // Check metadata digest
                    assert_eq!(pi.dm, child_pi.dm);
                    // Check MPT key and pointer
                    {
                        assert_eq!(pi.k, child_pi.k);

                        // child pointer - partial key length
                        let keys: Vec<Vec<u8>> = rlp::decode_list(node);
                        let nibbles = Nibbles::from_compact(&keys[0]);
                        let exp_ptr =
                            *child_pi.t - F::from_canonical_usize(nibbles.nibbles().len());
                        assert_eq!(*pi.t, exp_ptr);
                    }
                    // Check packed storage root hash
                    assert_eq!(pi.s, child_pi.s);

                    // Set the child proof.
                    child_proof = ext_proof;
                }
                Prototype::List(MPT_BRANCH_RLP_SIZE) => {
                    let input = CircuitInput::new_branch(node.to_vec(), child_proof.clone());
                    let branch_proof = generate_proof(&params, input)?;

                    // Check the branch public inputs.
                    let pi = ProofWithVK::deserialize(&branch_proof)?.proof.public_inputs;
                    let pi = PublicInputs::from_slice(&pi);
                    let child_pi = ProofWithVK::deserialize(&child_proof)?.proof.public_inputs;
                    let child_pi = PublicInputs::from_slice(&child_pi);
                    // Check packed block hash
                    {
                        let hash = keccak256(node).pack(Endianness::Little).to_fields();
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

                    // Set the child proof.
                    child_proof = branch_proof;
                }
                _ => panic!("Invalid RLP size for the state proof"),
            }
        }

        Ok(())
    }
}
