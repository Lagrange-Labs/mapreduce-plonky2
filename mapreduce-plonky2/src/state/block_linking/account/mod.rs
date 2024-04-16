use ethers::types::H160;
use plonky2::{
    iop::target::Target,
    plonk::{circuit_data::VerifierCircuitData, proof::ProofWithPublicInputs},
};
use recursion_framework::{
    circuit_builder::{CircuitWithUniversalVerifier, CircuitWithUniversalVerifierBuilder},
    framework::{prepare_recursive_circuit_for_circuit_set, RecursiveCircuits},
};
use serde::{Deserialize, Serialize};

use crate::{
    api::{default_config, ProofWithVK},
    rlp::MAX_ITEMS_IN_LIST,
    storage::{MAX_BRANCH_NODE_LEN, MAX_LEAF_NODE_LEN},
};

use self::{
    branch::{BranchCircuit, BranchWires as BranchNodeWires},
    extension::{ExtensionCircuit, ExtensionWires},
    leaf::{LeafInput, LeafRecursiveWires},
    public_inputs::PublicInputs,
};
use anyhow::{Error, Result};

mod branch;
mod extension;
mod leaf;
pub(crate) mod public_inputs;

type F = crate::api::F;
type C = crate::api::C;
const D: usize = crate::api::D;

type LeafWires = LeafRecursiveWires<MAX_LEAF_NODE_LEN>;
type BranchWires = BranchNodeWires<MAX_BRANCH_NODE_LEN>;

#[derive(Serialize, Deserialize)]
pub(crate) struct AccountCircuit {
    leaf: CircuitWithUniversalVerifier<F, C, D, 0, LeafWires>,
    extension: CircuitWithUniversalVerifier<F, C, D, 1, ExtensionWires>,
    branch: CircuitWithUniversalVerifier<F, C, D, 1, BranchWires>,
    circuit_set: RecursiveCircuits<F, C, D>,
}

pub(crate) struct AccountInputs {
    /// The contract address
    contract_address: H160,
    /// set of nodes in the MPT path
    nodes: Vec<Vec<u8>>,
}

impl AccountInputs {
    pub(crate) fn new(contract_address: H160, nodes: Vec<Vec<u8>>) -> Self {
        Self {
            contract_address,
            nodes,
        }
    }
}

const NUM_IO: usize = PublicInputs::<Target>::TOTAL_LEN;

impl AccountCircuit {
    pub(crate) fn build(storage_circuit_vk: VerifierCircuitData<F, C, D>) -> Self {
        let builder =
            CircuitWithUniversalVerifierBuilder::<F, D, NUM_IO>::new::<C>(default_config(), 3);
        let leaf = builder.build_circuit(storage_circuit_vk);
        let extension = builder.build_circuit(());
        let branch = builder.build_circuit(());

        let circuits = vec![
            prepare_recursive_circuit_for_circuit_set(&leaf),
            prepare_recursive_circuit_for_circuit_set(&extension),
            prepare_recursive_circuit_for_circuit_set(&branch),
        ];

        let circuit_set = RecursiveCircuits::new(circuits);

        Self {
            leaf,
            extension,
            branch,
            circuit_set,
        }
    }

    pub(crate) fn generate_proof(
        &self,
        storage_proof: &ProofWithPublicInputs<F, C, D>,
        inputs: &AccountInputs,
    ) -> Result<ProofWithVK> {
        let leaf_inputs = LeafInput::new(
            inputs.contract_address,
            inputs.nodes[0].clone(),
            storage_proof.clone(),
        )?;
        let leaf_proof = self
            .circuit_set
            .generate_proof(&self.leaf, [], [], leaf_inputs)?;
        let leaf_proof: ProofWithVK =
            (leaf_proof, self.leaf.circuit_data().verifier_only.clone()).into();
        inputs
            .nodes
            .clone()
            .into_iter()
            .skip(1)
            .fold(Ok(leaf_proof), |acc, node| {
                let (input_proof, input_vk) = acc?.into();
                match rlp::decode_list::<Vec<u8>>(node.as_slice()).len() {
                    2 => {
                        // It is an extension node
                        let proof = self.circuit_set.generate_proof(
                            &self.extension,
                            [input_proof],
                            [&input_vk],
                            ExtensionCircuit::new(node),
                        )?;
                        Ok((proof, self.extension.circuit_data().verifier_only.clone()).into())
                    }
                    MAX_ITEMS_IN_LIST => {
                        // it is a branch node
                        let proof = self.circuit_set.generate_proof(
                            &self.branch,
                            [input_proof],
                            [&input_vk],
                            BranchCircuit::new(node),
                        )?;
                        Ok((proof, self.branch.circuit_data().verifier_only.clone()).into())
                    }
                    n => Err(Error::msg(format!(
                        "invalid number of items found in MPT node: {}",
                        n
                    )))?,
                }
            })
    }

    pub(crate) fn get_account_circuit_set(&self) -> &RecursiveCircuits<F, C, D> {
        &self.circuit_set
    }
}

#[cfg(test)]
mod tests {
    use std::{str::FromStr, sync::Arc};

    use crate::{
        api::tests::TestDummyCircuit,
        eth::ProofQuery,
        storage::PublicInputs as StorageInputs,
        utils::{convert_u8_slice_to_u32_fields, keccak256},
    };
    use eth_trie::{EthTrie, MemoryDB, Trie};
    use ethers::{
        providers::{Http, Middleware, Provider},
        types::{Address, BlockId, BlockNumber, H256},
    };
    use mp2_test::{log::init_logging, utils::random_vector};
    use plonky2::field::types::Field;
    use serial_test::serial;

    use super::*;

    const NUM_STORAGE_INPUTS: usize = StorageInputs::<Target>::TOTAL_LEN;

    #[tokio::test]
    #[serial]
    async fn test_recursive_account_inputs_on_sepolia() -> Result<()> {
        #[cfg(feature = "ci")]
        let url = env::var("CI_SEPOLIA").expect("CI_SEPOLIA env var not set");
        #[cfg(not(feature = "ci"))]
        let url = "https://ethereum-sepolia-rpc.publicnode.com";

        let contract_address = "0xd6a2bFb7f76cAa64Dad0d13Ed8A9EFB73398F39E";

        test_account_inputs(url, contract_address).await
    }

    #[tokio::test]
    #[serial]
    async fn test_recursive_account_inputs_on_mainnet() -> Result<()> {
        #[cfg(feature = "ci")]
        let url = env::var("CI_ETH").expect("CI_ETH env var not set");
        #[cfg(not(feature = "ci"))]
        let url = "https://eth.llamarpc.com";
        // TODO: this Mainnet contract address only works with state proof
        let contract_address = "0x105dD0eF26b92a3698FD5AaaF688577B9Cafd970";

        test_account_inputs(url, contract_address).await
    }
    async fn test_account_inputs(url: &str, contract_address: &str) -> Result<()> {
        init_logging();

        let contract_address = Address::from_str(contract_address)?;

        let provider =
            Provider::<Http>::try_from(url).expect("could not instantiate HTTP Provider");

        let block_number = provider.get_block_number().await?;
        // Simple storage test
        let query = ProofQuery::new_simple_slot(contract_address, 0);
        let _ = provider
            .get_block_with_txs(BlockId::Number(BlockNumber::Number(block_number)))
            .await?
            .expect("should have been a block");
        let res = query
            .query_mpt_proof(
                &provider,
                Some(BlockId::Number(BlockNumber::Number(block_number))),
            )
            .await?;
        let account_proof = res
            .account_proof
            .iter()
            .rev()
            .map(|b| b.to_vec())
            .collect::<Vec<Vec<u8>>>();
        let state_root = keccak256(&account_proof.last().unwrap());
        let key = keccak256(&contract_address.as_bytes());
        let db = MemoryDB::new(true);
        let trie = EthTrie::new(Arc::new(db));
        let is_proof_valid = trie
            .verify_proof(H256::from_slice(&state_root), &key, account_proof.clone())
            .expect("proof should be valid");
        assert!(is_proof_valid.is_some());
        let storage_root = keccak256(&res.storage_proof[0].proof[0].clone());
        // manually construct random proofs inputs with specific contract address and storage root
        // as these are the two informations are used from the proof inside this circuit
        let mut storage_pi: Vec<_> = random_vector::<u32>(StorageInputs::<F>::TOTAL_LEN)
            .into_iter()
            .map(F::from_canonical_u32)
            .collect();
        storage_pi[StorageInputs::<F>::C1_IDX..StorageInputs::<F>::C2_IDX]
            .copy_from_slice(&convert_u8_slice_to_u32_fields(&storage_root));

        let dummy_storage_circuit = TestDummyCircuit::<NUM_STORAGE_INPUTS>::build();

        let storage_proof = dummy_storage_circuit.generate_proof(storage_pi.try_into().unwrap())?;

        let account_circuit =
            AccountCircuit::build(dummy_storage_circuit.circuit_data().verifier_data());

        account_circuit
            .generate_proof(
                &storage_proof,
                &AccountInputs {
                    contract_address,
                    nodes: account_proof,
                },
            )
            .unwrap();
        Ok(())
    }
}
