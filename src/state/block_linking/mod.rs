//! Block-linking circuit implemention used to prove the pre-computed state root
//! proof is linked to the specific block header.

mod account_inputs;
mod block_inputs;
mod public_inputs;
mod storage_proof;

use crate::{mpt_sequential::PAD_LEN, utils::keccak256};
use account_inputs::{AccountInputs, AccountInputsWires};
use anyhow::Result;
use block_inputs::{BlockInputs, BlockInputsWires};
use ethers::types::{Block, H256};
use plonky2::{
    field::extension::Extendable, hash::hash_types::RichField, iop::witness::PartialWitness,
    plonk::circuit_builder::CircuitBuilder,
};
use public_inputs::PublicInputs;
use storage_proof::{StorageInputs, StorageInputsWires};

/// Main block-linking wires
pub struct BlockLinkingWires<const DEPTH: usize, const NODE_LEN: usize, const BLOCK_LEN: usize>
where
    [(); PAD_LEN(NODE_LEN)]:,
    [(); DEPTH - 1]:,
{
    /// Account input data
    account_inputs: AccountInputsWires<DEPTH, NODE_LEN>,
    /// Block input data
    block_inputs: BlockInputsWires<BLOCK_LEN>,
    /// Previous storage proof
    /// TODO : to replace with real proof once recursion framework done
    storage_proof: StorageInputsWires,
}

/// Block-linking circuit used to prove the pre-computed state root proof is
/// linked to the specific block header.
#[derive(Clone, Debug)]
pub struct BlockLinkingCircuit<F, const DEPTH: usize, const NODE_LEN: usize, const BLOCK_LEN: usize>
{
    /// Account input data
    account_inputs: AccountInputs<DEPTH, NODE_LEN>,
    /// Block input data
    block_inputs: BlockInputs,
    /// Previous storage proof
    storage_proof: StorageInputs<F>,
}

impl<F, const DEPTH: usize, const NODE_LEN: usize, const BLOCK_LEN: usize>
    BlockLinkingCircuit<F, DEPTH, NODE_LEN, BLOCK_LEN>
where
    F: RichField,
    [(); PAD_LEN(NODE_LEN)]:,
    [(); DEPTH - 1]:,
{
    pub fn new(
        block: Block<H256>,
        storage_proof: StorageInputs<F>,
        // Nodes of state MPT, it's ordered from leaf to root.
        state_mpt_nodes: Vec<Vec<u8>>,
    ) -> Self {
        // Get the hash of state MPT root and create the block inputs gadget.
        let state_mpt_root = H256(
            keccak256(state_mpt_nodes.last().unwrap())
                .try_into()
                .unwrap(),
        );
        let block_inputs = BlockInputs::new(block, state_mpt_root);

        // Get the contract address and hash of storage MPT root, and create the
        // account inputs gadget.
        let contract_address = storage_proof.contract_address();
        let storage_mpt_root = storage_proof.mpt_root_value();
        let account_inputs =
            AccountInputs::new(contract_address, storage_mpt_root, state_mpt_nodes);

        Self {
            account_inputs,
            block_inputs,
            storage_proof,
        }
    }

    /// Build for circuit.
    pub fn build<const D: usize>(
        cb: &mut CircuitBuilder<F, D>,
    ) -> BlockLinkingWires<DEPTH, NODE_LEN, BLOCK_LEN>
    where
        F: RichField + Extendable<D>,
        [(); PAD_LEN(NODE_LEN)]:,
        [(); DEPTH - 1]:,
    {
        let account_inputs = AccountInputs::build(cb);
        let block_inputs = BlockInputs::build(cb);
        let storage_proof = StorageInputs::build(cb);

        // Verify the account node includes the hash of storage MPT root.
        AccountInputs::verify_storage_root_hash_inclusion(
            cb,
            &account_inputs,
            &storage_proof.mpt_root_target(),
        );

        // Verify the block header includes the hash of state MPT root.
        BlockInputs::verify_state_root_hash_inclusion(
            cb,
            &block_inputs,
            &account_inputs.state_mpt_output.root,
        );

        let wires = BlockLinkingWires {
            account_inputs,
            block_inputs,
            storage_proof,
        };

        // Register the public inputs.
        PublicInputs::<F>::register(cb, &wires);

        wires
    }

    /// Assign the wires.
    pub fn assign<const D: usize>(
        &self,
        pw: &mut PartialWitness<F>,
        wires: &BlockLinkingWires<DEPTH, NODE_LEN, BLOCK_LEN>,
    ) -> Result<()>
    where
        F: RichField + Extendable<D>,
    {
        self.storage_proof.assign(pw, &wires.storage_proof);
        self.account_inputs.assign(pw, &wires.account_inputs)?;
        self.block_inputs.assign(pw, &wires.block_inputs)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        storage_proof::{A_IDX, C1_IDX, C2_IDX, M_IDX, STORAGE_INPUT_LEN},
        *,
    };
    use crate::{
        benches::init_logging,
        circuit::{test::run_circuit, UserCircuit},
        eth::{ProofQuery, RLPBlock},
        keccak::HASH_LEN,
        utils::{convert_u8_slice_to_u32_fields, keccak256},
    };
    use anyhow::Result;
    use eth_trie::{EthTrie, MemoryDB, Trie};
    use ethers::{
        providers::{Http, Provider},
        types::{Address, H160},
    };
    use plonky2::plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::CircuitConfig,
        config::{GenericConfig, PoseidonGoldilocksConfig},
    };
    use rand::{thread_rng, Rng};
    use std::{str::FromStr, sync::Arc};

    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    /// Test state MPT
    struct TestStateMPT {
        /// Account address used to generate MPT key as `keccak(address)`
        account_address: H160,
        /// MPT root hash
        root_hash: H256,
        /// MPT nodes
        nodes: Vec<Vec<u8>>,
    }

    /// Test circuit
    #[derive(Clone, Debug)]
    struct TestCircuit<const DEPTH: usize, const NODE_LEN: usize, const BLOCK_LEN: usize> {
        c: BlockLinkingCircuit<F, DEPTH, NODE_LEN, BLOCK_LEN>,
    }

    impl<const DEPTH: usize, const NODE_LEN: usize, const BLOCK_LEN: usize> UserCircuit<F, D>
        for TestCircuit<DEPTH, NODE_LEN, BLOCK_LEN>
    where
        [(); PAD_LEN(NODE_LEN)]:,
        [(); DEPTH - 1]:,
    {
        type Wires = BlockLinkingWires<DEPTH, NODE_LEN, BLOCK_LEN>;

        fn build(cb: &mut CircuitBuilder<F, D>) -> Self::Wires {
            BlockLinkingCircuit::build(cb)
        }

        fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
            self.c.assign::<D>(pw, wires).unwrap();
        }
    }

    /// Test the block-linking circuit with a generated random MPT.
    #[test]
    fn test_block_linking_circuit_with_random_mpt() {
        init_logging();

        // Set maximum depth of the trie and Leave one for padding.
        const DEPTH: usize = 4;
        const ACTUAL_DEPTH: usize = DEPTH - 1;

        const BLOCK_LEN: usize = 600;
        const NODE_LEN: usize = 500;
        const VALUE_LEN: usize = 100;

        let state_mpt = generate_state_mpt::<DEPTH, VALUE_LEN>();
        let block = generate_block(&state_mpt);
        let storage_proof = generate_storage_proof(&state_mpt);

        let test_circuit = TestCircuit::<DEPTH, NODE_LEN, BLOCK_LEN> {
            c: BlockLinkingCircuit::new(block, storage_proof, state_mpt.nodes),
        };
        run_circuit::<F, D, C, _>(test_circuit);
    }

    /// Test the block-linking circuit with RPC `eth_getProof`.
    #[tokio::test]
    async fn test_block_linking_circuit_with_rpc() -> Result<()> {
        init_logging();

        #[cfg(feature = "ci")]
        let url = env::var("CI_SEPOLIA").expect("CI_SEPOLIA env var not set");
        #[cfg(not(feature = "ci"))]
        let url = "https://ethereum-sepolia-rpc.publicnode.com";
        let provider =
            Provider::<Http>::try_from(url).expect("could not instantiate HTTP Provider");

        // Sepolia contract
        let contract = Address::from_str("0xd6a2bFb7f76cAa64Dad0d13Ed8A9EFB73398F39E")?;
        // Simple storage test
        let query = ProofQuery::new_simple_slot(contract, 0);
        let res = query.query_mpt_proof(&provider).await?;

        // Written as constant from ^.
        const DEPTH: usize = 8;
        const BLOCK_LEN: usize = 600;
        const NODE_LEN: usize = 532;
        const VALUE_LEN: usize = 100;

        // Construct the state MPT via the RPC response.
        let account_address = query.contract;
        let nodes = res
            .account_proof
            .iter()
            .rev() // we want the leaf first and root last
            .map(|b| b.to_vec())
            .collect::<Vec<Vec<u8>>>();
        let root_hash = H256(keccak256(nodes.last().unwrap()).try_into().unwrap());
        let state_mpt = TestStateMPT {
            account_address,
            root_hash,
            nodes,
        };

        // TODO: test with a real block.
        let block = generate_block(&state_mpt);
        let storage_proof = generate_storage_proof(&state_mpt);

        let test_circuit = TestCircuit::<DEPTH, NODE_LEN, BLOCK_LEN> {
            c: BlockLinkingCircuit::new(block, storage_proof, state_mpt.nodes),
        };
        run_circuit::<F, D, C, _>(test_circuit);

        Ok(())
    }

    /// Generate a random state MPT. The account address is generated for MPT
    /// key as `keccak(address)`. The MPT nodes corresponding to that key is
    /// guaranteed to be of DEPTH length. Each leaves in the trie is of NODE_LEN
    /// length.
    fn generate_state_mpt<const DEPTH: usize, const VALUE_LEN: usize>() -> TestStateMPT {
        let mut address_key_pairs = Vec::new();
        let memdb = Arc::new(MemoryDB::new(true));
        let mut trie = EthTrie::new(Arc::clone(&memdb));

        // Loop to insert random elements as long as a random selected proof is
        // not of the right length.
        let mut rng = thread_rng();
        let (account_address, mpt_key) = loop {
            println!(
                "[+] Random mpt: insertion of {} elements so far...",
                address_key_pairs.len(),
            );

            // Generate a MPT key from an address.
            let address = rng.gen::<[u8; 20]>();
            let key = keccak256(&address);

            // Insert the key and value.
            let value: Vec<_> = (0..VALUE_LEN).map(|_| rng.gen::<u8>()).collect();
            trie.insert(&key, &value).unwrap();
            trie.root_hash().unwrap();

            // Save the address and key temporarily.
            address_key_pairs.push((H160(address), key));

            // Check if any node has the DEPTH elements.
            if let Some((address, key)) = address_key_pairs
                .iter()
                .find(|(_, key)| trie.get_proof(key).unwrap().len() == DEPTH)
            {
                break (*address, key);
            }
        };

        let root_hash = trie.root_hash().unwrap();
        let mut nodes = trie.get_proof(mpt_key).unwrap();
        nodes.reverse();
        assert!(keccak256(nodes.last().unwrap()) == root_hash.to_fixed_bytes());

        TestStateMPT {
            account_address,
            root_hash,
            nodes,
        }
    }

    /// Generate the test block header.
    fn generate_block(mpt: &TestStateMPT) -> Block<H256> {
        // Set to the MPT root hash.
        let state_root = mpt.root_hash;

        // Generate random block values.
        let mut rng = thread_rng();
        let number = Some(rng.gen::<u64>().into());
        let hash = Some(rng.gen::<[u8; 32]>().into());
        let parent_hash = rng.gen::<[u8; 32]>().into();

        Block {
            state_root,
            number,
            hash,
            parent_hash,
            ..Default::default()
        }
    }

    /// Generate the test storage proof.
    fn generate_storage_proof<F: RichField>(mpt: &TestStateMPT) -> StorageInputs<F> {
        let mut inner: [F; STORAGE_INPUT_LEN] = (0..STORAGE_INPUT_LEN)
            .map(|_| F::from_canonical_u64(thread_rng().gen::<u64>()))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        // Set the contract address to the public inputs of storage proof.
        let contract_address = convert_u8_slice_to_u32_fields(&mpt.account_address.0);
        inner[A_IDX..M_IDX].copy_from_slice(&contract_address);

        // Set the storage root hash to the public inputs of storage proof.
        let account_node = &mpt.nodes[0];
        // The real account node has 104 bytes and it's composed by
        // [nonce (U64), balance (U256), storage_hash (H256), code_hash (H256)]
        let start = thread_rng().gen_range(0..100 - HASH_LEN);
        let storage_root_hash =
            convert_u8_slice_to_u32_fields(&account_node[start..start + HASH_LEN]);
        inner[C1_IDX..C2_IDX].copy_from_slice(&storage_root_hash);

        StorageInputs { inner }
    }
}
