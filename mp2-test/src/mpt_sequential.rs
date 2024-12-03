use alloy::{
    eips::BlockNumberOrTag,
    network::TransactionBuilder,
    node_bindings::Anvil,
    primitives::{Address, U256},
    providers::{ext::AnvilApi, Provider, ProviderBuilder},
    sol,
};
use eth_trie::{EthTrie, MemoryDB, Trie};

use mp2_common::eth::{ReceiptProofInfo, ReceiptQuery};
use rand::{thread_rng, Rng};
use std::sync::Arc;

/// Simply the maximum number of nibbles a key can have.
const MAX_KEY_NIBBLE_LEN: usize = 64;

/// generate a random storage trie and a key. The MPT proof corresponding to
/// that key is guaranteed to be of DEPTH length. Each leaves in the trie
/// is of NODE_LEN length.
/// The returned key is RLP encoded
pub fn generate_random_storage_mpt<const DEPTH: usize, const VALUE_LEN: usize>(
) -> (EthTrie<MemoryDB>, Vec<u8>) {
    let memdb = Arc::new(MemoryDB::new(true));
    let mut trie = EthTrie::new(Arc::clone(&memdb));
    let mut keys = Vec::new();
    let right_key_idx: usize;
    // loop: insert random elements as long as a random selected proof is not of the right length
    loop {
        println!(
            "[+] Random mpt: insertion of {} elements so far...",
            keys.len()
        );
        let key = thread_rng().gen::<[u8; MAX_KEY_NIBBLE_LEN / 2]>().to_vec();
        let random_bytes = (0..VALUE_LEN)
            .map(|_| thread_rng().gen::<u8>())
            .collect::<Vec<_>>();
        trie.insert(&key, &random_bytes).expect("can't insert");
        keys.push(key.clone());
        trie.root_hash().expect("root hash problem");
        if let Some(idx) = (0..keys.len()).find(|k| {
            let ke = &keys[*k];
            let proof = trie.get_proof(ke).unwrap();
            proof.len() == DEPTH
        }) {
            right_key_idx = idx;
            break;
        }
    }
    (trie, keys[right_key_idx].to_vec())
}

#[derive(Debug, Clone)]
pub struct ReceiptTestInfo<const NO_TOPICS: usize, const MAX_DATA: usize> {
    /// The query which we have returned proofs for
    pub query: ReceiptQuery<NO_TOPICS, MAX_DATA>,
    /// The proofs for receipts relating to `self.query`
    pub proofs: Vec<ReceiptProofInfo>,
}

impl<const NO_TOPICS: usize, const MAX_DATA: usize> ReceiptTestInfo<NO_TOPICS, MAX_DATA> {
    /// Getter for the proofs
    pub fn proofs(&self) -> Vec<ReceiptProofInfo> {
        self.proofs.clone()
    }
    /// Getter for the query
    pub fn query(&self) -> &ReceiptQuery<NO_TOPICS, MAX_DATA> {
        &self.query
    }
}
/// This function is used so that we can generate a Receipt Trie for a blog with varying transactions
/// (i.e. some we are interested in and some we are not).
pub fn generate_receipt_test_info() -> ReceiptTestInfo<1, 0> {
    // Make a contract that emits events so we can pick up on them
    sol! {
        #[allow(missing_docs)]
    // solc v0.8.26; solc Counter.sol --via-ir --optimize --bin
    #[sol(rpc, abi, bytecode="6080604052348015600e575f80fd5b506102288061001c5f395ff3fe608060405234801561000f575f80fd5b506004361061004a575f3560e01c8063488814e01461004e5780638381f58a14610058578063d09de08a14610076578063db73227914610080575b5f80fd5b61005661008a565b005b6100606100f8565b60405161006d9190610165565b60405180910390f35b61007e6100fd565b005b610088610115565b005b5f547fdcd9c7fa0342f01013bd0bf2bec103a81936162dcebd1f0c38b1d4164c17e0fc60405160405180910390a26100c06100fd565b5f547fdcd9c7fa0342f01013bd0bf2bec103a81936162dcebd1f0c38b1d4164c17e0fc60405160405180910390a26100f66100fd565b565b5f5481565b5f8081548092919061010e906101ab565b9190505550565b5f547fdcd9c7fa0342f01013bd0bf2bec103a81936162dcebd1f0c38b1d4164c17e0fc60405160405180910390a261014b6100fd565b565b5f819050919050565b61015f8161014d565b82525050565b5f6020820190506101785f830184610156565b92915050565b7f4e487b71000000000000000000000000000000000000000000000000000000005f52601160045260245ffd5b5f6101b58261014d565b91507fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff82036101e7576101e661017e565b5b60018201905091905056fea26469706673582212202787ca0f2ea71e118bc4d1bf239cde5ec4730aeb35a404c44e6c9d587316418564736f6c634300081a0033")]
    contract EventEmitter {
        uint256 public number;
        event testEvent(uint256 indexed num);

        function testEmit() public {
            emit testEvent(number);
            increment();
        }

        function twoEmits() public {
            emit testEvent(number);
            increment();
            emit testEvent(number);
            increment();
        }

        function increment() public {
            number++;
        }
    }

        #[sol(rpc, abi, bytecode="6080604052348015600e575f80fd5b506102288061001c5f395ff3fe608060405234801561000f575f80fd5b506004361061004a575f3560e01c8063488814e01461004e5780637229db15146100585780638381f58a14610062578063d09de08a14610080575b5f80fd5b61005661008a565b005b6100606100f8565b005b61006a610130565b6040516100779190610165565b60405180910390f35b610088610135565b005b5f547fbe3cbcfa5d4a62a595b4a15f51de63c11797bbef2ff687873efb0bb2852ee20f60405160405180910390a26100c0610135565b5f547fbe3cbcfa5d4a62a595b4a15f51de63c11797bbef2ff687873efb0bb2852ee20f60405160405180910390a26100f6610135565b565b5f547fbe3cbcfa5d4a62a595b4a15f51de63c11797bbef2ff687873efb0bb2852ee20f60405160405180910390a261012e610135565b565b5f5481565b5f80815480929190610146906101ab565b9190505550565b5f819050919050565b61015f8161014d565b82525050565b5f6020820190506101785f830184610156565b92915050565b7f4e487b71000000000000000000000000000000000000000000000000000000005f52601160045260245ffd5b5f6101b58261014d565b91507fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff82036101e7576101e661017e565b5b60018201905091905056fea26469706673582212203b7602644bfff2df89c2fe9498cd533326876859a0df7b96ac10be1fdc09c3a064736f6c634300081a0033")]

       contract OtherEmitter {
        uint256 public number;
        event otherEvent(uint256 indexed num);

        function otherEmit() public {
            emit otherEvent(number);
            increment();
        }

        function twoEmits() public {
            emit otherEvent(number);
            increment();
            emit otherEvent(number);
            increment();
        }

        function increment() public {
            number++;
        }
    }
    }

    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        // Spin up a local node.

        let rpc = ProviderBuilder::new()
            .with_recommended_fillers()
            .on_anvil_with_config(|anvil| Anvil::arg(anvil, "--no-mining"));

        // Turn on auto mining to deploy the contracts
        rpc.anvil_set_auto_mine(true).await.unwrap();

        // Deploy the contract using anvil
        let event_contract = EventEmitter::deploy(rpc.root()).await.unwrap();

        // Deploy the contract using anvil
        let other_contract = OtherEmitter::deploy(rpc.root()).await.unwrap();

        // Disable auto mining so we can ensure that all the transaction appear in the same block
        rpc.anvil_set_auto_mine(false).await.unwrap();

        // Send a bunch of transactions, some of which are related to the event we are testing for.
        let mut pending_tx_builders = vec![];
        for i in 0..25 {
            let tx_req = match i % 4 {
                0 => event_contract.testEmit().into_transaction_request(),
                1 => event_contract.twoEmits().into_transaction_request(),
                2 => other_contract.otherEmit().into_transaction_request(),
                3 => other_contract.twoEmits().into_transaction_request(),
                _ => unreachable!(),
            };

            let sender_address = Address::random();
            let funding = U256::from(1e18 as u64);
            rpc.anvil_set_balance(sender_address, funding)
                .await
                .unwrap();
            rpc.anvil_auto_impersonate_account(true).await.unwrap();
            let new_req = tx_req.with_from(sender_address);
            let tx_req_final = rpc
                .fill(new_req)
                .await
                .unwrap()
                .as_builder()
                .unwrap()
                .clone();
            pending_tx_builders.push(rpc.send_transaction(tx_req_final).await.unwrap());
        }

        // Mine a block, it should include all the transactions created above.
        rpc.anvil_mine(Some(U256::from(1u8)), None).await.unwrap();

        let mut transactions = Vec::new();
        for pending in pending_tx_builders.into_iter() {
            let hash = pending.watch().await.unwrap();
            transactions.push(rpc.get_transaction_by_hash(hash).await.unwrap().unwrap());
        }

        let block_number = transactions.first().unwrap().block_number.unwrap();

        // We want to get the event signature so we can make a ReceiptQuery
        let all_events = EventEmitter::abi::events();

        let events = all_events.get("testEvent").unwrap();

        let receipt_query =
            ReceiptQuery::<1, 0>::new(*event_contract.address(), &events[0].signature());

        let proofs = receipt_query
            .query_receipt_proofs(rpc.root(), BlockNumberOrTag::Number(block_number))
            .await
            .unwrap();

        ReceiptTestInfo {
            query: receipt_query,
            proofs,
        }
    })
}
