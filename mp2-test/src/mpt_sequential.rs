use alloy::{
    eips::BlockNumberOrTag,
    network::TransactionBuilder,
    node_bindings::Anvil,
    primitives::{Address, B256, U256},
    providers::{ext::AnvilApi, Provider, ProviderBuilder},
    sol,
};
use eth_trie::{EthTrie, MemoryDB, Trie};

use mp2_common::eth::{EventLogInfo, ReceiptProofInfo};
use rand::{distributions::uniform::SampleRange, thread_rng, Rng};
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
pub struct ReceiptTestInfo<const NO_TOPICS: usize, const MAX_DATA_WORDS: usize> {
    /// The event which we have returned proofs for
    pub event: EventLogInfo<NO_TOPICS, MAX_DATA_WORDS>,
    /// The proofs for receipts relating to `self.query`
    pub proofs: Vec<ReceiptProofInfo>,
    /// The root of the Receipt Trie at this block (in case there are no relevant events)
    pub receipts_root: B256,
}

impl<const NO_TOPICS: usize, const MAX_DATA_WORDS: usize>
    ReceiptTestInfo<NO_TOPICS, MAX_DATA_WORDS>
{
    /// Getter for the proofs
    pub fn proofs(&self) -> Vec<ReceiptProofInfo> {
        self.proofs.clone()
    }
    /// Getter for the query
    pub fn info(&self) -> &EventLogInfo<NO_TOPICS, MAX_DATA_WORDS> {
        &self.event
    }
}
/// This function is used so that we can generate a Receipt Trie for a blog with varying transactions
/// (i.e. some we are interested in and some we are not).
pub fn generate_receipt_test_info<const NO_TOPICS: usize, const MAX_DATA_WORDS: usize>(
) -> ReceiptTestInfo<NO_TOPICS, MAX_DATA_WORDS> {
    // Make a contract that emits events so we can pick up on them
    sol! {
        #[allow(missing_docs)]
    // solc v0.8.26; solc Counter.sol --via-ir --optimize --bin
    #[sol(rpc, abi, bytecode="6080604052348015600e575f80fd5b506104ed8061001c5f395ff3fe608060405234801561000f575f80fd5b5060043610610085575f3560e01c80638381f58a116100595780638381f58a146100b1578063d09de08a146100cf578063d857c891146100d9578063db732279146100f557610085565b80623c7e56146100895780632dc347641461009357806331c1c63b1461009d578063338b538a146100a7575b5f80fd5b6100916100ff565b005b61009b61016b565b005b6100a56101e6565b005b6100af61023a565b005b6100b9610280565b6040516100c69190610377565b60405180910390f35b6100d7610285565b005b6100f360048036038101906100ee91906103be565b61029d565b005b6100fd610327565b005b60025f5461010d9190610416565b60015f5461011b9190610416565b5f547ff57f433eb9493cf4d9cb5763c12221d9b095804644d4ee006a78c72076cff94760035f5461014c9190610416565b6040516101599190610377565b60405180910390a4610169610285565b565b60025f546101799190610416565b60015f546101879190610416565b5f547ff03d29753fbd5ac209bab88a99b396bcc25c3e72530d02c81aea4d324ab3d74260035f546101b89190610416565b60045f546101c69190610416565b6040516101d4929190610449565b60405180910390a46101e4610285565b565b60025f546101f49190610416565b60015f546102029190610416565b5f547f1d18de2cd8798a1c29b9255930c807eb6c84ae0acb2219acbb11e0f65cf813e960405160405180910390a4610238610285565b565b60015f546102489190610416565b5f547fa6baf14d8f11d7a4497089bb3fca0adfc34837cfb1f4aa370634d36ef0305b4660405160405180910390a361027e610285565b565b5f5481565b5f8081548092919061029690610470565b9190505550565b5f81036102b9576102ac610327565b6102b4610327565b610324565b600181036102d6576102c961023a565b6102d161023a565b610323565b600281036102f3576102e66101e6565b6102ee6101e6565b610322565b60038103610310576103036100ff565b61030b6100ff565b610321565b61031861016b565b61032061016b565b5b5b5b5b50565b5f547fdcd9c7fa0342f01013bd0bf2bec103a81936162dcebd1f0c38b1d4164c17e0fc60405160405180910390a261035d610285565b565b5f819050919050565b6103718161035f565b82525050565b5f60208201905061038a5f830184610368565b92915050565b5f80fd5b61039d8161035f565b81146103a7575f80fd5b50565b5f813590506103b881610394565b92915050565b5f602082840312156103d3576103d2610390565b5b5f6103e0848285016103aa565b91505092915050565b7f4e487b71000000000000000000000000000000000000000000000000000000005f52601160045260245ffd5b5f6104208261035f565b915061042b8361035f565b9250828201905080821115610443576104426103e9565b5b92915050565b5f60408201905061045c5f830185610368565b6104696020830184610368565b9392505050565b5f61047a8261035f565b91507fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff82036104ac576104ab6103e9565b5b60018201905091905056fea2646970667358221220f5d14aba97b2168309da4d73f65e2c98d90f3c697213c6e51c2520cee4816aea64736f6c634300081a0033")]
    contract EventEmitter {
        uint256 public number;
        event testEvent(uint256 indexed num);
        event twoIndexed(uint256 indexed num, uint256 indexed numTwo);
        event threeIndexed(uint256 indexed num, uint256 indexed numTwo, uint256 indexed numThree);
        event oneData(uint256 indexed num, uint256 indexed numTwo, uint256 indexed numThree, uint256 numFour);
        event twoData(uint256 indexed num, uint256 indexed numTwo, uint256 indexed numThree, uint256 numFour, uint256 numFive);


        function testEmit() public {
            emit testEvent(number);
            increment();
        }

        function testTwoIndexed() public {
            emit twoIndexed(number, number + 1);
            increment();
        }

        function testThreeIndexed() public {
            emit threeIndexed(number, number + 1, number + 2);
            increment();
        }

        function testOneData() public {
            emit oneData(number, number + 1, number + 2, number + 3);
            increment();
        }

        function testTwoData() public {
            emit twoData(number, number + 1, number + 2, number + 3, number + 4);
            increment();
        }

        function twoEmits(uint256 flag) public {
            if (flag == 0) {
                testEmit();
                testEmit();
            } else if (flag == 1) {
                testTwoIndexed();
                testTwoIndexed();
            } else if (flag == 2) {
                testThreeIndexed();
                testThreeIndexed();
            } else if (flag == 3) {
                testOneData();
                testOneData();
            } else {
                testTwoData();
                testTwoData();
            }
        }

        function increment() public {
            number++;
        }
    }

        #[sol(rpc, abi, bytecode="6080604052348015600e575f80fd5b506102288061001c5f395ff3fe608060405234801561000f575f80fd5b506004361061004a575f3560e01c8063488814e01461004e5780637229db15146100585780638381f58a14610062578063d09de08a14610080575b5f80fd5b61005661008a565b005b6100606100f8565b005b61006a610130565b6040516100779190610165565b60405180910390f35b610088610135565b005b5f547fbe3cbcfa5d4a62a595b4a15f51de63c11797bbef2ff687873efb0bb2852ee20f60405160405180910390a26100c0610135565b5f547fbe3cbcfa5d4a62a595b4a15f51de63c11797bbef2ff687873efb0bb2852ee20f60405160405180910390a26100f6610135565b565b5f547fbe3cbcfa5d4a62a595b4a15f51de63c11797bbef2ff687873efb0bb2852ee20f60405160405180910390a261012e610135565b565b5f5481565b5f80815480929190610146906101ab565b9190505550565b5f819050919050565b61015f8161014d565b82525050565b5f6020820190506101785f830184610156565b92915050565b7f4e487b71000000000000000000000000000000000000000000000000000000005f52601160045260245ffd5b5f6101b58261014d565b91507fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff82036101e7576101e661017e565b5b60018201905091905056fea2646970667358221220aacdd709f2f5e659587a60249419a4459e23d06c85d31d2c0b55c3fafbf3a2cb64736f6c634300081a0033")]

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
        rpc.anvil_auto_impersonate_account(true).await.unwrap();
        // Send a bunch of transactions, some of which are related to the event we are testing for.
        let mut pending_tx_builders = vec![];
        let mut rng = rand::thread_rng();
        for i in 0..25 {
            let random = match (0..5).sample_single(&mut rng) {
                0 => event_contract.testEmit().into_transaction_request(),
                1 => event_contract.testTwoIndexed().into_transaction_request(),
                2 => event_contract.testThreeIndexed().into_transaction_request(),
                3 => event_contract.testOneData().into_transaction_request(),
                4 => event_contract.testTwoData().into_transaction_request(),
                _ => unreachable!(),
            };

            let tx_req = match i % 4 {
                0 | 1 => random,
                2 => other_contract.otherEmit().into_transaction_request(),
                3 => other_contract.twoEmits().into_transaction_request(),
                _ => unreachable!(),
            };

            let sender_address = Address::random();

            let funding = U256::from(1e18 as u64);
            rpc.anvil_set_balance(sender_address, funding)
                .await
                .unwrap();

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

        // Finally we guarantee at least three of the event we are going to query for
        for _ in 0..3 {
            let queried_event_req = match (NO_TOPICS, MAX_DATA_WORDS) {
                (1, 0) => event_contract.testEmit().into_transaction_request(),
                (2, 0) => event_contract.testTwoIndexed().into_transaction_request(),
                (3, 0) => event_contract.testThreeIndexed().into_transaction_request(),
                (3, 1) => event_contract.testOneData().into_transaction_request(),
                (3, 2) => event_contract.testTwoData().into_transaction_request(),
                _ => unreachable!(),
            };

            let sender_address = Address::random();
            let funding = U256::from(1e18 as u64);
            rpc.anvil_set_balance(sender_address, funding)
                .await
                .unwrap();
            rpc.anvil_auto_impersonate_account(true).await.unwrap();
            let new_req = queried_event_req.with_from(sender_address);
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

        let chain_id = rpc.get_chain_id().await.unwrap();
        let events = match (NO_TOPICS, MAX_DATA_WORDS) {
            (1, 0) => all_events.get("testEvent").unwrap(),
            (2, 0) => all_events.get("twoIndexed").unwrap(),
            (3, 0) => all_events.get("threeIndexed").unwrap(),
            (3, 1) => all_events.get("oneData").unwrap(),
            (3, 2) => all_events.get("twoData").unwrap(),
            _ => panic!(),
        };

        let event = EventLogInfo::<NO_TOPICS, MAX_DATA_WORDS>::new(
            *event_contract.address(),
            chain_id,
            &events[0].signature(),
        );

        let (proofs, receipts_root) = event
            .query_receipt_proofs(rpc.root(), BlockNumberOrTag::Number(block_number))
            .await
            .unwrap();

        ReceiptTestInfo {
            event,
            proofs,
            receipts_root,
        }
    })
}
