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
    #[sol(rpc, abi, bytecode="6080604052348015600e575f80fd5b506106cf8061001c5f395ff3fe608060405234801561000f575f80fd5b50600436106100e6575f3560e01c806346d6a7b51161008a5780638381f58a116100645780638381f58a1461014e578063b1e057a91461016c578063c024200014610176578063d09de08a14610180576100e6565b806346d6a7b51461013057806363eb70f01461013a578063729d452014610144576100e6565b806331c1c63b116100c657806331c1c63b14610108578063338b538a146101125780634282ed581461011c5780634369f72814610126576100e6565b80623c7e56146100ea578062d83b55146100f45780632dc34764146100fe575b5f80fd5b6100f261018a565b005b6100fc6101f6565b005b610106610255565b005b6101106102d0565b005b61011a610324565b005b61012461036a565b005b61012e610397565b005b6101386103e7565b005b610142610438565b005b61014c610496565b005b6101566104ce565b60405161016391906105b2565b60405180910390f35b6101746104d3565b005b61017e610540565b005b610188610582565b005b60025f5461019891906105f8565b60015f546101a691906105f8565b5f547ff57f433eb9493cf4d9cb5763c12221d9b095804644d4ee006a78c72076cff94760035f546101d791906105f8565b6040516101e491906105b2565b60405180910390a46101f4610582565b565b5f547fef4c88193498df237f039055d1212ac2a3b93ed8aea88c814312e50f6a32592d60015f5461022791906105f8565b60025f5461023591906105f8565b60405161024392919061062b565b60405180910390a2610253610582565b565b60025f5461026391906105f8565b60015f5461027191906105f8565b5f547ff03d29753fbd5ac209bab88a99b396bcc25c3e72530d02c81aea4d324ab3d74260035f546102a291906105f8565b60045f546102b091906105f8565b6040516102be92919061062b565b60405180910390a46102ce610582565b565b60025f546102de91906105f8565b60015f546102ec91906105f8565b5f547f1d18de2cd8798a1c29b9255930c807eb6c84ae0acb2219acbb11e0f65cf813e960405160405180910390a4610322610582565b565b60015f5461033291906105f8565b5f547fa6baf14d8f11d7a4497089bb3fca0adfc34837cfb1f4aa370634d36ef0305b4660405160405180910390a3610368610582565b565b7ef7c74f0533aa15e5ac7cafa9f9261d14da1e78830deba7110fbc79001ed15e60405160405180910390a1565b5f547f168718c0b1eb6bfd7b0edecea5c6fc6502737ad73a4c9f52ffa7e553c8eb9f5360015f546103c891906105f8565b6040516103d591906105b2565b60405180910390a26103e5610582565b565b7f2fa61517ddf9dc7f2f3d5ca72414a01c834d9c5bb7c336c977423c85094bba615f5460015f5461041891906105f8565b60405161042692919061062b565b60405180910390a1610436610582565b565b60015f5461044691906105f8565b5f547f3bb2d6337882faa5526cf806c9763904a90f3363590dd4386913e3fcd8a2e1d160025f5461047791906105f8565b60405161048491906105b2565b60405180910390a3610494610582565b565b5f547fc2809a1a2fb95d84cfdc488cdb320a144c158f8d44836c9c2d4badba082bfdfa60405160405180910390a26104cc610582565b565b5f5481565b60015f546104e191906105f8565b5f547f4b92229abe204a30d7b088d8110291760934d65b3c960680ad94e05f52a8860560025f5461051291906105f8565b60035f5461052091906105f8565b60405161052e92919061062b565b60405180910390a361053e610582565b565b7f04f7fb289e51ea9996ec98e62ff4b651becfa6e53f3b850be209b69741c66f245f5460405161057091906105b2565b60405180910390a1610580610582565b565b5f8081548092919061059390610652565b9190505550565b5f819050919050565b6105ac8161059a565b82525050565b5f6020820190506105c55f8301846105a3565b92915050565b7f4e487b71000000000000000000000000000000000000000000000000000000005f52601160045260245ffd5b5f6106028261059a565b915061060d8361059a565b9250828201905080821115610625576106246105cb565b5b92915050565b5f60408201905061063e5f8301856105a3565b61064b60208301846105a3565b9392505050565b5f61065c8261059a565b91507fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff820361068e5761068d6105cb565b5b60018201905091905056fea2646970667358221220700680d82e015428138cb99290dc38d4593806c6cc40652ebd841185a38a133564736f6c634300081a0033")]
    contract EventEmitter {
        uint256 public number;
        event noIndexed();
    event oneIndexed(uint256 indexed num);
    event twoIndexed(uint256 indexed num, uint256 indexed numTwo);
    event threeIndexed(
        uint256 indexed num,
        uint256 indexed numTwo,
        uint256 indexed numThree
    );
    event oneData(
        uint256 indexed num,
        uint256 indexed numTwo,
        uint256 indexed numThree,
        uint256 numFour
    );
    event twoData(
        uint256 indexed num,
        uint256 indexed numTwo,
        uint256 indexed numThree,
        uint256 numFour,
        uint256 numFive
    );
    event noIOneD(uint256 num);
    event noITwoD(uint256 num, uint256 numTwo);
    event oneIOneD(uint256 indexed num, uint256 numTwo);
    event oneITwoD(uint256 indexed num, uint256 numTwo, uint256 numThree);
    event twoIOneD(
        uint256 indexed num,
        uint256 indexed numTwo,
        uint256 numThree
    );
    event twoITwoD(
        uint256 indexed num,
        uint256 indexed numTwo,
        uint256 numThree,
        uint256 numFour
    );

    function testNoIndexed() public {
        emit noIndexed();
    }

    function testOneIndexed() public {
        emit oneIndexed(number);
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

    function testNoIOneD() public {
        emit noIOneD(number);
        increment();
    }

    function testNoITwoD() public {
        emit noITwoD(number, number + 1);
        increment();
    }

    function testOneIOneD() public {
        emit oneIOneD(number, number + 1);
        increment();
    }

    function testOneITwoD() public {
        emit oneITwoD(number, number + 1, number + 2);
        increment();
    }

    function testTwoIOneD() public {
        emit twoIOneD(number, number + 1, number + 2);
        increment();
    }

    function testTwoITwoD() public {
        emit twoITwoD(number, number + 1, number + 2, number + 3);
        increment();
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
        // Pick a random number, this will be the number of relevant events to include.
        let relevant_event_count = rng.gen_range(5..15);
        for i in 0..150 {
            let tx_req = if i < relevant_event_count || (128 < i && i < 133) {
                match (NO_TOPICS, MAX_DATA_WORDS) {
                    (0, 0) => event_contract.testNoIndexed().into_transaction_request(),
                    (1, 0) => event_contract.testOneIndexed().into_transaction_request(),
                    (2, 0) => event_contract.testTwoIndexed().into_transaction_request(),
                    (3, 0) => event_contract.testThreeIndexed().into_transaction_request(),
                    (0, 1) => event_contract.testNoIOneD().into_transaction_request(),
                    (0, 2) => event_contract.testNoITwoD().into_transaction_request(),
                    (1, 1) => event_contract.testOneIOneD().into_transaction_request(),
                    (1, 2) => event_contract.testOneITwoD().into_transaction_request(),
                    (2, 1) => event_contract.testTwoIOneD().into_transaction_request(),
                    (2, 2) => event_contract.testTwoITwoD().into_transaction_request(),
                    (3, 1) => event_contract.testOneData().into_transaction_request(),
                    (3, 2) => event_contract.testTwoData().into_transaction_request(),
                    _ => unreachable!(),
                }
            } else {
                // Randomly pick a pair that is not equal to `(NO_TOPICS, MAX_DATA_WORDS`
                let mut first_random = rand::random::<usize>() % 4;
                let mut second_random = rand::random::<usize>() % 3;
                while (first_random, second_random) == (NO_TOPICS, MAX_DATA_WORDS) {
                    first_random = rand::random::<usize>() % 4;
                    second_random = rand::random::<usize>() % 3;
                }
                match (first_random, second_random) {
                    (0, 0) | (1, 0) => other_contract.otherEmit().into_transaction_request(),
                    (2, 0) => other_contract.twoEmits().into_transaction_request(),
                    (3, 0) => event_contract.testThreeIndexed().into_transaction_request(),
                    (0, 1) => event_contract.testNoIOneD().into_transaction_request(),
                    (0, 2) => event_contract.testNoITwoD().into_transaction_request(),
                    (1, 1) => event_contract.testOneIOneD().into_transaction_request(),
                    (1, 2) => event_contract.testOneITwoD().into_transaction_request(),
                    (2, 1) => event_contract.testTwoIOneD().into_transaction_request(),
                    (2, 2) => event_contract.testTwoITwoD().into_transaction_request(),
                    (3, 1) => event_contract.testOneData().into_transaction_request(),
                    (3, 2) => event_contract.testTwoData().into_transaction_request(),
                    _ => unreachable!(),
                }
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
            (0, 0) => all_events.get("noIndexed"),
            (1, 0) => all_events.get("oneIndexed"),
            (2, 0) => all_events.get("twoIndexed"),
            (3, 0) => all_events.get("threeIndexed"),
            (0, 1) => all_events.get("noIOneD"),
            (0, 2) => all_events.get("noITwoD"),
            (1, 1) => all_events.get("oneIOneD"),
            (1, 2) => all_events.get("oneITwoD"),
            (2, 1) => all_events.get("twoIOneD"),
            (2, 2) => all_events.get("twoITwoD"),
            (3, 1) => all_events.get("oneData"),
            (3, 2) => all_events.get("twoData"),
            _ => panic!(),
        };

        let event = EventLogInfo::<NO_TOPICS, MAX_DATA_WORDS>::new(
            *event_contract.address(),
            chain_id,
            &events.unwrap()[0].signature(),
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
