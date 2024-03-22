//! Block-linking circuit implemention used to prove the pre-computed state root
//! proof is linked to the specific block header.

mod account;
mod block;
mod public_inputs;

use crate::{
    api::{default_config, deserialize_proof, serialize_proof, ProofWithVK},
    mpt_sequential::PAD_LEN,
    storage::PublicInputs as StorageInputs,
    verifier_gadget::VerifierTarget,
};
use account::{Account, AccountInputsWires};
use anyhow::Result;
use block::{BlockHeader, BlockInputsWires};
use ethers::types::H160;
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::{target::Target, witness::PartialWitness},
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData, VerifierCircuitData, VerifierOnlyCircuitData},
        proof::ProofWithPublicInputs,
    },
};

pub use public_inputs::BlockLinkingInputs;
use recursion_framework::serialization::{deserialize, serialize};
use serde::{Deserialize, Serialize};

use self::block::SEPOLIA_NUMBER_LEN;

#[derive(Serialize, Deserialize)]
/// Main block-linking wires
pub struct BlockLinkingWires<const DEPTH: usize, const NODE_LEN: usize, const BLOCK_LEN: usize>
where
    [(); PAD_LEN(NODE_LEN)]:,
    [(); PAD_LEN(BLOCK_LEN)]:,
    [(); DEPTH - 1]:,
{
    /// Account input data
    pub(super) account_inputs: AccountInputsWires<DEPTH, NODE_LEN>,
    /// Block input data
    block_inputs: BlockInputsWires<BLOCK_LEN>,
}

/// Block-linking circuit used to prove the pre-computed state root proof is
/// linked to the specific block header.
#[derive(Clone, Debug)]
pub struct BlockLinkingCircuit<
    const DEPTH: usize,
    const NODE_LEN: usize,
    const BLOCK_LEN: usize,
    const NUMBER_LEN: usize,
> {
    /// Account input data
    account: Account<DEPTH, NODE_LEN>,
    /// Block input data
    block: BlockHeader<NUMBER_LEN>,
}

impl<
        const DEPTH: usize,
        const NODE_LEN: usize,
        const BLOCK_LEN: usize,
        const NUMBER_LEN: usize,
    > BlockLinkingCircuit<DEPTH, NODE_LEN, BLOCK_LEN, NUMBER_LEN>
where
    [(); PAD_LEN(NODE_LEN)]:,
    [(); PAD_LEN(BLOCK_LEN)]:,
    [(); DEPTH - 1]:,
{
    pub fn new<F: RichField>(
        storage_pi: &[F],
        contract_address: H160,
        header_rlp: Vec<u8>,
        // Nodes of state MPT, it's ordered from leaf to root.
        state_mpt_nodes: Vec<Vec<u8>>,
    ) -> Self {
        // Create the block inputs gadget.
        let block_inputs = BlockHeader::<NUMBER_LEN>::new(header_rlp);

        // Get the contract address and hash of storage MPT root, and create the
        // account inputs gadget.
        let storage_pi = StorageInputs::from(storage_pi);
        let storage_mpt_root = storage_pi.mpt_root_value();
        let account_inputs = Account::new(contract_address, storage_mpt_root, state_mpt_nodes);

        Self {
            account: account_inputs,
            block: block_inputs,
        }
    }

    /// Build for circuit.
    pub fn build<F, const D: usize>(
        cb: &mut CircuitBuilder<F, D>,
        storage_pi: &[Target],
    ) -> BlockLinkingWires<DEPTH, NODE_LEN, BLOCK_LEN>
    where
        F: RichField + Extendable<D>,
        [(); PAD_LEN(NODE_LEN)]:,
        [(); DEPTH - 1]:,
    {
        let account_inputs = Account::build(cb, storage_pi);
        let block_inputs = BlockHeader::<NUMBER_LEN>::build(cb);

        // Verify the account node includes the hash of storage MPT root.
        let storage_pi = StorageInputs::from(storage_pi);
        Account::verify_storage_root_hash_inclusion(cb, &account_inputs, &storage_pi.mpt_root());

        //Verify the block header includes the hash of state MPT root.
        BlockHeader::<NUMBER_LEN>::verify_state_root_hash_inclusion(
            cb,
            &block_inputs,
            &account_inputs.state_mpt_output.root,
        );

        let wires = BlockLinkingWires {
            account_inputs,
            block_inputs,
        };

        // Register the public inputs.
        BlockLinkingInputs::<F>::register(cb, &wires, &storage_pi);

        wires
    }

    /// Assign the wires.
    pub fn assign<F, const D: usize>(
        &self,
        pw: &mut PartialWitness<F>,
        wires: &BlockLinkingWires<DEPTH, NODE_LEN, BLOCK_LEN>,
    ) -> Result<()>
    where
        F: RichField + Extendable<D>,
    {
        self.account.assign(pw, &wires.account_inputs)?;
        self.block.assign(pw, &wires.block_inputs)
    }
}

type F = crate::api::F;
type C = crate::api::C;
const D: usize = crate::api::D;

const MAX_DEPTH_TRIE: usize = 9;
// 16*32 hashes + 16 RLP headers associated + 1 empty RLP headers (last slot) + (1 + 2) list RLP header
const MAX_NODE_LEN: usize = 532;
const MAX_BLOCK_LEN: usize = 620;
const NUMBER_LEN: usize = SEPOLIA_NUMBER_LEN;

#[derive(Serialize, Deserialize)]
pub(crate) struct Parameters<const DEPTH: usize, const NODE_LEN: usize, const BLOCK_LEN: usize>
where
    [(); DEPTH - 1]:,
    [(); PAD_LEN(NODE_LEN)]:,
    [(); PAD_LEN(BLOCK_LEN)]:,
{
    #[serde(serialize_with = "serialize", deserialize_with = "deserialize")]
    data: CircuitData<F, C, D>,
    wires: BlockLinkingWires<DEPTH, NODE_LEN, BLOCK_LEN>,
    storage_circuit_wires: VerifierTarget<D>,
}

pub(crate) type PublicParameters = Parameters<MAX_DEPTH_TRIE, MAX_NODE_LEN, MAX_BLOCK_LEN>;
/// Data structure holding the portion of inputs related to block linking logic,
/// which are necessary to generate a proof for the block linking circuit
pub type BlockLinkingCircuitInputs =
    BlockLinkingCircuit<MAX_DEPTH_TRIE, MAX_NODE_LEN, MAX_BLOCK_LEN, NUMBER_LEN>;

impl PublicParameters {
    /// Build circuit parameters for block linking circuit. It expects the circuit parameters
    /// of the digest_equal circuit. See `state/storage/digest_equal.rs` for more info.
    pub(crate) fn build(storage_circuit_vk: &VerifierCircuitData<F, C, D>) -> Self {
        let config = default_config();
        let mut cb = CircuitBuilder::<F, D>::new(config);
        let storage_circuit_wires = VerifierTarget::verify_proof(&mut cb, storage_circuit_vk);
        let storage_pi = storage_circuit_wires.get_proof().public_inputs.as_slice();
        let wires = BlockLinkingCircuitInputs::build(&mut cb, storage_pi);
        let data = cb.build::<C>();

        Self {
            data,
            wires,
            storage_circuit_wires,
        }
    }

    /// Generate proof for digest equal circuit employiing the circuit parameters found in  `self`
    /// and the necessary inputs values
    pub(crate) fn generate_proof(
        &self,
        inputs: &CircuitInput,
        vk: &VerifierOnlyCircuitData<C, D>,
    ) -> Result<Vec<u8>> {
        let mut pw = PartialWitness::<F>::new();
        inputs.circuit_inputs.assign::<F, D>(&mut pw, &self.wires)?;
        self.storage_circuit_wires
            .set_target(&mut pw, &inputs.storage_proof, vk);
        let proof = self.data.prove(pw)?;
        serialize_proof(&proof)
    }

    /// Get the `CircuitData` of the digest equal circuit
    pub(crate) fn circuit_data(&self) -> &CircuitData<F, C, D> {
        &self.data
    }
}

/// Data structure containing the inputs to be provided to the API in order to
/// generate a proof for the block linking circuit
pub struct CircuitInput {
    pub(crate) storage_proof: ProofWithPublicInputs<F, C, D>,
    circuit_inputs: BlockLinkingCircuitInputs,
}

impl CircuitInput {
    /// Instantiate `CircuitInput` for block linking circuit employing a proof for the
    /// digest equal circuit and the set of inputs to prove block linkink logic
    pub fn new(
        storage_proof: Vec<u8>,
        header_rlp: Vec<u8>,
        state_mpt_nodes: Vec<Vec<u8>>,
        contract_address: H160,
    ) -> Self {
        let storage_proof = deserialize_proof(&storage_proof).unwrap();
        let inputs = BlockLinkingCircuitInputs::new(
            &storage_proof.public_inputs,
            contract_address,
            header_rlp,
            state_mpt_nodes,
        );
        Self {
            storage_proof,
            circuit_inputs: inputs,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        api::tests::TestDummyCircuit,
        benches::init_logging,
        circuit::{test::run_circuit, UserCircuit},
        eth::{ProofQuery, RLPBlock},
        keccak::{OutputHash, HASH_LEN},
        utils::{convert_u8_slice_to_u32_fields, convert_u8_to_u32_slice, keccak256},
    };
    use anyhow::Result;
    use eth_trie::{EthTrie, MemoryDB, Trie};
    use ethers::{
        providers::{Http, Middleware, Provider},
        types::{Address, Block, H160, H256, U64},
    };
    use plonky2::{
        field::types::Field,
        iop::witness::WitnessWrite,
        plonk::{
            circuit_builder::CircuitBuilder,
            config::{GenericConfig, PoseidonGoldilocksConfig},
        },
    };
    use plonky2_crypto::u32::{
        arithmetic_u32::{CircuitBuilderU32, U32Target},
        witness::WitnessU32,
    };
    use rand::{thread_rng, Rng};
    use serial_test::serial;
    use std::{str::FromStr, sync::Arc};
    use tests::block::SEPOLIA_NUMBER_LEN;

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
    struct TestCircuit<
        const DEPTH: usize,
        const NODE_LEN: usize,
        const BLOCK_LEN: usize,
        const NUMBER_LEN: usize,
    > {
        exp_block_number: U64,
        exp_parent_hash: H256,
        exp_hash: H256,
        c: BlockLinkingCircuit<DEPTH, NODE_LEN, BLOCK_LEN, NUMBER_LEN>,
        storage_pi: Vec<F>,
    }

    impl<
            const DEPTH: usize,
            const NODE_LEN: usize,
            const BLOCK_LEN: usize,
            const NUMBER_LEN: usize,
        > UserCircuit<F, D> for TestCircuit<DEPTH, NODE_LEN, BLOCK_LEN, NUMBER_LEN>
    where
        [(); PAD_LEN(NODE_LEN)]:,
        [(); PAD_LEN(BLOCK_LEN)]:,
        [(); DEPTH - 1]:,
    {
        type Wires = (
            Vec<Target>,
            U32Target,
            OutputHash,
            OutputHash,
            BlockLinkingWires<DEPTH, NODE_LEN, BLOCK_LEN>,
        );

        fn build(cb: &mut CircuitBuilder<F, D>) -> Self::Wires {
            let storage_pi = cb.add_virtual_targets(StorageInputs::<Target>::TOTAL_LEN);

            let block_number = cb.add_virtual_u32_target();
            let parent_hash = OutputHash::new(cb);
            let hash = OutputHash::new(cb);
            let wires = BlockLinkingCircuit::<DEPTH, NODE_LEN, BLOCK_LEN, NUMBER_LEN>::build(
                cb,
                &storage_pi,
            );

            cb.connect(wires.block_inputs.number.0, block_number.0);
            parent_hash.enforce_equal(cb, &wires.block_inputs.parent_hash);
            hash.enforce_equal(cb, &wires.block_inputs.hash.output_array);

            (storage_pi, block_number, parent_hash, hash, wires)
        }

        fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
            pw.set_target_arr(&wires.0, &self.storage_pi);
            let block_number = self.exp_block_number.as_u32();
            pw.set_u32_target(wires.1, block_number);

            [(&wires.2, self.exp_parent_hash), (&wires.3, self.exp_hash)]
                .iter()
                .for_each(|(wires, value)| {
                    let value = convert_u8_to_u32_slice(&value.0)
                        .into_iter()
                        .map(F::from_canonical_u32)
                        .collect::<Vec<_>>()
                        .try_into()
                        .unwrap();
                    wires.assign(pw, &value);
                });

            self.c.assign::<F, D>(pw, &wires.4).unwrap();
        }
    }

    /// Test the block-linking circuit with a generated random MPT.
    #[test]
    fn test_block_linking_circuit_with_random_mpt() {
        init_logging();

        const DEPTH: usize = 3;
        const BLOCK_LEN: usize = 600;
        const NODE_LEN: usize = 512;
        const VALUE_LEN: usize = 50;

        let state_mpt = generate_state_mpt::<DEPTH, VALUE_LEN>();
        let storage_pi = generate_storage_inputs::<_, VALUE_LEN>(&state_mpt);

        let block = generate_block(&state_mpt);
        let header_rlp = rlp::encode(&RLPBlock(&block)).to_vec();
        let exp_hash = H256(keccak256(&header_rlp).try_into().unwrap());

        let test_circuit = TestCircuit::<DEPTH, NODE_LEN, BLOCK_LEN, 4> {
            exp_block_number: block.number.unwrap(),
            exp_parent_hash: block.parent_hash,
            exp_hash,
            c: BlockLinkingCircuit::new(
                &storage_pi,
                state_mpt.account_address,
                header_rlp,
                state_mpt.nodes,
            ),
            storage_pi,
        };
        run_circuit::<F, D, C, _>(test_circuit);
    }

    #[test]
    #[serial]
    fn test_block_linking_circuit_parameters() {
        init_logging();

        const NUM_PUBLIC_INPUTS: usize = StorageInputs::<'_, Target>::TOTAL_LEN;
        const VALUE_LEN: usize = 50;

        let test_storage_circuit = TestDummyCircuit::<NUM_PUBLIC_INPUTS>::build();
        let params = PublicParameters::build(&test_storage_circuit.circuit_data().verifier_data());

        // generate inputs
        let state_mpt = generate_state_mpt::<3, VALUE_LEN>();
        let storage_pi = generate_storage_inputs::<_, VALUE_LEN>(&state_mpt);
        let block = generate_block(&state_mpt);
        let header_rlp = rlp::encode(&RLPBlock(&block)).to_vec();
        let inputs = BlockLinkingCircuitInputs::new(
            &storage_pi,
            state_mpt.account_address,
            header_rlp,
            state_mpt.nodes,
        );
        // generate dummy storage proof with expected public inputs
        let storage_proof = test_storage_circuit
            .generate_proof(storage_pi.try_into().unwrap())
            .unwrap();
        let inputs = CircuitInput {
            storage_proof,
            circuit_inputs: inputs,
        };
        let proof = params
            .generate_proof(&inputs, &test_storage_circuit.circuit_data().verifier_only)
            .unwrap();

        params
            .data
            .verify(bincode::deserialize(&proof).unwrap())
            .unwrap()
    }

    /// Test the block-linking circuit with Sepolia RPC.
    #[tokio::test]
    #[serial]
    async fn test_block_linking_circuit_on_sepolia() -> Result<()> {
        #[cfg(feature = "ci")]
        let url = env::var("CI_SEPOLIA").expect("CI_SEPOLIA env var not set");
        #[cfg(not(feature = "ci"))]
        let url = "https://ethereum-sepolia-rpc.publicnode.com";

        let contract_address = "0xd6a2bFb7f76cAa64Dad0d13Ed8A9EFB73398F39E";

        // Written as constants from the result.
        const DEPTH: usize = 8;
        const NODE_LEN: usize = 532;
        const BLOCK_LEN: usize = 620;
        const VALUE_LEN: usize = 50;

        test_with_rpc::<DEPTH, NODE_LEN, BLOCK_LEN, VALUE_LEN, SEPOLIA_NUMBER_LEN>(
            url,
            contract_address,
        )
        .await
    }

    /// Test the block-linking circuit with Mainnet RPC.
    #[tokio::test]
    #[serial]
    async fn test_block_linking_circuit_on_mainnet() -> Result<()> {
        let url = "https://eth.llamarpc.com";
        // TODO: this Mainnet contract address only works with state proof
        //let contract_address = "0x105dD0eF26b92a3698FD5AaaF688577B9Cafd970";

        // pidgy pinguins
        let contract_address = "0xBd3531dA5CF5857e7CfAA92426877b022e612cf8";

        // Written as constants from the result.
        const DEPTH: usize = 9;
        const NODE_LEN: usize = 532;
        const BLOCK_LEN: usize = 620;
        const VALUE_LEN: usize = 50;

        test_with_rpc::<MAX_DEPTH_TRIE, MAX_NODE_LEN, MAX_BLOCK_LEN, VALUE_LEN, SEPOLIA_NUMBER_LEN>(
            url,
            contract_address,
        )
        .await
    }

    /// Test with RPC `eth_getProof`.
    async fn test_with_rpc<
        const DEPTH: usize,
        const NODE_LEN: usize,
        const BLOCK_LEN: usize,
        const VALUE_LEN: usize,
        const NUMBER_LEN: usize,
    >(
        url: &str,
        contract_address: &str,
    ) -> Result<()>
    where
        [(); PAD_LEN(NODE_LEN)]:,
        [(); PAD_LEN(BLOCK_LEN)]:,
        [(); DEPTH - 1]:,
    {
        init_logging();

        let contract_address = Address::from_str(contract_address)?;

        let provider =
            Provider::<Http>::try_from(url).expect("could not instantiate HTTP Provider");

        // Get the latest block number.
        let block_number = provider.get_block_number().await?;
        // Get block.
        let block = provider.get_block(block_number).await?.unwrap();
        // Query the MPT proof.
        let query = ProofQuery::new_simple_slot(contract_address, 0);
        let res = query
            .query_mpt_proof(&provider, Some(block_number.into()))
            .await?;
        // TODO: this Mainnet contract address only works with state proof
        // (not storage proof) for now.
        query.verify_state_proof(&res)?;

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

        let storage_pi = generate_storage_inputs::<_, VALUE_LEN>(&state_mpt);

        let header_rlp = rlp::encode(&RLPBlock(&block)).to_vec();
        let exp_hash = H256(keccak256(&header_rlp).try_into().unwrap());

        let test_circuit = TestCircuit::<DEPTH, NODE_LEN, BLOCK_LEN, NUMBER_LEN> {
            exp_block_number: block.number.unwrap(),
            exp_parent_hash: block.parent_hash,
            exp_hash,
            c: BlockLinkingCircuit::new(&storage_pi, account_address, header_rlp, state_mpt.nodes),
            storage_pi,
        };
        let proof = run_circuit::<F, D, C, _>(test_circuit);
        let pi = BlockLinkingInputs::<F>::from_slice(&proof.public_inputs);
        let computed_bn = pi.block_number();
        assert_eq!(
            F::from_canonical_u32(block.number.unwrap().as_u32()),
            *computed_bn
        );

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
        let number = Some(rng.gen::<u32>().into());
        let hash = Some(rng.gen::<[u8; 32]>().into());
        let parent_hash = rng.gen::<[u8; 32]>().into();

        Block::<H256> {
            state_root,
            number,
            hash,
            parent_hash,
            ..Default::default()
        }
    }

    /// Generate the test storage proof inputs as if it was given by a real proof.
    fn generate_storage_inputs<F: RichField, const VALUE_LEN: usize>(mpt: &TestStateMPT) -> Vec<F> {
        let mut storage_pi: Vec<_> = (0..StorageInputs::<F>::TOTAL_LEN)
            .map(|_| F::from_canonical_u64(thread_rng().gen::<u64>()))
            .collect();

        // Set the storage root hash to the public inputs of storage proof.
        let account_node = &mpt.nodes[0];
        // The account node length is restricted in 7-bits.
        // <https://github.com/Lagrange-Labs/mapreduce-plonky2/blob/42aa493c80c51fd533d389d7db6ce557d0e696a4/mapreduce-plonky2/src/state/block_linking/account.rs#L190>
        assert!(account_node.len() < 128);
        // The real account node has 104 bytes and it's composed by
        // [nonce (U64), balance (U256), storage_hash (H256), code_hash (H256)]
        let start = thread_rng().gen_range(0..VALUE_LEN - HASH_LEN);
        let storage_root_hash =
            convert_u8_slice_to_u32_fields(&account_node[start..start + HASH_LEN]);
        storage_pi[StorageInputs::<F>::C1_IDX..StorageInputs::<F>::C2_IDX]
            .copy_from_slice(&storage_root_hash);

        storage_pi
    }
}
