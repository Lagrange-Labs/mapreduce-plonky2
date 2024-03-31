#![feature(iter_map_windows)]
#![feature(generic_const_exprs)]
#![feature(generic_arg_infer)]
#![feature(const_for)]
#![feature(generic_const_items)]
use anyhow::Result;
use backtrace::Backtrace;
use eth_trie::Nibbles;
use ethers::types::TxHash;
use ethers::{
    providers::{Http, Middleware, Provider},
    types::{Address, Block, BlockId, BlockNumber, EIP1186ProofResponse, H256, U64},
};
use hashbrown::HashMap;
use log::{log_enabled, Level, LevelFilter};
use mapreduce_plonky2::block::{
    block_leaf_hash, empty_merkle_root, merkle_root, merkle_root_bytes,
};
use mapreduce_plonky2::eth::BlockUtil;
use mapreduce_plonky2::state::{self, block_linking};
use mapreduce_plonky2::{
    api::{self, CircuitInput},
    eth::{get_mainnet_url, ProofQuery, RLPBlock},
    storage::{
        self,
        key::SimpleSlot,
        length_match,
        lpn::{self, leaf_hash_for_mapping, LeafCircuit, NodeInputs},
        mapping, MAX_BRANCH_NODE_LEN,
    },
    types::HashOutput,
};
use plonky2::hash::hash_types::HashOut;
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::plonk::config::{GenericConfig, GenericHashOut, Hasher, PoseidonGoldilocksConfig};
use rmp_serde::Serializer;
use serde::{Deserialize, Serialize};
use serde_json::map;
use std::{collections::VecDeque, env, fs::File, str::FromStr};
use std::{io::Write, panic};
use storage::length_extract::ArrayLengthExtractCircuit;

use clap::Parser;
use mapreduce_plonky2::{
    eth::{left_pad32, StorageSlot},
    utils::keccak256,
};

const PARAM_FILE: &str = "mapreduce_test.params";
// depth of the lpn block database
const MAX_BLOCK_DEPTH: usize = 2;
// max depth of storage MPT trie we support for extracting the length
const MAX_STORAGE_DEPTH: usize = 5;

#[derive(Parser)]
struct CliParams {
    /// set to true if you want to load the params from the file
    /// otherwise it generates them by default
    #[arg(short, long)]
    load: Option<bool>,
}

/// NOTE: might require tweaking /etc/security/limits file if STACK error appears
#[tokio::main]
async fn main() -> Result<()> {
    pretty_env_logger::init_timed();

    panic::set_hook(Box::new(|panic_info| {
        let backtrace = Backtrace::new();
        log::error!("Panic occurred: {:?}", panic_info);
        log::error!("Backtrace: {:?}", backtrace);
    }));
    let args = CliParams::parse();
    println!("Hello, world!");
    let ctx = Context::build(args).await?;
    full_flow_pudgy(ctx).await?;
    Ok(())
}

fn enable_logging() {
    if !log_enabled!(Level::Debug) {
        env::set_var("RUST_LOG", "debug");
        let _ = env_logger::builder()
            .format(|buf, record| writeln!(buf, "    {}", record.args()))
            .try_init();
        log::set_max_level(LevelFilter::Debug);
    }
}

fn load_or_generate_params<F, T: Serialize + for<'a> Deserialize<'a>>(
    load: bool,
    factory: F,
) -> Result<T>
where
    F: FnOnce() -> T,
{
    let file_exists = std::path::Path::new(PARAM_FILE).exists();
    if file_exists && load {
        log::info!("File exists, loading parameters");
        let file = File::open(PARAM_FILE)?;
        let params = bincode::deserialize_from(&file)?;
        Ok(params)
    } else {
        log::info!("Building parameters (file exists {})", file_exists);
        let file = File::create(PARAM_FILE)?;
        let params = factory();
        log::info!("Serializing the parameters");
        bincode::serialize_into(file, &params)?;
        Ok(params)
    }
}

struct Context {
    params: api::PublicParameters<MAX_BLOCK_DEPTH>,
    provider: Provider<Http>,
    mapping_slot: u8,
    length_slot: u8,
    contract: Address,
    owner: Address,
    nft_ids: Vec<u32>,
    block: Block<TxHash>,
    mapping_keys: Vec<[u8; 32]>,
}

fn build_params() -> api::PublicParameters<MAX_BLOCK_DEPTH> {
    crate::api::build_circuits_params::<MAX_BLOCK_DEPTH>()
}

fn build_fake() -> Vec<u8> {
    vec![1, 2, 3, 4]
}

impl Context {
    async fn build(c: CliParams) -> Result<Self> {
        log::info!(
            "Fetching/Generating parameters (load={})",
            c.load.unwrap_or(false)
        );
        let params = load_or_generate_params(c.load.unwrap_or(false), build_params)?;
        let url = get_mainnet_url();
        log::info!("Using JSON RPC url {}", url);
        let provider =
            Provider::<Http>::try_from(url).expect("could not instantiate HTTP Provider");

        // jonathan uploaded contract, erc721enumerable
        let contract = Address::from_str("0x363971EE2b96f360Ec9D04b5809aFD15c77B1af1").unwrap();
        let mapping_slot = 2;
        let length_slot = 8;
        // info extracted from explorer https://sepolia.etherscan.io/address/0x363971EE2b96f360Ec9D04b5809aFD15c77B1af1
        let owner = Address::from_str("0x48211415Fc3e48b1aC5389fdDD4c1755783F6199").unwrap();
        let nft_ids: Vec<u32> = vec![0, 1];
        let block_number = provider.get_block_number().await.unwrap();
        let block = provider.get_block(block_number).await?.unwrap();
        let mapping_keys = nft_ids
            .iter()
            .map(|id| left_pad32(&id.to_be_bytes().to_vec()))
            .collect::<Vec<_>>();
        Ok(Self {
            params,
            provider,
            mapping_slot,
            length_slot,
            contract,
            owner,
            nft_ids,
            block,
            mapping_keys,
        })
    }

    async fn mapping_proofs(&self) -> Result<EIP1186ProofResponse> {
        log::info!("Fetching mapping mpt proofs from JSON RPC");
        let storage_slots = self
            .mapping_keys
            .iter()
            .map(|mk| StorageSlot::Mapping(mk.to_vec(), self.mapping_slot as usize))
            .collect::<Vec<_>>();
        let locations = storage_slots
            .iter()
            .map(|s| s.location())
            .collect::<Vec<_>>();
        let block = BlockId::Number(BlockNumber::Number(self.block.number.unwrap()));
        let res = self
            .provider
            .get_proof(self.contract, locations, Some(block))
            .await?;
        Ok(res)
    }

    async fn length_extract_proof(&self) -> Result<EIP1186ProofResponse> {
        log::info!("Fetching length extract proof from JSON RPC");
        let query = SimpleSlot::new(self.length_slot);
        let block = self.provider.get_block_number().await.unwrap();
        let block = BlockId::Number(BlockNumber::Number(block));
        let res = self
            .provider
            .get_proof(self.contract, vec![query.location()], Some(block))
            .await?;
        Ok(res)
    }

    fn mapping_values(&self) -> Vec<Vec<u8>> {
        // same owner for all the nft ids
        std::iter::repeat(left_pad32(&self.owner.to_fixed_bytes()).to_vec())
            .take(self.mapping_keys.len())
            .collect()
    }

    fn mapping_keys_vec(&self) -> Vec<Vec<u8>> {
        self.mapping_keys.iter().map(|k| k.to_vec()).collect()
    }
}

struct StorageProver<'a> {
    ctx: &'a Context,
    mpt_root_proof: Vec<u8>,
}

impl<'a> StorageProver<'a> {
    async fn build_storage_proofs(
        ctx: &'a Context,
        mpt_proofs: &EIP1186ProofResponse,
    ) -> Result<Self> {
        // create list of all MPT storage node related to the mappping to prove
        // key is hash of the nodes, value is the struct
        let mut leaf_hashes = Vec::new();
        let mut node_set =
            mpt_proofs
                .storage_proof
                .iter()
                .enumerate()
                .fold(HashMap::new(), |mut acc, (i, p)| {
                    leaf_hashes.push(keccak256(&p.proof.last().cloned().unwrap()));
                    let _ = p.proof.iter().rev().map_windows(|[child, parent]| {
                        let parent_hash = keccak256(parent);
                        let node_type = {
                            let list: Vec<Vec<u8>> = rlp::decode_list(child);
                            match list.len() {
                                17 => NodeType::Branch,
                                2 => {
                                    let nib = Nibbles::from_compact(&list[0]);
                                    if nib.is_leaf() {
                                        NodeType::Leaf(ctx.mapping_keys[i])
                                    } else {
                                        NodeType::Extension
                                    }
                                }
                                _ => panic!("unexpected node type"),
                            }
                        };
                        let ntp = NodeToProve::new(child.to_vec(), parent_hash.clone(), node_type);
                        let entry = acc.entry(ntp.hash()).or_insert(ntp);
                        entry.increase_child_count();
                        assert_eq!(entry.parent_hash, parent_hash);
                    });
                    acc
                });
        // start proving the leaf hashes and continuously prove parents nodes until we reach the root
        let mut nodes_to_prove = VecDeque::from(leaf_hashes.clone());
        let root_hash = keccak256(&mpt_proofs.storage_proof[0].proof[0]);
        let mut root_proof = None;
        while nodes_to_prove.len() > 0 {
            let node_hash = nodes_to_prove.pop_front().unwrap();
            let node = node_set.get(&node_hash).unwrap();
            let node_buff = node.node.clone();
            let circuit_input = match node.node_type {
                NodeType::Leaf(mapping_key) => {
                    log::info!(
                        "Proving leaf hash {}/{}: {}",
                        leaf_hashes.len() - nodes_to_prove.len(),
                        leaf_hashes.len(),
                        hex::encode(&node_hash)
                    );
                    storage::mapping::api::CircuitInput::new_leaf(
                        node_buff,
                        ctx.mapping_slot as usize,
                        mapping_key.to_vec(),
                    )
                }
                NodeType::Extension => {
                    log::info!("Proving extension hash: {}", hex::encode(&node_hash));
                    storage::mapping::CircuitInput::new_extension(
                        node_buff,
                        node.children_proofs[0].clone(),
                    )
                }
                NodeType::Branch => {
                    log::info!("Proving branch node hash: {}", hex::encode(&node_hash));
                    storage::mapping::CircuitInput::new_branch(
                        node_buff,
                        node.children_proofs.clone(),
                    )
                }
            };
            let proof = crate::api::generate_proof(
                &ctx.params,
                crate::api::CircuitInput::Mapping(circuit_input),
            )?;
            let parent_hash = node.parent_hash.clone();
            let parent = node_set.get_mut(&parent_hash).unwrap();
            if parent_hash == root_hash {
                root_proof = Some(proof);
                break;
            }
            parent.add_child_proof(proof);
            if parent.is_ready_to_be_proven() {
                log::info!(
                    "Parent node pushed to proving queue, hash: {}",
                    hex::encode(parent.hash())
                );
                nodes_to_prove.push_back(parent.hash());
            }
        }
        assert!(root_proof.is_some());
        let root_proof = root_proof.unwrap();
        Ok(Self {
            ctx,
            mpt_root_proof: root_proof,
        })
    }
}

async fn full_flow_pudgy(ctx: Context) -> Result<()> {
    log::info!("Fetching mapping mpt proofs");
    let mpt_proofs = ctx.mapping_proofs().await?;
    ProofQuery::verify_storage_proof(&mpt_proofs)?;
    log::info!("Fetching length mpt proofs");
    let length_mpt_proofs = ctx.length_extract_proof().await?;
    ProofQuery::verify_storage_proof(&length_mpt_proofs)?;
    log::info!("building storage proofs");
    let storage_prover = StorageProver::build_storage_proofs(&ctx, &mpt_proofs).await?;
    // we want to extract the length of the mapping
    let length_extract_input =
        ArrayLengthExtractCircuit::<MAX_STORAGE_DEPTH, MAX_BRANCH_NODE_LEN>::new(
            ctx.length_slot,
            length_mpt_proofs.storage_proof[0]
                .proof
                .iter()
                .rev()
                .map(|b| b.to_vec())
                .collect::<Vec<_>>(),
        );
    log::info!("Generating length_extract proof");
    let length_proof = crate::api::generate_proof(
        &ctx.params,
        crate::api::CircuitInput::LengthExtract(length_extract_input),
    )?;
    log::info!("Generating length_match proof");
    // now we want to do the length equality check
    let length_match_input =
        length_match::CircuitInput::new(storage_prover.mpt_root_proof.clone(), length_proof);
    let length_match_proof = crate::api::generate_proof(
        &ctx.params,
        crate::api::CircuitInput::LengthMatch(length_match_input),
    )?;

    // now we need to build the tree of the LPN storage DB
    let lpn_storage_root = build_storage_db(ctx.mapping_keys_vec(), ctx.mapping_values());
    let lpn_storage_root_proof =
        build_storage_proofs(&ctx, ctx.mapping_keys_vec(), ctx.mapping_values())?;
    // create the proof of equivalence
    let inputs = api::CircuitInput::DigestEqual(storage::digest_equal::CircuitInput::new(
        lpn_storage_root_proof,
        length_match_proof,
    ));
    let digest_equivalence_proof = api::generate_proof(&ctx.params, inputs)?;
    // now create the block linking proof
    let block_linking_inputs = mapreduce_plonky2::state::block_linking::CircuitInput::new(
        digest_equivalence_proof,
        ctx.block.rlp(),
        mpt_proofs
            .account_proof
            .iter()
            .map(|p| p.to_vec())
            .rev()
            .collect::<Vec<_>>(),
        ctx.contract,
    );
    let block_linking_proof = api::generate_proof(
        &ctx.params,
        api::CircuitInput::BlockLinking(block_linking_inputs),
    )?;
    // now we need to create the LPN state tree
    // in v0, only one contract supported so it's easy
    let state_leaf = state::lpn::state_leaf_hash(
        ctx.contract,
        ctx.mapping_slot,
        ctx.length_slot,
        lpn_storage_root,
    );
    let lpn_state_root = state_leaf.clone();
    let state_leaf_proof = api::generate_proof(
        &ctx.params,
        api::CircuitInput::State(state::lpn::api::CircuitInput::new_leaf(block_linking_proof)),
    )?;

    // then we can finally build the state database
    let (_, lpn_db_root, frontier) = build_first_block_root(&ctx, lpn_state_root);
    let lpn_block_input = mapreduce_plonky2::block::BlockTreeCircuit::new(0, lpn_db_root, frontier);
    let inputs = mapreduce_plonky2::block::CircuitInput::input_for_first_block(
        lpn_block_input,
        state_leaf_proof.to_vec(),
    );
    let lpn_block_proof = api::generate_proof(&ctx.params, api::CircuitInput::BlockDB(inputs))?;
    Ok(())
}

pub const D: usize = 2;
pub type C = PoseidonGoldilocksConfig;
pub type F = <C as GenericConfig<D>>::F;

fn build_first_block_root(
    ctx: &Context,
    state_root: HashOutput,
) -> (HashOutput, HashOutput, Vec<HashOutput>) {
    let first_leaf = block_leaf_hash(
        ctx.block.number.unwrap().as_u32(),
        &keccak256(&ctx.block.rlp()).try_into().unwrap(),
        &state_root,
    );
    let leaf_count = 1 << MAX_BLOCK_DEPTH;
    let leaves = std::iter::once(first_leaf.to_vec())
        .chain(std::iter::repeat(vec![]).take(leaf_count - 1))
        .collect::<Vec<_>>();
    let root = merkle_root_bytes(leaves);
    // we dont include the root in the merkle proof
    let frontiers = (0..MAX_BLOCK_DEPTH - 1)
        .map(|i| {
            // we create the empty node at each depth since the first leaf always
            // has empty siblings
            (0..i).fold(HashOut::<F>::from_partial(&[]), |hash, _| {
                PoseidonHash::two_to_one(hash, hash)
            })
        })
        .map(|h| h.to_bytes().try_into().unwrap())
        .collect::<Vec<HashOutput>>();
    (first_leaf, root, frontiers)
}

fn build_storage_proofs(
    ctx: &Context,
    mapping_keys: Vec<Vec<u8>>,
    mapping_values: Vec<Vec<u8>>,
) -> Result<Vec<u8>> {
    let leaves_proof = mapping_keys
        .iter()
        .zip(mapping_values.iter())
        .map(|(k, v)| {
            storage::lpn::api::Input::Leaf(LeafCircuit {
                mapping_key: left_pad32(k),
                mapping_value: left_pad32(v),
            })
        })
        .map(|input| {
            let proof = crate::api::generate_proof(&ctx.params, CircuitInput::Storage(input));
            proof
        })
        .collect::<Result<Vec<_>>>()?;
    let mut nodes = VecDeque::from(leaves_proof.clone());
    let mut new_nodes = VecDeque::new();
    loop {
        while nodes.len() != 1 {
            let left = nodes.pop_front().unwrap();
            let right = nodes.pop_front().unwrap();
            let input = storage::lpn::api::Input::Node(NodeInputs::new(left, right));
            let proof = crate::api::generate_proof(&ctx.params, CircuitInput::Storage(input))?;
            nodes.push_back(proof);
        }
        if nodes.len() == 1 {
            new_nodes.push_back(nodes.pop_back().unwrap());
        }
        nodes = new_nodes.clone();
        new_nodes.clear();
        if nodes.len() == 1 {
            break;
        }
    }
    Ok(nodes.pop_front().unwrap())
}
fn build_storage_db(mapping_keys: Vec<Vec<u8>>, mapping_values: Vec<Vec<u8>>) -> HashOutput {
    assert_eq!(mapping_keys.len(), mapping_values.len());
    let leaves = mapping_keys
        .iter()
        .zip(mapping_values.iter())
        .map(|(k, v)| leaf_hash_for_mapping(k, v))
        .collect::<Vec<_>>();
    let mut nodes = VecDeque::from(leaves.clone());
    // l1,l2,l3 ==>
    //    - l1,l2 => l12,l3
    //    - l12,l3 => root

    let mut new_nodes = VecDeque::new();
    while true {
        while nodes.len() > 1 {
            let left = nodes.pop_front().unwrap();
            let right = nodes.pop_front().unwrap();
            let parent = storage::lpn::intermediate_node_hash(&left, &right);
            new_nodes.push_back(parent);
        }
        if nodes.len() == 1 {
            new_nodes.push_back(nodes.pop_back().unwrap());
        }
        nodes = new_nodes.clone();
        new_nodes.clear();
        if nodes.len() == 1 {
            break;
        }
    }
    nodes.pop_front().unwrap()
}

#[derive(Debug, Clone)]
struct NodeToProve {
    node: Vec<u8>,
    parent_hash: Vec<u8>,
    exp_children: usize,
    children_proofs: Vec<Vec<u8>>,
    node_type: NodeType,
}

#[derive(Debug, Clone)]
enum NodeType {
    // mapping key
    Leaf([u8; 32]),
    Extension,
    Branch,
}

impl NodeToProve {
    fn new(node: Vec<u8>, parent_hash: Vec<u8>, node_type: NodeType) -> Self {
        Self {
            node_type,
            node,
            parent_hash,
            exp_children: 0,
            children_proofs: Vec::new(),
        }
    }
    fn add_child_proof(&mut self, child_proof: Vec<u8>) {
        self.children_proofs.push(child_proof);
    }

    fn is_ready_to_be_proven(&self) -> bool {
        self.children_proofs.len() == self.exp_children
    }
    fn hash(&self) -> Vec<u8> {
        keccak256(&self.node)
    }
    fn increase_child_count(&mut self) {
        self.exp_children += 1;
    }
}

struct LPNValue {
    mapping_key: Vec<u8>,
    mapping_value: Vec<u8>,
}
