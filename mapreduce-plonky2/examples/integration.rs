#![feature(iter_map_windows)]
#![feature(generic_const_exprs)]
#![feature(generic_arg_infer)]
#![feature(const_for)]
#![feature(generic_const_items)]
use anyhow::Result;
use backtrace::Backtrace;
use eth_trie::Nibbles;
use ethers::{
    providers::{Http, Middleware, Provider},
    types::{Address, BlockId, BlockNumber, EIP1186ProofResponse, U64},
};
use hashbrown::HashMap;
use log::{log_enabled, Level, LevelFilter};
use mapreduce_plonky2::{
    api,
    eth::{get_mainnet_url, ProofQuery},
    storage::{self, key::SimpleSlot, length_match, MAX_BRANCH_NODE_LEN},
    types::HashOutput,
};
use std::{env, fs::File, str::FromStr};
use std::{io::Write, panic};
use storage::length_extract::ArrayLengthExtractCircuit;

use clap::Parser;
use mapreduce_plonky2::{
    eth::{left_pad32, StorageSlot},
    utils::keccak256,
};

const PARAM_FILE: &str = "mapreduce_test.params";
const BLOCK_DEPTH: usize = 2;
const MAX_STORAGE_DEPTH: usize = 5;

#[derive(Parser)]
struct CliParams {
    /// set to true if you want to load the params from the file
    /// otherwise it generates them by default
    #[arg(short, long)]
    load: Option<bool>,
}

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

fn load_or_generate_params<const BD: usize>(load: bool) -> Result<api::PublicParameters<BD>> {
    let mut file = File::create(PARAM_FILE)?;
    if load {
        let params = bincode::deserialize_from(&mut file)?;
        Ok(params)
    } else {
        let params = crate::api::build_circuits_params::<BD>();
        bincode::serialize_into(&mut file, &params)?;
        Ok(params)
    }
}

struct Context {
    params: api::PublicParameters<BLOCK_DEPTH>,
    provider: Provider<Http>,
    mapping_slot: u8,
    length_slot: u8,
    contract: Address,
    owner: Address,
    nft_ids: Vec<u32>,
    block: U64,
    mapping_keys: Vec<[u8; 32]>,
}

impl Context {
    async fn build(c: CliParams) -> Result<Self> {
        log::info!(
            "Fetching/Generating parameters (load={})",
            c.load.unwrap_or(false)
        );
        let params = load_or_generate_params::<BLOCK_DEPTH>(c.load.unwrap_or(false))?;
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
        let block = provider.get_block_number().await.unwrap();
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
        let block = BlockId::Number(BlockNumber::Number(self.block));
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
}

async fn full_flow_pudgy(ctx: Context) -> Result<()> {
    let mpt_proofs = ctx.mapping_proofs().await?;
    let length_mpt_proofs = ctx.length_extract_proof().await?;
    ProofQuery::verify_storage_proof(&mpt_proofs)?;
    ProofQuery::verify_storage_proof(&length_mpt_proofs)?;
    // create a list of all the mapping keys/values pair we want to transform in our database
    let values = mpt_proofs
        .storage_proof
        .iter()
        .map(|p| {
            let list: Vec<Vec<u8>> = rlp::decode_list(&p.proof.last().cloned().unwrap());
            let mut mapping_key = Vec::new();
            p.key.to_big_endian(&mut mapping_key[..]);
            let value: Vec<u8> = rlp::decode(&list[1]).unwrap();
            LPNValue {
                mapping_key,
                mapping_value: value,
            }
        })
        .collect::<Vec<_>>();
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
    use std::collections::VecDeque;
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
                storage::mapping::CircuitInput::new_branch(node_buff, node.children_proofs.clone())
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
    let length_match_input = length_match::CircuitInput::new(root_proof.unwrap(), length_proof);
    let length_match_proof = crate::api::generate_proof(
        &ctx.params,
        crate::api::CircuitInput::LengthMatch(length_match_input),
    )?;

    // now we need to build the tree of the LPN storage DB

    Ok(())
}

//fn build_storage_db(mapping_keys: Vec<Vec<u8>>, mapping_values: Vec<Vec<u8>>) -> HashOutput {
//
//}

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
