use crate::storage::{self, key::MappingSlot};
use anyhow::Result;
use eth_trie::Nibbles;
use ethers::{
    providers::{Http, Middleware, Provider},
    types::Address,
};
use hashbrown::HashMap;
use std::{collections::HashSet, fs::File, str::FromStr};

use crate::{
    eth::{left_pad32, StorageSlot},
    utils::keccak256,
};

const PARAM_FILE: &str = "mapreduce_test.params";
const BLOCK_DEPTH: usize = 2;

fn load_or_generate_params<const BD: usize>(
    load: bool,
) -> Result<crate::api::PublicParameters<BD>> {
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

async fn full_flow_pudgy() -> Result<()> {
    let params = load_or_generate_params::<BLOCK_DEPTH>(false)?;
    #[cfg(feature = "ci")]
    let url = env::var("CI_RPC_URL").expect("CI_RPC_URL env var not set");
    #[cfg(not(feature = "ci"))]
    let url = "https://eth.llamarpc.com";
    let provider = Provider::<Http>::try_from(url).expect("could not instantiate HTTP Provider");

    let contract = Address::from_str("0x188B264AA1456B869C3a92eeeD32117EbB835f47").unwrap();
    let mapping_slot = 3;
    let length_slot = 2;
    let nft_ids: Vec<u32> = vec![0, 1, 2, 3];
    let nft_owners = vec![
        Address::from_str("0x188B264AA1456B869C3a92eeeD32117EbB835f47").unwrap(),
        Address::from_str("0x188B264AA1456B869C3a92eeeD32117EbB835f47").unwrap(),
        Address::from_str("0x188B264AA1456B869C3a92eeeD32117EbB835f47").unwrap(),
        Address::from_str("0x188B264AA1456B869C3a92eeeD32117EbB835f47").unwrap(),
    ];
    let mapping_keys = nft_ids
        .iter()
        .map(|id| left_pad32(&id.to_be_bytes().to_vec()))
        .collect::<Vec<_>>();
    let storage_slots = mapping_keys
        .iter()
        .map(|mk| StorageSlot::Mapping(mk.to_vec(), mapping_slot))
        .collect::<Vec<_>>();
    let locations = storage_slots
        .iter()
        .map(|s| s.location())
        .collect::<Vec<_>>();

    let mpt_proofs = provider.get_proof(contract, locations, None).await?;
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
                                    NodeType::Leaf(mapping_keys[i])
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
    let mut nodes_to_prove = VecDeque::from(leaf_hashes);
    while nodes_to_prove.len() > 0 {
        let node_hash = nodes_to_prove.pop_front().unwrap();
        let node = node_set.get(&node_hash).unwrap();
        let node_buff = node.node.clone();
        let circuit_input = match node.node_type {
            NodeType::Leaf(mapping_key) => {
                let leaf_input = storage::mapping::leaf::LeafCircuit {
                    node: node_buff,
                    slot: MappingSlot::new(mapping_slot as u8, mapping_key.to_vec()),
                };
                storage::mapping::CircuitInput::Leaf(leaf_input)
            }
            NodeType::Extension => storage::mapping::CircuitInput::new_extension(
                node_buff,
                node.children_proofs[0].clone(),
            ),
            NodeType::Branch => {
                storage::mapping::CircuitInput::new_branch(node_buff, node.children_proofs.clone())
            }
        };
        let proof =
            crate::api::generate_proof(&params, crate::api::CircuitInput::Mapping(circuit_input))?;
        let parent_hash = node.parent_hash.clone();
        let parent = node_set.get_mut(&parent_hash).unwrap();
        parent.add_child_proof(proof);
        if parent.is_ready_to_be_proven() {
            nodes_to_prove.push_back(parent.hash());
        }
    }
    Ok(())
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
