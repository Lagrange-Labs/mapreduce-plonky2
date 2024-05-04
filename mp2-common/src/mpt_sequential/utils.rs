//! MPT utility functions

use crate::{
    array::Array,
    rlp::short_string_len,
    utils::{find_index_subvector, keccak256},
};
use eth_trie::Nibbles;
use plonky2::{
    field::extension::Extendable, hash::hash_types::RichField, iop::target::Target,
    plonk::circuit_builder::CircuitBuilder,
};

pub fn bytes_to_nibbles(bytes: &[u8]) -> Vec<u8> {
    let mut nibbles = Vec::new();
    for b in bytes {
        nibbles.push(b >> 4);
        nibbles.push(b & 0x0F);
    }
    nibbles
}

pub fn nibbles_to_bytes(nibbles: &[u8]) -> Vec<u8> {
    let mut padded = nibbles.to_vec();
    if padded.len() % 2 == 1 {
        padded.insert(0, 0);
    }
    let mut bytes = Vec::new();
    for i in 0..nibbles.len() / 2 {
        bytes.push((nibbles[i * 2] << 4) | (nibbles[i * 2 + 1] & 0x0F));
    }
    bytes
}

/// Left pad the leaf value and return as big-endian.
pub fn left_pad_leaf_value<
    F: RichField + Extendable<D>,
    const D: usize,
    const VALUE_LEN: usize,
    const PADDED_LEN: usize,
>(
    b: &mut CircuitBuilder<F, D>,
    value: &Array<Target, VALUE_LEN>,
) -> Array<Target, PADDED_LEN> {
    // Read the length of the relevant RLP data (RLP header - 0x80).
    let data_len = short_string_len(b, &value[0]);

    // Create vector of only the relevant data - skipping the RLP header and
    // stick with the same encoding of the data but pad_left32.
    value
        .take_last::<F, D, PADDED_LEN>()
        .into_vec(data_len)
        .normalize_left::<_, _, PADDED_LEN>(b)
}

pub fn visit_proof(proof: &[Vec<u8>]) {
    let mut child_hash = vec![];
    let mut partial_key = vec![];
    for node in proof.iter() {
        visit_node(node, &child_hash, &mut partial_key);
        child_hash = keccak256(node);
        println!(
            "\t=> full partial key: hex {:?}",
            hex::encode(nibbles_to_bytes(&partial_key))
        );
    }
}

pub fn visit_node(node: &[u8], child_hash: &[u8], partial_key: &mut Vec<u8>) {
    println!("[+] Node ({} bytes) {}", node.len(), hex::encode(node));
    let node_list: Vec<Vec<u8>> = rlp::decode_list(node);
    match node_list.len() {
        2 => {
            // extension case: verify the hash is present and lookup the key
            if !child_hash.is_empty() {
                let _ = find_index_subvector(node, child_hash)
                    .expect("extension should contain hash of child");
            }
            // we don't need to decode the RLP header on top of it, since it is
            // already done in the decode_list function.
            let key_nibbles_struct = Nibbles::from_compact(&node_list[0]);
            let key_nibbles = key_nibbles_struct.nibbles();
            println!(
                "\t=> Leaf/Extension node: partial key extracted: {:?}",
                hex::encode(nibbles_to_bytes(key_nibbles))
            );
            partial_key.splice(0..0, key_nibbles.to_vec());
        }
        16 | 17 => {
            // branch case: search the nibble where the hash is present
            let branch_idx = node_list
                .iter()
                .enumerate()
                .find(|(_, h)| *h == child_hash)
                .map(|(i, _)| i)
                .expect("didn't find hash in parent") as u8;
            println!(
                "\t=> Branch node: (len branch = {}) partial key (nibble): {:?}",
                node_list.len(),
                hex::encode(vec![branch_idx]).pop().unwrap()
            );
            partial_key.insert(0, branch_idx);
        }
        _ => {
            panic!("invalid node")
        }
    }
}
