//! MPT utility functions

use crate::{
    array::Array,
    utils::{find_index_subvector, keccak256, less_than},
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

/// Decodes the RLP header (assuming it's a value < 0x80 or less than 55 bytes)
///
/// Left pad the leaf value
/// return as big-endian.
/// NOTE: WARNING: RLP_VALUE_LEN MUST include an additional byte for a potential
/// RLP header. For example, in EVM, every value can be up to 32 bytes. One must
/// input 33 in this function because the RLP header might take a full additional byte.
pub fn left_pad_leaf_value<
    F: RichField + Extendable<D>,
    const D: usize,
    const RLP_VALUE_LEN: usize,
    const PADDED_LEN: usize,
>(
    b: &mut CircuitBuilder<F, D>,
    value: &Array<Target, RLP_VALUE_LEN>,
) -> Array<Target, PADDED_LEN> {
    // Read the length of the relevant data (RLP header - 0x80)
    let zero = b.zero();
    let one = b.one();

    let prefix = value[0];
    let byte_80 = b.constant(F::from_canonical_usize(128));
    let is_single_byte = less_than(b, prefix, byte_80, 8);
    let value_len_80 = b.sub(value[0], byte_80);
    let value_len = b.select(is_single_byte, one, value_len_80);
    let offset = b.select(is_single_byte, zero, one);

    // So the value is just in the first byte if is_single_byte is true
    // Hence the first index we take is offset + value_len - 1 and then we continue until we hit
    // offset
    let tmp = b.add(offset, value_len);
    let start = b.sub(tmp, one);

    let mut last_byte_found = b._false();

    let mut result_bytes = [zero; PADDED_LEN];

    // Need the length to be a power of two
    let ram_value = if !value.arr.len().is_power_of_two() {
        let new_size = value.arr.len().next_power_of_two();
        let mut value_vec = value.arr.to_vec();
        value_vec.resize(new_size, zero);
        value_vec
    } else {
        value.arr.to_vec()
    };

    result_bytes
        .iter_mut()
        .rev()
        .enumerate()
        .for_each(|(i, out_byte)| {
            // offset = info.byte_offset + i
            let index = b.constant(F::from_canonical_usize(i));
            let inner_offset = b.sub(start, index);
            // Set to 0 if found the last byte.
            let inner_offset = b.select(last_byte_found, zero, inner_offset);

            // Since VALUE_LEN is a constant that is determined at compile time this conditional won't
            // cause any issues with the circuit.
            let byte = if RLP_VALUE_LEN <= 64 {
                b.random_access(inner_offset, ram_value.clone())
            } else {
                value.random_access_large_array(b, inner_offset)
            };

            // Now if `last_byte_found` is true we add zero, otherwise add `byte`
            let to_add = b.select(last_byte_found, zero, byte);

            *out_byte = b.add(*out_byte, to_add);
            // is_last_byte = offset == last_byte_offset
            let is_last_byte = b.is_equal(inner_offset, offset);
            // last_byte_found |= is_last_byte
            last_byte_found = b.or(last_byte_found, is_last_byte);
        });

    Array::<Target, PADDED_LEN>::from_array(result_bytes)

    // value
    //     // WARNING: this is a hack to avoid another const generic but
    //     // what we should really do here is extract RLP_VALUE_LEN-1 because we
    //     // consider 1 extra byte for the RLP header always (which may or may not exist)
    //     .extract_array::<F, _, RLP_VALUE_LEN>(b, offset)
    //     .into_vec(value_len)
    //     .normalize_left::<_, _, PADDED_LEN>(b)
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
