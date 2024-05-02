use eth_trie::{EthTrie, MemoryDB, Trie};
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
