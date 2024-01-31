use crate::{
    array::{Array, Vector, VectorWire},
    keccak::{InputData, KeccakWires, HASH_LEN, PACKED_HASH_LEN},
    rlp::{
        decode_compact_encoding, decode_fixed_list, decode_header, decode_tuple, extract_array,
        RlpList, MAX_ITEMS_IN_LIST, MAX_KEY_NIBBLE_LEN,
    },
    utils::{convert_u8_to_u32, find_index_subvector, keccak256, less_than},
};
use anyhow::{anyhow, Result};
use core::array::from_fn as create_array;
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::{
        target::{BoolTarget, Target},
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::circuit_builder::CircuitBuilder,
};
use plonky2_crypto::u32::arithmetic_u32::U32Target;

use crate::keccak::{compute_size_with_padding, KeccakCircuit, OutputHash};
/// Number of items in the RLP encoded list in a leaf node.
const NB_ITEMS_LEAF: usize = 2;
/// Currently a constant set to denote the length of the value we are extracting from the MPT trie.
/// This can later be also be done in a generic way to allow different sizes.
/// Given we target MPT storage proof, the value is 32 bytes.
const MAX_LEAF_VALUE: usize = HASH_LEN;

/// a simple alias to keccak::compute_size_with_padding to make the code a bit
/// more tiny with all these const generics
#[allow(non_snake_case)]
const fn PAD_LEN(d: usize) -> usize {
    compute_size_with_padding(d)
}
/// Circuit that simoply proves the inclusion of a value inside a MPT tree.
/// * DEPTH is the maximal depth of the tree. If the tree is smaller, the circuit
/// will continue proving for "imaginary" nodes
/// * NODE_LEN is the max length of a node in the list of MPT nodes that form
/// the MPT proof. For example, in storage trie, a leaf is 32 bytes max, and a
/// branch node can be up to 32 * 17 = 544 bytes.
///     - Note since it uses keccak, the array being hashed is larger because
/// keccak requires padding.
#[derive(Clone, Debug)]
struct Circuit<const DEPTH: usize, const NODE_LEN: usize> {
    /// for ease of usage, we take vector here and the circuit is doing the padding
    nodes: Vec<Vec<u8>>,
}

struct Wires<const DEPTH: usize, const NODE_LEN: usize>
where
    [(); PAD_LEN(NODE_LEN)]:,
    [(); DEPTH - 1]:,
{
    /// a vector of buffers whose size is the padded size of the maximum node length
    /// the padding may occur anywhere in the array but it can fit the maximum node size
    /// NOTE: this makes the code a bit harder grasp at first, but it's a straight
    /// way to define everything according to max size of the data and
    /// "not care" about the padding size (almost!)
    nodes: [VectorWire<{ PAD_LEN(NODE_LEN) }>; DEPTH],

    /// We need to keep around the hashes wires because keccak needs to assign
    /// some additional wires for each input (see keccak circuit for more info.).
    keccak_wires: [KeccakWires<{ PAD_LEN(NODE_LEN) }>; DEPTH],

    /// in the case of a fixed circuit, the actual tree depth might be smaller.
    /// In this case, we set false on the part of the path we should not process.
    /// NOTE: for node at index i in the path, the boolean indicating if we should
    /// process it is at index i-1
    should_process: [BoolTarget; DEPTH - 1],
    /// At each intermediate node up to the root, we should find the hash of the children
    /// in its byte representation. That array indicates where the hash is located in the
    /// node.
    /// NOTE: for node at index  i in the path, the index where to find the children hash is
    /// located at index i-1.
    child_hash_index: [Target; DEPTH - 1],
    /// The leaf value wires. It is provably extracted from the leaf node.
    leaf: Array<Target, MAX_LEAF_VALUE>,
}

impl<const DEPTH: usize, const NODE_LEN: usize> Circuit<DEPTH, NODE_LEN>
where
    [(); PAD_LEN(NODE_LEN)]:,
    [(); DEPTH - 1]:,
{
    pub fn new(nodes: Vec<Vec<u8>>) -> Self {
        Self { nodes }
    }
    /// Build the sequential hashing of nodes. It returns the wires that contains
    /// the root hash (according to the "should_process" array) and the wires
    /// to assign during proving time, including each of the nodes in the path.
    pub fn build<F, const D: usize>(
        b: &mut CircuitBuilder<F, D>,
    ) -> (OutputHash, Wires<DEPTH, NODE_LEN>)
    where
        F: RichField + Extendable<D>,
    {
        let zero = b.zero();
        // full key is expected to be given by verifier (done in UserCircuit impl)
        // initial key has the pointer that is set at the maximum length - 1 (it's an index, so 0-based)
        let full_key = b.add_virtual_target_arr::<MAX_KEY_NIBBLE_LEN>();
        let mut iterative_key = MPTKeyWire {
            key: Array::<Target, MAX_KEY_NIBBLE_LEN>::new(b),
            pointer: b.constant(F::from_canonical_usize(MAX_KEY_NIBBLE_LEN).sub_one()),
        };
        let should_process: [BoolTarget; DEPTH - 1] =
            create_array(|_| b.add_virtual_bool_target_safe());
        let index_hashes: [Target; DEPTH - 1] = create_array(|_| b.add_virtual_target());
        // nodes should be ordered from leaf to root and padded at the end
        let nodes: [VectorWire<_>; DEPTH] =
            create_array(|_| VectorWire::<{ PAD_LEN(NODE_LEN) }>::new(b));
        // hash the leaf first and advance the key
        let leaf_hash = KeccakCircuit::<{ PAD_LEN(NODE_LEN) }>::hash_vector(b, &nodes[0]);
        // we don't anything with the value apart from setting it in the wire so the circuit using this can decide
        // what to do with it (exposing as public input, computing over it etc)
        let leaf_headers = decode_fixed_list::<_, _, NB_ITEMS_LEAF>(b, &nodes[0].arr.arr, zero);
        let (iterative_key, leaf_value, is_leaf) =
            Self::advance_key_leaf_or_extension(b, &nodes[0].arr, &iterative_key, &leaf_headers);
        let mut last_hash_output = leaf_hash.output_array.clone();
        let mut keccak_wires = vec![leaf_hash];
        let t = b._true();
        // we skip the first node which is the leaf
        for i in 1..DEPTH {
            let is_real = should_process[i - 1];
            let at = index_hashes[i - 1];
            // hash the next node first. We do this so we can get the U32 equivalence of the node
            let hash_wires = KeccakCircuit::<{ PAD_LEN(NODE_LEN) }>::hash_vector(b, &nodes[i]);
            // look if hash is inside the node:
            // extract the hash from u8 array and then convert to u32 and then compare
            let exp_child_hash: Array<Target, HASH_LEN> = nodes[i].arr.extract_array(b, at);
            // TODO : try to use the const generics, for some reason it doesn't work here
            let exp_hash_u32 = Array::<U32Target, PACKED_HASH_LEN> {
                arr: convert_u8_to_u32(b, &exp_child_hash.arr)
                    .try_into()
                    .unwrap(),
            };
            let found_hash_in_parent = exp_hash_u32.equals(b, &last_hash_output);

            // if we don't have to process it, then circuit should never fail at that step
            // otherwise, we should always enforce finding the hash in the parent node
            let is_parent = b.select(is_real, found_hash_in_parent.target, t.target);
            b.connect(is_parent, t.target);

            // and select whether we should update or not
            last_hash_output = hash_wires
                .output_array
                .select(b, is_real, &last_hash_output);
            keccak_wires.push(hash_wires);
        }
        (
            last_hash_output,
            Wires {
                keccak_wires: keccak_wires.try_into().unwrap(),
                nodes,
                should_process,
                child_hash_index: index_hashes,
                leaf: leaf_value,
            },
        )
    }

    /// Assign the nodes to the wires, assign which nodes in the full length array
    /// should we look at (i.e. padding), and the indices where to find the children
    /// hash in the parent hashes.
    fn assign<F: RichField + Extendable<D>, const D: usize>(
        &self,
        p: &mut PartialWitness<F>,
        wires: &Wires<DEPTH, NODE_LEN>,
    ) -> Result<()> {
        let pad_len = DEPTH - self.nodes.len();
        // convert nodes to array and pad with empty array if needed
        let padded_nodes = self
            .nodes
            .iter()
            .map(|n| Vector::<{ PAD_LEN(NODE_LEN) }>::from_vec(n.clone()))
            .chain((0..pad_len).map(|_| Vector::<{ PAD_LEN(NODE_LEN) }>::from_vec(vec![])))
            .collect::<Result<Vec<_>>>()?;
        for (i, (wire, node)) in wires.nodes.iter().zip(padded_nodes.iter()).enumerate() {
            wire.assign(p, node);
            KeccakCircuit::<{ PAD_LEN(NODE_LEN) }>::assign(
                p,
                &wires.keccak_wires[i],
                // Given we already assign the input data elsewhere, we notify to keccak circuit
                // that it doesn't need to assign it again, just its add. wires.
                // TODO: this might be doable via a generator implementation with Plonky2...?
                &InputData::Assigned(node),
            );
        }
        // find the index of the child hash in the parent nodes for all nodes in the path
        // and set to true the nodes we should process
        for i in 1..DEPTH {
            if i < self.nodes.len() {
                // we always process the leaf so we start at index 0 for parent of leaf
                p.set_bool_target(wires.should_process[i - 1], true);
                let child_hash = keccak256(&self.nodes[i - 1]);
                let idx = find_index_subvector(&self.nodes[i], &child_hash)
                    .ok_or(anyhow!("can't find hash in parent node!"))?;
                p.set_target(wires.child_hash_index[i - 1], F::from_canonical_usize(idx));
            } else {
                p.set_bool_target(wires.should_process[i - 1], false);
                p.set_target(wires.child_hash_index[i - 1], F::ZERO);
            }
        }
        Ok(())
    }

    /// Returns the MPT key advanced, depending on if it's a branch of leaf node, and returns
    /// the designated children value/hash from the node.
    ///
    /// It tries to decode the node as a branch node, and as an extension / leaf node,
    /// and select the right key depending on the number of elements found in the node.
    /// nibble is used to lookup the right item if it's a branch node
    /// Return is the (key,value). Key is in nibble format. Value is in bytes,
    /// and is either the hash of the child node, or the value of the leaf.
    /// ASSUMPTION: value of leaf is always 32 bytes.
    fn advance_key<F: RichField + Extendable<D>, const D: usize>(
        b: &mut CircuitBuilder<F, D>,
        node: &Array<Target, { PAD_LEN(NODE_LEN) }>,
        key: &MPTKeyWire,
    ) -> (MPTKeyWire, Array<Target, HASH_LEN>) {
        let zero = b.zero();
        let two = b.two();
        // It will try to decode a RLP list of the maximum number of items there can be
        // in a list, which is 16 for a branch node (Excluding value).
        // It returns the actual number of items decoded.
        // If it's 2 ==> node's a leaf or an extension
        //              RLP ( RLP ( enc (key)), RLP( hash / value))
        // if it's more ==> node's a branch node
        //              RLP ( RLP(hash1), RLP(hash2), ... RLP(hash16), RLP(value))
        //              (can be shorter than that ofc)
        let rlp_headers = decode_fixed_list::<F, D, MAX_ITEMS_IN_LIST>(b, &node.arr, zero);
        let is_tuple = b.is_equal(rlp_headers.num_fields, two);
        let leaf_info = Self::advance_key_leaf_or_extension(b, node, key, &rlp_headers);
        let tuple_condition = b.and(is_tuple, leaf_info.2);
        let branch_info = Self::advance_key_branch(b, node, key, &rlp_headers);
        // Ensures that conditions in a tuple are valid OR conditions in a branch are valid. So we can select the
        // right output depending only on one condition only.
        let mut branch_condition = b.not(is_tuple);
        branch_condition = b.and(branch_condition, branch_info.2);
        let tuple_or_branch = b.or(branch_condition, tuple_condition);
        b.assert_bool(tuple_or_branch);

        // select between the two outputs
        // Note we assume that if it is not a tuple, it is necessarily a branch node.
        // If attacker gives invalid node, hash will not match anyway.
        let child_hash = leaf_info.1.select(b, tuple_condition, &branch_info.1);
        let new_key = leaf_info.0.select(b, tuple_condition, &branch_info.0);
        (new_key, child_hash)
    }

    /// Returns the key with the pointer moved, returns the child hash / value of the node,
    /// and returns booleans that must be true IF the given node is a leaf or an extension.
    fn advance_key_branch<F: RichField + Extendable<D>, const D: usize>(
        b: &mut CircuitBuilder<F, D>,
        node: &Array<Target, { PAD_LEN(NODE_LEN) }>,
        key: &MPTKeyWire,
        rlp_headers: &RlpList<MAX_ITEMS_IN_LIST>,
    ) -> (MPTKeyWire, Array<Target, HASH_LEN>, BoolTarget) {
        let one = b.one();
        // assume it's a node and return the boolean condition that must be true if
        // it is a node - decided in advance_key function
        let is_node = b._true();
        // Given we are reading the nibble from the key itself, we don't need to do
        // any more checks on it. The key and pointer will be given by the verifier so
        // attacker can't indicate a different nibble
        let nibble = key.current_nibble(b);
        // assert that the nibble is less than the number of items since it's given by prover
        let lt = less_than(b, nibble, rlp_headers.num_fields, 4);
        let branch_condition = b.and(is_node, lt);

        // we advance the pointer for the next iteration
        let new_key = key.advance_by(b, one);
        let nibble_header = rlp_headers.select(b, nibble);
        let branch_child_hash = node.extract_array::<F, D, HASH_LEN>(b, nibble_header.offset);
        (new_key, branch_child_hash, branch_condition)
    }
    /// Returns the key with the pointer moved, returns the child hash / value of the node,
    /// and returns booleans that must be true IF the given node is a leaf or an extension.
    fn advance_key_leaf_or_extension<
        F: RichField + Extendable<D>,
        const D: usize,
        const LIST_LEN: usize,
    >(
        b: &mut CircuitBuilder<F, D>,
        node: &Array<Target, { PAD_LEN(NODE_LEN) }>,
        key: &MPTKeyWire,
        rlp_headers: &RlpList<LIST_LEN>,
    ) -> (MPTKeyWire, Array<Target, HASH_LEN>, BoolTarget) {
        let zero = b.zero();
        let two = b.two();
        let condition = b.is_equal(rlp_headers.num_fields, two);
        let key_header = rlp_headers.select(b, zero);
        let (extracted_key, should_true) = decode_compact_encoding(b, node, &key_header);
        let value_header = decode_header(b, &node.arr, rlp_headers.offset[1]);
        // it's either the _value_ of the leaf, OR the _hash_ of the child node if node = ext.
        let leaf_child_hash = node.extract_array::<F, D, HASH_LEN>(b, value_header.offset);
        // note we are going _backwards_ on the key, so we need to substract the expected key length
        // we want to check against
        let new_key = key.advance_by(b, extracted_key.real_len);
        // NOTE: there is no need to check if the extracted_key is indeed a subvector of the full key
        // in this case. Indeed, in leaf/ext. there is only one key possible. Since we decoded it
        // from the beginning of the node, and that the hash of the node also starts at the beginning,
        // either the attacker give the right node or it gives an invalid node and hashes will not
        // match.
        let condition = b.and(condition, should_true);
        (new_key, leaf_child_hash, condition)
    }
}

/// A structure that keeps a running pointer to the portion of the key the circuit
/// already has proven.
pub struct MPTKeyWire {
    /// Represents the full key of the value(s) we're looking at in the MPT trie.
    pub key: Array<Target, MAX_KEY_NIBBLE_LEN>,
    /// Represents which portion of the key we already processed. The pointer
    /// goes _backwards_ since circuit starts proving from the leaf up to the root.
    /// i.e. pointer must be equal to 0 when we reach the root.
    pub pointer: Target,
}

impl MPTKeyWire {
    pub fn current_nibble<F: RichField + Extendable<D>, const D: usize>(
        &self,
        b: &mut CircuitBuilder<F, D>,
    ) -> Target {
        self.key.value_at(b, self.pointer)
    }

    /// move the pointer to the next nibble. In this implementation it is the
    /// _previous_ nibble since we are proving from bottom to up in the trie.
    pub fn advance_by<F: RichField + Extendable<D>, const D: usize>(
        &self,
        b: &mut CircuitBuilder<F, D>,
        len: Target,
    ) -> Self {
        Self {
            key: self.key.clone(),
            pointer: b.sub(self.pointer, len),
        }
    }

    /// Returns self if condition is true, otherwise returns other.
    /// NOTE: it is expected the two keys are the same, it always return
    /// the key from `self`. Only the pointer is selected.
    pub fn select<F: RichField + Extendable<D>, const D: usize>(
        &self,
        b: &mut CircuitBuilder<F, D>,
        condition: BoolTarget,
        other: &Self,
    ) -> Self {
        Self {
            key: self.key.clone(),
            pointer: b.select(condition, self.pointer, other.pointer),
        }
    }

    /// Create a new fresh key wire
    pub fn new<F: RichField + Extendable<D>, const D: usize>(b: &mut CircuitBuilder<F, D>) -> Self {
        Self {
            key: Array::<Target, MAX_KEY_NIBBLE_LEN>::new(b),
            pointer: b.add_virtual_target(),
        }
    }
    /// Assign the key wire to the circuit.
    pub fn assign<F: RichField>(
        &self,
        p: &mut PartialWitness<F>,
        key_nibbles: &[u8; MAX_KEY_NIBBLE_LEN],
        ptr: usize,
    ) {
        let f_nibbles = create_array(|i| F::from_canonical_u8(key_nibbles[i]));
        self.key.assign(p, &f_nibbles);
        p.set_target(self.pointer, F::from_canonical_usize(ptr));
    }
}

fn bytes_to_nibbles(bytes: &[u8]) -> Vec<u8> {
    let mut nibbles = Vec::new();
    for b in bytes {
        nibbles.push(b >> 4);
        nibbles.push(b & 0x0F);
    }
    nibbles
}
fn nibbles_to_bytes(nibbles: &[u8]) -> Vec<u8> {
    let mut padded = nibbles.to_vec();
    if padded.len() % 2 == 1 {
        padded.push(0);
    }
    let mut bytes = Vec::new();
    for i in 0..nibbles.len() / 2 {
        bytes.push((nibbles[i * 2] << 4) | (nibbles[i * 2 + 1] & 0x0F));
    }
    bytes
}

#[cfg(test)]
pub mod test {
    use std::sync::Arc;

    use eth_trie::{EthTrie, MemoryDB, Nibbles, Trie};
    use itertools::Itertools;
    use plonky2::field::types::Field;
    use plonky2::iop::witness::WitnessWrite;
    use plonky2::{
        field::extension::Extendable,
        hash::hash_types::RichField,
        iop::{target::Target, witness::PartialWitness},
        plonk::{
            circuit_builder::CircuitBuilder,
            circuit_data::CircuitConfig,
            config::{GenericConfig, PoseidonGoldilocksConfig},
        },
    };
    use rand::{thread_rng, Rng};

    use crate::mpt_sequential::{bytes_to_nibbles, nibbles_to_bytes};
    use crate::rlp::{decode_fixed_list, MAX_ITEMS_IN_LIST, MAX_KEY_NIBBLE_LEN};
    use crate::{
        array::{Array, VectorWire},
        circuit::{test::test_simple_circuit, UserCircuit},
        keccak::OutputHash,
        mpt_sequential::MPTKeyWire,
        utils::{find_index_subvector, keccak256},
    };

    use super::{Circuit, Wires, PAD_LEN};
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    #[derive(Clone, Debug)]
    struct TestCircuit<const DEPTH: usize, const NODE_LEN: usize> {
        c: Circuit<DEPTH, NODE_LEN>,
        exp_root: [u8; 32],
    }
    impl<F, const D: usize, const DEPTH: usize, const NODE_LEN: usize> UserCircuit<F, D>
        for TestCircuit<DEPTH, NODE_LEN>
    where
        F: RichField + Extendable<D>,
        [(); PAD_LEN(NODE_LEN)]:,
        [(); DEPTH - 1]:,
        [(); PAD_LEN(NODE_LEN) / 4]:,
    {
        type Wires = (OutputHash, Wires<DEPTH, NODE_LEN>);

        fn build(c: &mut CircuitBuilder<F, D>) -> Self::Wires {
            let leaf = VectorWire::<{ PAD_LEN(NODE_LEN) }>::new(c);
            Circuit::build(c)
        }

        fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
            self.c.assign(pw, &wires.1).unwrap();
        }
    }
    #[test]
    fn test_mpt_proof_verification() {
        // max depth of the trie
        const DEPTH: usize = 4;
        // leave one for padding
        const ACTUAL_DEPTH: usize = DEPTH - 1;
        // max len of a node
        const NODE_LEN: usize = 80;
        let (mut trie, key) = generate_random_storage_mpt::<ACTUAL_DEPTH, NODE_LEN>();
        let root = trie.root_hash().unwrap();
        // root is first so we reverse the order as in circuit we prove the opposite way
        let mut proof = trie.get_proof(&key).unwrap();
        proof.reverse();
        assert!(proof.len() == ACTUAL_DEPTH);
        assert!(proof.len() <= DEPTH);
        assert!(keccak256(proof.last().unwrap()) == root.to_fixed_bytes());
        println!("PROOF LEN = {}", proof.len());
        for i in 1..proof.len() {
            let child_hash = keccak256(&proof[i - 1]);
            let u8idx = find_index_subvector(&proof[i], &child_hash);
            assert!(u8idx.is_some());
        }
        // println!(
        //     "first item {:?} vs root {:} vs last item {:?}",
        //     hex::encode(keccak256(proof.first().unwrap())),
        //     hex::encode(root.to_fixed_bytes()),
        //     hex::encode(keccak256(proof.last().unwrap()))
        // );
        let circuit = TestCircuit::<DEPTH, NODE_LEN> {
            c: Circuit::<DEPTH, NODE_LEN>::new(proof),
            exp_root: root.to_fixed_bytes(),
        };
        test_simple_circuit::<F, D, C, _>(circuit);
    }

    fn visit_node(node: &[u8], child_hash: &[u8], partial_key: &mut Vec<u8>) {
        let node_list: Vec<Vec<u8>> = rlp::decode_list(&node);
        match node_list.len() {
            2 => {
                // extension case: verify the hash is present and lookup the key
                find_index_subvector(node, child_hash)
                    .expect("extension should contain hash of child");
                // we don't need to decode the RLP header on top of it, since it is
                // already done in the decode_list function.
                let key_nibbles_struct = Nibbles::from_compact(&node_list[0]);
                let key_nibbles = key_nibbles_struct.nibbles();
                println!(
                    "[+] Leaf/Extension node: partial key extracted: {:?}",
                    hex::encode(&nibbles_to_bytes(key_nibbles))
                );
                partial_key.splice(0..0, key_nibbles.to_vec());
            }
            16 | 17 => {
                // branch case: search the nibble where the hash is present
                let branch_idx = node_list
                    .iter()
                    .enumerate()
                    .find(|(_, h)| *h == &child_hash)
                    .map(|(i, _)| i)
                    .expect("didn't find hash in parent") as u8;
                println!(
                    "[+] Branch node: (len branch = {}) partial key (nibble): {:?}",
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

    #[test]
    fn mpt_comprehension() {
        const DEPTH: usize = 4;
        const NODE_LEN: usize = 80;
        const VALUE_LEN: usize = 32;
        let (mut trie, mut key) = generate_random_storage_mpt::<DEPTH, VALUE_LEN>();
        let mut proof = trie.get_proof(&key).unwrap();
        proof.reverse();
        let key_nibbles = bytes_to_nibbles(&key);
        assert_eq!(key_nibbles.len(), MAX_KEY_NIBBLE_LEN);
        println!("[+] key original: {:?}", hex::encode(&key));
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
        assert_eq!(key_nibbles, partial_key);
    }

    #[test]
    fn test_extract_hash_intermediate() {
        const DEPTH: usize = 4;
        const NODE_LEN: usize = 80;
        const VALUE_LEN: usize = 32;
        let (mut trie, key) = generate_random_storage_mpt::<DEPTH, VALUE_LEN>();
        let mut proof = trie.get_proof(&key).unwrap();
        proof.reverse();
        let key_nibbles = bytes_to_nibbles(&key);
        assert_eq!(key_nibbles.len(), MAX_KEY_NIBBLE_LEN);
        // try with the parent of the leaf
        let mut node_byte: Vec<u8> = proof[1].clone();
        let node_list: Vec<Vec<u8>> = rlp::decode_list(&node_byte);
        // make sure the node is a branch node
        assert_eq!(node_list.len(), 17);
        // first see the leaf to determine the partial key length
        let mut leaf_node: Vec<u8> = proof[0].clone();
        // RLP ( RLP (compact(partial_key_in_nibble)), RLP(value))
        let leaf_tuple: Vec<Vec<u8>> = rlp::decode_list(&leaf_node);
        assert_eq!(leaf_tuple.len(), 2);
        let leaf_value: Vec<u8> = rlp::decode(&leaf_tuple[1]).unwrap();
        let leaf_partial_key_struct = Nibbles::from_compact(&leaf_tuple[0]);
        let leaf_partial_key_nibbles = leaf_partial_key_struct.nibbles();
        let leaf_partial_key_ptr = MAX_KEY_NIBBLE_LEN - 1 - leaf_partial_key_nibbles.len();
        // since it's a branch node, we know the pointer is one less
        let node_partial_key_ptr = leaf_partial_key_ptr - 1;
        println!("[+] Node partial key ptr = {}", node_partial_key_ptr);

        let config = CircuitConfig::standard_recursion_config();
        let mut pw = PartialWitness::new();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let zero = builder.zero();
        let node = Array::<Target, { PAD_LEN(NODE_LEN) }>::new(&mut builder);
        let key_wire = MPTKeyWire::new(&mut builder);
        let rlp_headers =
            decode_fixed_list::<F, D, MAX_ITEMS_IN_LIST>(&mut builder, &node.arr, zero);
        let (advanced_key, value, should_true) = Circuit::<DEPTH, NODE_LEN>::advance_key_branch(
            &mut builder,
            &node,
            &key_wire,
            &rlp_headers,
        );
        builder.assert_bool(should_true);
        let exp_key_ptr = builder.add_virtual_target();
        builder.connect(advanced_key.pointer, exp_key_ptr);
        let exp_value = Array::<Target, VALUE_LEN>::new(&mut builder);
        let should_be_true = exp_value.equals(&mut builder, &value);
        builder.assert_bool(should_be_true);
        let data = builder.build::<C>();

        node_byte.resize(PAD_LEN(NODE_LEN), 0);
        let node_f = node_byte
            .iter()
            .map(|b| F::from_canonical_u8(*b))
            .collect::<Vec<_>>();
        node.assign(&mut pw, &node_f.try_into().unwrap());
        let mut key_nibbles = bytes_to_nibbles(&key);
        key_nibbles.resize(MAX_KEY_NIBBLE_LEN, 0);
        key_wire.assign(
            &mut pw,
            &key_nibbles.try_into().unwrap(),
            // we start from the pointer that should have been updated by processing the leaf
            leaf_partial_key_ptr,
        );
        pw.set_target(exp_key_ptr, F::from_canonical_usize(node_partial_key_ptr));
        exp_value.assign(
            &mut pw,
            &leaf_value
                .into_iter()
                .map(F::from_canonical_u8)
                .collect::<Vec<_>>()
                .try_into()
                .unwrap(),
        );
        let proof = data.prove(pw).unwrap();
        data.verify(proof).unwrap();
    }
    #[test]
    fn test_extract_hash_leaf() {
        const DEPTH: usize = 4;
        const NODE_LEN: usize = 80;
        const VALUE_LEN: usize = 32;
        let (mut trie, mut key) = generate_random_storage_mpt::<DEPTH, VALUE_LEN>();
        let mut proof = trie.get_proof(&key).unwrap();
        proof.reverse();
        // try with a leaf MPT encoded node first
        let mut leaf_node: Vec<u8> = proof.first().unwrap().clone();
        let leaf_tuple: Vec<Vec<u8>> = rlp::decode_list(&leaf_node);
        // we rlp-decode again because the value itself is rlp-encoded
        let leaf_value: Vec<u8> = rlp::decode(&leaf_tuple[1]).unwrap();
        let partial_key_struct = Nibbles::from_compact(&leaf_tuple[0]);
        let partial_key_nibbles = partial_key_struct.nibbles();
        let partial_key_ptr = MAX_KEY_NIBBLE_LEN - 1 - partial_key_nibbles.len();
        println!(
            "[+] leaf partial key nibbles = {:?}",
            hex::encode(nibbles_to_bytes(partial_key_nibbles))
        );
        println!("[+] key pointer = {}", partial_key_ptr);

        let config = CircuitConfig::standard_recursion_config();
        let mut pw = PartialWitness::new();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let zero = builder.zero();
        let node = Array::<Target, { PAD_LEN(NODE_LEN) }>::new(&mut builder);
        let key_wire = MPTKeyWire::new(&mut builder);
        let rlp_headers =
            decode_fixed_list::<F, D, MAX_ITEMS_IN_LIST>(&mut builder, &node.arr, zero);
        let (advanced_key, value, should_true) =
            Circuit::<DEPTH, NODE_LEN>::advance_key_leaf_or_extension(
                &mut builder,
                &node,
                &key_wire,
                &rlp_headers,
            );
        let exp_key_ptr = builder.add_virtual_target();
        builder.connect(advanced_key.pointer, exp_key_ptr);
        let exp_value = Array::<Target, VALUE_LEN>::new(&mut builder);
        let should_be_true = exp_value.equals(&mut builder, &value);
        let tt = builder.and(should_be_true, should_true);
        builder.assert_bool(tt);
        let data = builder.build::<C>();

        leaf_node.resize(PAD_LEN(NODE_LEN), 0);
        let leaf_f = leaf_node
            .iter()
            .map(|b| F::from_canonical_u8(*b))
            .collect::<Vec<_>>();
        node.assign(&mut pw, &leaf_f.try_into().unwrap());
        let mut key_nibbles = bytes_to_nibbles(&key);
        key_nibbles.resize(MAX_KEY_NIBBLE_LEN, 0);
        key_wire.assign(
            &mut pw,
            &key_nibbles.try_into().unwrap(),
            MAX_KEY_NIBBLE_LEN - 1,
        );
        pw.set_target(exp_key_ptr, F::from_canonical_usize(partial_key_ptr));
        exp_value.assign(
            &mut pw,
            &leaf_value
                .into_iter()
                .map(F::from_canonical_u8)
                .collect::<Vec<_>>()
                .try_into()
                .unwrap(),
        );
        let proof = data.prove(pw).unwrap();
        data.verify(proof).unwrap();
    }

    // generate a random storage trie and a key. The MPT proof corresponding to
    // that key is guaranteed to be of DEPTH length. Each leaves in the trie
    // is of NODE_LEN length.
    // The returned key is RLP encoded
    pub fn generate_random_storage_mpt<const DEPTH: usize, const VALUE_LEN: usize>(
    ) -> (EthTrie<MemoryDB>, Vec<u8>) {
        let memdb = Arc::new(MemoryDB::new(true));
        let mut trie = EthTrie::new(Arc::clone(&memdb));
        let mut keys = Vec::new();
        let right_key_idx: usize;
        // loop: insert random elements as long as a random selected proof is not of the right length
        loop {
            println!("-> Insertion of {} elements so far...", keys.len());
            let key = thread_rng().gen::<[u8; MAX_KEY_NIBBLE_LEN / 2]>().to_vec();
            let random_bytes = (0..VALUE_LEN)
                .map(|_| thread_rng().gen::<u8>())
                .collect::<Vec<_>>();
            trie.insert(&key, &rlp::encode(&random_bytes))
                .expect("can't insert");
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
}
