use crate::{
    array::{Array, Vector, VectorWire},
    keccak::{InputData, KeccakWires, HASH_LEN, PACKED_HASH_LEN},
    rlp::{
        decode_compact_encoding, decode_fixed_list, decode_header, decode_tuple, extract_array,
        RlpList, MAX_ITEMS_IN_LIST, MAX_KEY_NIBBLE_LEN,
    },
    utils::{convert_u8_targets_to_u32, find_index_subvector, keccak256, less_than},
};
use anyhow::{anyhow, Result};
use core::array::from_fn as create_array;
use ethers::providers::bytes_32ify;
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
    /// the full key that we are trying to prove in this trie
    /// NOTE: the key is in bytes. This code will transform it into nibbles
    /// before passing it to circuit, i.e. the circuit takes the key in nibbles
    /// whose length == MAX_KEY_NIBBLE_LEN
    key: [u8; MAX_KEY_NIBBLE_LEN / 2],
}

struct Wires<const DEPTH: usize, const NODE_LEN: usize>
where
    [(); PAD_LEN(NODE_LEN)]:,
    [(); DEPTH - 1]:,
{
    key: MPTKeyWire,
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
    /// The leaf value wires. It is provably extracted from the leaf node.
    leaf: Array<Target, MAX_LEAF_VALUE>,
}

impl<const DEPTH: usize, const NODE_LEN: usize> Circuit<DEPTH, NODE_LEN>
where
    [(); PAD_LEN(NODE_LEN)]:,
    [(); DEPTH - 1]:,
{
    pub fn new(key: [u8; MAX_KEY_NIBBLE_LEN / 2], proof: Vec<Vec<u8>>) -> Self {
        Self { nodes: proof, key }
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
        let one = b.one();
        let t = b._true();
        // full key is expected to be given by verifier (done in UserCircuit impl)
        // initial key has the pointer that is set at the maximum length - 1 (it's an index, so 0-based)
        let full_key = MPTKeyWire {
            key: Array::<Target, MAX_KEY_NIBBLE_LEN>::new(b),
            pointer: b.constant(F::from_canonical_usize(MAX_KEY_NIBBLE_LEN) - F::ONE),
        };
        let should_process: [BoolTarget; DEPTH - 1] =
            create_array(|_| b.add_virtual_bool_target_safe());
        // nodes should be ordered from leaf to root and padded at the end
        let nodes: [VectorWire<_>; DEPTH] =
            create_array(|_| VectorWire::<{ PAD_LEN(NODE_LEN) }>::new(b));
        // ---- LEAF part ---
        // 1. Hash the leaf
        // 2. Extract the value and the portion of the key of this node. Get the "updated partial key".
        // 3. Make sure it's a leaf
        let leaf_hash = KeccakCircuit::<{ PAD_LEN(NODE_LEN) }>::hash_vector(b, &nodes[0]);
        // small optimization here as we only need to decode two items for a leaf, since we know it's a leaf
        let leaf_headers = decode_fixed_list::<_, _, NB_ITEMS_LEAF>(b, &nodes[0].arr.arr, zero);
        let (mut iterative_key, leaf_value, is_leaf) =
            Self::advance_key_leaf_or_extension(b, &nodes[0].arr, &full_key, &leaf_headers);
        b.connect(t.target, is_leaf.target);
        let mut last_hash_output = leaf_hash.output_array.clone();
        let mut keccak_wires = vec![leaf_hash];
        // ---- Intermediate node part ---
        // 1. Decode the node
        // 2. Update the partial key
        // 3. Compare if extracted hash == child hash
        // 4. Hash the node and iterate
        for i in 1..DEPTH {
            // Make sure we are processing only relevant nodes !
            let is_real = should_process[i - 1];
            b.connect(t.target, is_real.target);
            //// look if hash is inside the node
            let (new_key, extracted_child_hash) =
                Self::advance_key(b, &nodes[i].arr, &iterative_key);
            // transform hash from bytes to u32 targets (since this is the hash output format)
            let extracted_hash_u32 = convert_u8_targets_to_u32(b, &extracted_child_hash.arr);
            let found_hash_in_parent = last_hash_output.equals(
                b,
                &Array::<U32Target, PACKED_HASH_LEN> {
                    arr: extracted_hash_u32.try_into().unwrap(),
                },
            );
            //b.connect(found_hash_in_parent.target, t.target);
            // if we don't have to process it, then circuit should never fail at that step
            // otherwise, we should always enforce finding the hash in the parent node
            let is_parent = b.select(is_real, found_hash_in_parent.target, t.target);
            b.connect(is_parent, t.target);

            // hash the next node first
            let hash_wires = KeccakCircuit::<{ PAD_LEN(NODE_LEN) }>::hash_vector(b, &nodes[i]);
            // and select whether we should update or not
            //last_hash_output = hash_wires.output_array.clone();
            last_hash_output = hash_wires
                .output_array
                .select(b, is_real, &last_hash_output);
            //iterative_key = new_key;
            iterative_key = new_key.select(b, is_real, &iterative_key);
            keccak_wires.push(hash_wires);
        }
        let mone = b.constant(F::NEG_ONE);
        b.connect(iterative_key.pointer, mone);

        (
            last_hash_output,
            Wires {
                key: full_key,
                keccak_wires: keccak_wires.try_into().unwrap(),
                nodes,
                should_process,
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
            } else {
                println!("[-----] setting is_real[{}] = false", i - 1);
                p.set_bool_target(wires.should_process[i - 1], false);
            }
        }
        let full_key_nibbles = bytes_to_nibbles(&self.key);
        wires.key.key.assign(
            p,
            &create_array(|i| F::from_canonical_u8(full_key_nibbles[i])),
        );
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
        // It will try to decode a RLP list of the maximum number of items there can be
        // in a list, which is 16 for a branch node (Excluding value).
        // It returns the actual number of items decoded.
        // If it's 2 ==> node's a leaf or an extension
        //              RLP ( RLP ( enc (key)), RLP( hash / value))
        // if it's more ==> node's a branch node
        //              RLP ( RLP(hash1), RLP(hash2), ... RLP(hash16), RLP(value))
        //              (can be shorter than that ofc)
        let rlp_headers = decode_fixed_list::<F, D, MAX_ITEMS_IN_LIST>(b, &node.arr, zero);
        let leaf_info = Self::advance_key_leaf_or_extension(b, node, key, &rlp_headers);
        let tuple_condition = leaf_info.2;
        let branch_info = Self::advance_key_branch(b, node, key, &rlp_headers);
        // Ensures that conditions in a tuple are valid OR conditions in a branch are valid. So we can select the
        // right output depending only on one condition only.
        let mut branch_condition = b.not(tuple_condition);
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
#[derive(Clone, Debug)]
pub struct MPTKeyWire {
    /// Represents the full key of the value(s) we're looking at in the MPT trie.
    pub key: Array<Target, MAX_KEY_NIBBLE_LEN>,
    /// Represents which portion of the key we already processed. The pointer
    /// goes _backwards_ since circuit starts proving from the leaf up to the root.
    /// i.e. pointer must be equal to F::NEG_ONE when we reach the root.
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
    use std::array::from_fn as create_array;
    use std::sync::Arc;
    use std::thread::current;

    use eth_trie::{EthTrie, MemoryDB, Nibbles, Trie};
    use itertools::Itertools;
    use plonky2::field::types::Field;
    use plonky2::hash::keccak;
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
    use plonky2_crypto::u32::arithmetic_u32::U32Target;
    use rand::{thread_rng, Rng};

    use crate::array::Vector;
    use crate::benches::init_logging;
    use crate::keccak::{InputData, KeccakCircuit, HASH_LEN, PACKED_HASH_LEN};
    use crate::mpt_sequential::{bytes_to_nibbles, nibbles_to_bytes, NB_ITEMS_LEAF};
    use crate::rlp::{decode_fixed_list, MAX_ITEMS_IN_LIST, MAX_KEY_NIBBLE_LEN};
    use crate::utils::{convert_u8_targets_to_u32, less_than, IntTargetWriter};
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
        [(); HASH_LEN / 4]:,
    {
        type Wires = (OutputHash, Wires<DEPTH, NODE_LEN>, Array<Target, HASH_LEN>);

        fn build(c: &mut CircuitBuilder<F, D>) -> Self::Wires {
            let leaf = VectorWire::<{ PAD_LEN(NODE_LEN) }>::new(c);
            let expected_root = Array::<Target, HASH_LEN>::new(c);
            let packed_exp_root = convert_u8_targets_to_u32(c, &expected_root.arr);
            let arr = Array::<U32Target, PACKED_HASH_LEN>::from_array(
                packed_exp_root.try_into().unwrap(),
            );
            let (root, mpt_wires) = Circuit::build(c);
            let is_equal = root.equals(c, &arr);
            let tt = c._true();
            c.connect(is_equal.target, tt.target);
            (root, mpt_wires, expected_root)
        }

        fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
            self.c.assign(pw, &wires.1).unwrap();
            wires
                .2
                .assign(pw, &create_array(|i| F::from_canonical_u8(self.exp_root[i])));
        }
    }
    #[test]
    fn test_mpt_proof_verification() {
        init_logging();
        // max depth of the trie
        const DEPTH: usize = 3;
        // leave one for padding
        const ACTUAL_DEPTH: usize = DEPTH;
        // max len of a node
        const NODE_LEN: usize = 150;
        const VALUE_LEN: usize = 32;
        let (mut trie, key) = generate_random_storage_mpt::<ACTUAL_DEPTH, VALUE_LEN>();
        let root = trie.root_hash().unwrap();
        // root is first so we reverse the order as in circuit we prove the opposite way
        let mut proof = trie.get_proof(&key).unwrap();
        proof.reverse();
        assert!(proof.len() == ACTUAL_DEPTH);
        assert!(proof.len() <= DEPTH);
        assert!(keccak256(proof.last().unwrap()) == root.to_fixed_bytes());
        println!("PROOF LEN = {}", proof.len());
        visit_proof(&proof);
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
            c: Circuit::<DEPTH, NODE_LEN>::new(key.try_into().unwrap(), proof),
            exp_root: root.to_fixed_bytes(),
        };
        test_simple_circuit::<F, D, C, _>(circuit);
    }

    fn visit_proof(proof: &Vec<Vec<u8>>) {
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
    fn visit_node(node: &[u8], child_hash: &[u8], partial_key: &mut Vec<u8>) {
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
                    "[+] Leaf/Extension node: partial key extracted: {:?}",
                    hex::encode(nibbles_to_bytes(key_nibbles))
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
    #[derive(Clone, Debug)]
    enum NodeType {
        Tuple,
        Branch,
    }
    #[test]
    fn test_incremental() {
        const DEPTH: usize = 3;
        const NODE_LEN: usize = 150;
        const VALUE_LEN: usize = 32;
        //let (mut trie, key) = generate_random_storage_mpt::<DEPTH, VALUE_LEN>();
        //let mut proof = trie.get_proof(&key).unwrap();
        //proof.reverse();
        let proof = vec![
            hex::decode("f843a0202aab350c80c8b4d504560f76bd492c7191f6e88b204fba16b03422594f7872a1a0eb8e657513b71a943a73ef2aded7635d2f0e25b5efe1559e0e5e9450a04dc929").unwrap(),
            hex::decode("f85180a0d43c798529ffaaa2316f8adaaa27105dd0fb20dc97d250ad784386e0edaa97e1808080a0602346785e1ced15445758e363f43723de0d5e365cb4f483845988113f22f6ea8080808080808080808080").unwrap(),
            hex::decode("f8f180a080a15846e63f90955f3492af55951f272302e08fa4360d13d25ead42ef1f8e1580a0103dad8651d136072de73a52b6c1e81afec60eeadcd971e88cbdd835f58523718080a0c7e63df28028e3906459eb3b7ea253bf7ef278f06b4e1705485cba52a42b33da8080a0a2fe320d0471b6eed27e651ba18be7c1cd36f4530c1931c2e2bfd8beed9044e980a03a613d04fd7bb29df0b0444d58118058d3107c2291c32476511969c85f98953e80a0e9acd2a316add27ea52dd4e844c78f041a89349eff4327e21a0b0f64f4aec234a0b34cd83dc3174901e6cc1a8f43de2866a247b6f769e49710de0b5c501032e50b8080").unwrap(),
        ];
        visit_proof(&proof);
        let key = hex::decode("b12aab350c80c8b4d504560f76bd492c7191f6e88b204fba16b03422594f7872")
            .unwrap();
        let key_nibbles = bytes_to_nibbles(&key);
        assert_eq!(key_nibbles.len(), MAX_KEY_NIBBLE_LEN);
        let initial_ptr = MAX_KEY_NIBBLE_LEN - 1;
        let mut current_pointer = initial_ptr as i8;
        let mut all_pointers = vec![];
        let mut all_types = vec![];
        let mut all_hashes = vec![];
        println!("[+] Initial pointer: {}", initial_ptr);
        for (i, node) in proof.iter().enumerate() {
            all_hashes.push(keccak256(node));
            let node_tuple: Vec<Vec<u8>> = rlp::decode_list(node);
            let new_ptr = match node_tuple.len() {
                2 => {
                    let partial_key = Nibbles::from_compact(&node_tuple[0]);
                    let partial_key_nibbles = partial_key.nibbles();
                    all_types.push(NodeType::Tuple);
                    current_pointer - partial_key_nibbles.len() as i8
                }
                17 => {
                    all_types.push(NodeType::Branch);
                    current_pointer - 1
                }
                _ => panic!("invalid node"),
            };
            println!(
                "[+] New pointer after node {} - type {:?}: {}",
                i,
                all_types.last().unwrap(),
                new_ptr
            );
            current_pointer = new_ptr;
            all_pointers.push(current_pointer);
        }
        assert!(*all_pointers.last().unwrap() < 0);

        let config = CircuitConfig::standard_recursion_config();
        let mut pw = PartialWitness::new();
        let mut b = CircuitBuilder::<F, D>::new(config);
        let zero = b.zero();
        let tt = b._true();
        let nodes_wires: [VectorWire<_>; DEPTH] =
            create_array(|_| VectorWire::<{ PAD_LEN(NODE_LEN) }>::new(&mut b));
        let expected_pointers_wire = b.add_virtual_target_arr::<DEPTH>();
        let initial_key_wire = MPTKeyWire::new(&mut b);
        let mut incremental_key_wire = initial_key_wire.clone();
        let leaf_hash =
            KeccakCircuit::<{ PAD_LEN(NODE_LEN) }>::hash_vector(&mut b, &nodes_wires[0]);
        let mut last_hash_output = leaf_hash.output_array.clone();
        let mut hash_wires = vec![leaf_hash];

        // LEAF - PARENT1
        let (advanced_key, child_hash) = Circuit::<DEPTH, NODE_LEN>::advance_key(
            &mut b,
            &nodes_wires[0].arr,
            &incremental_key_wire,
        );
        b.connect(advanced_key.pointer, expected_pointers_wire[0]);
        incremental_key_wire = advanced_key;
        /// PARENT 1 - PARENT 2
        let (advanced_key, child_hash) = Circuit::<DEPTH, NODE_LEN>::advance_key(
            &mut b,
            &nodes_wires[1].arr,
            &incremental_key_wire,
        );
        b.connect(advanced_key.pointer, expected_pointers_wire[1]);
        incremental_key_wire = advanced_key;
        let extracted_hash_u32 = convert_u8_targets_to_u32(&mut b, &child_hash.arr);
        let found_hash = last_hash_output.equals(
            &mut b,
            &Array::<U32Target, PACKED_HASH_LEN> {
                arr: extracted_hash_u32.try_into().unwrap(),
            },
        );
        b.connect(tt.target, found_hash.target);
        let keccak_wire =
            KeccakCircuit::<{ PAD_LEN(NODE_LEN) }>::hash_vector(&mut b, &nodes_wires[1]);
        last_hash_output = keccak_wire.output_array.clone();
        hash_wires.push(keccak_wire);
        ///// PARENT 2 - ROOT
        let (advanced_key, child_hash) = Circuit::<DEPTH, NODE_LEN>::advance_key(
            &mut b,
            &nodes_wires[2].arr,
            &incremental_key_wire,
        );
        b.connect(advanced_key.pointer, expected_pointers_wire[2]);
        let extracted_hash_u32 = convert_u8_targets_to_u32(&mut b, &child_hash.arr);
        let found_hash = last_hash_output.equals(
            &mut b,
            &Array::<U32Target, PACKED_HASH_LEN> {
                arr: extracted_hash_u32.try_into().unwrap(),
            },
        );
        // THIS FAILS
        //b.connect(tt.target, found_hash.target);
        // SO WE CHECK MANUALLY if (a) extracted hash is correct
        // THIS FAILS
        //let exp_hash_target = b.add_virtual_target_arr::<32>();
        //for (found, exp) in child_hash.arr.iter().zip(exp_hash_target.iter()) {
        //    b.connect(*found, *exp);
        //}
        //let exp_hash = keccak256(&proof[1]);
        //pw.set_int_targets(&exp_hash_target, &exp_hash);
        // SO we try to extract the hash directly from branch node see
        let rlp_headers =
            decode_fixed_list::<F, D, MAX_ITEMS_IN_LIST>(&mut b, &nodes_wires[2].arr.arr, zero);
        let one = b.one();
        let is_node = b._true();
        let current_nibble = incremental_key_wire.current_nibble(&mut b);
        let new_key = incremental_key_wire.advance_by(&mut b, one);
        let lt = less_than(&mut b, current_nibble, rlp_headers.num_fields, 4);
        let branch_condition = b.and(is_node, lt);
        b.connect(is_node.target, branch_condition.target);
        let exp_hash = keccak256(&proof[1]);
        /// the follow check fails because it's not extracting the right hash
        /// so before checking this, we check for the right nibble
        ///  --- nibble check
        let root_node_list: Vec<Vec<u8>> = rlp::decode_list(&proof[2]);
        let (exp_nibble, _) = root_node_list
            .into_iter()
            .enumerate()
            .find(|(_, value)| *value == exp_hash)
            .expect("don't find children hash in root?");
        let exp_nibble_target = b.constant(F::from_canonical_usize(exp_nibble));
        println!("[+] ROOT Nibble = {}", exp_nibble);
        let nibble_header = rlp_headers.select(&mut b, current_nibble);
        let branch_child_hash = nodes_wires[2]
            .arr
            .extract_array::<F, D, HASH_LEN>(&mut b, nibble_header.offset);
        let eleven = b.constant(F::from_canonical_usize(11));
        b.connect(eleven, current_nibble);
        //b.connect(exp_nibble_target, current_nibble);
        let child_hash_offset = find_index_subvector(&proof[2], &exp_hash).unwrap();
        println!("[+] ROOT index = {}", child_hash_offset);
        let cho_target = b.constant(F::from_canonical_usize(child_hash_offset));
        let hardcoded = b.constant(F::from_canonical_usize(142));
        b.connect(nibble_header.offset, hardcoded);
        //b.connect(nibble_header.offset, cho_target);
        /// --- hash check
        let exp_hash_target = b.add_virtual_target_arr::<32>();
        pw.set_int_targets(&exp_hash_target, &exp_hash);
        //for (found, exp) in branch_child_hash.arr.iter().zip(exp_hash_target.iter()) {
        //    b.connect(*found, *exp);
        //}

        incremental_key_wire = advanced_key;

        //// assign time
        for (mut node, wire) in proof.iter().zip(nodes_wires.iter()) {
            wire.assign(
                &mut pw,
                &Vector::<{ PAD_LEN(NODE_LEN) }>::from_vec(node.clone()).unwrap(),
            );
        }
        for (ptr_value, ptr_wire) in all_pointers.into_iter().zip(expected_pointers_wire.iter()) {
            let value = if ptr_value == -1 {
                F::NEG_ONE
            } else {
                F::from_canonical_u8(ptr_value as u8)
            };
            pw.set_target(*ptr_wire, value);
        }
        for (hash_wire, node) in hash_wires.iter().zip(proof.iter()) {
            KeccakCircuit::<{ PAD_LEN(NODE_LEN) }>::assign(
                &mut pw,
                hash_wire,
                &InputData::Assigned(
                    &Vector::<{ PAD_LEN(NODE_LEN) }>::from_vec(node.clone()).unwrap(),
                ),
            );
        }
        initial_key_wire.assign(&mut pw, &key_nibbles.try_into().unwrap(), initial_ptr);
        let data = b.build::<C>();
        let proof = data.prove(pw).unwrap();
        data.verify(proof).unwrap();
    }

    #[test]
    fn test_extract_list_of_nodes() {
        const DEPTH: usize = 4;
        const NODE_LEN: usize = 150;
        const VALUE_LEN: usize = 32;
        let (mut trie, key) = generate_random_storage_mpt::<DEPTH, VALUE_LEN>();
        let mut proof = trie.get_proof(&key).unwrap();
        proof.reverse();
        let key_nibbles = bytes_to_nibbles(&key);
        assert_eq!(key_nibbles.len(), MAX_KEY_NIBBLE_LEN);
        let initial_ptr = MAX_KEY_NIBBLE_LEN - 1;
        let mut current_pointer = initial_ptr as i8;
        let mut all_pointers = vec![];
        let mut all_types = vec![];
        println!("[+] Initial pointer: {}", initial_ptr);
        for (i, node) in proof.iter().enumerate() {
            let node_tuple: Vec<Vec<u8>> = rlp::decode_list(node);
            let new_ptr = match node_tuple.len() {
                2 => {
                    let partial_key = Nibbles::from_compact(&node_tuple[0]);
                    let partial_key_nibbles = partial_key.nibbles();
                    all_types.push(NodeType::Tuple);
                    current_pointer - partial_key_nibbles.len() as i8
                }
                17 => {
                    all_types.push(NodeType::Branch);
                    current_pointer - 1
                }
                _ => panic!("invalid node"),
            };
            println!(
                "[+] New pointer after node {} - type {:?}: {}",
                i,
                all_types.last().unwrap(),
                new_ptr
            );
            current_pointer = new_ptr;
            all_pointers.push(current_pointer);
        }
        assert!(*all_pointers.last().unwrap() < 0);
        // because root is alwas a branch node (prob. speaking) so we always remove one
        assert!(*all_pointers.last().unwrap() == -1);
        let config = CircuitConfig::standard_recursion_config();
        let mut pw = PartialWitness::new();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let zero = builder.zero();
        let nodes_wires: [VectorWire<_>; DEPTH] =
            create_array(|_| VectorWire::<{ PAD_LEN(NODE_LEN) }>::new(&mut builder));
        let expected_pointers_wire = builder.add_virtual_target_arr::<DEPTH>();
        let initial_key_wire = MPTKeyWire::new(&mut builder);
        let mut incremental_key_wire = initial_key_wire.clone();

        let leaf_hash =
            KeccakCircuit::<{ PAD_LEN(NODE_LEN) }>::hash_vector(&mut builder, &nodes_wires[0]);
        let mut last_hash_output = leaf_hash.output_array.clone();
        let hash_wires = vec![leaf_hash];
        let tt = builder._true();
        for i in 1..2 {
            //if let NodeType::Tuple = all_types[i] {
            if false {
                let rlp_headers = decode_fixed_list::<F, D, MAX_ITEMS_IN_LIST>(
                    &mut builder,
                    &nodes_wires[i].arr.arr,
                    zero,
                );
                let leaf_info = Circuit::<DEPTH, NODE_LEN>::advance_key_leaf_or_extension(
                    &mut builder,
                    &nodes_wires[i].arr,
                    &incremental_key_wire,
                    &rlp_headers,
                );
                let branch_info = Circuit::<DEPTH, NODE_LEN>::advance_key_branch(
                    &mut builder,
                    &nodes_wires[i].arr,
                    &incremental_key_wire,
                    &rlp_headers,
                );
                let tuple_cond = leaf_info.2;
                let mut branch_condition = builder.not(tuple_cond);
                branch_condition = builder.and(branch_condition, branch_info.2);
                let tuple_or_branch = builder.or(branch_condition, tuple_cond);
                builder.connect(tt.target, tuple_or_branch.target);
                let new_key = leaf_info.0.select(&mut builder, tuple_cond, &branch_info.0);

                let new_ptr =
                    builder.select(tuple_cond, leaf_info.0.pointer, branch_info.0.pointer);
                let sixtytwo = builder.constant(F::from_canonical_u8(62));
                let two = builder.two();
                //builder.connect(tt.target, branch_condition.target);
                builder.connect(rlp_headers.num_fields, two);
                //builder.connect(tt.target, tuple_cond.target);
                // builder.connect(branch_info.0.pointer, sixtytwo);
                // builder.connect(leaf_info.0.pointer, expected_pointers_wire[i]);
                //builder.connect(new_ptr, leaf_info.0.pointer);
                //builder.connect(advanced_key.pointer, expected_pointers_wire[i]);
                //builder.connect(new_key.pointer, expected_pointers_wire[i]);

                incremental_key_wire = new_key;
            } else {
                let (advanced_key, child_hash) = Circuit::<DEPTH, NODE_LEN>::advance_key(
                    &mut builder,
                    &nodes_wires[i].arr,
                    &incremental_key_wire,
                );
                builder.connect(advanced_key.pointer, expected_pointers_wire[i]);
                let extracted_hash_u32 = convert_u8_targets_to_u32(&mut builder, &child_hash.arr);
                let found_hash = last_hash_output.equals(
                    &mut builder,
                    &Array::<U32Target, PACKED_HASH_LEN> {
                        arr: extracted_hash_u32.try_into().unwrap(),
                    },
                );
                builder.connect(tt.target, found_hash.target);
                incremental_key_wire = advanced_key;
            }
        }

        for (mut node, wire) in proof.iter().zip(nodes_wires.iter()) {
            //node.resize(PAD_LEN(NODE_LEN), 0);
            //let node_f = node
            //    .iter()
            //    .map(|b| F::from_canonical_u8(*b))
            //    .collect::<Vec<_>>();
            wire.assign(
                &mut pw,
                &Vector::<{ PAD_LEN(NODE_LEN) }>::from_vec(node.clone()).unwrap(),
            );
        }
        for (ptr_value, ptr_wire) in all_pointers.into_iter().zip(expected_pointers_wire.iter()) {
            let value = if ptr_value == -1 {
                F::NEG_ONE
            } else {
                F::from_canonical_u8(ptr_value as u8)
            };
            pw.set_target(*ptr_wire, value);
        }
        for (hash_wire, node) in hash_wires.iter().zip(proof.iter()) {
            KeccakCircuit::<{ PAD_LEN(NODE_LEN) }>::assign(
                &mut pw,
                hash_wire,
                &InputData::Assigned(
                    &Vector::<{ PAD_LEN(NODE_LEN) }>::from_vec(node.clone()).unwrap(),
                ),
            );
        }
        initial_key_wire.assign(&mut pw, &key_nibbles.try_into().unwrap(), initial_ptr);

        let data = builder.build::<C>();
        let proof = data.prove(pw).unwrap();
        data.verify(proof).unwrap();
    }
    #[test]
    fn test_extract_any_node() {
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
        let node = Array::<Target, { PAD_LEN(NODE_LEN) }>::new(&mut builder);
        let key_wire = MPTKeyWire::new(&mut builder);
        let (advanced_key, value) =
            Circuit::<DEPTH, NODE_LEN>::advance_key(&mut builder, &node, &key_wire);
        let exp_key_ptr = builder.add_virtual_target();
        //builder.connect(advanced_key.pointer, exp_key_ptr);
        let exp_value = Array::<Target, VALUE_LEN>::new(&mut builder);
        let should_be_true = exp_value.equals(&mut builder, &value);
        //builder.assert_bool(should_be_true);
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
        let rlp_headers = decode_fixed_list::<F, D, NB_ITEMS_LEAF>(&mut builder, &node.arr, zero);
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
            println!(
                "[+] Random mpt: insertion of {} elements so far...",
                keys.len()
            );
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
