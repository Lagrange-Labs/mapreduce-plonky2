use crate::{
    array::{Array, Vector, VectorWire},
    keccak::{InputData, KeccakWires, HASH_LEN, PACKED_HASH_LEN},
    rlp::{
        decode_compact_encoding, decode_fixed_list, decode_header, decode_tuple, MAX_ITEMS_IN_LIST,
        MAX_KEY_NIBBLE_LEN,
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
        let should_process: [BoolTarget; DEPTH - 1] =
            create_array(|_| b.add_virtual_bool_target_safe());
        let index_hashes: [Target; DEPTH - 1] = create_array(|_| b.add_virtual_target());
        // nodes should be ordered from leaf to root and padded at the end
        let nodes: [VectorWire<_>; DEPTH] =
            create_array(|_| VectorWire::<{ PAD_LEN(NODE_LEN) }>::new(b));
        // hash the leaf first
        let leaf_hash = KeccakCircuit::<{ PAD_LEN(NODE_LEN) }>::hash_vector(b, &nodes[0]);
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

    /// Extract the key + value/hash from the node. It tries to decode the node as
    /// a branch node, and as an extension / leaf node, and select the right
    /// key depending on the number of elements found in the node.
    /// nibble is used to lookup the right item if it's a branch node
    /// Return is the (key,value). Key is in nibble format. Value is in bytes,
    /// and is either the hash of the child node, or the value of the leaf.
    /// In our case, value of leaf is always 32 bytes.
    fn advance_key<F: RichField + Extendable<D>, const D: usize>(
        b: &mut CircuitBuilder<F, D>,
        node: &Array<Target, NODE_LEN>,
        key: MPTKeyWire,
    ) -> MPTKeyWire {
        let zero = b.zero();
        let one = b.one();
        let two = b.two();
        let sixteen = b.constant(F::from_canonical_u8(16));
        let t = b._true();
        // It will try to decode a RLP list of the maximum number of items there can be
        // in a list, which is 16 for a branch node (Excluding value).
        // It returns the actual number of items decoded.
        // If it's 2 ==> node's a leaf or an extension
        //              RLP ( RLP ( enc (key)), RLP( hash / value))
        // if it's more ==> node's a branch node
        //              RLP ( RLP(hash1), RLP(hash2), ... RLP(hash16), RLP(value))
        //              (can be shorter than that ofc)
        let rlp_headers = decode_fixed_list::<F, D, MAX_ITEMS_IN_LIST>(b, &node.arr, zero);
        // -------------------------
        // leaf / extension part
        //
        let is_tuple = b.is_equal(rlp_headers.num_fields, two);
        let key_header = decode_header(b, &node.arr, rlp_headers.offset[0]);
        let extracted_key = decode_compact_encoding(b, node, &key_header);
        let value_header = decode_header(b, &node.arr, rlp_headers.offset[1]);
        let value_or_value = node.extract_array::<F, D, HASH_LEN>(b, value_header.offset);
        // check extract key is a subset to the key we're looking for

        // -------------------------
        // branch node part
        //
        let is_node = b.not(is_tuple);
        let nibble = key.current_nibble(b);
        // assert that the nibble is less than the number of items !
        let lt = less_than(b, nibble, rlp_headers.num_fields, 4);
        let branch_condition = b.and(is_node, lt);
        let nibble_header = rlp_headers.select(b, nibble);
        let hash = node.extract_array::<F, D, HASH_LEN>(b, nibble_header.offset);
        //let new_pointer = key.pointer.add(b, one);
        key
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
    /// Create a new fresh key wire
    pub fn new<F: RichField + Extendable<D>, const D: usize>(b: &mut CircuitBuilder<F, D>) -> Self {
        Self {
            key: Array::<Target, MAX_KEY_NIBBLE_LEN>::new(b),
            pointer: b.add_virtual_target(),
        }
    }
    /// Assign the key wire to the circuit.
    pub fn assign<F: RichField + Extendable<D>, const D: usize>(
        &self,
        p: &mut PartialWitness<F>,
        key: &[u8],
        ptr: usize,
    ) {
        let full_key = create_array(|i| {
            if i < key.len() {
                F::from_canonical_usize(key[i] as usize)
            } else {
                F::ZERO
            }
        });
        self.key.assign(p, &full_key);
        p.set_target(self.pointer, F::from_canonical_usize(ptr));
    }
}

#[cfg(test)]
mod test {
    use std::sync::Arc;

    use eth_trie::{EthTrie, MemoryDB, Trie};
    use plonky2::{
        field::extension::Extendable,
        hash::hash_types::RichField,
        iop::witness::PartialWitness,
        plonk::{
            circuit_builder::CircuitBuilder,
            config::{GenericConfig, PoseidonGoldilocksConfig},
        },
    };
    use rand::{thread_rng, Rng};

    use crate::{
        array::VectorWire,
        circuit::{test::test_simple_circuit, UserCircuit},
        keccak::OutputHash,
        utils::{convert_u8_to_u32_slice, find_index_subvector, keccak256},
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
    fn test_subvector() {
        let node = hex::decode(
            "e48200a0a06b4a71765e17649ab73c5e176281619faf173519718e6e95a40a8768685a26c6",
        )
        .unwrap();
        let child_hash =
            hex::decode("6b4a71765e17649ab73c5e176281619faf173519718e6e95a40a8768685a26c6")
                .unwrap();
        find_index_subvector(&node, &child_hash).unwrap();
    }
    #[test]
    fn test_mpt_proof_verification() {
        // max depth of the trie
        const DEPTH: usize = 4;
        // leave one for padding
        const ACTUAL_DEPTH: usize = DEPTH - 1;
        // max len of a node
        const NODE_LEN: usize = 80;
        // build a random MPT trie
        let memdb = Arc::new(MemoryDB::new(true));
        let mut trie = EthTrie::new(Arc::clone(&memdb));
        let mut keys = Vec::new();
        #[allow(unused_assignments)]
        let mut right_key_idx = 0;
        // loop: insert random elements as long as a random selected proof is not of the right length
        loop {
            println!("-> Insertion of {} elements so far...", keys.len());
            let karr = thread_rng().gen::<[u8; 32]>().to_vec();
            let key = rlp::encode(&karr);
            let random_len = thread_rng().gen_range(64..NODE_LEN);
            let random_bytes = (0..random_len)
                .map(|_| thread_rng().gen::<u8>())
                .collect::<Vec<_>>();
            trie.insert(&key, &rlp::encode(&random_bytes))
                .expect("can't insert");
            keys.push(key.clone());
            trie.root_hash().expect("root hash problem");
            if let Some(idx) = (0..keys.len()).find(|k| {
                let ke = &keys[*k];
                let proof = trie.get_proof(ke).unwrap();
                proof.len() == ACTUAL_DEPTH
            }) {
                right_key_idx = idx;
                break;
            }
        }
        let root = trie.root_hash().unwrap();
        // root is first so we reverse the order as in circuit we prove the opposite way
        let key = keys.get(right_key_idx).unwrap();
        let mut proof = trie.get_proof(key).unwrap();
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
}
