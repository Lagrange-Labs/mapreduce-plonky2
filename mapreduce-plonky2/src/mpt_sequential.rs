use crate::{
    array::{Array, Vector, VectorWire},
    keccak::{InputData, KeccakWires, HASH_LEN, PACKED_HASH_LEN},
    rlp::{
        decode_compact_encoding, decode_fixed_list, decode_header, RlpHeader, RlpList,
        MAX_ITEMS_IN_LIST, MAX_KEY_NIBBLE_LEN,
    },
    utils::{convert_u8_targets_to_u32, find_index_subvector, keccak256, less_than},
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
use recursion_framework::serialization::deserialize_array;
use recursion_framework::serialization::deserialize_long_array;
use recursion_framework::serialization::serialize_array;
use recursion_framework::serialization::serialize_long_array;
use serde::{Deserialize, Serialize};

use crate::keccak::{compute_size_with_padding, KeccakCircuit, OutputHash};
/// Number of items in the RLP encoded list in a leaf node.
const NB_ITEMS_LEAF: usize = 2;
/// Currently a constant set to denote the length of the value we are extracting from the MPT trie.
/// This can later be also be done in a generic way to allow different sizes.
/// Given we target MPT storage proof, the value is 32 bytes + 1 byte for RLP encoding.
pub const MAX_LEAF_VALUE_LEN: usize = 33;

/// a simple alias to keccak::compute_size_with_padding to make the code a bit
/// more tiny with all these const generics
#[allow(non_snake_case)]
pub const fn PAD_LEN(d: usize) -> usize {
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
pub struct Circuit<const DEPTH: usize, const NODE_LEN: usize> {
    /// for ease of usage, we take vector here and the circuit is doing the padding
    nodes: Vec<Vec<u8>>,
    /// the full key that we are trying to prove in this trie
    /// NOTE: the key is in bytes. This code will transform it into nibbles
    /// before passing it to circuit, i.e. the circuit takes the key in nibbles
    /// whose length == MAX_KEY_NIBBLE_LEN
    key: [u8; MAX_KEY_NIBBLE_LEN / 2],
}
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct InputWires<const DEPTH: usize, const NODE_LEN: usize>
where
    [(); PAD_LEN(NODE_LEN)]:,
    [(); DEPTH - 1]:,
{
    pub(crate) key: MPTKeyWire,
    /// a vector of buffers whose size is the padded size of the maximum node length
    /// the padding may occur anywhere in the array but it can fit the maximum node size
    /// NOTE: this makes the code a bit harder grasp at first, but it's a straight
    /// way to define everything according to max size of the data and
    /// "not care" about the padding size (almost!)
    #[serde(
        serialize_with = "serialize_long_array",
        deserialize_with = "deserialize_long_array"
    )]
    pub(crate) nodes: [VectorWire<Target, { PAD_LEN(NODE_LEN) }>; DEPTH],
    /// in the case of a fixed circuit, the actual tree depth might be smaller.
    /// In this case, we set false on the part of the path we should not process.
    /// NOTE: for node at index i in the path, the boolean indicating if we should
    /// process it is at index i-1
    #[serde(
        serialize_with = "serialize_array",
        deserialize_with = "deserialize_array"
    )]
    should_process: [BoolTarget; DEPTH - 1],
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct OutputWires<const DEPTH: usize, const NODE_LEN: usize>
where
    [(); PAD_LEN(NODE_LEN)]:,
    [(); DEPTH - 1]:,
{
    /// We need to keep around the hashes wires because keccak needs to assign
    /// some additional wires for each input (see keccak circuit for more info.).
    #[serde(
        serialize_with = "serialize_long_array",
        deserialize_with = "deserialize_long_array"
    )]
    keccak_wires: [KeccakWires<{ PAD_LEN(NODE_LEN) }>; DEPTH],
    /// The leaf value wires. It is provably extracted from the leaf node.
    pub(crate) leaf: Array<Target, MAX_LEAF_VALUE_LEN>,
    /// The root hash value wire.
    pub(crate) root: OutputHash,
}

impl<const DEPTH: usize, const NODE_LEN: usize> Circuit<DEPTH, NODE_LEN>
where
    [(); PAD_LEN(NODE_LEN)]:,
    [(); DEPTH - 1]:,
{
    pub fn new(key: [u8; MAX_KEY_NIBBLE_LEN / 2], proof: Vec<Vec<u8>>) -> Self {
        Self { nodes: proof, key }
    }

    pub fn create_input_wires<F, const D: usize>(
        b: &mut CircuitBuilder<F, D>,
        key: Option<MPTKeyWire>, // Could set the full key from outside
    ) -> InputWires<DEPTH, NODE_LEN>
    where
        F: RichField + Extendable<D>,
    {
        // full key is expected to be given by verifier (done in UserCircuit impl)
        // initial key has the pointer that is set at the maximum length - 1 (it's an index, so 0-based)
        let key = key.unwrap_or_else(|| MPTKeyWire {
            key: Array::<Target, MAX_KEY_NIBBLE_LEN>::new(b),
            pointer: b.constant(F::from_canonical_usize(MAX_KEY_NIBBLE_LEN) - F::ONE),
        });
        let should_process: [BoolTarget; DEPTH - 1] =
            create_array(|_| b.add_virtual_bool_target_safe());
        // nodes should be ordered from leaf to root and padded at the end
        let nodes: [VectorWire<Target, _>; DEPTH] =
            create_array(|_| VectorWire::<Target, { PAD_LEN(NODE_LEN) }>::new(b));
        InputWires {
            key,
            nodes,
            should_process,
        }
    }
    /// Build the sequential hashing of nodes. It returns the wires that contains
    /// the root hash (according to the "should_process" array) and the wires
    /// to assign during proving time, including each of the nodes in the path.
    /// WARNING: the nodes in the inputs are NOT range checked to be bytes. This has
    /// to be done by the caller.
    pub fn verify_mpt_proof<F, const D: usize>(
        b: &mut CircuitBuilder<F, D>,
        inputs: &InputWires<DEPTH, NODE_LEN>,
    ) -> OutputWires<DEPTH, NODE_LEN>
    where
        F: RichField + Extendable<D>,
    {
        let zero = b.zero();
        let t = b._true();
        // ---- LEAF part ---
        // 1. Hash the leaf
        // 2. Extract the value and the portion of the key of this node. Get the "updated partial key".
        // 3. Make sure it's a leaf
        let leaf_hash = KeccakCircuit::<{ PAD_LEN(NODE_LEN) }>::hash_vector(b, &inputs.nodes[0]);
        // small optimization here as we only need to decode two items for a leaf, since we know it's a leaf
        let leaf_headers =
            decode_fixed_list::<_, _, NB_ITEMS_LEAF>(b, &inputs.nodes[0].arr.arr, zero);
        let (mut iterative_key, leaf_value, is_leaf) = Self::advance_key_leaf_or_extension(
            b,
            &inputs.nodes[0].arr,
            &inputs.key,
            &leaf_headers,
        );
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
            let is_real = inputs.should_process[i - 1];
            // look if hash is inside the node
            let (new_key, extracted_child_hash, valid_node) =
                Self::advance_key(b, &inputs.nodes[i].arr, &iterative_key);
            // transform hash from bytes to u32 targets (since this is the hash output format)
            let extracted_hash_u32 = convert_u8_targets_to_u32(b, &extracted_child_hash.arr);
            let found_hash_in_parent = last_hash_output.equals(
                b,
                &Array::<U32Target, PACKED_HASH_LEN> {
                    arr: extracted_hash_u32.try_into().unwrap(),
                },
            );
            // condition that must be true if we're processing a real node
            let cond = b.and(valid_node, found_hash_in_parent);
            // if we don't have to process it, then circuit should never fail at that step
            // otherwise, we should always enforce finding the hash in the parent node
            let is_parent = b.select(is_real, cond.target, t.target);
            b.connect(is_parent, t.target);

            // hash the next node first
            let hash_wires =
                KeccakCircuit::<{ PAD_LEN(NODE_LEN) }>::hash_vector(b, &inputs.nodes[i]);
            // and select whether we should update or not
            //last_hash_output = hash_wires.output_array.clone();
            last_hash_output = hash_wires
                .output_array
                .select(b, is_real, &last_hash_output);
            iterative_key = new_key.select(b, is_real, &iterative_key);
            keccak_wires.push(hash_wires);
        }
        let mone = b.constant(F::NEG_ONE);
        b.connect(iterative_key.pointer, mone);

        OutputWires {
            keccak_wires: keccak_wires.try_into().unwrap(),
            leaf: leaf_value,
            root: last_hash_output,
        }
    }

    /// Assign the nodes to the wires. The reason we have the output wires
    /// as well is due to the keccak circuit that requires some special assignement
    /// from the raw vectors.
    pub fn assign_wires<F: RichField + Extendable<D>, const D: usize>(
        &self,
        p: &mut PartialWitness<F>,
        inputs: &InputWires<DEPTH, NODE_LEN>,
        outputs: &OutputWires<DEPTH, NODE_LEN>,
    ) -> Result<()> {
        let pad_len = DEPTH.checked_sub(self.nodes.len()).ok_or(anyhow!(
            "Circuit depth {} too small for this MPT proof {}!",
            DEPTH,
            self.nodes.len()
        ))?;
        // convert nodes to array and pad with empty array if needed
        let padded_nodes = self
            .nodes
            .iter()
            .map(|n| Vector::<u8, { PAD_LEN(NODE_LEN) }>::from_vec(n))
            .chain((0..pad_len).map(|_| Ok(Vector::<u8, { PAD_LEN(NODE_LEN) }>::empty())))
            .collect::<Result<Vec<_>>>()?;
        for (i, (wire, node)) in inputs.nodes.iter().zip(padded_nodes.iter()).enumerate() {
            wire.assign(p, node);
            KeccakCircuit::<{ PAD_LEN(NODE_LEN) }>::assign(
                p,
                &outputs.keccak_wires[i],
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
                p.set_bool_target(inputs.should_process[i - 1], true);
                // Safety measure to make sure we're proving a correct MPT proof
                // It helps rather than debugging plonky2 output.
                let child_hash = keccak256(&self.nodes[i - 1]);
                find_index_subvector(&self.nodes[i], &child_hash)
                    .ok_or(anyhow!("can't find hash in parent node!"))?;
            } else {
                p.set_bool_target(inputs.should_process[i - 1], false);
            }
        }
        let full_key_nibbles = bytes_to_nibbles(&self.key);
        inputs.key.key.assign(
            p,
            &create_array(|i| F::from_canonical_u8(full_key_nibbles[i])),
        );
        Ok(())
    }

    /// Returns the MPT key advanced, depending on if it's a branch node, or extension node
    /// and returns the designated children value/hash from the node.
    ///
    /// It tries to decode the node as a branch node, and as an extension node,
    /// and select the right key depending on the number of elements found in the node.
    /// nibble is used to lookup the right item if it's a branch node
    /// Return is the (key,value). Key is in nibble format. Value is in bytes,
    /// and is either the hash of the child node, or the value of the leaf.
    /// WARNING: Do NOT call this function on a leaf node, it will return potentially truncated
    /// result since the length can be up to 33 bytes there. On extension, the raw hash
    /// of 32 bytes is returned.
    pub fn advance_key<F: RichField + Extendable<D>, const D: usize>(
        b: &mut CircuitBuilder<F, D>,
        node: &Array<Target, { PAD_LEN(NODE_LEN) }>,
        key: &MPTKeyWire,
    ) -> (MPTKeyWire, Array<Target, HASH_LEN>, BoolTarget) {
        let zero = b.zero();
        // It will try to decode a RLP list of the maximum number of items there can be
        // in a list, which is 16 for a branch node (Excluding value).
        // It returns the actual number of items decoded.
        // If it's 2 ==> node's a leaf or an extension <-- FOCUS on extension in this method
        //              RLP ( RLP ( enc (key)), RLP (hash ) )
        // if it's more ==> node's a branch node
        //              RLP ( RLP(hash1), RLP(hash2), ... RLP(hash16), RLP(value))
        let rlp_headers = decode_fixed_list::<F, D, MAX_ITEMS_IN_LIST>(b, &node.arr, zero);
        let leaf_info = Self::advance_key_leaf_or_extension(b, node, key, &rlp_headers);
        let tuple_condition = leaf_info.2;
        let branch_info = Self::advance_key_branch(b, node, key, &rlp_headers);
        // ensures it's either a branch or leaf/extension
        let tuple_or_branch = b.or(leaf_info.2, branch_info.2);

        // select between the two outputs
        // Note we assume that if it is not a tuple, it is necessarily a branch node.
        // If attacker gives invalid node, hash will not match anyway.
        let child_hash = leaf_info.1.select(b, tuple_condition, &branch_info.1);
        let new_key = leaf_info.0.select(b, tuple_condition, &branch_info.0);

        (new_key, child_hash, tuple_or_branch)
    }

    /// This function advances the pointer of the MPT key. The parameters are:
    /// * The key where to lookup the next nibble and thus the hash stored at
    ///   nibble position in the branch node.
    /// * RLP headers of the current node.
    /// And it returns:
    /// * New key with the pointer moved.
    /// * The child hash / value of the node.
    /// * A boolean that must be true if the given node is a leaf or an extension.
    /// * The nibble position before this advance.
    pub(crate) fn advance_key_branch<F: RichField + Extendable<D>, const D: usize>(
        b: &mut CircuitBuilder<F, D>,
        node: &Array<Target, { PAD_LEN(NODE_LEN) }>,
        key: &MPTKeyWire,
        rlp_headers: &RlpList<MAX_ITEMS_IN_LIST>,
    ) -> (MPTKeyWire, Array<Target, HASH_LEN>, BoolTarget, Target) {
        let one = b.one();
        // assume it's a node and return the boolean condition that must be true if
        // it is a node - decided in advance_key function
        let seventeen = b.constant(F::from_canonical_usize(MAX_ITEMS_IN_LIST));
        let branch_condition = b.is_equal(seventeen, rlp_headers.num_fields);

        // Given we are reading the nibble from the key itself, we don't need to do
        // any more checks on it. The key and pointer will be given by the verifier so
        // attacker can't indicate a different nibble
        let nibble = key.current_nibble(b);

        // we advance the pointer for the next iteration
        let new_key = key.advance_by(b, one);
        let nibble_header = rlp_headers.select(b, nibble);
        let branch_child_hash = node.extract_array::<F, D, HASH_LEN>(b, nibble_header.offset);
        (new_key, branch_child_hash, branch_condition, nibble)
    }

    /// Returns the key with the pointer moved, returns the child hash / value of the node,
    /// and returns booleans that must be true IF the given node is a leaf or an extension.
    pub(crate) fn advance_key_leaf_or_extension<
        F: RichField + Extendable<D>,
        const D: usize,
        const LIST_LEN: usize,
        // in case of a leaf, the value can be up to 33 bytes because of additional RLP encoding
        // in case of extension, the value is 32 bytes
        const VALUE_LEN: usize,
    >(
        b: &mut CircuitBuilder<F, D>,
        node: &Array<Target, { PAD_LEN(NODE_LEN) }>,
        key: &MPTKeyWire,
        rlp_headers: &RlpList<LIST_LEN>,
    ) -> (MPTKeyWire, Array<Target, VALUE_LEN>, BoolTarget) {
        let two = b.two();
        let condition = b.is_equal(rlp_headers.num_fields, two);
        let key_header = RlpHeader {
            data_type: rlp_headers.data_type[0],
            offset: rlp_headers.offset[0],
            len: rlp_headers.len[0],
        };
        let (extracted_key, should_true) = decode_compact_encoding(b, node, &key_header);
        // it's either the _value_ of the leaf, OR the _hash_ of the child node if node = ext.
        let leaf_child_hash = node.extract_array::<F, D, VALUE_LEN>(b, rlp_headers.offset[1]);
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
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
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

    /// Proves the prefix of this key and other's key up to pointer, not included,
    /// are the same and check both pointers are the same.
    /// i.e. check self.key[0..self.pointer] == other.key[0..other.pointer]
    /// Note how it's not `0..=self.pointer`, we check up to pointer excluded.
    pub fn enforce_prefix_equal<F: RichField + Extendable<D>, const D: usize>(
        &self,
        b: &mut CircuitBuilder<F, D>,
        other: &Self,
    ) {
        b.connect(self.pointer, other.pointer);
        self.key.enforce_slice_equals(b, &other.key, self.pointer);
    }
    /// Register the key and pointer as public inputs.
    pub fn register_as_input<F: RichField + Extendable<D>, const D: usize>(
        &self,
        b: &mut CircuitBuilder<F, D>,
    ) {
        self.key.register_as_public_input(b);
        b.register_public_input(self.pointer);
    }

    /// Initialize a new MPTKeyWire from the array of `U32Target`.
    /// It returns a MPTKeyWire with the pointer set to the last nibble, as in an initial
    /// case.
    pub fn init_from_u32_targets<F: RichField + Extendable<D>, const D: usize>(
        b: &mut CircuitBuilder<F, D>,
        arr: &Array<U32Target, PACKED_HASH_LEN>,
    ) -> Self {
        Self {
            key: Array {
                arr: arr
                    .arr
                    .iter()
                    .flat_map(|u32_limb| {
                        // decompose the `U32Target` in 16 limbs of 2 bits each; the output limbs are already range-checked
                        // by the `split_le_base` operation
                        let limbs: [Target; 16] =
                            b.split_le_base::<4>(u32_limb.0, 16).try_into().unwrap();
                        // now we need to pack each pair of 2 bit limbs into a nibble, but for each byte we want nibbles to
                        // be ordered in big-endian
                        limbs
                            .chunks(4)
                            .flat_map(|chunk| {
                                vec![
                                    b.mul_const_add(F::from_canonical_u8(4), chunk[3], chunk[2]),
                                    b.mul_const_add(F::from_canonical_u8(4), chunk[1], chunk[0]),
                                ]
                            })
                            .collect::<Vec<_>>()
                    })
                    .collect::<Vec<_>>()
                    .try_into()
                    .unwrap(),
            },
            pointer: b.constant(F::from_canonical_usize(MAX_KEY_NIBBLE_LEN - 1)),
        }
    }
}

pub(crate) fn bytes_to_nibbles(bytes: &[u8]) -> Vec<u8> {
    let mut nibbles = Vec::new();
    for b in bytes {
        nibbles.push(b >> 4);
        nibbles.push(b & 0x0F);
    }
    nibbles
}
pub(crate) fn nibbles_to_bytes(nibbles: &[u8]) -> Vec<u8> {
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

#[cfg(test)]
pub mod test {
    use std::array::from_fn as create_array;
    use std::env;
    use std::str::FromStr;
    use std::sync::Arc;

    use eth_trie::{EthTrie, MemoryDB, Nibbles, Trie};
    use ethers::providers::{Http, Provider};
    use ethers::types::{Address, EIP1186ProofResponse};
    use itertools::Itertools;
    use plonky2::field::types::Field;
    use plonky2::iop::witness::WitnessWrite;
    use plonky2::{
        field::extension::Extendable,
        hash::hash_types::RichField,
        iop::{
            target::{BoolTarget, Target},
            witness::PartialWitness,
        },
        plonk::{
            circuit_builder::CircuitBuilder,
            circuit_data::CircuitConfig,
            config::{GenericConfig, PoseidonGoldilocksConfig},
        },
    };
    use plonky2_crypto::u32::arithmetic_u32::U32Target;
    use rand::{thread_rng, Rng, RngCore};

    use crate::api::mapping::leaf::VALUE_LEN;
    use crate::array::Vector;
    use crate::benches::init_logging;
    use crate::eth::ProofQuery;
    use crate::keccak::{InputData, KeccakCircuit, HASH_LEN, PACKED_HASH_LEN};
    use crate::mpt_sequential::{bytes_to_nibbles, nibbles_to_bytes, NB_ITEMS_LEAF};
    use crate::rlp::{
        decode_compact_encoding, decode_fixed_list, decode_header, MAX_ITEMS_IN_LIST,
        MAX_KEY_NIBBLE_LEN,
    };
    use crate::utils::{convert_u8_targets_to_u32, less_than, IntTargetWriter};
    use crate::{
        array::{Array, VectorWire},
        circuit::{test::run_circuit, UserCircuit},
        keccak::OutputHash,
        mpt_sequential::MPTKeyWire,
        utils::{find_index_subvector, keccak256},
    };

    use super::{Circuit, InputWires, OutputWires, MAX_LEAF_VALUE_LEN, PAD_LEN};
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    #[derive(Clone, Debug)]
    struct TestCircuit<const DEPTH: usize, const NODE_LEN: usize> {
        c: Circuit<DEPTH, NODE_LEN>,
        exp_root: [u8; 32],
        exp_value: [u8; MAX_LEAF_VALUE_LEN],
        // The flag identifies if need to check the expected leaf value, it's
        // set to true for storage proof, and false for state proof (unconcern).
        checking_value: bool,
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
        type Wires = (
            InputWires<DEPTH, NODE_LEN>,
            OutputWires<DEPTH, NODE_LEN>,
            Array<Target, HASH_LEN>,           // root
            Array<Target, MAX_LEAF_VALUE_LEN>, // value
            BoolTarget,                        // checking_value
        );

        fn build(c: &mut CircuitBuilder<F, D>) -> Self::Wires {
            let expected_root = Array::<Target, HASH_LEN>::new(c);
            let packed_exp_root = convert_u8_targets_to_u32(c, &expected_root.arr);
            let arr = Array::<U32Target, PACKED_HASH_LEN>::from_array(
                packed_exp_root.try_into().unwrap(),
            );
            let input_wires = Circuit::create_input_wires(c, None);
            let output_wires = Circuit::verify_mpt_proof(c, &input_wires);
            let is_equal = output_wires.root.equals(c, &arr);
            let tt = c._true();
            c.connect(is_equal.target, tt.target);
            let value_wire = Array::<Target, MAX_LEAF_VALUE_LEN>::new(c);
            let values_equal = value_wire.equals(c, &output_wires.leaf);
            let checking_value = c.add_virtual_bool_target_safe();
            let values_equal = c.select(checking_value, values_equal.target, tt.target);
            c.connect(tt.target, values_equal);
            (
                input_wires,
                output_wires,
                expected_root,
                value_wire,
                checking_value,
            )
        }

        fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
            self.c.assign_wires(pw, &wires.0, &wires.1).unwrap();
            wires.2.assign(
                pw,
                &create_array(|i| F::from_canonical_u8(self.exp_root[i])),
            );
            wires.3.assign(
                pw,
                &create_array(|i| F::from_canonical_u8(self.exp_value[i])),
            );
            pw.set_bool_target(wires.4, self.checking_value);
        }
    }
    use anyhow::Result;

    #[tokio::test]
    async fn test_kashish_contract_simple_slot() -> Result<()> {
        // https://sepolia.etherscan.io/address/0xd6a2bFb7f76cAa64Dad0d13Ed8A9EFB73398F39E#code
        #[cfg(feature = "ci")]
        let url = env::var("CI_SEPOLIA").expect("CI_SEPOLIA env var not set");
        #[cfg(not(feature = "ci"))]
        let url = "https://ethereum-sepolia-rpc.publicnode.com";

        let provider =
            Provider::<Http>::try_from(url).expect("could not instantiate HTTP Provider");

        // sepolia contract
        let contract = Address::from_str("0xd6a2bFb7f76cAa64Dad0d13Ed8A9EFB73398F39E")?;
        // simple storage test
        let query = ProofQuery::new_simple_slot(contract, 0);
        let res = query.query_mpt_proof(&provider, None).await?;

        // Verify both storage and state proofs by this MPT circuit.

        // Written as constant from ^
        const DEPTH: usize = 2;
        const NODE_LEN: usize = 150;
        verify_storage_proof_from_query::<DEPTH, NODE_LEN>(&query, &res)?;
        verify_state_proof_from_query(&query, &res)
    }

    /// Verify the storage proof from query result.
    pub(crate) fn verify_storage_proof_from_query<const DEPTH: usize, const NODE_LEN: usize>(
        query: &ProofQuery,
        res: &EIP1186ProofResponse,
    ) -> Result<()>
    where
        [(); PAD_LEN(NODE_LEN)]:,
        [(); DEPTH - 1]:,
        [(); PAD_LEN(NODE_LEN) / 4]:,
    {
        ProofQuery::verify_storage_proof(&res)?;

        let value = res.storage_proof[0].value;
        let mut value_bytes = [0u8; VALUE_LEN];
        value.to_big_endian(&mut value_bytes);
        let encoded_value = rlp::encode(&value_bytes.to_vec()).to_vec();
        let mpt_proof = res.storage_proof[0]
            .proof
            .iter()
            .rev() // we want the leaf first and root last
            .map(|b| b.to_vec())
            .collect::<Vec<Vec<u8>>>();
        let root = keccak256(mpt_proof.last().unwrap());
        let mpt_key = query.slot.mpt_key_vec();
        println!("proof depth : {}", mpt_proof.len());
        println!(
            "proof max len node : {}",
            mpt_proof.iter().map(|node| node.len()).max().unwrap()
        );
        visit_proof(&mpt_proof);
        for i in 1..mpt_proof.len() {
            let child_hash = keccak256(&mpt_proof[i - 1]);
            let u8idx = find_index_subvector(&mpt_proof[i], &child_hash);
            assert!(u8idx.is_some());
        }
        let circuit = TestCircuit::<DEPTH, NODE_LEN> {
            c: Circuit::<DEPTH, NODE_LEN>::new(mpt_key.try_into().unwrap(), mpt_proof),
            exp_root: root.try_into().unwrap(),
            exp_value: encoded_value.try_into().unwrap(),
            checking_value: false,
        };
        run_circuit::<F, D, C, _>(circuit);

        Ok(())
    }

    /// Verify the state proof from query result.
    fn verify_state_proof_from_query(query: &ProofQuery, res: &EIP1186ProofResponse) -> Result<()> {
        query.verify_state_proof(&res)?;

        let mpt_proof = res
            .account_proof
            .iter()
            .rev() // we want the leaf first and root last
            .map(|b| b.to_vec())
            .collect::<Vec<Vec<u8>>>();
        let root = keccak256(mpt_proof.last().unwrap());
        let mpt_key = keccak256(&query.contract.0);
        println!("Account proof depth : {}", mpt_proof.len());
        println!(
            "Account proof max len node : {}",
            mpt_proof.iter().map(|node| node.len()).max().unwrap()
        );
        // Written as constant from ^.
        const DEPTH: usize = 9;
        const NODE_LEN: usize = 532;
        visit_proof(&mpt_proof);
        for i in 1..mpt_proof.len() {
            let child_hash = keccak256(&mpt_proof[i - 1]);
            let u8idx = find_index_subvector(&mpt_proof[i], &child_hash);
            assert!(u8idx.is_some());
        }
        let circuit = TestCircuit::<DEPTH, NODE_LEN> {
            c: Circuit::<DEPTH, NODE_LEN>::new(mpt_key.try_into().unwrap(), mpt_proof),
            exp_root: root.try_into().unwrap(),
            exp_value: [0; MAX_LEAF_VALUE_LEN],
            // the reason we don't check the value is the circuit is made for storage proof and it extracts a 32bytes
            // value. In the case of state trie, the value is 104 bytes so value is never gonna be equal.
            checking_value: false,
        };
        run_circuit::<F, D, C, _>(circuit);

        Ok(())
    }

    #[test]
    fn test_mpt_proof_verification() {
        init_logging();
        // max depth of the trie
        const DEPTH: usize = 4;
        // leave one for padding
        const ACTUAL_DEPTH: usize = DEPTH - 1;
        // max len of a node
        const NODE_LEN: usize = 500;
        const VALUE_LEN: usize = 32;
        let (proof, key, root, value) = if true {
            let (mut trie, key) = generate_random_storage_mpt::<ACTUAL_DEPTH, VALUE_LEN>();
            let root = trie.root_hash().unwrap();
            // root is first so we reverse the order as in circuit we prove the opposite way
            let mut proof = trie.get_proof(&key).unwrap();
            proof.reverse();
            assert!(proof.len() == ACTUAL_DEPTH);
            assert!(proof.len() <= DEPTH);
            assert!(keccak256(proof.last().unwrap()) == root.to_fixed_bytes());
            let value = trie.get(&key).unwrap().unwrap();
            (proof, key, root.to_fixed_bytes(), value)
        } else {
            // easy switch case for specific proofs that were not validated by the circuits
            // to debug
            let p = vec![
                hex::decode("f842a020ac931c0565bcf8dae7f3c47f474033bc59cfa0779d95915c8be47e54b2a7eaa03e49459d835b45480f665734072c215077c2e47b50b4d00924e12af93a783e64").unwrap(),
                hex::decode("f85180808080808080808080a029767ccc229b9de90f860d127ecd43bcf52bce1a2411325f6a404b62ab88fd9a808080a08abe136d0af8f9c2c0d199ba338b0f5998d8a878842d020a0aba80322159db328080").unwrap(),
                hex::decode("e21ba0ec450eb88a0e3357e72daee1a35e06df534309e73bfbf2d9707db683e1804982").unwrap(),
                ];
            let key =
                hex::decode("baac931c0565bcf8dae7f3c47f474033bc59cfa0779d95915c8be47e54b2a7ea")
                    .unwrap();
            let root = keccak256(p.last().unwrap()).try_into().unwrap();
            let tuple: Vec<Vec<u8>> = rlp::decode_list(p.first().unwrap());
            (p, key, root, tuple[1].clone())
        };
        println!("KEY = {}", hex::encode(&key));
        println!("PROOF LEN = {}", proof.len());
        visit_proof(&proof);
        for i in 1..proof.len() {
            let child_hash = keccak256(&proof[i - 1]);
            let u8idx = find_index_subvector(&proof[i], &child_hash);
            assert!(u8idx.is_some());
        }
        let circuit = TestCircuit::<DEPTH, NODE_LEN> {
            c: Circuit::<DEPTH, NODE_LEN>::new(key.try_into().unwrap(), proof),
            exp_root: root,
            // simply pad it to max size
            exp_value: create_array(|i| if i < VALUE_LEN { value[i] } else { 0 }),
            checking_value: true,
        };
        run_circuit::<F, D, C, _>(circuit);
    }

    pub(crate) fn visit_proof(proof: &[Vec<u8>]) {
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
    fn test_extract_any_node() {
        const DEPTH: usize = 4;
        const NODE_LEN: usize = 500;
        const VALUE_LEN: usize = 32;
        let (proof, key) = if true {
            let (mut trie, key) = generate_random_storage_mpt::<DEPTH, VALUE_LEN>();
            let mut proof = trie.get_proof(&key).unwrap();
            proof.reverse();
            for (i, node) in proof.iter().enumerate() {
                println!("[+] node {}: {} ", i, hex::encode(node));
            }
            println!("[+] key: {}", hex::encode(&key));
            (proof, key)
        } else {
            let p = vec![
                hex::decode("f842a020ac931c0565bcf8dae7f3c47f474033bc59cfa0779d95915c8be47e54b2a7eaa03e49459d835b45480f665734072c215077c2e47b50b4d00924e12af93a783e64").unwrap(),
                hex::decode("f85180808080808080808080a029767ccc229b9de90f860d127ecd43bcf52bce1a2411325f6a404b62ab88fd9a808080a08abe136d0af8f9c2c0d199ba338b0f5998d8a878842d020a0aba80322159db328080").unwrap(),
                hex::decode("e21ba0ec450eb88a0e3357e72daee1a35e06df534309e73bfbf2d9707db683e1804982").unwrap(),
                ];
            let key =
                hex::decode("baac931c0565bcf8dae7f3c47f474033bc59cfa0779d95915c8be47e54b2a7ea")
                    .unwrap();
            (p, key)
        };
        let key_nibbles = bytes_to_nibbles(&key);
        assert_eq!(key_nibbles.len(), MAX_KEY_NIBBLE_LEN);
        // try with the parent of the leaf
        let node_byte: Vec<u8> = proof[1].clone();
        let node_list: Vec<Vec<u8>> = rlp::decode_list(&node_byte);
        // make sure the node is a branch node
        assert_eq!(node_list.len(), 17);
        // first see the leaf to determine the partial key length
        let leaf_node: Vec<u8> = proof[0].clone();
        // RLP ( RLP (compact(partial_key_in_nibble)), RLP(value))
        let leaf_tuple: Vec<Vec<u8>> = rlp::decode_list(&leaf_node);
        assert_eq!(leaf_tuple.len(), 2);
        let leaf_value: Vec<u8> = leaf_tuple[1].clone();
        let leaf_partial_key_struct = Nibbles::from_compact(&leaf_tuple[0]);
        let leaf_partial_key_nibbles = leaf_partial_key_struct.nibbles();
        let leaf_partial_key_ptr = MAX_KEY_NIBBLE_LEN - 1 - leaf_partial_key_nibbles.len();
        // since it's a branch node, we know the pointer is one less
        let node_partial_key_ptr = leaf_partial_key_ptr - 1;
        println!("[+] Node partial key ptr = {}", node_partial_key_ptr);

        let try_with =
            |mut chosen_node: Vec<u8>, exp_byte_value: Vec<u8>, input_ptr: i32, output_ptr: i32| {
                let config = CircuitConfig::standard_recursion_config();
                let mut pw = PartialWitness::new();
                let mut b = CircuitBuilder::<F, D>::new(config);
                let tr = b._true();
                let zero = b.zero();
                let node = Array::<Target, { PAD_LEN(NODE_LEN) }>::new(&mut b);
                let key_wire = MPTKeyWire::new(&mut b);
                let (advanced_key, value, valid_node) =
                    Circuit::<DEPTH, NODE_LEN>::advance_key(&mut b, &node, &key_wire);
                b.connect(tr.target, valid_node.target);
                let exp_key_ptr = b.add_virtual_target();
                b.connect(advanced_key.pointer, exp_key_ptr);
                let exp_value = Array::<Target, VALUE_LEN>::new(&mut b);
                let should_be_true = value.contains_array(&mut b, &exp_value, zero);
                b.connect(tr.target, should_be_true.target);
                let data = b.build::<C>();
                chosen_node.resize(PAD_LEN(NODE_LEN), 0);
                let node_f = chosen_node
                    .iter()
                    .map(|b| F::from_canonical_u8(*b))
                    .collect::<Vec<_>>();
                node.assign(&mut pw, &node_f.try_into().unwrap());
                let key_nibbles = bytes_to_nibbles(&key);
                key_wire.assign(
                    &mut pw,
                    &key_nibbles.try_into().unwrap(),
                    // we start from the pointer that should have been updated by processing the leaf
                    input_ptr as usize,
                );
                if output_ptr < 0 {
                    pw.set_target(exp_key_ptr, F::NEG_ONE);
                } else {
                    pw.set_target(exp_key_ptr, F::from_canonical_usize(output_ptr as usize));
                }
                exp_value.assign(
                    &mut pw,
                    &exp_byte_value
                        .into_iter()
                        .map(F::from_canonical_u8)
                        .collect::<Vec<_>>()
                        .try_into()
                        .unwrap(),
                );
                let proof = data.prove(pw).unwrap();
                data.verify(proof).unwrap();
            };

        println!("[+] Proof Generation with leaf");
        try_with(
            leaf_node.clone(),
            // works because value is 32 byte same as a hash, otherwisewould need to use vector
            leaf_value,
            (MAX_KEY_NIBBLE_LEN - 1) as i32,
            leaf_partial_key_ptr as i32,
        );
        let mut curr_pointer = leaf_partial_key_ptr as i32;
        let mut exp_value = keccak256(&leaf_node);
        for (i, node) in proof[1..].iter().enumerate() {
            let node_list: Vec<Vec<u8>> = rlp::decode_list(node);
            let (output_ptr, must_prove) = if node_list.len() == 17 {
                println!("[+] trying out with branch node {} in proof", i + 1);
                (curr_pointer - 1, true)
            } else if node_list.len() == 2 {
                let nibbles = Nibbles::from_compact(&node_list[0]);
                let nibbles_bytes = nibbles.nibbles();
                println!(
                    "[+] trying out with extension node {} in proof - key portion {}",
                    i + 1,
                    hex::encode(nibbles_to_bytes(nibbles_bytes))
                );
                (curr_pointer - nibbles_bytes.len() as i32, true)
            } else {
                panic!("invalid node");
            };
            if must_prove {
                println!("[+] Launching Proof Generation");
                try_with(node.clone(), exp_value.clone(), curr_pointer, output_ptr);
            }
            curr_pointer = output_ptr;
            exp_value = keccak256(node);
        }
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
        let leaf_value: Vec<u8> = leaf_tuple[1].clone();
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
        let tt = builder._true();
        let node = Array::<Target, { PAD_LEN(NODE_LEN) }>::new(&mut builder);
        let key_wire = MPTKeyWire::new(&mut builder);
        let rlp_headers =
            decode_fixed_list::<F, D, MAX_ITEMS_IN_LIST>(&mut builder, &node.arr, zero);
        let (advanced_key, value, should_true, _) = Circuit::<DEPTH, NODE_LEN>::advance_key_branch(
            &mut builder,
            &node,
            &key_wire,
            &rlp_headers,
        );
        builder.connect(tt.target, should_true.target);
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
        let leaf_value: Vec<u8> = leaf_tuple[1].clone();
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
        let tt = builder._true();
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
        let all_true = builder.and(should_be_true, should_true);
        builder.connect(tt.target, all_true.target);
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

    #[test]
    fn test_mpt_key_from_bytes() {
        // test the from bytes capacity
        let config = CircuitConfig::standard_recursion_config();
        let mut pw = PartialWitness::new();
        let mut b = CircuitBuilder::<F, D>::new(config);
        let tt = b._true();
        let key_bytes = Array::<Target, HASH_LEN>::new(&mut b);
        let key_u32: Array<U32Target, PACKED_HASH_LEN> =
            convert_u8_targets_to_u32(&mut b, &key_bytes.arr)
                .into_iter()
                .collect::<Vec<_>>()
                .try_into()
                .unwrap();
        let key_nibbles = MPTKeyWire::init_from_u32_targets(&mut b, &key_u32);
        let exp_nibbles = Array::<Target, MAX_KEY_NIBBLE_LEN>::new(&mut b);
        let eq = key_nibbles.key.equals(&mut b, &exp_nibbles);
        b.connect(tt.target, eq.target);

        let mut mpt_key = vec![0u8; 32];
        thread_rng().fill_bytes(&mut mpt_key);
        let mpt_nibbles = bytes_to_nibbles(&mpt_key);
        key_bytes.assign_bytes(&mut pw, &mpt_key.try_into().unwrap());
        exp_nibbles.assign_bytes(&mut pw, &mpt_nibbles.try_into().unwrap());

        let data = b.build::<C>();
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
}
