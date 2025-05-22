//! Gadget to reconstruct the Merkle root of a tree from a Merkle path

use std::{array, iter::once};

use crate::{CBuilder, D, F};
use alloy::primitives::U256;
use anyhow::{ensure, Result};
use itertools::Itertools;
use mp2_common::{
    hash::hash_maybe_first,
    poseidon::empty_poseidon_hash,
    serialization::{
        circuit_data_serialization::SerializableRichField, deserialize, deserialize_array,
        deserialize_long_array, serialize, serialize_array, serialize_long_array,
    },
    types::HashOutput,
    u256::{CircuitBuilderU256, UInt256Target, WitnessWriteU256, NUM_LIMBS},
    utils::{FromFields, FromTargets, HashBuilder, SelectTarget, ToFields, ToTargets, TryIntoBool},
};
use mp2_test::utils::gen_random_field_hash;
use plonky2::{
    field::types::Field,
    hash::hash_types::{HashOut, HashOutTarget, NUM_HASH_OUT_ELTS},
    iop::{
        target::{BoolTarget, Target},
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{circuit_builder::CircuitBuilder, config::GenericHashOut},
};
use rand::Rng;
use serde::{Deserialize, Serialize};

use super::utils::{ChildPosition, NodeInfo, NodeInfoTarget};

#[derive(Clone, Debug, Serialize, Deserialize)]
/// Input wires for Merkle path verification gadget
pub struct MerklePathTargetInputs<const MAX_DEPTH: usize>
where
    [(); MAX_DEPTH - 1]:,
{
    #[serde(
        serialize_with = "serialize_array",
        deserialize_with = "deserialize_array"
    )]
    is_left_child: [BoolTarget; MAX_DEPTH - 1],
    #[serde(
        serialize_with = "serialize_array",
        deserialize_with = "deserialize_array"
    )]
    sibling_hash: [HashOutTarget; MAX_DEPTH - 1],
    #[serde(
        serialize_with = "serialize_array",
        deserialize_with = "deserialize_array"
    )]
    node_min: [UInt256Target; MAX_DEPTH - 1],
    #[serde(
        serialize_with = "serialize_array",
        deserialize_with = "deserialize_array"
    )]
    node_max: [UInt256Target; MAX_DEPTH - 1],
    #[serde(
        serialize_with = "serialize_array",
        deserialize_with = "deserialize_array"
    )]
    node_value: [UInt256Target; MAX_DEPTH - 1],
    #[serde(
        serialize_with = "serialize_array",
        deserialize_with = "deserialize_array"
    )]
    embedded_tree_hash: [HashOutTarget; MAX_DEPTH - 1],
    /// Array of MAX_DEPTH-1 flags specifying whether the current node is a real node in the path or a dummy one.
    /// That is, if the path being proven has depth d <= MAX_DEPTH, then the first d-1 entries of this array
    /// are true, while the remaining D-d ones are false
    #[serde(
        serialize_with = "serialize_array",
        deserialize_with = "deserialize_array"
    )]
    is_real_node: [BoolTarget; MAX_DEPTH - 1],
}
#[derive(Clone, Debug, Serialize, Deserialize)]
/// Input wires related to the data of the end node whose membership in the tree
/// is proven with `MerklePathWithNeighborsGadget`.
pub struct EndNodeInputs {
    // minimum of the end node. It is necessary to recompute the hash of the node
    // inside the circuit
    node_min: UInt256Target,
    // maximum of the end node. It is necessary to recompute the hash of the node
    // inside the circuit
    node_max: UInt256Target,
    #[serde(serialize_with = "serialize", deserialize_with = "deserialize")]
    // Flag specifying whether the end node has a left child
    left_child_exists: BoolTarget,
    // The data about the left child of the node, which might be necessary to
    // extract the value of the predecessor of the end node
    left_child_info: NodeInfoTarget,
    #[serde(serialize_with = "serialize", deserialize_with = "deserialize")]
    // Flag specifying whether the end node has a right child
    right_child_exists: BoolTarget,
    // The data about the right child of the node, which might be necessary to
    // extract the value of the successor of the end node
    right_child_info: NodeInfoTarget,
}

impl EndNodeInputs {
    pub(crate) fn build(b: &mut CBuilder) -> Self {
        let [node_min, node_max] = b.add_virtual_u256_arr_unsafe();
        let [left_child_exists, right_child_exists] =
            array::from_fn(|_| b.add_virtual_bool_target_safe());

        Self {
            node_min,
            node_max,
            left_child_exists,
            left_child_info: NodeInfoTarget::build_unsafe(b),
            right_child_exists,
            right_child_info: NodeInfoTarget::build_unsafe(b),
        }
    }
}

#[derive(Clone, Debug)]
/// Set of input/output wires built by merkle path verification gadget
pub struct MerklePathTarget<const MAX_DEPTH: usize>
where
    [(); MAX_DEPTH - 1]:,
{
    pub(crate) inputs: MerklePathTargetInputs<MAX_DEPTH>,
    /// Recomputed root for the Merkle path
    pub(crate) root: HashOutTarget,
}
#[derive(Clone, Debug)]
/// Target containing data about a neighbor of a node (neighbor can be
/// either the predecessor or the successor of a node)
pub struct NeighborInfoTarget {
    /// Boolean flag specifying whether the node has the given neighbor
    pub(crate) is_found: BoolTarget,
    /// Boolean flag specifying whether the neighbor is in the path from the
    /// given node up to the root
    pub(crate) is_in_path: BoolTarget,
    /// Value of the neighbor (if the neighbor exists, otherwise a dummy value can be employed)
    pub(crate) value: UInt256Target,
    /// Hash of the neighbor node (if the neighbor exists, otherwise a dummy value can be employed)
    pub(crate) hash: HashOutTarget,
}

impl NeighborInfoTarget {
    pub(crate) fn new_dummy_predecessor(b: &mut CircuitBuilder<F, D>) -> Self {
        Self {
            is_found: b._false(),
            is_in_path: b._true(), // the circuit still looks at the predecessor in the path
            value: b.zero_u256(),
            hash: b.constant_hash(*empty_poseidon_hash()),
        }
    }

    pub(crate) fn new_dummy_successor(b: &mut CircuitBuilder<F, D>) -> Self {
        Self {
            is_found: b._false(),
            is_in_path: b._true(), // the circuit still looks at the predecessor in the path
            value: b.constant_u256(U256::MAX),
            hash: b.constant_hash(*empty_poseidon_hash()),
        }
    }
}

impl ToTargets for NeighborInfoTarget {
    fn to_targets(&self) -> Vec<Target> {
        once(self.is_found.target)
            .chain(once(self.is_in_path.target))
            .chain(self.value.to_targets())
            .chain(self.hash.to_targets())
            .collect()
    }
}

impl FromTargets for NeighborInfoTarget {
    const NUM_TARGETS: usize = 2 + NUM_LIMBS + NUM_HASH_OUT_ELTS;

    fn from_targets(t: &[Target]) -> Self {
        Self {
            is_found: BoolTarget::new_unsafe(t[0]),
            is_in_path: BoolTarget::new_unsafe(t[1]),
            value: UInt256Target::from_targets(&t[2..]),
            hash: HashOutTarget::from_targets(&t[2 + NUM_LIMBS..]),
        }
    }
}

impl SelectTarget for NeighborInfoTarget {
    fn select<F: SerializableRichField<D>, const D: usize>(
        b: &mut CircuitBuilder<F, D>,
        cond: &BoolTarget,
        first: &Self,
        second: &Self,
    ) -> Self {
        Self {
            is_found: BoolTarget::new_unsafe(b.select(
                *cond,
                first.is_found.target,
                second.is_found.target,
            )),
            is_in_path: BoolTarget::new_unsafe(b.select(
                *cond,
                first.is_in_path.target,
                second.is_in_path.target,
            )),
            value: b.select_u256(*cond, &first.value, &second.value),
            hash: b.select_hash(*cond, &first.hash, &second.hash),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
/// Set of input wires for the merkle path with neighbors gadget
pub struct MerklePathWithNeighborsTargetInputs<const MAX_DEPTH: usize>
where
    [(); MAX_DEPTH - 1]:,
{
    pub(crate) path_inputs: MerklePathTargetInputs<MAX_DEPTH>,
    pub(crate) end_node_inputs: EndNodeInputs,
}

#[derive(Clone, Debug)]
#[allow(dead_code)]
/// Set of input/output wires built by merkle path with neighbors gadget
pub struct MerklePathWithNeighborsTarget<const MAX_DEPTH: usize>
where
    [(); MAX_DEPTH - 1]:,
{
    pub(crate) inputs: MerklePathWithNeighborsTargetInputs<MAX_DEPTH>,
    /// Recomputed root for the Merkle path
    pub(crate) root: HashOutTarget,
    /// Hash of the node at the end of the path
    pub(crate) end_node_hash: HashOutTarget,
    /// Info about the predecessor of the node at the end of the path
    pub(crate) predecessor_info: NeighborInfoTarget,
    /// Info about the successor of the node at the end of the path
    pub(crate) successor_info: NeighborInfoTarget,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct MerklePathGadget<const MAX_DEPTH: usize>
where
    [(); MAX_DEPTH - 1]:,
{
    /// Array of MAX_DEPTH-1 flags, each specifying whether the previous node in the path
    /// is the left child of a given node in the path
    #[serde(
        serialize_with = "serialize_long_array",
        deserialize_with = "deserialize_long_array"
    )]
    is_left_child: [bool; MAX_DEPTH - 1],
    /// Hash of the sibling of the previous node in the path (empty hash if there is no sibling)
    #[serde(
        serialize_with = "serialize_long_array",
        deserialize_with = "deserialize_long_array"
    )]
    sibling_hash: [HashOut<F>; MAX_DEPTH - 1],
    /// Minimum value associated to each node in the path
    #[serde(
        serialize_with = "serialize_long_array",
        deserialize_with = "deserialize_long_array"
    )]
    node_min: [U256; MAX_DEPTH - 1],
    /// Maximum value associated to each node in the path
    #[serde(
        serialize_with = "serialize_long_array",
        deserialize_with = "deserialize_long_array"
    )]
    node_max: [U256; MAX_DEPTH - 1],
    /// Value stored in each node in the path
    #[serde(
        serialize_with = "serialize_long_array",
        deserialize_with = "deserialize_long_array"
    )]
    node_value: [U256; MAX_DEPTH - 1],
    /// Hash of the embedded tree stored in each node in the path
    #[serde(
        serialize_with = "serialize_long_array",
        deserialize_with = "deserialize_long_array"
    )]
    embedded_tree_hash: [HashOut<F>; MAX_DEPTH - 1],
    /// Number of real nodes in the path
    num_real_nodes: usize,
}

impl<const MAX_DEPTH: usize> Default for MerklePathGadget<MAX_DEPTH>
where
    [(); MAX_DEPTH - 1]:,
{
    fn default() -> Self {
        Self {
            is_left_child: [Default::default(); MAX_DEPTH - 1],
            sibling_hash: [Default::default(); MAX_DEPTH - 1],
            node_min: [Default::default(); MAX_DEPTH - 1],
            node_max: [Default::default(); MAX_DEPTH - 1],
            node_value: [Default::default(); MAX_DEPTH - 1],
            embedded_tree_hash: [Default::default(); MAX_DEPTH - 1],
            num_real_nodes: Default::default(),
        }
    }
}

impl<const MAX_DEPTH: usize> MerklePathGadget<MAX_DEPTH>
where
    [(); MAX_DEPTH - 1]:,
{
    /// Build a new instance of `Self`, representing the `path` provided as input. The `siblings`
    /// input provides the siblings of the nodes in the path, if any
    pub fn new(
        path: &[(NodeInfo, ChildPosition)],
        siblings: &[Option<HashOutput>],
    ) -> Result<Self> {
        let num_real_nodes = path.len();
        ensure!(
            siblings.len() == num_real_nodes,
            "Number of siblings must be the same as the nodes in the path"
        );

        let mut is_left_child = [false; MAX_DEPTH - 1];
        let mut embedded_tree_hash = [HashOut::default(); MAX_DEPTH - 1];
        let mut node_min = [U256::default(); MAX_DEPTH - 1];
        let mut node_max = [U256::default(); MAX_DEPTH - 1];
        let mut node_value = [U256::default(); MAX_DEPTH - 1];

        path.iter().enumerate().for_each(|(i, (node, position))| {
            is_left_child[i] = match position {
                ChildPosition::Left => true,
                ChildPosition::Right => false,
            };
            embedded_tree_hash[i] = node.embedded_tree_hash;
            node_min[i] = node.min;
            node_max[i] = node.max;
            node_value[i] = node.value;
        });

        let sibling_hash = array::from_fn(|i| {
            siblings
                .get(i)
                .and_then(|sibling| {
                    sibling.map(|node_hash| HashOut::from_bytes((&node_hash).into()))
                })
                .unwrap_or(*empty_poseidon_hash())
        });

        Ok(Self {
            is_left_child,
            sibling_hash,
            node_min,
            node_max,
            node_value,
            embedded_tree_hash,
            num_real_nodes,
        })
    }

    /// Build wires for `MerklePathGadget`. The required inputs are:
    /// - `end_node`: The hash of the first node in the path
    /// - `index_id`: Integer identifier of the index column to be placed in the hash
    ///     of the nodes of the path
    pub fn build(
        b: &mut CircuitBuilder<F, D>,
        end_node: HashOutTarget,
        index_id: Target,
    ) -> MerklePathTarget<MAX_DEPTH> {
        let (inputs, path) = Self::build_path(b, end_node, index_id);

        MerklePathTarget {
            inputs,
            root: *path.last().unwrap(),
        }
    }

    /// Gadget to compute the hashes of all the nodes in the path from `end_node` to the root of
    /// a Merkle-tree
    fn build_path(
        b: &mut CircuitBuilder<F, D>,
        end_node: HashOutTarget,
        index_id: Target,
    ) -> (
        MerklePathTargetInputs<MAX_DEPTH>,
        [HashOutTarget; MAX_DEPTH - 1],
    ) {
        let is_left_child = array::from_fn(|_| b.add_virtual_bool_target_unsafe());
        let [sibling_hash, embedded_tree_hash] =
            [0, 1].map(|_| array::from_fn(|_| b.add_virtual_hash()));
        let [node_min, node_max, node_value] = [0, 1, 2].map(
            |_| b.add_virtual_u256_arr_unsafe(), // unsafe should be ok since we just need to hash them
        );
        let is_real_node = array::from_fn(|_| b.add_virtual_bool_target_safe());
        let mut final_hash = end_node;
        let mut path_nodes = vec![];
        for i in 0..MAX_DEPTH - 1 {
            let rest = node_min[i]
                .to_targets()
                .into_iter()
                .chain(node_max[i].to_targets())
                .chain(once(index_id))
                .chain(node_value[i].to_targets())
                .chain(embedded_tree_hash[i].to_targets())
                .collect_vec();
            let node_hash = HashOutTarget::from_vec(hash_maybe_first(
                b,
                is_left_child[i],
                sibling_hash[i].elements,
                final_hash.elements,
                rest.as_slice(),
            ));
            final_hash = b.select_hash(is_real_node[i], &node_hash, &final_hash);
            path_nodes.push(final_hash);
        }

        let inputs = MerklePathTargetInputs {
            is_left_child,
            sibling_hash,
            node_min,
            node_max,
            node_value,
            embedded_tree_hash,
            is_real_node,
        };

        // ensure there is always one node in the path even if `MAX_DEPTH=1`
        if path_nodes.is_empty() {
            path_nodes.push(end_node);
        }

        (inputs, path_nodes.try_into().unwrap())
    }

    pub fn assign(&self, pw: &mut PartialWitness<F>, wires: &MerklePathTargetInputs<MAX_DEPTH>) {
        self.is_left_child
            .iter()
            .zip(wires.is_left_child)
            .for_each(|(&value, target)| pw.set_bool_target(target, value));
        [
            (self.sibling_hash, wires.sibling_hash),
            (self.embedded_tree_hash, wires.embedded_tree_hash),
        ]
        .into_iter()
        .for_each(|(value_hash, target_hash)| {
            value_hash
                .iter()
                .zip(target_hash)
                .for_each(|(&value, target)| pw.set_hash_target(target, value))
        });
        [
            (self.node_min, &wires.node_min),
            (self.node_max, &wires.node_max),
            (self.node_value, &wires.node_value),
        ]
        .into_iter()
        .for_each(|(values, targets)| {
            values
                .iter()
                .zip(targets)
                .for_each(|(&value, target)| pw.set_u256_target(target, value))
        });
        wires
            .is_real_node
            .iter()
            .enumerate()
            .for_each(|(i, &target)| pw.set_bool_target(target, i < self.num_real_nodes));
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct MerklePathWithNeighborsGadget<const MAX_DEPTH: usize>
where
    [(); MAX_DEPTH - 1]:,
{
    path_gadget: MerklePathGadget<MAX_DEPTH>,
    // minimum value of the node whose membership in in tree is
    // being proven with this gadget (referred to as `end_node`).
    // It is necessary to recompute the hash of the end node
    end_node_min: U256,
    // maximum value of the end node whose membership in the tree is
    // being proven with this gadget (referred to as `end_node`).
    // It is necessary to recompute the hash of the end node
    end_node_max: U256,
    // Data about the children of the end node whose membership in the
    // tree is being proven with this gadget (referred to as `end_node`).
    // Children data might be necessary to compute the value of the
    // predecessor/successor of the end node
    end_node_children: [Option<NodeInfo>; 2],
}

impl<const MAX_DEPTH: usize> MerklePathWithNeighborsGadget<MAX_DEPTH>
where
    [(); MAX_DEPTH - 1]:,
{
    /// Build a new instance of `Self`, representing the path from `end_node` to the root.
    /// Such path is provided as input, altogether with the siblings of the nodes in such
    /// path, if any. The method requires also the data about the children of `end_node`,
    /// if any.
    pub fn new(
        path: &[(NodeInfo, ChildPosition)],
        siblings: &[Option<HashOutput>],
        end_node: &NodeInfo,
        end_node_children: [Option<NodeInfo>; 2],
    ) -> Result<Self> {
        let path_gadget = MerklePathGadget::new(path, siblings)?;
        Ok(Self {
            path_gadget,
            end_node_min: end_node.min,
            end_node_max: end_node.max,
            end_node_children,
        })
    }

    /// Build wires for `MerklePathGadget`. The required inputs are:
    /// - `end_node_value`: Value stored in the first node in the path
    /// - `end_node_tree_hash` : Hash of the embedded tree stored in the first node in the path
    /// - `index_id`: Integer identifier of the index column to be placed in the hash
    ///     of the nodes of the path
    pub fn build(
        b: &mut CircuitBuilder<F, D>,
        end_node_value: UInt256Target,
        end_node_tree_hash: HashOutTarget,
        index_id: Target,
    ) -> MerklePathWithNeighborsTarget<MAX_DEPTH> {
        let end_node_info = EndNodeInputs::build(b);
        // compute end node hash
        let left_child_hash = end_node_info.left_child_info.compute_node_hash(b, index_id);
        let right_child_hash = end_node_info
            .right_child_info
            .compute_node_hash(b, index_id);
        let empty_hash = b.constant_hash(*empty_poseidon_hash());
        let left_child_hash = b.select_hash(
            end_node_info.left_child_exists,
            &left_child_hash,
            &empty_hash,
        );
        let right_child_hash = b.select_hash(
            end_node_info.right_child_exists,
            &right_child_hash,
            &empty_hash,
        );
        let end_node = NodeInfoTarget {
            embedded_tree_hash: end_node_tree_hash,
            child_hashes: [left_child_hash, right_child_hash],
            value: end_node_value,
            min: end_node_info.node_min.clone(),
            max: end_node_info.node_max.clone(),
        };
        let end_node_hash = end_node.compute_node_hash(b, index_id);
        let (inputs, path) = MerklePathGadget::build_path(b, end_node_hash, index_id);
        // we need to initialize predecessor and successor data
        let (mut predecessor_info, mut successor_info) = {
            // the predecessor of end_node is an ancestor of end_node iff end_node has no left child
            let is_predecessor_in_path = b.not(end_node_info.left_child_exists);
            let zero_u256 = b.zero_u256();
            let max_u256 = b.constant_u256(U256::MAX);
            // Initialize value of predecessor node of end_node to a dummy value if the predecessor node
            // will be found in the path; otherwise, the predecessor_value is the maximum value in
            // the subtree rooted in the left child of end_node
            let predecessor_value = b.select_u256(
                is_predecessor_in_path,
                &zero_u256,
                &end_node_info.left_child_info.max,
            );
            // the predecessor value is already found if end_node has a left child
            let predecessor_found = end_node_info.left_child_exists;
            // Initialize predecessor node hash to a dummy value
            let predecessor_hash = b.constant_hash(*empty_poseidon_hash());
            // build predecessor info
            let predecessor_info = NeighborInfoTarget {
                is_found: predecessor_found,
                is_in_path: is_predecessor_in_path,
                value: predecessor_value,
                hash: predecessor_hash,
            };

            // the successor of end_node is an ancestor of end_node iff end_node has no right child
            let is_successor_in_path = b.not(end_node_info.right_child_exists);
            // Initialize value of successor node of end_node to a dummy value if the successor node
            // will be found in the path; otherwise, successor_value is the minimum value in
            // the subtree rooted in the right child of end_node
            let successor_value = b.select_u256(
                is_successor_in_path,
                &max_u256, // set dummy value of success to `U256::MAX`, it allows to satisfy constraints of
                // `are_consecutive_nodes` gadget in case the node has no successor in the tree
                &end_node_info.right_child_info.min,
            );
            // the successor value is already found if end_node has a right child
            let successor_found = end_node_info.right_child_exists;
            // Initialize successor node hash to a dummy value
            let successor_hash = b.constant_hash(*empty_poseidon_hash());
            // build successor info
            let successor_info = NeighborInfoTarget {
                is_found: successor_found,
                is_in_path: is_successor_in_path,
                value: successor_value,
                hash: successor_hash,
            };
            (predecessor_info, successor_info)
        };

        #[allow(clippy::needless_range_loop)]
        for i in 0..MAX_DEPTH - 1 {
            // we need to look for the predecessor
            let is_right_child = b.not(inputs.is_left_child[i]);
            /* First, we determine if the current node is the predecessor */
            let mut is_current_node_predecessor = b.not(predecessor_info.is_found); // current node cannot
                                                                                    // be the predecessor if predecessor has already been found
            is_current_node_predecessor =
                b.and(is_current_node_predecessor, inputs.is_real_node[i]); // current node
                                                                            // cannot be the predecessor if it's not a real node
            is_current_node_predecessor = b.and(is_current_node_predecessor, is_right_child); // current node
                                                                                              // is the predecessor if the previous node in the path is its right child
                                                                                              // we update predecessor_info.hash if current node is the predecessor
            predecessor_info.hash = b.select_hash(
                is_current_node_predecessor,
                &path[i],
                &predecessor_info.hash,
            );
            // we update predecessor_info.value if current node is the predecessor
            predecessor_info.value = b.select_u256(
                is_current_node_predecessor,
                &inputs.node_value[i],
                &predecessor_info.value,
            );
            // set predecessor_info.is_found if current node is the predecessor
            predecessor_info.is_found =
                b.or(predecessor_info.is_found, is_current_node_predecessor);

            // we need to look for the successor
            /* First, we determine if the current node is the successor */
            let mut is_current_node_successor = b.not(successor_info.is_found); // current node cannot
                                                                                // be the successor if successor has already been found
            is_current_node_successor = b.and(is_current_node_successor, inputs.is_real_node[i]); // current node
                                                                                                  // cannot be the successor if it's not a real node
            is_current_node_successor = b.and(is_current_node_successor, inputs.is_left_child[i]); // current node
                                                                                                   // is the successor if the previous node in the path is its left child
                                                                                                   // we update successor_info.hash if current node is the successor
            successor_info.hash =
                b.select_hash(is_current_node_successor, &path[i], &successor_info.hash);
            // we update successor_info.value if current node is the successor
            successor_info.value = b.select_u256(
                is_current_node_successor,
                &inputs.node_value[i],
                &successor_info.value,
            );
            // set successor_info.is_found if current node is the successor
            successor_info.is_found = b.or(successor_info.is_found, is_current_node_successor);
        }

        MerklePathWithNeighborsTarget {
            inputs: MerklePathWithNeighborsTargetInputs {
                path_inputs: inputs,
                end_node_inputs: end_node_info,
            },
            root: *path.last().unwrap(),
            end_node_hash,
            predecessor_info,
            successor_info,
        }
    }

    pub fn assign(
        &self,
        pw: &mut PartialWitness<F>,
        wires: &MerklePathWithNeighborsTargetInputs<MAX_DEPTH>,
    ) {
        self.path_gadget.assign(pw, &wires.path_inputs);
        pw.set_u256_target_arr(
            &[
                wires.end_node_inputs.node_min.clone(),
                wires.end_node_inputs.node_max.clone(),
            ],
            &[self.end_node_min, self.end_node_max],
        );
        pw.set_bool_target(
            wires.end_node_inputs.left_child_exists,
            self.end_node_children[0].is_some(),
        );
        pw.set_bool_target(
            wires.end_node_inputs.right_child_exists,
            self.end_node_children[1].is_some(),
        );
        let left_child_info = self.end_node_children[0].unwrap_or_default();
        let right_child_info = self.end_node_children[1].unwrap_or_default();
        wires
            .end_node_inputs
            .left_child_info
            .set_target(pw, &left_child_info);
        wires
            .end_node_inputs
            .right_child_info
            .set_target(pw, &right_child_info);
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct NeighborInfo {
    pub(crate) is_found: bool,
    pub(crate) is_in_path: bool,
    pub(crate) value: U256,
    pub(crate) hash: HashOut<F>,
}

impl FromFields<F> for NeighborInfo {
    fn from_fields(t: &[F]) -> Self {
        assert!(t.len() >= NeighborInfoTarget::NUM_TARGETS);
        Self {
            is_found: t[0].try_into_bool().unwrap(),
            is_in_path: t[1].try_into_bool().unwrap(),
            value: U256::from_fields(&t[2..2 + NUM_LIMBS]),
            hash: HashOut::from_vec(t[2 + NUM_LIMBS..NeighborInfoTarget::NUM_TARGETS].to_vec()),
        }
    }
}

impl ToFields<F> for NeighborInfo {
    fn to_fields(&self) -> Vec<F> {
        [F::from_bool(self.is_found), F::from_bool(self.is_in_path)]
            .into_iter()
            .chain(self.value.to_fields())
            .chain(self.hash.to_fields())
            .collect()
    }
}

impl NeighborInfo {
    // Initialize `Self` for the predecessor/successor of a node. `value`
    // must be the value of the predecessor/successor, while `hash` must
    // be its hash. If `hash` is `None`, it is assumed that the
    // predecessor/successor is not located in the path of the node
    pub(crate) fn new(value: U256, hash: Option<HashOut<F>>) -> Self {
        Self {
            is_found: true,
            is_in_path: hash.is_some(),
            value,
            hash: hash.unwrap_or(*empty_poseidon_hash()),
        }
    }
    /// Generate at random data about the successor/predecessor of a node. The generated
    /// predecessor/successor must have the `value` provided as input;
    /// the existence of the generated predecessor/successor depends on the `is_found` input:
    /// - if `is_found` is `None`, then the existence of the generated predecessor/successor
    ///   is chosen at random
    /// - otherwise, the generated predecessor/successor will be marked as found if and only if
    ///   the flag wrapped by `is_found` is `true`
    pub(crate) fn sample<R: Rng>(rng: &mut R, value: U256, is_found: Option<bool>) -> Self {
        NeighborInfo {
            is_found: is_found.unwrap_or(rng.gen()),
            is_in_path: rng.gen(),
            value,
            hash: gen_random_field_hash(),
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::array;

    use alloy::primitives::U256;
    use mp2_common::{
        poseidon::empty_poseidon_hash,
        types::HashOutput,
        u256::{CircuitBuilderU256, UInt256Target, WitnessWriteU256},
        utils::{FromFields, FromTargets, ToTargets},
        C, D, F,
    };
    use mp2_test::{
        circuit::{run_circuit, UserCircuit},
        utils::{gen_random_field_hash, gen_random_u256},
    };
    use plonky2::{
        field::types::Sample,
        hash::hash_types::{HashOut, HashOutTarget, NUM_HASH_OUT_ELTS},
        iop::{
            target::Target,
            witness::{PartialWitness, WitnessWrite},
        },
        plonk::{
            circuit_builder::CircuitBuilder, config::GenericHashOut, proof::ProofWithPublicInputs,
        },
    };
    use rand::thread_rng;

    use crate::query::utils::{ChildPosition, NodeInfo};

    use super::{
        MerklePathGadget, MerklePathTargetInputs, MerklePathWithNeighborsGadget,
        MerklePathWithNeighborsTargetInputs, NeighborInfo, NeighborInfoTarget,
    };

    #[derive(Clone, Debug)]
    struct TestMerklePathGadget<const MAX_DEPTH: usize>
    where
        [(); MAX_DEPTH - 1]:,
    {
        merkle_path_inputs: MerklePathGadget<MAX_DEPTH>,
        end_node: NodeInfo,
        index_id: F,
    }

    impl<const MAX_DEPTH: usize> UserCircuit<F, D> for TestMerklePathGadget<MAX_DEPTH>
    where
        [(); MAX_DEPTH - 1]:,
    {
        type Wires = (MerklePathTargetInputs<MAX_DEPTH>, HashOutTarget, Target);

        fn build(c: &mut CircuitBuilder<F, D>) -> Self::Wires {
            let index_id = c.add_virtual_target();
            let end_node = c.add_virtual_hash();
            let merkle_path_wires = MerklePathGadget::build(c, end_node, index_id);

            c.register_public_inputs(&merkle_path_wires.root.to_targets());

            (merkle_path_wires.inputs, end_node, index_id)
        }

        fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
            self.merkle_path_inputs.assign(pw, &wires.0);
            pw.set_hash_target(wires.1, self.end_node.compute_node_hash(self.index_id));
            pw.set_target(wires.2, self.index_id);
        }
    }

    impl NeighborInfo {
        // Initialize `Self` for a node with no predecessor
        pub(crate) fn new_dummy_predecessor() -> Self {
            Self {
                is_found: false,
                is_in_path: true, // the circuit still looks at the predecessor in the path
                value: U256::ZERO,
                hash: *empty_poseidon_hash(),
            }
        }

        // Initialize `Self` for a node with no successor
        pub(crate) fn new_dummy_successor() -> Self {
            Self {
                is_found: false,
                is_in_path: true, // the circuit still looks at the successor in the path
                value: U256::MAX,
                hash: *empty_poseidon_hash(),
            }
        }
    }

    #[derive(Clone, Debug)]
    struct TestMerklePathWithNeighborsGadget<const MAX_DEPTH: usize>
    where
        [(); MAX_DEPTH - 1]:,
    {
        merkle_path_inputs: MerklePathWithNeighborsGadget<MAX_DEPTH>,
        end_node: NodeInfo,
        index_id: F,
    }

    impl<const MAX_DEPTH: usize> UserCircuit<F, D> for TestMerklePathWithNeighborsGadget<MAX_DEPTH>
    where
        [(); MAX_DEPTH - 1]:,
    {
        type Wires = (
            MerklePathWithNeighborsTargetInputs<MAX_DEPTH>,
            HashOutTarget,
            UInt256Target,
            Target,
        );

        fn build(c: &mut CircuitBuilder<F, D>) -> Self::Wires {
            let index_id = c.add_virtual_target();
            let end_node_tree_hash = c.add_virtual_hash();
            let end_node_value = c.add_virtual_u256_unsafe();
            let merkle_path_wires = MerklePathWithNeighborsGadget::build(
                c,
                end_node_value.clone(),
                end_node_tree_hash,
                index_id,
            );

            c.register_public_inputs(&merkle_path_wires.root.to_targets());
            c.register_public_inputs(&merkle_path_wires.end_node_hash.to_targets());
            c.register_public_inputs(&merkle_path_wires.predecessor_info.to_targets());
            c.register_public_inputs(&merkle_path_wires.successor_info.to_targets());

            (
                merkle_path_wires.inputs,
                end_node_tree_hash,
                end_node_value,
                index_id,
            )
        }

        fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
            self.merkle_path_inputs.assign(pw, &wires.0);
            pw.set_hash_target(wires.1, self.end_node.embedded_tree_hash);
            pw.set_u256_target(&wires.2, self.end_node.value);
            pw.set_target(wires.3, self.index_id);
        }
    }

    // method to build a `NodeInfo` for a node from the provided inputs
    pub(crate) fn build_node(
        left_child: Option<&NodeInfo>,
        right_child: Option<&NodeInfo>,
        node_value: U256,
        embedded_tree_hash: HashOutput,
        index_id: F,
    ) -> NodeInfo {
        let node_min = if let Some(node) = &left_child {
            node.min
        } else {
            node_value
        };
        let node_max = if let Some(node) = &right_child {
            node.max
        } else {
            node_value
        };
        let left_child = left_child
            .map(|node| HashOutput::try_from(node.compute_node_hash(index_id).to_bytes()).unwrap());
        let right_child = right_child
            .map(|node| HashOutput::try_from(node.compute_node_hash(index_id).to_bytes()).unwrap());
        NodeInfo::new(
            &embedded_tree_hash,
            left_child.as_ref(),
            right_child.as_ref(),
            node_value,
            node_min,
            node_max,
        )
    }

    /// Build the following Merkle-tree to be employed in tests, using
    /// the `index_id` provided as input to compute the hash of the nodes
    ///              A
    ///          B       C
    ///      D               G
    ///   E      F
    pub(crate) fn generate_test_tree(
        index_id: F,
        value_range: Option<(U256, U256)>,
    ) -> [NodeInfo; 7] {
        let rng = &mut thread_rng();
        // closure to generate a random node of the tree from the 2 children, if any
        let random_node = |left_child: Option<&NodeInfo>,
                           right_child: Option<&NodeInfo>,
                           node_value: U256|
         -> NodeInfo {
            let embedded_tree_hash =
                HashOutput::try_from(gen_random_field_hash::<F>().to_bytes()).unwrap();
            build_node(
                left_child,
                right_child,
                node_value,
                embedded_tree_hash,
                index_id,
            )
        };
        let mut values: [U256; 7] = array::from_fn(|_| gen_random_u256(rng));
        if let Some((min_range, max_range)) = value_range {
            // trim random values to the range specified as input
            values.iter_mut().for_each(|value| {
                *value = min_range + *value % (max_range - min_range + U256::from(1))
            });
        }
        values.sort();
        let node_e = random_node(None, None, values[0]); // it's a leaf node, so no children
        let node_f = random_node(None, None, values[2]);
        let node_g = random_node(None, None, values[6]);
        let node_d = random_node(Some(&node_e), Some(&node_f), values[1]);
        let node_b = random_node(Some(&node_d), None, values[3]);
        let node_c = random_node(None, Some(&node_g), values[5]);
        let node_a = random_node(Some(&node_b), Some(&node_c), values[4]);
        [node_a, node_b, node_c, node_d, node_e, node_f, node_g]
    }

    #[test]
    fn test_merkle_path() {
        // first, build the Merkle-tree
        let index_id = F::rand();
        let [node_a, node_b, node_c, node_d, node_e, node_f, node_g] =
            generate_test_tree(index_id, None);
        let root = node_a.compute_node_hash(index_id);
        // verify Merkle-path related to leaf F
        const MAX_DEPTH: usize = 10;
        let path = vec![
            (node_d, ChildPosition::Right), // we start from the ancestor of the start node of the path
            (node_b, ChildPosition::Left),
            (node_a, ChildPosition::Left),
        ];
        let node_e_hash = HashOutput::from(node_e.compute_node_hash(index_id));
        let node_c_hash = HashOutput::from(node_c.compute_node_hash(index_id));
        let siblings = vec![Some(node_e_hash), None, Some(node_c_hash)];
        let merkle_path_inputs = MerklePathGadget::<MAX_DEPTH>::new(&path, &siblings).unwrap();

        let circuit = TestMerklePathGadget::<MAX_DEPTH> {
            merkle_path_inputs,
            end_node: node_f,
            index_id,
        };

        let proof = run_circuit::<F, D, C, _>(circuit);
        // check that the re-computed root is correct
        assert_eq!(proof.public_inputs, root.to_vec());

        // verify Merkle-path related to leaf G
        let path = vec![
            (node_c, ChildPosition::Right),
            (node_a, ChildPosition::Right),
        ];
        let node_b_hash = HashOutput::from(node_b.compute_node_hash(index_id));
        let siblings = vec![None, Some(node_b_hash)];
        let merkle_path_inputs = MerklePathGadget::<MAX_DEPTH>::new(&path, &siblings).unwrap();
        let circuit = TestMerklePathGadget::<MAX_DEPTH> {
            merkle_path_inputs,
            end_node: node_g,
            index_id,
        };

        let proof = run_circuit::<F, D, C, _>(circuit);
        // check that the re-computed root is correct
        assert_eq!(proof.public_inputs, root.to_vec());

        // Verify Merkle-path related to node D
        let path = vec![(node_b, ChildPosition::Left), (node_a, ChildPosition::Left)];
        let siblings = vec![None, Some(node_c_hash)];
        let merkle_path_inputs = MerklePathGadget::<MAX_DEPTH>::new(&path, &siblings).unwrap();
        let circuit = TestMerklePathGadget::<MAX_DEPTH> {
            merkle_path_inputs,
            end_node: node_d,
            index_id,
        };

        let proof = run_circuit::<F, D, C, _>(circuit);
        // check that the re-computed root is correct
        assert_eq!(proof.public_inputs, root.to_vec());
    }

    #[test]
    fn test_merkle_path_with_neighbors() {
        // first, build the Merkle-tree
        let index_id = F::rand();
        let [node_a, node_b, node_c, node_d, node_e, node_f, node_g] =
            generate_test_tree(index_id, None);
        let root = node_a.compute_node_hash(index_id);
        // verify Merkle-path related to leaf F
        const MAX_DEPTH: usize = 10;
        let path = vec![
            (node_d, ChildPosition::Right), // we start from the ancestor of the start node of the path
            (node_b, ChildPosition::Left),
            (node_a, ChildPosition::Left),
        ];
        let node_e_hash = HashOutput::from(node_e.compute_node_hash(index_id));
        let node_c_hash = HashOutput::from(node_c.compute_node_hash(index_id));
        let siblings = vec![Some(node_e_hash), None, Some(node_c_hash)];
        let merkle_path_inputs = MerklePathWithNeighborsGadget::<MAX_DEPTH>::new(
            &path,
            &siblings,
            &node_f,
            [None, None], // it's a leaf node
        )
        .unwrap();

        let circuit = TestMerklePathWithNeighborsGadget::<MAX_DEPTH> {
            merkle_path_inputs,
            end_node: node_f,
            index_id,
        };

        let proof = run_circuit(circuit);

        // closure to check correctness of public inputs
        let check_public_inputs = |proof: ProofWithPublicInputs<F, C, D>,
                                   node: &NodeInfo,
                                   node_name: &str,
                                   predecessor_info,
                                   successor_info| {
            // check that the re-computed root is correct
            assert_eq!(
                proof.public_inputs[..NUM_HASH_OUT_ELTS],
                root.to_vec(),
                "failed for node {node_name}"
            );
            // check that the hash of node_F is correct
            let node_hash = node.compute_node_hash(index_id);
            assert_eq!(
                proof.public_inputs[NUM_HASH_OUT_ELTS..2 * NUM_HASH_OUT_ELTS],
                node_hash.elements,
                "failed for node {node_name}"
            );
            // check predecessor info extracted in the circuit
            assert_eq!(
                NeighborInfo::from_fields(&proof.public_inputs[2 * NUM_HASH_OUT_ELTS..]),
                predecessor_info,
                "failed for node {node_name}"
            );
            // check successor info extracted in the circuit
            assert_eq!(
                NeighborInfo::from_fields(
                    &proof.public_inputs[2 * NUM_HASH_OUT_ELTS + NeighborInfoTarget::NUM_TARGETS..]
                ),
                successor_info,
                "failed for node {node_name}"
            );
        };
        // build predecessor and successor info for node_F
        // predecessor should be node_D
        let node_d_hash = node_d.compute_node_hash(index_id);
        let predecessor_info = NeighborInfo::new(node_d.value, Some(node_d_hash));
        // successor should be node_B
        let node_b_hash = node_b.compute_node_hash(index_id);
        let successor_info = NeighborInfo::new(node_b.value, Some(node_b_hash));
        check_public_inputs(proof, &node_f, "node F", predecessor_info, successor_info);

        // verify Merkle-path related to leaf E
        let path = vec![
            (node_d, ChildPosition::Left), // we start from the ancestor of the start node of the path
            (node_b, ChildPosition::Left),
            (node_a, ChildPosition::Left),
        ];
        let node_f_hash = HashOutput::from(node_f.compute_node_hash(index_id));
        let siblings = vec![Some(node_f_hash), None, Some(node_c_hash)];
        let merkle_path_inputs = MerklePathWithNeighborsGadget::<MAX_DEPTH>::new(
            &path,
            &siblings,
            &node_e,
            [None, None], // it's a leaf node
        )
        .unwrap();

        let circuit = TestMerklePathWithNeighborsGadget::<MAX_DEPTH> {
            merkle_path_inputs,
            end_node: node_e,
            index_id,
        };

        let proof = run_circuit(circuit);

        // build predecessor and successor info for node_E
        // There should be no predecessor
        let predecessor_info = NeighborInfo::new_dummy_predecessor();
        // successor should be node_D
        let successor_info = NeighborInfo::new(node_d.value, Some(node_d_hash));
        check_public_inputs(proof, &node_e, "node E", predecessor_info, successor_info);

        // verify Merkle-path related to node D
        let path = vec![(node_b, ChildPosition::Left), (node_a, ChildPosition::Left)];
        let siblings = vec![None, Some(node_c_hash)];
        let merkle_path_inputs = MerklePathWithNeighborsGadget::<MAX_DEPTH>::new(
            &path,
            &siblings,
            &node_d,
            [Some(node_e), Some(node_f)],
        )
        .unwrap();

        let circuit = TestMerklePathWithNeighborsGadget::<MAX_DEPTH> {
            merkle_path_inputs,
            end_node: node_d,
            index_id,
        };

        let proof = run_circuit(circuit);

        // build predecessor and successor info for node_D
        // predecessor should be node_E, but it's not in the path
        let predecessor_info = NeighborInfo::new(node_e.value, None);
        // successor should be node_F, but it's not in the path
        let successor_info = NeighborInfo::new(node_f.value, None);
        check_public_inputs(proof, &node_d, "node D", predecessor_info, successor_info);

        // verify Merkle-path related to node B
        let path = vec![(node_a, ChildPosition::Left)];
        let siblings = vec![Some(node_c_hash)];
        let merkle_path_inputs = MerklePathWithNeighborsGadget::<MAX_DEPTH>::new(
            &path,
            &siblings,
            &node_b,
            [Some(node_d), None], // Node D is the left child
        )
        .unwrap();

        let circuit = TestMerklePathWithNeighborsGadget::<MAX_DEPTH> {
            merkle_path_inputs,
            end_node: node_b,
            index_id,
        };

        let proof = run_circuit(circuit);

        // build predecessor and successor info for node_B
        // predecessor should be node_F, but it's not in the path
        let predecessor_info = NeighborInfo::new(node_f.value, None);
        // successor should be node_A
        let successor_info = NeighborInfo::new(node_a.value, Some(root));
        check_public_inputs(proof, &node_b, "node B", predecessor_info, successor_info);

        // verify Merkle-path related to leaf G
        let path = vec![
            (node_c, ChildPosition::Right),
            (node_a, ChildPosition::Right),
        ];
        let siblings = vec![None, Some(HashOutput::from(node_b_hash))];
        let merkle_path_inputs = MerklePathWithNeighborsGadget::<MAX_DEPTH>::new(
            &path,
            &siblings,
            &node_g,
            [None, None], // it's a leaf node
        )
        .unwrap();

        let circuit = TestMerklePathWithNeighborsGadget::<MAX_DEPTH> {
            merkle_path_inputs,
            end_node: node_g,
            index_id,
        };

        let proof = run_circuit(circuit);

        // build predecessor and successor info for node_G
        // predecessor should be node_C
        let predecessor_info = NeighborInfo::new(
            node_c.value,
            Some(HashOut::from_bytes((&node_c_hash).into())),
        );
        // There should be no successor
        let successor_info = NeighborInfo::new_dummy_successor();
        check_public_inputs(proof, &node_g, "node G", predecessor_info, successor_info);

        // verify Merkle-path related to root node A
        let path = vec![];
        let siblings = vec![];
        let merkle_path_inputs = MerklePathWithNeighborsGadget::<MAX_DEPTH>::new(
            &path,
            &siblings,
            &node_a,
            [Some(node_b), Some(node_c)], // it's a leaf node
        )
        .unwrap();

        let circuit = TestMerklePathWithNeighborsGadget::<MAX_DEPTH> {
            merkle_path_inputs,
            end_node: node_a,
            index_id,
        };

        let proof = run_circuit(circuit);

        // build predecessor and successor info for node_A
        // predecessor should be node_B, but it's not in the path
        let predecessor_info = NeighborInfo::new(node_b.value, None);
        // successor should be node_C, but it's not in the path
        let successor_info = NeighborInfo::new(node_c.value, None);
        check_public_inputs(proof, &node_a, "node A", predecessor_info, successor_info);
    }
}
