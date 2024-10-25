//! Gadget to reconstruct the Merkle root of a tree from a Merkle path

use std::{array, iter::once};

use alloy::primitives::U256;
use anyhow::{ensure, Result};
use itertools::Itertools;
use mp2_common::{
    hash::hash_maybe_first,
    poseidon::empty_poseidon_hash,
    serialization::{
        deserialize_array, deserialize_long_array, serialize_array, serialize_long_array,
    },
    types::{CBuilder, HashOutput},
    u256::{CircuitBuilderU256, UInt256Target, WitnessWriteU256, NUM_LIMBS},
    utils::{Fieldable, FromTargets, SelectHashBuilder, ToTargets},
    D, F,
};
use plonky2::{
    hash::hash_types::{HashOut, HashOutTarget, NUM_HASH_OUT_ELTS},
    iop::{
        target::{BoolTarget, Target},
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{circuit_builder::CircuitBuilder, config::GenericHashOut},
};
use serde::{Deserialize, Serialize};

use super::aggregation::{ChildPosition, NodeInfo, NodeInfoTarget};

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
#[derive(Clone, Debug)]
/// Input wires related to the data of the end node whose membership in the tree
/// is proven with `MerklePathWithNeighborsGadget`.
pub struct EndNodeInputs {
    // minimum of the end node. It is necessary to recompute the hash of the node
    // inside the circuit
    node_min: UInt256Target,
    // maximum of the end node. It is necessary to recompute the hash of the node
    // inside the circuit
    node_max: UInt256Target,
    // Flag specifying whether the end node has a left child
    left_child_exists: BoolTarget,
    // The data about the left child of the node, which might be necessary to
    // extract the value of the predecessor of the end node
    left_child_info: NodeInfoTarget,
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
    is_found: BoolTarget,
    /// Boolean flag specifying whether the neighbor is in the path from the
    /// given node up to the root
    is_in_path: BoolTarget,
    /// Value of the neighbor (if the neighbor exists, otherwise a dummy value can be employed)
    value: UInt256Target,
    /// Hash of the neighbor node (if the neighbor exists, otherwise a dummy value can be employed)
    hash: HashOutTarget,
}

impl NeighborInfoTarget {
    const NUM_ELEMENTS: usize = 2 + NUM_LIMBS + NUM_HASH_OUT_ELTS;
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
    fn from_targets(t: &[Target]) -> Self {
        Self {
            is_found: BoolTarget::new_unsafe(t[0]),
            is_in_path: BoolTarget::new_unsafe(t[1]),
            value: UInt256Target::from_targets(&t[2..]),
            hash: HashOutTarget::from_targets(&t[2 + NUM_LIMBS..]),
        }
    }
}
#[derive(Clone, Debug)]
/// Set of input wires for the merkle path with neighbors gadget
pub struct MerklePathWithNeighborsTargetInputs<const MAX_DEPTH: usize>
where
    [(); MAX_DEPTH - 1]:,
{
    pub(crate) path_inputs: MerklePathTargetInputs<MAX_DEPTH>,
    pub(crate) end_node_inputs: EndNodeInputs,
}

#[derive(Clone, Debug)]
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
                    sibling
                        .clone()
                        .and_then(|node_hash| Some(HashOut::from_bytes((&node_hash).into())))
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
            root: path.last().unwrap().clone(),
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
        if path_nodes.len() == 0 {
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
                &zero_u256,
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
            root: path.last().unwrap().clone(),
            end_node_hash,
            predecessor_info: predecessor_info,
            successor_info: successor_info,
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

#[cfg(test)]
mod tests {
    use alloy::primitives::U256;
    use mp2_common::{
        poseidon::empty_poseidon_hash,
        types::HashOutput,
        u256::{CircuitBuilderU256, UInt256Target, WitnessWriteU256, NUM_LIMBS},
        utils::{FromFields, ToTargets, TryIntoBool},
        C, D, F,
    };
    use mp2_test::{
        circuit::{run_circuit, UserCircuit},
        utils::{gen_random_field_hash, gen_random_u256},
    };
    use plonky2::{
        field::types::{PrimeField64, Sample},
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

    use crate::query::aggregation::{ChildPosition, NodeInfo};

    use super::{
        MerklePathGadget, MerklePathTargetInputs, MerklePathWithNeighborsGadget,
        MerklePathWithNeighborsTargetInputs, NeighborInfoTarget,
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

    #[derive(Clone, Debug, Eq, PartialEq)]
    pub(crate) struct NeighborInfo {
        is_found: bool,
        is_in_path: bool,
        value: U256,
        hash: HashOut<F>,
    }

    impl FromFields<F> for NeighborInfo {
        fn from_fields(t: &[F]) -> Self {
            assert!(t.len() >= NeighborInfoTarget::NUM_ELEMENTS);
            Self {
                is_found: t[0].try_into_bool().unwrap(),
                is_in_path: t[1].try_into_bool().unwrap(),
                value: U256::from_fields(&t[2..2 + NUM_LIMBS]),
                hash: HashOut::from_vec(
                    t[2 + NUM_LIMBS..NeighborInfoTarget::NUM_ELEMENTS].to_vec(),
                ),
            }
        }
    }

    impl NeighborInfo {
        pub(crate) fn assign(&self, pw: &mut PartialWitness<F>, wires: &NeighborInfoTarget) {
            [
                (wires.is_found, self.is_found),
                (wires.is_in_path, self.is_in_path),
            ]
            .into_iter()
            .for_each(|(target, value)| pw.set_bool_target(target, value));
            pw.set_u256_target(&wires.value, self.value);
            pw.set_hash_target(wires.hash, self.hash);
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
    // Build the following Merkle-tree to be employed in tests, using
    // the `index_id` provided as input to compute the hash of the nodes
    //              A
    //          B       C
    //      D               G
    //   E      F
    fn generate_test_tree(index_id: F) -> [NodeInfo; 7] {
        let rng = &mut thread_rng();
        // closure to generate a random node of the tree from the 2 children, if any
        let mut random_node =
            |left_child: Option<&NodeInfo>, right_child: Option<&NodeInfo>| -> NodeInfo {
                let embedded_tree_hash =
                    HashOutput::try_from(gen_random_field_hash::<F>().to_bytes()).unwrap();
                let node_value = gen_random_u256(rng);
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
                let left_child = left_child.map(|node| {
                    HashOutput::try_from(node.compute_node_hash(index_id).to_bytes()).unwrap()
                });
                let right_child = right_child.map(|node| {
                    HashOutput::try_from(node.compute_node_hash(index_id).to_bytes()).unwrap()
                });
                NodeInfo::new(
                    &embedded_tree_hash,
                    left_child.as_ref(),
                    right_child.as_ref(),
                    node_value,
                    node_min,
                    node_max,
                )
            };

        let node_E = random_node(None, None); // it's a leaf node, so no children
        let node_F = random_node(None, None);
        let node_G = random_node(None, None);
        let node_D = random_node(Some(&node_E), Some(&node_F));
        let node_B = random_node(Some(&node_D), None);
        let node_C = random_node(None, Some(&node_G));
        let node_A = random_node(Some(&node_B), Some(&node_C));
        [node_A, node_B, node_C, node_D, node_E, node_F, node_G]
    }

    #[test]
    fn test_merkle_path() {
        // first, build the Merkle-tree
        let index_id = F::rand();
        let [node_A, node_B, node_C, node_D, node_E, node_F, node_G] = generate_test_tree(index_id);
        let root = node_A.compute_node_hash(index_id);
        // verify Merkle-path related to leaf F
        const MAX_DEPTH: usize = 10;
        let path = vec![
            (node_D.clone(), ChildPosition::Right), // we start from the ancestor of the start node of the path
            (node_B.clone(), ChildPosition::Left),
            (node_A.clone(), ChildPosition::Left),
        ];
        let node_E_hash = HashOutput::try_from(node_E.compute_node_hash(index_id)).unwrap();
        let node_C_hash = HashOutput::try_from(node_C.compute_node_hash(index_id)).unwrap();
        let siblings = vec![Some(node_E_hash), None, Some(node_C_hash.clone())];
        let merkle_path_inputs = MerklePathGadget::<MAX_DEPTH>::new(&path, &siblings).unwrap();

        let circuit = TestMerklePathGadget::<MAX_DEPTH> {
            merkle_path_inputs,
            end_node: node_F.clone(),
            index_id,
        };

        let proof = run_circuit::<F, D, C, _>(circuit);
        // check that the re-computed root is correct
        assert_eq!(proof.public_inputs, root.to_vec());

        // verify Merkle-path related to leaf G
        let path = vec![
            (node_C.clone(), ChildPosition::Right),
            (node_A.clone(), ChildPosition::Right),
        ];
        let node_B_hash = HashOutput::try_from(node_B.compute_node_hash(index_id)).unwrap();
        let siblings = vec![None, Some(node_B_hash)];
        let merkle_path_inputs = MerklePathGadget::<MAX_DEPTH>::new(&path, &siblings).unwrap();
        let circuit = TestMerklePathGadget::<MAX_DEPTH> {
            merkle_path_inputs,
            end_node: node_G.clone(),
            index_id,
        };

        let proof = run_circuit::<F, D, C, _>(circuit);
        // check that the re-computed root is correct
        assert_eq!(proof.public_inputs, root.to_vec());

        // Verify Merkle-path related to node D
        let path = vec![
            (node_B.clone(), ChildPosition::Left),
            (node_A.clone(), ChildPosition::Left),
        ];
        let siblings = vec![None, Some(node_C_hash)];
        let merkle_path_inputs = MerklePathGadget::<MAX_DEPTH>::new(&path, &siblings).unwrap();
        let circuit = TestMerklePathGadget::<MAX_DEPTH> {
            merkle_path_inputs,
            end_node: node_D.clone(),
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
        let [node_A, node_B, node_C, node_D, node_E, node_F, node_G] = generate_test_tree(index_id);
        let root = node_A.compute_node_hash(index_id);
        // verify Merkle-path related to leaf F
        const MAX_DEPTH: usize = 10;
        let path = vec![
            (node_D.clone(), ChildPosition::Right), // we start from the ancestor of the start node of the path
            (node_B.clone(), ChildPosition::Left),
            (node_A.clone(), ChildPosition::Left),
        ];
        let node_E_hash = HashOutput::try_from(node_E.compute_node_hash(index_id)).unwrap();
        let node_C_hash = HashOutput::try_from(node_C.compute_node_hash(index_id)).unwrap();
        let siblings = vec![Some(node_E_hash), None, Some(node_C_hash.clone())];
        let merkle_path_inputs = MerklePathWithNeighborsGadget::<MAX_DEPTH>::new(
            &path,
            &siblings,
            &node_F,
            [None, None], // it's a leaf node
        )
        .unwrap();

        let circuit = TestMerklePathWithNeighborsGadget::<MAX_DEPTH> {
            merkle_path_inputs,
            end_node: node_F.clone(),
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
                    &proof.public_inputs
                        [2 * NUM_HASH_OUT_ELTS + NeighborInfoTarget::NUM_ELEMENTS..]
                ),
                successor_info,
                "failed for node {node_name}"
            );
        };
        // build predecessor and successor info for node_F
        // predecessor should be node_D
        let node_D_hash = node_D.compute_node_hash(index_id);
        let predecessor_info = NeighborInfo {
            is_found: true,
            is_in_path: true,
            value: node_D.value,
            hash: node_D_hash,
        };
        // successor should be node_B
        let node_B_hash = node_B.compute_node_hash(index_id);
        let successor_info = NeighborInfo {
            is_found: true,
            is_in_path: true,
            value: node_B.value,
            hash: node_B_hash,
        };
        check_public_inputs(proof, &node_F, "node F", predecessor_info, successor_info);

        // verify Merkle-path related to leaf E
        let path = vec![
            (node_D.clone(), ChildPosition::Left), // we start from the ancestor of the start node of the path
            (node_B.clone(), ChildPosition::Left),
            (node_A.clone(), ChildPosition::Left),
        ];
        let node_F_hash = HashOutput::try_from(node_F.compute_node_hash(index_id)).unwrap();
        let siblings = vec![Some(node_F_hash), None, Some(node_C_hash.clone())];
        let merkle_path_inputs = MerklePathWithNeighborsGadget::<MAX_DEPTH>::new(
            &path,
            &siblings,
            &node_E,
            [None, None], // it's a leaf node
        )
        .unwrap();

        let circuit = TestMerklePathWithNeighborsGadget::<MAX_DEPTH> {
            merkle_path_inputs,
            end_node: node_E.clone(),
            index_id,
        };

        let proof = run_circuit(circuit);

        // build predecessor and successor info for node_E
        // There should be no predecessor
        let predecessor_info = NeighborInfo {
            is_found: false,
            is_in_path: true, // the circuit still looks at the predecessor in the path
            value: U256::ZERO,
            hash: *empty_poseidon_hash(),
        };
        // successor should be node_D
        let successor_info = NeighborInfo {
            is_found: true,
            is_in_path: true,
            value: node_D.value,
            hash: node_D_hash,
        };
        check_public_inputs(proof, &node_E, "node E", predecessor_info, successor_info);

        // verify Merkle-path related to node D
        let path = vec![
            (node_B.clone(), ChildPosition::Left),
            (node_A.clone(), ChildPosition::Left),
        ];
        let siblings = vec![None, Some(node_C_hash.clone())];
        let merkle_path_inputs = MerklePathWithNeighborsGadget::<MAX_DEPTH>::new(
            &path,
            &siblings,
            &node_D,
            [Some(node_E.clone()), Some(node_F.clone())],
        )
        .unwrap();

        let circuit = TestMerklePathWithNeighborsGadget::<MAX_DEPTH> {
            merkle_path_inputs,
            end_node: node_D.clone(),
            index_id,
        };

        let proof = run_circuit(circuit);

        // build predecessor and successor info for node_D
        // predecessor should be node_E, but it's not in the path
        let predecessor_info = NeighborInfo {
            is_found: true,
            is_in_path: false,
            value: node_E.value,
            hash: *empty_poseidon_hash(), // dummy value since the predecessor is not found in the path
        };
        // successor should be node_F, but it's not in the path
        let successor_info = NeighborInfo {
            is_found: true,
            is_in_path: false,
            value: node_F.value,
            hash: *empty_poseidon_hash(), // dummy value since the predecessor is not found in the path
        };
        check_public_inputs(proof, &node_D, "node D", predecessor_info, successor_info);

        // verify Merkle-path related to node B
        let path = vec![(node_A.clone(), ChildPosition::Left)];
        let siblings = vec![Some(node_C_hash.clone())];
        let merkle_path_inputs = MerklePathWithNeighborsGadget::<MAX_DEPTH>::new(
            &path,
            &siblings,
            &node_B,
            [Some(node_D.clone()), None], // Node D is the left child
        )
        .unwrap();

        let circuit = TestMerklePathWithNeighborsGadget::<MAX_DEPTH> {
            merkle_path_inputs,
            end_node: node_B.clone(),
            index_id,
        };

        let proof = run_circuit(circuit);

        // build predecessor and successor info for node_B
        // predecessor should be node_F, but it's not in the path
        let predecessor_info = NeighborInfo {
            is_found: true,
            is_in_path: false,
            value: node_F.value,
            hash: *empty_poseidon_hash(), // dummy value since the predecessor is not found in the path
        };
        // successor should be node_A
        let successor_info = NeighborInfo {
            is_found: true,
            is_in_path: true,
            value: node_A.value,
            hash: root,
        };
        check_public_inputs(proof, &node_B, "node B", predecessor_info, successor_info);

        // verify Merkle-path related to leaf G
        let path = vec![
            (node_C.clone(), ChildPosition::Right),
            (node_A.clone(), ChildPosition::Right),
        ];
        let siblings = vec![
            None,
            Some(HashOutput::try_from(node_B_hash.to_bytes()).unwrap()),
        ];
        let merkle_path_inputs = MerklePathWithNeighborsGadget::<MAX_DEPTH>::new(
            &path,
            &siblings,
            &node_G,
            [None, None], // it's a leaf node
        )
        .unwrap();

        let circuit = TestMerklePathWithNeighborsGadget::<MAX_DEPTH> {
            merkle_path_inputs,
            end_node: node_G.clone(),
            index_id,
        };

        let proof = run_circuit(circuit);

        // build predecessor and successor info for node_G
        // predecessor should be node_C
        let predecessor_info = NeighborInfo {
            is_found: true,
            is_in_path: true,
            value: node_C.value,
            hash: HashOut::from_bytes((&node_C_hash).into()),
        };
        // There should be no successor
        let successor_info = NeighborInfo {
            is_found: false,
            is_in_path: true,
            value: U256::ZERO,
            hash: *empty_poseidon_hash(),
        };
        check_public_inputs(proof, &node_G, "node G", predecessor_info, successor_info);

        // verify Merkle-path related to root node A
        let path = vec![];
        let siblings = vec![];
        let merkle_path_inputs = MerklePathWithNeighborsGadget::<MAX_DEPTH>::new(
            &path,
            &siblings,
            &node_A,
            [Some(node_B), Some(node_C)], // it's a leaf node
        )
        .unwrap();

        let circuit = TestMerklePathWithNeighborsGadget::<MAX_DEPTH> {
            merkle_path_inputs,
            end_node: node_A.clone(),
            index_id,
        };

        let proof = run_circuit(circuit);

        // build predecessor and successor info for node_A
        // predecessor should be node_B, but it's not in the path
        let predecessor_info = NeighborInfo {
            is_found: true,
            is_in_path: false,
            value: node_B.value,
            hash: *empty_poseidon_hash(), // dummy value since the predecessor is not found in the path
        };
        // successor should be node_C, but it's not in the path
        let successor_info = NeighborInfo {
            is_found: true,
            is_in_path: false,
            value: node_C.value,
            hash: *empty_poseidon_hash(), // dummy value since the successor is not found in the path
        };
        check_public_inputs(proof, &node_A, "node A", predecessor_info, successor_info);
    }
}
