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
    types::HashOutput,
    u256::{CircuitBuilderU256, UInt256Target, WitnessWriteU256},
    utils::{SelectHashBuilder, ToTargets},
    D, F,
};
use plonky2::{
    hash::hash_types::{HashOut, HashOutTarget},
    iop::{
        target::{BoolTarget, Target},
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{circuit_builder::CircuitBuilder, config::GenericHashOut},
};
use serde::{Deserialize, Serialize};

use super::aggregation::{ChildPosition, NodeInfo};

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
/// Set of input/output wires built by merkle path verification gadget
pub struct MerklePathTarget<const MAX_DEPTH: usize>
where
    [(); MAX_DEPTH - 1]:,
{
    pub(crate) inputs: MerklePathTargetInputs<MAX_DEPTH>,
    /// Recomputed root for the Merkle path
    pub(crate) root: HashOutTarget,
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
                    sibling.and_then(|node_hash| Some(HashOut::from_bytes(node_hash.as_ref())))
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

    /// Build wires for `MerklePathGadget`. The requrested inputs are:
    /// - `start_node`: The hash of the first node in the path
    /// - `index_id`: Integer identifier of the index column to be placed in the hash
    ///     of the nodes of the path
    pub fn build(
        b: &mut CircuitBuilder<F, D>,
        start_node: HashOutTarget,
        index_id: Target,
    ) -> MerklePathTarget<MAX_DEPTH> {
        let is_left_child = array::from_fn(|_| b.add_virtual_bool_target_unsafe());
        let [sibling_hash, embedded_tree_hash] =
            [0, 1].map(|_| array::from_fn(|_| b.add_virtual_hash()));
        let [node_min, node_max, node_value] = [0, 1, 2].map(
            |_| b.add_virtual_u256_arr_unsafe(), // unsafe should be ok since we just need to hash them
        );
        let is_real_node = array::from_fn(|_| b.add_virtual_bool_target_safe());

        let mut final_hash = start_node;
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
        }

        MerklePathTarget {
            inputs: MerklePathTargetInputs {
                is_left_child,
                sibling_hash,
                node_min,
                node_max,
                node_value,
                embedded_tree_hash,
                is_real_node,
            },
            root: final_hash,
        }
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

#[cfg(test)]
mod tests {
    use std::array;

    use mp2_common::{types::HashOutput, utils::ToTargets, C, D, F};
    use mp2_test::{
        circuit::{run_circuit, UserCircuit},
        utils::{gen_random_field_hash, gen_random_u256},
    };
    use plonky2::{
        field::types::Sample,
        hash::hash_types::HashOutTarget,
        iop::{
            target::Target,
            witness::{PartialWitness, WitnessWrite},
        },
        plonk::{circuit_builder::CircuitBuilder, config::GenericHashOut},
    };
    use rand::thread_rng;

    use crate::query::aggregation::{ChildPosition, NodeInfo};

    use super::{MerklePathGadget, MerklePathTargetInputs};

    #[derive(Clone, Debug)]
    struct TestMerklePathGadget<const MAX_DEPTH: usize>
    where
        [(); MAX_DEPTH - 1]:,
    {
        merkle_path_inputs: MerklePathGadget<MAX_DEPTH>,
        start_node: NodeInfo,
        index_id: F,
    }

    impl<const MAX_DEPTH: usize> UserCircuit<F, D> for TestMerklePathGadget<MAX_DEPTH>
    where
        [(); MAX_DEPTH - 1]:,
    {
        type Wires = (MerklePathTargetInputs<MAX_DEPTH>, HashOutTarget, Target);

        fn build(c: &mut CircuitBuilder<F, D>) -> Self::Wires {
            let index_id = c.add_virtual_target();
            let start_node = c.add_virtual_hash();
            let merkle_path_wires = MerklePathGadget::build(c, start_node, index_id);

            c.register_public_inputs(&merkle_path_wires.root.to_targets());

            (merkle_path_wires.inputs, start_node, index_id)
        }

        fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
            self.merkle_path_inputs.assign(pw, &wires.0);
            pw.set_hash_target(wires.1, self.start_node.compute_node_hash(self.index_id));
            pw.set_target(wires.2, self.index_id);
        }
    }

    #[test]
    fn test_merkle_path() {
        // Test a Merkle-path on the following Merkle-tree
        //              A
        //          B       C
        //      D               G
        //   E      F

        // first, build the Merkle-tree
        let rng = &mut thread_rng();
        let index_id = F::rand();
        // closure to generate a random node of the tree from the 2 children, if any
        let mut random_node =
            |left_child: Option<&HashOutput>, right_child: Option<&HashOutput>| -> NodeInfo {
                let embedded_tree_hash =
                    HashOutput::try_from(gen_random_field_hash::<F>().to_bytes()).unwrap();
                let [node_min, node_max, node_value] = array::from_fn(|_| gen_random_u256(rng));
                NodeInfo::new(
                    &embedded_tree_hash,
                    left_child,
                    right_child,
                    node_value,
                    node_min,
                    node_max,
                )
            };

        let node_e = random_node(None, None); // it's a leaf node, so no children
        let node_f = random_node(None, None);
        let node_g = random_node(None, None);
        let node_e_hash =
            HashOutput::try_from(node_e.compute_node_hash(index_id).to_bytes()).unwrap();
        let node_d = random_node(
            Some(&node_e_hash),
            Some(&HashOutput::try_from(node_f.compute_node_hash(index_id).to_bytes()).unwrap()),
        );
        let node_b = random_node(
            Some(&HashOutput::try_from(node_d.compute_node_hash(index_id).to_bytes()).unwrap()),
            None,
        );
        let node_c = random_node(
            None,
            Some(&HashOutput::try_from(node_g.compute_node_hash(index_id).to_bytes()).unwrap()),
        );
        let node_b_hash =
            HashOutput::try_from(node_b.compute_node_hash(index_id).to_bytes()).unwrap();
        let node_c_hash =
            HashOutput::try_from(node_c.compute_node_hash(index_id).to_bytes()).unwrap();
        let node_a = random_node(Some(&node_b_hash), Some(&node_c_hash));
        let root = node_a.compute_node_hash(index_id);

        // verify Merkle-path related to leaf F
        const MAX_DEPTH: usize = 10;
        let path = vec![
            (node_d, ChildPosition::Right), // we start from the ancestor of the start node of the path
            (node_b, ChildPosition::Left),
            (node_a, ChildPosition::Left),
        ];
        let siblings = vec![Some(node_e_hash), None, Some(node_c_hash)];
        let merkle_path_inputs = MerklePathGadget::<MAX_DEPTH>::new(&path, &siblings).unwrap();

        let circuit = TestMerklePathGadget::<MAX_DEPTH> {
            merkle_path_inputs,
            start_node: node_f,
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
        let siblings = vec![None, Some(node_b_hash)];
        let merkle_path_inputs = MerklePathGadget::<MAX_DEPTH>::new(&path, &siblings).unwrap();
        let circuit = TestMerklePathGadget::<MAX_DEPTH> {
            merkle_path_inputs,
            start_node: node_g,
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
            start_node: node_d,
            index_id,
        };

        let proof = run_circuit::<F, D, C, _>(circuit);
        // check that the re-computed root is correct
        assert_eq!(proof.public_inputs, root.to_vec());
    }
}
