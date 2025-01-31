use anyhow::Result;
use std::array;

use alloy::primitives::U256;
use mp2_common::{
    poseidon::empty_poseidon_hash,
    public_inputs::PublicInputCommon,
    serialization::{deserialize, deserialize_long_array, serialize, serialize_long_array},
    u256::{CircuitBuilderU256, UInt256Target, WitnessWriteU256},
    utils::ToTargets,
    D, F,
};
use plonky2::{
    hash::hash_types::{HashOut, HashOutTarget},
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{circuit_builder::CircuitBuilder, proof::ProofWithPublicInputsTarget},
};
use recursion_framework::circuit_builder::CircuitLogicWires;
use serde::{Deserialize, Serialize};

use crate::query::{
    api::TreePathInputs,
    merkle_path::{
        MerklePathWithNeighborsGadget, MerklePathWithNeighborsTargetInputs, NeighborInfoTarget,
    },
    output_computation::compute_dummy_output_targets,
    pi_len,
    public_inputs::PublicInputsQueryCircuits,
    row_chunk_gadgets::{BoundaryRowDataTarget, BoundaryRowNodeInfoTarget},
    universal_circuit::{
        ComputationalHash, ComputationalHashTarget, PlaceholderHash, PlaceholderHashTarget,
    },
    utils::QueryBounds,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NonExistenceWires<const INDEX_TREE_MAX_DEPTH: usize, const MAX_NUM_RESULTS: usize>
where
    [(); INDEX_TREE_MAX_DEPTH - 1]:,
{
    index_path: MerklePathWithNeighborsTargetInputs<INDEX_TREE_MAX_DEPTH>,
    index_node_value: UInt256Target,
    #[serde(serialize_with = "serialize", deserialize_with = "deserialize")]
    index_node_subtree_hash: HashOutTarget,
    primary_index_id: Target,
    #[serde(
        serialize_with = "serialize_long_array",
        deserialize_with = "deserialize_long_array"
    )]
    ops: [Target; MAX_NUM_RESULTS],
    #[serde(serialize_with = "serialize", deserialize_with = "deserialize")]
    computational_hash: ComputationalHashTarget,
    #[serde(serialize_with = "serialize", deserialize_with = "deserialize")]
    placeholder_hash: PlaceholderHashTarget,
    min_query_primary: UInt256Target,
    max_query_primary: UInt256Target,
}

/// Circuit employed to prove the non-existence of a node in the index tree with
/// a value in the query range [min_query_primary, max_query_primary]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NonExistenceCircuit<const INDEX_TREE_MAX_DEPTH: usize, const MAX_NUM_RESULTS: usize>
where
    [(); INDEX_TREE_MAX_DEPTH - 1]:,
{
    // path of the index tree node employed to prove non-existence
    index_path: MerklePathWithNeighborsGadget<INDEX_TREE_MAX_DEPTH>,
    // Value of the index tree node employed to prove non-existence
    index_node_value: U256,
    // Hash of the subtree stored in the index tree node employed to
    // prove non-existence
    index_node_subtree_hash: HashOut<F>,
    // Integer identifier of primary index column
    primary_index_id: F,
    // Set of identifiers of the aggregation operations
    // (provided only to be exposed for public input compliance)
    #[serde(
        serialize_with = "serialize_long_array",
        deserialize_with = "deserialize_long_array"
    )]
    ops: [F; MAX_NUM_RESULTS],
    // Computational hash associated to the query
    // (provided only to be exposed for public input compliance)
    computational_hash: ComputationalHash,
    // Placeholder hash associated to the placeholders employed
    // in the query (provided only to be exposed for public
    // input compliance)
    placeholder_hash: PlaceholderHash,
    // lower bound of the query range
    min_query_primary: U256,
    // upper bound of the query range
    max_query_primary: U256,
}

impl<const INDEX_TREE_MAX_DEPTH: usize, const MAX_NUM_RESULTS: usize>
    NonExistenceCircuit<INDEX_TREE_MAX_DEPTH, MAX_NUM_RESULTS>
where
    [(); INDEX_TREE_MAX_DEPTH - 1]:,
{
    pub(crate) fn new(
        path: &TreePathInputs,
        primary_index: F,
        aggregation_ops: [F; MAX_NUM_RESULTS],
        computational_hash: ComputationalHash,
        placeholder_hash: PlaceholderHash,
        query_bounds: &QueryBounds,
    ) -> Result<Self> {
        Ok(Self {
            index_path: MerklePathWithNeighborsGadget::new(
                &path.path,
                &path.siblings,
                &path.node_info,
                path.children,
            )?,
            index_node_value: path.node_info.value,
            index_node_subtree_hash: path.node_info.embedded_tree_hash,
            primary_index_id: primary_index,
            ops: aggregation_ops,
            computational_hash,
            placeholder_hash,
            min_query_primary: query_bounds.min_query_primary(),
            max_query_primary: query_bounds.max_query_primary(),
        })
    }

    pub(crate) fn build(
        b: &mut CircuitBuilder<F, D>,
    ) -> NonExistenceWires<INDEX_TREE_MAX_DEPTH, MAX_NUM_RESULTS> {
        let index_node_value = b.add_virtual_u256_unsafe(); // unsafe is ok since it's hashed
                                                            // in `MerklePathGadgetWithNeighbors`
        let [index_node_subtree_hash, computational_hash, placeholder_hash] =
            array::from_fn(|_| b.add_virtual_hash());
        let primary_index = b.add_virtual_target();
        let ops = b.add_virtual_target_arr::<MAX_NUM_RESULTS>();
        let [min_query_primary, max_query_primary] = b.add_virtual_u256_arr_unsafe(); // unsafe is ok
                                                                                      // since they are exposed as public inputs
        let index_path = MerklePathWithNeighborsGadget::build(
            b,
            index_node_value,
            index_node_subtree_hash,
            primary_index,
        );
        // check that index_node_value is out of range
        let smaller_than_min = b.is_less_than_u256(&index_node_value, &min_query_primary);
        let bigger_than_max = b.is_less_than_u256(&max_query_primary, &index_node_value);
        let is_out_of_range = b.or(smaller_than_min, bigger_than_max);
        b.assert_one(is_out_of_range.target);
        let predecessor_info = &index_path.predecessor_info;
        let successor_info = &index_path.successor_info;
        // assert NOT predecessor_info.is_found OR predecessor_info.value < min_query_primary
        // equivalent to: assert predecessor_info.is_found AND predecessor_info.value < min_query_primary == predecessor_info.is_found
        let predecessor_smaller = b.is_less_than_u256(&predecessor_info.value, &min_query_primary);
        let predecessor_flag = b.and(predecessor_info.is_found, predecessor_smaller);
        b.connect(predecessor_flag.target, predecessor_info.is_found.target);
        // assert NOT successor_info.is_found OR successor_info.value > max_query_primary
        // equivalent to: assert successor_info.is_found AND successor_info.value > max_query_primary == successor_info.is_found
        let successor_bigger = b.is_less_than_u256(&max_query_primary, &successor_info.value);
        let successor_flag = b.and(successor_info.is_found, successor_bigger);
        b.connect(successor_flag.target, successor_info.is_found.target);
        // compute dummy output values
        let outputs = compute_dummy_output_targets(b, &ops);

        // generate fake `BoundaryRowNodeInfo` for a fake rows tree node, to satisfy
        // the constraints in the revelation circuit
        let row_node_data = {
            // We simulate that the rows tree node associated to this row is the minimum node in the rows tree,
            // which means there is no predecessor
            let row_node_predecessor = NeighborInfoTarget::new_dummy_predecessor(b);
            // We simulate that the rows tree node associated to this row is also the maximum node in the rows
            // tree, which means there is no successor
            let row_node_successor = NeighborInfoTarget::new_dummy_successor(b);
            BoundaryRowNodeInfoTarget {
                end_node_hash: b.constant_hash(*empty_poseidon_hash()),
                predecessor_info: row_node_predecessor,
                successor_info: row_node_successor,
            }
        };
        let boundary_row = BoundaryRowDataTarget {
            row_node_info: row_node_data,
            index_node_info: BoundaryRowNodeInfoTarget::from(&index_path),
        };

        // expose public inputs
        let zero = b.zero();
        // query bounds on secondary index needs to be exposed as public inputs, but they
        // can be dummy values since they are un-used in this circuit
        let min_secondary = b.zero_u256();
        let max_secondary = b.constant_u256(U256::MAX);
        PublicInputsQueryCircuits::<Target, MAX_NUM_RESULTS>::new(
            &index_path.root.to_targets(),
            &outputs,
            &[zero], // there are no matching rows
            &ops,
            &boundary_row.to_targets(),
            &boundary_row.to_targets(),
            &min_query_primary.to_targets(),
            &max_query_primary.to_targets(),
            &min_secondary.to_targets(),
            &max_secondary.to_targets(),
            &[zero], // no arithmetic operations done, so no error occurred
            &computational_hash.to_targets(),
            &placeholder_hash.to_targets(),
        )
        .register(b);

        NonExistenceWires {
            index_path: index_path.inputs,
            index_node_value,
            index_node_subtree_hash,
            primary_index_id: primary_index,
            ops,
            computational_hash,
            placeholder_hash,
            min_query_primary,
            max_query_primary,
        }
    }

    pub(crate) fn assign(
        &self,
        pw: &mut PartialWitness<F>,
        wires: &NonExistenceWires<INDEX_TREE_MAX_DEPTH, MAX_NUM_RESULTS>,
    ) {
        self.index_path.assign(pw, &wires.index_path);
        [
            (self.index_node_value, &wires.index_node_value),
            (self.min_query_primary, &wires.min_query_primary),
            (self.max_query_primary, &wires.max_query_primary),
        ]
        .into_iter()
        .for_each(|(value, target)| pw.set_u256_target(target, value));
        pw.set_target_arr(&wires.ops, &self.ops);
        pw.set_target(wires.primary_index_id, self.primary_index_id);
        [
            (self.index_node_subtree_hash, wires.index_node_subtree_hash),
            (self.computational_hash, wires.computational_hash),
            (self.placeholder_hash, wires.placeholder_hash),
        ]
        .into_iter()
        .for_each(|(value, target)| pw.set_hash_target(target, value));
    }
}

impl<const INDEX_TREE_MAX_DEPTH: usize, const MAX_NUM_RESULTS: usize> CircuitLogicWires<F, D, 0>
    for NonExistenceWires<INDEX_TREE_MAX_DEPTH, MAX_NUM_RESULTS>
where
    [(); INDEX_TREE_MAX_DEPTH - 1]:,
{
    type CircuitBuilderParams = ();

    type Inputs = NonExistenceCircuit<INDEX_TREE_MAX_DEPTH, MAX_NUM_RESULTS>;

    const NUM_PUBLIC_INPUTS: usize = pi_len::<MAX_NUM_RESULTS>();

    fn circuit_logic(
        builder: &mut CircuitBuilder<F, D>,
        _verified_proofs: [&ProofWithPublicInputsTarget<D>; 0],
        _builder_parameters: Self::CircuitBuilderParams,
    ) -> Self {
        NonExistenceCircuit::build(builder)
    }

    fn assign_input(&self, inputs: Self::Inputs, pw: &mut PartialWitness<F>) -> anyhow::Result<()> {
        inputs.assign(pw, self);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::array;

    use alloy::primitives::U256;
    use mp2_common::{check_panic, poseidon::empty_poseidon_hash, utils::ToFields, C, D, F};
    use mp2_test::{
        circuit::{run_circuit, UserCircuit},
        utils::gen_random_field_hash,
    };
    use plonky2::{
        field::types::{Field, Sample},
        iop::witness::PartialWitness,
        plonk::{circuit_builder::CircuitBuilder, proof::ProofWithPublicInputs},
    };
    use rand::thread_rng;

    use crate::{
        query::{
            api::TreePathInputs,
            merkle_path::{tests::generate_test_tree, NeighborInfo},
            output_computation::tests::compute_dummy_output_values,
            public_inputs::PublicInputsQueryCircuits,
            row_chunk_gadgets::{BoundaryRowData, BoundaryRowNodeInfo},
            universal_circuit::universal_circuit_inputs::Placeholders,
            utils::{ChildPosition, QueryBounds},
        },
        test_utils::{gen_values_in_range, random_aggregation_operations},
    };

    use super::{NonExistenceCircuit, NonExistenceWires};

    const INDEX_TREE_MAX_DEPTH: usize = 15;
    const MAX_NUM_RESULTS: usize = 10;

    impl UserCircuit<F, D> for NonExistenceCircuit<INDEX_TREE_MAX_DEPTH, MAX_NUM_RESULTS> {
        type Wires = NonExistenceWires<INDEX_TREE_MAX_DEPTH, MAX_NUM_RESULTS>;

        fn build(c: &mut CircuitBuilder<F, D>) -> Self::Wires {
            NonExistenceCircuit::build(c)
        }

        fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
            self.assign(pw, wires);
        }
    }

    #[test]
    fn test_non_existence_circuit() {
        let primary_index = F::rand();
        let rng = &mut thread_rng();
        let [computational_hash, placeholder_hash] = array::from_fn(|_| gen_random_field_hash());
        let ops = random_aggregation_operations();
        // generate min_query_primary and max_query_primary
        let [min_query_primary, max_query_primary] =
            gen_values_in_range(rng, U256::from(42), U256::MAX - U256::from(42));
        let query_bounds = QueryBounds::new(
            &Placeholders::new_empty(min_query_primary, max_query_primary),
            None,
            None,
        )
        .unwrap();
        // generate a test index tree with all nodes bigger than max_primary
        let [node_a, node_b, _node_c, node_d, node_e, _node_f, _node_g] = generate_test_tree(
            primary_index,
            Some((max_query_primary + U256::from(1), U256::MAX)),
        );
        // we prove non-existence employing the minimum node of the tree as the proven node, which is node_e
        let path_e = vec![
            (node_d, ChildPosition::Left),
            (node_b, ChildPosition::Left),
            (node_a, ChildPosition::Left),
        ];
        let merkle_path_e = TreePathInputs::new(node_e, path_e, [None, None]);
        let circuit = NonExistenceCircuit::new(
            &merkle_path_e,
            primary_index,
            ops,
            computational_hash,
            placeholder_hash,
            &query_bounds,
        )
        .unwrap();

        let proof = run_circuit::<F, D, C, _>(circuit);

        let check_public_inputs = |proof: &ProofWithPublicInputs<F, C, D>,
                                   expected_root,
                                   expected_index_node_info: BoundaryRowNodeInfo,
                                   expected_query_bounds: &QueryBounds,
                                   test_name: &str| {
            let pis =
                PublicInputsQueryCircuits::<F, MAX_NUM_RESULTS>::from_slice(&proof.public_inputs);
            assert_eq!(
                pis.tree_hash(),
                expected_root,
                "failed for test {test_name}",
            );
            let expected_outputs = compute_dummy_output_values(&ops);
            assert_eq!(
                pis.to_values_raw(),
                &expected_outputs,
                "failed for test {test_name}",
            );
            assert_eq!(
                pis.num_matching_rows(),
                F::ZERO,
                "failed for test {test_name}",
            );
            let expected_boundary_row = {
                // build the same dummy `BoundaryRowNodeInfo` built inside the circuit
                let dummy_row_node_info = BoundaryRowNodeInfo {
                    end_node_hash: *empty_poseidon_hash(),
                    predecessor_info: NeighborInfo::new_dummy_predecessor(),
                    successor_info: NeighborInfo::new_dummy_successor(),
                };
                BoundaryRowData {
                    row_node_info: dummy_row_node_info,
                    index_node_info: expected_index_node_info,
                }
            }
            .to_fields();
            assert_eq!(
                pis.to_left_row_raw(),
                expected_boundary_row,
                "failed for test {test_name}",
            );
            assert_eq!(
                pis.to_right_row_raw(),
                expected_boundary_row,
                "failed for test {test_name}",
            );
            assert_eq!(
                pis.min_primary(),
                expected_query_bounds.min_query_primary(),
                "failed for test {test_name}",
            );
            assert_eq!(
                pis.max_primary(),
                expected_query_bounds.max_query_primary(),
                "failed for test {test_name}",
            );
            assert!(!pis.overflow_flag(), "failed for test {test_name}");
            assert_eq!(
                pis.computational_hash(),
                computational_hash,
                "failed for test {test_name}",
            );
            assert_eq!(
                pis.placeholder_hash(),
                placeholder_hash,
                "failed for test {test_name}",
            );
        };
        let expected_root = node_a.compute_node_hash(primary_index);
        let expected_index_node_info = {
            // node_e has no predecessor
            let predecessor_e = NeighborInfo::new_dummy_predecessor();
            // node_e successor is node_d, which is in the path
            let node_d_hash = node_d.compute_node_hash(primary_index);
            let successor_e = NeighborInfo::new(node_d.value, Some(node_d_hash));
            BoundaryRowNodeInfo {
                end_node_hash: node_e.compute_node_hash(primary_index),
                predecessor_info: predecessor_e,
                successor_info: successor_e,
            }
        };

        check_public_inputs(
            &proof,
            expected_root,
            expected_index_node_info,
            &query_bounds,
            "all bigger",
        );

        // generate a test index tree with all nodes smaller than min_query_primary
        let [node_a, _node_b, node_c, _node_d, _node_e, _node_f, node_g] = generate_test_tree(
            primary_index,
            Some((U256::ZERO, min_query_primary - U256::from(1))),
        );
        // we prove non-existence employing the maximum node of the tree as the proven node, which is node_g
        let path_g = vec![
            (node_c, ChildPosition::Right),
            (node_a, ChildPosition::Right),
        ];
        let merkle_path_g = TreePathInputs::new(node_g, path_g, [None, None]);

        let circuit = NonExistenceCircuit::new(
            &merkle_path_g,
            primary_index,
            ops,
            computational_hash,
            placeholder_hash,
            &query_bounds,
        )
        .unwrap();

        let proof = run_circuit::<F, D, C, _>(circuit);

        let expected_index_node_info = {
            // node_g predecessor is node_c, which is in the path
            let node_c_hash = node_c.compute_node_hash(primary_index);
            let predecessor_g = NeighborInfo::new(node_c.value, Some(node_c_hash));
            // node_g has no successor
            let successor_g = NeighborInfo::new_dummy_successor();
            BoundaryRowNodeInfo {
                end_node_hash: node_g.compute_node_hash(primary_index),
                predecessor_info: predecessor_g,
                successor_info: successor_g,
            }
        };
        let expected_root = node_a.compute_node_hash(primary_index);
        check_public_inputs(
            &proof,
            expected_root,
            expected_index_node_info,
            &query_bounds,
            "all smaller",
        );

        // now, we test non-existence over a tree where some nodes are smaller than min_query_primary, and all other nodes are
        // bigger than max_query_primary
        // We generate a test tree with random values, and then we set min_query_primary and max_query_primary to values which are
        // between node_f.value and node_b.value
        let ([node_a, node_b, node_c, node_d, node_e, node_f, _node_g], query_bounds) = loop {
            let [node_a, node_b, node_c, node_d, node_e, node_f, node_g] =
                generate_test_tree(primary_index, None);
            if node_b.value.checked_sub(node_f.value).unwrap() > U256::from(2) {
                // if there is room between node_f.value and node_b.value, we
                // set min_query_primary = node_f.value + 1 and max_query_primary = node_b.value - 1
                let min_query_primary = node_f.value + U256::from(1);
                let max_query_primary = node_b.value - U256::from(1);

                break (
                    [node_a, node_b, node_c, node_d, node_e, node_f, node_g],
                    QueryBounds::new(
                        &Placeholders::new_empty(min_query_primary, max_query_primary),
                        None,
                        None,
                    )
                    .unwrap(),
                );
            }
            // otherwise, we need to re-generate the tree
        };
        // in this case, we can use either node_b or node_f to prove non-existence
        // prove with node_f
        let path_f = vec![
            (node_d, ChildPosition::Right),
            (node_b, ChildPosition::Left),
            (node_a, ChildPosition::Left),
        ];
        let merkle_path_f = TreePathInputs::new(node_f, path_f, [None, None]);

        let circuit = NonExistenceCircuit::new(
            &merkle_path_f,
            primary_index,
            ops,
            computational_hash,
            placeholder_hash,
            &query_bounds,
        )
        .unwrap();

        let proof = run_circuit::<F, D, C, _>(circuit);
        let expected_index_node_info = {
            // node_f predecessor is node_d, which is in the path
            let node_d_hash = node_d.compute_node_hash(primary_index);
            let predecessor_f = NeighborInfo::new(node_d.value, Some(node_d_hash));
            // node_f successor is node_b, which is in the path
            let node_b_hash = node_b.compute_node_hash(primary_index);
            let successor_f = NeighborInfo::new(node_b.value, Some(node_b_hash));
            BoundaryRowNodeInfo {
                end_node_hash: node_f.compute_node_hash(primary_index),
                predecessor_info: predecessor_f,
                successor_info: successor_f,
            }
        };
        let expected_root = node_a.compute_node_hash(primary_index);
        check_public_inputs(
            &proof,
            expected_root,
            expected_index_node_info,
            &query_bounds,
            "smaller predecessor",
        );

        // we try to prove also with node_b
        let path_b = vec![(node_a, ChildPosition::Left)];
        let merkle_path_b = TreePathInputs::new(node_b, path_b, [Some(node_d), None]);

        let circuit = NonExistenceCircuit::new(
            &merkle_path_b,
            primary_index,
            ops,
            computational_hash,
            placeholder_hash,
            &query_bounds,
        )
        .unwrap();

        let proof = run_circuit::<F, D, C, _>(circuit);
        let expected_index_node_info = {
            // node_b predecessor is node_f, which is not in the path
            let predecessor_b = NeighborInfo::new(node_f.value, None);
            // node_b successor is node_a, which is in the path
            let successor_b = NeighborInfo::new(node_a.value, Some(expected_root));
            BoundaryRowNodeInfo {
                end_node_hash: node_b.compute_node_hash(primary_index),
                predecessor_info: predecessor_b,
                successor_info: successor_b,
            }
        };
        check_public_inputs(
            &proof,
            expected_root,
            expected_index_node_info,
            &query_bounds,
            "bigger successor",
        );

        // negative test: check that if there are nodes in the query range, then the circuit fail for each node in
        // the tree
        // set min_query_primary = node_f.value, max_query_primary = node_a.value
        let query_bounds = QueryBounds::new(
            &Placeholders::new_empty(node_f.value, node_a.value),
            None,
            None,
        )
        .unwrap();
        // try generate prove with node_a
        let path_a = vec![];
        let merkle_path_a = TreePathInputs::new(node_a, path_a, [Some(node_b), Some(node_c)]);

        let circuit = NonExistenceCircuit::new(
            &merkle_path_a,
            primary_index,
            ops,
            computational_hash,
            placeholder_hash,
            &query_bounds,
        )
        .unwrap();

        check_panic!(
            || run_circuit::<F, D, C, _>(circuit),
            "circuit didn't fail for node_a"
        );

        // try to generate proof with node_b
        let circuit = NonExistenceCircuit::new(
            &merkle_path_b,
            primary_index,
            ops,
            computational_hash,
            placeholder_hash,
            &query_bounds,
        )
        .unwrap();

        check_panic!(
            || run_circuit::<F, D, C, _>(circuit),
            "circuit didn't fail for node_b"
        );

        // try generate prove with node_c
        let path_c = vec![(node_a, ChildPosition::Right)];
        let merkle_path_c = TreePathInputs::new(node_c, path_c, [None, Some(node_g)]);

        let circuit = NonExistenceCircuit::new(
            &merkle_path_c,
            primary_index,
            ops,
            computational_hash,
            placeholder_hash,
            &query_bounds,
        )
        .unwrap();

        check_panic!(
            || run_circuit::<F, D, C, _>(circuit),
            "circuit didn't fail for node_c"
        );

        // try generate prove with node_d
        let path_d = vec![(node_b, ChildPosition::Left), (node_a, ChildPosition::Left)];
        let merkle_path_d = TreePathInputs::new(node_d, path_d, [Some(node_e), Some(node_f)]);

        let circuit = NonExistenceCircuit::new(
            &merkle_path_d,
            primary_index,
            ops,
            computational_hash,
            placeholder_hash,
            &query_bounds,
        )
        .unwrap();

        check_panic!(
            || run_circuit::<F, D, C, _>(circuit),
            "circuit didn't fail for node_d"
        );

        // try generate prove with node_e
        let path_e = vec![
            (node_d, ChildPosition::Left),
            (node_b, ChildPosition::Left),
            (node_a, ChildPosition::Left),
        ];
        let merkle_path_e = TreePathInputs::new(node_e, path_e, [None, None]);

        let circuit = NonExistenceCircuit::new(
            &merkle_path_e,
            primary_index,
            ops,
            computational_hash,
            placeholder_hash,
            &query_bounds,
        )
        .unwrap();

        check_panic!(
            || run_circuit::<F, D, C, _>(circuit),
            "circuit didn't fail for node_e"
        );

        // try to generate proof with node_f
        let circuit = NonExistenceCircuit::new(
            &merkle_path_f,
            primary_index,
            ops,
            computational_hash,
            placeholder_hash,
            &query_bounds,
        )
        .unwrap();

        check_panic!(
            || run_circuit::<F, D, C, _>(circuit),
            "circuit didn't fail for node_f"
        );

        // try to generate proof with node_g
        // try generate prove with node_d
        let path_g = vec![
            (node_c, ChildPosition::Right),
            (node_a, ChildPosition::Right),
        ];
        let merkle_path_g = TreePathInputs::new(node_g, path_g, [None, None]);

        let circuit = NonExistenceCircuit::new(
            &merkle_path_g,
            primary_index,
            ops,
            computational_hash,
            placeholder_hash,
            &query_bounds,
        )
        .unwrap();

        check_panic!(
            || run_circuit::<F, D, C, _>(circuit),
            "circuit didn't fail for node_g"
        );
    }
}
