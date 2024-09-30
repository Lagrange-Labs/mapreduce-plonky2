use crate::results_tree::extraction::PublicInputs;
use anyhow::Result;
use mp2_common::{
    poseidon::{empty_poseidon_hash, H},
    public_inputs::PublicInputCommon,
    serialization::{deserialize, serialize},
    types::CBuilder,
    u256::CircuitBuilderU256,
    utils::{greater_than, less_than, SelectHashBuilder, ToTargets},
    D, F,
};
use plonky2::{
    iop::{
        target::{BoolTarget, Target},
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::proof::ProofWithPublicInputsTarget,
};
use recursion_framework::circuit_builder::CircuitLogicWires;
use serde::{Deserialize, Serialize};
use std::iter;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NoChildIncludedSinglePathNodeWires {
    #[serde(serialize_with = "serialize", deserialize_with = "deserialize")]
    left_child_exists: BoolTarget,
    #[serde(serialize_with = "serialize", deserialize_with = "deserialize")]
    right_child_exists: BoolTarget,
    #[serde(serialize_with = "serialize", deserialize_with = "deserialize")]
    is_rows_tree: BoolTarget,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NoChildIncludedSinglePathNodeCircuit {
    /// Boolean flag specifying whether the node has a left child or not
    pub(crate) left_child_exists: bool,
    /// Boolean flag specifying whether the node has a right child or not
    pub(crate) right_child_exists: bool,
    /// Boolean flag specifying whether the current node is a node of
    /// a rows tree or of the index tree
    pub(crate) is_rows_tree: bool,
}

impl NoChildIncludedSinglePathNodeCircuit {
    pub fn build(
        b: &mut CBuilder,
        subtree_proof: &PublicInputs<Target>,
        child_proofs: &[PublicInputs<Target>; 2],
    ) -> NoChildIncludedSinglePathNodeWires {
        let empty_hash = b.constant_hash(*empty_poseidon_hash());
        let one = b.one();
        let ttrue = b._true();

        let [child_proof1, child_proof2] = child_proofs;
        let [left_child_exists, right_child_exists, is_rows_tree] =
            [0; 3].map(|_| b.add_virtual_bool_target_safe());
        let index_value = subtree_proof.primary_index_value_target();

        let left_hash = b.select_hash(
            left_child_exists,
            &child_proof1.tree_hash_target(),
            &empty_hash,
        );
        let right_hash = b.select_hash(
            right_child_exists,
            &child_proof2.tree_hash_target(),
            &empty_hash,
        );
        let column_id = b.select(
            is_rows_tree,
            subtree_proof.index_ids_target()[1],
            subtree_proof.index_ids_target()[0],
        );
        let node_value = b.select_u256(
            is_rows_tree,
            &subtree_proof.min_value_target(),
            &index_value,
        );
        let node_min = b.select_u256(
            left_child_exists,
            &child_proof1.min_value_target(),
            &node_value,
        );
        let node_max = b.select_u256(
            right_child_exists,
            &child_proof2.max_value_target(),
            &node_value,
        );

        // H(left_hash || right_hash || node_min || node_max || column_id || node_value || p.H)
        let hash_inputs = left_hash
            .to_targets()
            .into_iter()
            .chain(right_hash.to_targets())
            .chain(node_min.to_targets())
            .chain(node_max.to_targets())
            .chain(iter::once(column_id))
            .chain(node_value.to_targets())
            .chain(subtree_proof.tree_hash_target().to_targets())
            .collect();
        let node_hash = b.hash_n_to_hash_no_pad::<H>(hash_inputs);

        // Enforce consistency of counters
        let min_minus_one = b.sub(subtree_proof.min_counter_target(), one);
        let max_plus_one = b.add(subtree_proof.max_counter_target(), one);
        let max_left = b.select(
            left_child_exists,
            child_proof1.max_counter_target(),
            min_minus_one,
        );
        let min_right = b.select(
            right_child_exists,
            child_proof2.min_counter_target(),
            max_plus_one,
        );
        // assert max_left + 1 == p.min_counter
        let left_plus_one = b.add(max_left, one);
        b.connect(left_plus_one, subtree_proof.min_counter_target());
        // assert p.max_counter + 1 == min_right
        b.connect(max_plus_one, min_right);

        // Ensure that all the records in the subtree rooted in the left child,
        // if there is a left child, are associated to counters outside of the
        // range specified by the query
        // max_left < p.offset_range_max
        let is_less = less_than(b, max_left, subtree_proof.offset_range_min_target(), 32);
        b.connect(is_less.target, ttrue.target);

        // Enforce that all the records in the subtree rooted in the right child,
        // if there is a right child, are associated to counters outside of the
        // range specified by the query
        // min_right > p.offset_range_min
        let is_greater = greater_than(b, min_right, subtree_proof.offset_range_max_target(), 32);
        b.connect(is_greater.target, ttrue.target);

        let min_counter = b.select(
            left_child_exists,
            child_proof1.min_counter_target(),
            subtree_proof.min_counter_target(),
        );
        let max_counter = b.select(
            right_child_exists,
            child_proof2.max_counter_target(),
            subtree_proof.max_counter_target(),
        );

        // Register the public inputs.
        PublicInputs::new(
            &node_hash.to_targets(),
            &node_min.to_targets(),
            &node_max.to_targets(),
            subtree_proof.to_primary_index_value_raw(),
            subtree_proof.to_index_ids_raw(),
            &[min_counter],
            &[max_counter],
            &[*subtree_proof.to_offset_range_min_raw()],
            &[*subtree_proof.to_offset_range_max_raw()],
            subtree_proof.to_accumulator_raw(),
        )
        .register(b);

        NoChildIncludedSinglePathNodeWires {
            left_child_exists,
            right_child_exists,
            is_rows_tree,
        }
    }

    fn assign(&self, pw: &mut PartialWitness<F>, wires: &NoChildIncludedSinglePathNodeWires) {
        pw.set_bool_target(wires.left_child_exists, self.left_child_exists);
        pw.set_bool_target(wires.right_child_exists, self.right_child_exists);
        pw.set_bool_target(wires.is_rows_tree, self.is_rows_tree);
    }
}

/// Subtree proof number = 1, child proof number = 2
pub(crate) const NUM_VERIFIED_PROOFS: usize = 3;

impl CircuitLogicWires<F, D, NUM_VERIFIED_PROOFS> for NoChildIncludedSinglePathNodeWires {
    type CircuitBuilderParams = ();
    type Inputs = NoChildIncludedSinglePathNodeCircuit;

    const NUM_PUBLIC_INPUTS: usize = PublicInputs::<F>::total_len();

    fn circuit_logic(
        builder: &mut CBuilder,
        verified_proofs: [&ProofWithPublicInputsTarget<D>; NUM_VERIFIED_PROOFS],
        _builder_parameters: Self::CircuitBuilderParams,
    ) -> Self {
        // The first one is the subtree proof, and the remainings are child proofs.
        let [subtree_proof, child_proof1, child_proof2] =
            verified_proofs.map(|p| PublicInputs::from_slice(&p.public_inputs));

        Self::Inputs::build(builder, &subtree_proof, &[child_proof1, child_proof2])
    }

    fn assign_input(&self, inputs: Self::Inputs, pw: &mut PartialWitness<F>) -> Result<()> {
        inputs.assign(pw, self);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::results_tree::extraction::{
        tests::{random_results_extraction_public_inputs, unify_child_proof, unify_subtree_proof},
        PI_LEN,
    };
    use mp2_common::{utils::ToFields, C};
    use mp2_test::circuit::{run_circuit, UserCircuit};
    use plonky2::plonk::config::Hasher;
    use std::array;

    #[derive(Clone, Debug)]
    struct TestNoChildIncludedSinglePathNodeCircuit<'a> {
        c: NoChildIncludedSinglePathNodeCircuit,
        subtree_proof: &'a [F],
        left_child_proof: &'a [F],
        right_child_proof: &'a [F],
    }

    impl<'a> UserCircuit<F, D> for TestNoChildIncludedSinglePathNodeCircuit<'a> {
        // Circuit wires + subtree proof + left child proof + right child proof
        type Wires = (
            NoChildIncludedSinglePathNodeWires,
            Vec<Target>,
            Vec<Target>,
            Vec<Target>,
        );

        fn build(b: &mut CBuilder) -> Self::Wires {
            let proofs = array::from_fn(|_| b.add_virtual_target_arr::<{ PI_LEN }>().to_vec());

            let [subtree_pi, left_child_pi, right_child_pi] =
                array::from_fn(|i| PublicInputs::<Target>::from_slice(&proofs[i]));

            let wires = NoChildIncludedSinglePathNodeCircuit::build(
                b,
                &subtree_pi,
                &[left_child_pi, right_child_pi],
            );

            let [subtree_proof, left_child_proof, right_child_proof] = proofs;

            (wires, subtree_proof, left_child_proof, right_child_proof)
        }

        fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
            self.c.assign(pw, &wires.0);
            pw.set_target_arr(&wires.1, self.subtree_proof);
            pw.set_target_arr(&wires.2, self.left_child_proof);
            pw.set_target_arr(&wires.3, self.right_child_proof);
        }
    }

    fn test_no_child_included_single_path_node_circuit(
        is_rows_tree: bool,
        left_child_exists: bool,
        right_child_exists: bool,
    ) {
        // Generate the input proofs.
        let [mut subtree_proof, mut left_child_proof, mut right_child_proof] =
            random_results_extraction_public_inputs::<3>();
        unify_subtree_proof(&mut subtree_proof);
        let subtree_pi = PublicInputs::from_slice(&subtree_proof);
        [
            (&mut left_child_proof, true),
            (&mut right_child_proof, false),
        ]
        .iter_mut()
        .for_each(|(p, is_left_child)| {
            unify_child_proof(p, is_rows_tree, *is_left_child, &subtree_pi)
        });
        let left_child_pi = PublicInputs::from_slice(&left_child_proof);
        let right_child_pi = PublicInputs::from_slice(&right_child_proof);

        // Construct the expected public input values.
        let index_ids = subtree_pi.index_ids();
        let primary_index_value = subtree_pi.primary_index_value();
        let node_value = if is_rows_tree {
            subtree_pi.min_value()
        } else {
            primary_index_value
        };
        let node_min = if left_child_exists {
            left_child_pi.min_value()
        } else {
            node_value
        };
        let node_max = if right_child_exists {
            right_child_pi.max_value()
        } else {
            node_value
        };
        let min_counter = if left_child_exists {
            left_child_pi.min_counter()
        } else {
            subtree_pi.min_counter()
        };
        let max_counter = if right_child_exists {
            right_child_pi.max_counter()
        } else {
            subtree_pi.max_counter()
        };

        // Construct the test circuit.
        let test_circuit = TestNoChildIncludedSinglePathNodeCircuit {
            c: NoChildIncludedSinglePathNodeCircuit {
                left_child_exists,
                right_child_exists,
                is_rows_tree,
            },
            subtree_proof: &subtree_proof,
            left_child_proof: &left_child_proof,
            right_child_proof: &right_child_proof,
        };

        // Prove for the test circuit.
        let proof = run_circuit::<F, D, C, _>(test_circuit);
        let pi = PublicInputs::<_>::from_slice(&proof.public_inputs);

        // Check the public inputs.
        // Tree hash
        {
            let column_id = if is_rows_tree {
                index_ids[1]
            } else {
                index_ids[0]
            };
            let empty_hash = empty_poseidon_hash();
            let left_hash = if left_child_exists {
                left_child_pi.tree_hash()
            } else {
                *empty_hash
            };
            let right_hash = if right_child_exists {
                right_child_pi.tree_hash()
            } else {
                *empty_hash
            };
            let hash_inputs: Vec<_> = left_hash
                .to_fields()
                .into_iter()
                .chain(right_hash.to_fields())
                .chain(node_min.to_fields())
                .chain(node_max.to_fields())
                .chain(iter::once(column_id))
                .chain(node_value.to_fields())
                .chain(subtree_pi.tree_hash().to_fields())
                .collect();
            let exp_hash = H::hash_no_pad(&hash_inputs);
            assert_eq!(pi.tree_hash(), exp_hash);
        }

        // Minimum value
        assert_eq!(pi.min_value(), node_min);

        // Maximum value
        assert_eq!(pi.max_value(), node_max);

        // Primary index value
        assert_eq!(pi.primary_index_value(), subtree_pi.primary_index_value());

        // Index IDs
        assert_eq!(pi.index_ids(), index_ids);

        // Minimum counter
        assert_eq!(pi.min_counter(), min_counter);

        // Maximum counter
        assert_eq!(pi.max_counter(), max_counter);

        // Offset range min
        assert_eq!(pi.offset_range_min(), subtree_pi.offset_range_min());

        // Offset range max
        assert_eq!(pi.offset_range_max(), subtree_pi.offset_range_max());

        // Accumulator
        assert_eq!(pi.accumulator(), subtree_pi.accumulator());
    }

    #[test]
    fn test_no_child_included_for_row_node_with_no_child() {
        test_no_child_included_single_path_node_circuit(true, false, false);
    }
    #[test]
    fn test_no_child_included_for_row_node_with_left_child() {
        test_no_child_included_single_path_node_circuit(true, true, false);
    }
    #[test]
    fn test_no_child_included_for_row_node_with_right_child() {
        test_no_child_included_single_path_node_circuit(true, false, true);
    }
    #[test]
    fn test_no_child_included_for_row_node_with_both_children() {
        test_no_child_included_single_path_node_circuit(true, true, true);
    }
    #[test]
    fn test_no_child_included_for_index_node_with_no_child() {
        test_no_child_included_single_path_node_circuit(false, false, false);
    }
    #[test]
    fn test_no_child_included_for_index_node_with_left_child() {
        test_no_child_included_single_path_node_circuit(false, true, false);
    }
    #[test]
    fn test_no_child_included_for_index_node_with_right_child() {
        test_no_child_included_single_path_node_circuit(false, false, true);
    }
    #[test]
    fn test_no_child_included_for_index_node_with_both_children() {
        test_no_child_included_single_path_node_circuit(false, true, true);
    }
}
