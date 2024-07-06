//! This circuits is employed for all the ancestor nodes of the new inserted node,
//! in order to compute the new hash of the tree while recomputing the previous hash
//! of the tree, proving over the same path.

use super::public_inputs::PublicInputs;
use anyhow::Result;
use ethers::prelude::U256;
use mp2_common::{
    public_inputs::PublicInputCommon,
    serialization::{deserialize, serialize},
    types::CBuilder,
    u256::{CircuitBuilderU256, UInt256Target, WitnessWriteU256},
    utils::{FromTargets, ToTargets},
    CHasher, D, F,
};
use plonky2::{
    hash::hash_types::{HashOut, HashOutTarget},
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::proof::ProofWithPublicInputsTarget,
};
use recursion_framework::circuit_builder::CircuitLogicWires;
use serde::{Deserialize, Serialize};
use std::iter;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct MembershipWires {
    block_id: Target,
    index_value: UInt256Target,
    old_min: UInt256Target,
    old_max: UInt256Target,
    #[serde(serialize_with = "serialize", deserialize_with = "deserialize")]
    left_child: HashOutTarget,
    #[serde(serialize_with = "serialize", deserialize_with = "deserialize")]
    rows_tree_hash: HashOutTarget,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct MembershipCircuit {
    /// Identifier of the block number column
    pub(crate) index_identifier: F,
    /// Block number of the current node
    pub(crate) index_value: U256,
    /// Minimum block number found in the subtree rooted in the current node in the old tree
    pub(crate) old_min: U256,
    /// Maximum block number found in the subtree rooted in the current node in the old tree
    pub(crate) old_max: U256,
    /// Hash of the left child of the current node
    pub(crate) left_child: HashOut<F>,
    /// Hash of the rows tree stored in this node
    pub(crate) rows_tree_hash: HashOut<F>,
}

impl MembershipCircuit {
    fn build(b: &mut CBuilder, child_pi: &[Target]) -> MembershipWires {
        let ttrue = b._true();

        let index_identifier = b.add_virtual_target();
        let [index_value, old_min, old_max] = [0; 3].map(|_| b.add_virtual_u256());
        let [left_child, rows_tree_hash] = [0; 2].map(|_| b.add_virtual_hash());

        let child_pi = PublicInputs::<Target>::from_slice(child_pi);

        // Compute the hash of the node in the old tree.
        // H_old = H(left_child || p.H_old || old_min || old_max || block_id || block_number || rows_tree_hash)
        let inputs = left_child
            .to_targets()
            .iter()
            .chain(child_pi.h_old)
            .cloned()
            .chain(old_min.to_targets())
            .chain(old_max.to_targets())
            .chain(iter::once(index_identifier))
            .chain(index_value.to_targets())
            .chain(rows_tree_hash.to_targets())
            .collect();
        let h_old = b.hash_n_to_hash_no_pad::<CHasher>(inputs).elements;

        // Check that the BST property is preserved also in the new tree
        // remember we only append to the right so the right children minimum should
        // always be superior to the parent minimum.
        let child_min = UInt256Target::from_targets(child_pi.min);
        let block_num_lt_child_min = b.is_less_than_u256(&index_value, &child_min);
        b.connect(block_num_lt_child_min.target, ttrue.target);

        // Compute the hash of the node in the new tree.
        // We insert the node in the right subtree, so minimum value should be unchanged
        // node_min = old_min
        // node_max = p.max
        // H_new = H(left_child || p.H_new || node_min || node_max || block_id || block_number || rows_tree_hash)
        let inputs = left_child
            .to_targets()
            .iter()
            .chain(child_pi.h_new)
            .cloned()
            .chain(old_min.to_targets()) // node_min
            .chain(child_pi.max.iter().cloned()) // node_max
            .chain(iter::once(index_identifier))
            .chain(index_value.to_targets())
            .chain(rows_tree_hash.to_targets())
            .collect();
        let h_new = b.hash_n_to_hash_no_pad::<CHasher>(inputs).elements;

        // Register the public inputs.
        PublicInputs::new(
            &h_new,
            &h_old,
            &old_min.to_targets(), // node_min
            child_pi.max,          // node_max
            child_pi.block_number,
            child_pi.block_hash,
            child_pi.prev_block_hash,
            child_pi.metadata_hash,
            child_pi.new_node_digest,
        )
        .register(b);

        MembershipWires {
            block_id: index_identifier,
            index_value,
            old_min,
            old_max,
            left_child,
            rows_tree_hash,
        }
    }

    /// Assign the wires.
    fn assign(&self, pw: &mut PartialWitness<F>, wires: &MembershipWires) {
        pw.set_target(wires.block_id, self.index_identifier);
        [
            (&wires.index_value, self.index_value),
            (&wires.old_min, self.old_min),
            (&wires.old_max, self.old_max),
        ]
        .into_iter()
        .for_each(|(t, v)| pw.set_u256_target(t, v));
        [
            (wires.left_child, self.left_child),
            (wires.rows_tree_hash, self.rows_tree_hash),
        ]
        .into_iter()
        .for_each(|(t, v)| pw.set_hash_target(t, v));
    }
}

/// Num of children = 1
impl CircuitLogicWires<F, D, 1> for MembershipWires {
    type CircuitBuilderParams = ();

    type Inputs = MembershipCircuit;

    const NUM_PUBLIC_INPUTS: usize = PublicInputs::<F>::TOTAL_LEN;

    fn circuit_logic(
        builder: &mut CBuilder,
        verified_proofs: [&ProofWithPublicInputsTarget<D>; 1],
        _builder_parameters: Self::CircuitBuilderParams,
    ) -> Self {
        let child_pi = &verified_proofs[0].public_inputs;
        MembershipCircuit::build(builder, child_pi)
    }

    fn assign_input(&self, inputs: Self::Inputs, pw: &mut PartialWitness<F>) -> Result<()> {
        inputs.assign(pw, self);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{super::tests::random_block_index_pi, *};
    use mp2_common::{
        poseidon::H,
        utils::{Fieldable, ToFields},
        C,
    };
    use mp2_test::{
        circuit::{run_circuit, UserCircuit},
        utils::random_vector,
    };
    use plonky2::{hash::hash_types::NUM_HASH_OUT_ELTS, plonk::config::Hasher};
    use rand::{thread_rng, Rng};

    #[derive(Clone, Debug)]
    struct TestMembershipCircuit<'a> {
        c: MembershipCircuit,
        child_pi: &'a [F],
    }

    impl<'a> UserCircuit<F, D> for TestMembershipCircuit<'a> {
        // Membership wires + child public inputs
        type Wires = (MembershipWires, Vec<Target>);

        fn build(b: &mut CBuilder) -> Self::Wires {
            let child_pi = b.add_virtual_targets(PublicInputs::<Target>::TOTAL_LEN);

            let membership_wires = MembershipCircuit::build(b, &child_pi);

            (membership_wires, child_pi)
        }

        fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
            self.c.assign(pw, &wires.0);

            assert_eq!(wires.1.len(), PublicInputs::<Target>::TOTAL_LEN);
            pw.set_target_arr(&wires.1, self.child_pi);
        }
    }

    #[test]
    fn test_block_index_membership_circuit() {
        let mut rng = thread_rng();

        let index_identifier = rng.gen::<u32>().to_field();
        let [index_value, old_min, old_max] = [0; 3].map(|_| U256(rng.gen::<[u64; 4]>()));
        let [left_child, rows_tree_hash] =
            [0; 2].map(|_| HashOut::from_vec(random_vector::<u32>(NUM_HASH_OUT_ELTS).to_fields()));

        let child_pi =
            &random_block_index_pi(&mut rng, index_value + 1, index_value + 2, index_value + 2);

        let test_circuit = TestMembershipCircuit {
            c: MembershipCircuit {
                index_identifier,
                index_value,
                old_min,
                old_max,
                left_child,
                rows_tree_hash,
            },
            child_pi,
        };

        let proof = run_circuit::<F, D, C, _>(test_circuit);
        let pi = PublicInputs::from_slice(&proof.public_inputs);
        let child_pi = PublicInputs::from_slice(child_pi);

        // Check old hash
        {
            let inputs: Vec<_> = left_child
                .to_fields()
                .iter()
                .chain(child_pi.h_old)
                .cloned()
                .chain(old_min.to_fields())
                .chain(old_max.to_fields())
                .chain(iter::once(index_identifier))
                .chain(index_value.to_fields())
                .chain(rows_tree_hash.to_fields())
                .collect();
            let exp_hash = H::hash_no_pad(&inputs).elements;

            assert_eq!(pi.h_old, exp_hash);

            exp_hash
        };
        // Check new hash
        {
            let inputs: Vec<_> = left_child
                .to_fields()
                .iter()
                .chain(child_pi.h_new)
                .cloned()
                .chain(old_min.to_fields())
                .chain(child_pi.max.iter().cloned())
                .chain(iter::once(index_identifier))
                .chain(index_value.to_fields())
                .chain(rows_tree_hash.to_fields())
                .collect();
            let exp_hash = H::hash_no_pad(&inputs);

            assert_eq!(pi.h_new, exp_hash.elements);
        }
        // Check minimum block number
        {
            assert_eq!(pi.min, old_min.to_fields());
        }
        // Check maximum block number
        {
            assert_eq!(pi.max, child_pi.max);
        }
        // Check block number
        {
            assert_eq!(pi.block_number, child_pi.block_number);
        }
        // Check block hash
        {
            assert_eq!(pi.block_hash, child_pi.block_hash);
        }
        // Check previous block hash
        {
            assert_eq!(pi.prev_block_hash, child_pi.prev_block_hash);
        }
        // Check metadata hash
        {
            assert_eq!(pi.metadata_hash, child_pi.metadata_hash);
        }
        // Check new node digest
        {
            assert_eq!(pi.new_node_digest, child_pi.new_node_digest);
        }
    }
}
