//! This circuit is employed when the new node is inserted as parent of an existing node,
//! referred to as old node.

use super::{compute_index_digest, public_inputs::PublicInputs};
use crate::{
    extraction::{ExtractionPI, ExtractionPIWrap},
    row_tree,
};
use alloy::primitives::U256;
use anyhow::Result;
use mp2_common::{
    default_config,
    group_hashing::CircuitBuilderGroupHashing,
    poseidon::{empty_poseidon_hash, H},
    proof::ProofWithVK,
    public_inputs::PublicInputCommon,
    serialization::{deserialize, serialize},
    types::CBuilder,
    u256::{CircuitBuilderU256, UInt256Target, WitnessWriteU256},
    utils::{FromTargets, ToTargets},
    CHasher, C, D, F,
};
use plonky2::{
    hash::hash_types::{HashOut, HashOutTarget},
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{circuit_builder::CircuitBuilder, config::Hasher, proof::ProofWithPublicInputsTarget},
};
use recursion_framework::{
    circuit_builder::CircuitLogicWires,
    framework::{
        RecursiveCircuits, RecursiveCircuitsVerifierGagdet, RecursiveCircuitsVerifierTarget,
    },
};
use serde::{Deserialize, Serialize};
use std::{iter, marker::PhantomData};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct ParentWires {
    index_identifier: Target,
    old_index_value: UInt256Target,
    old_min: UInt256Target,
    old_max: UInt256Target,
    #[serde(serialize_with = "serialize", deserialize_with = "deserialize")]
    left_child: HashOutTarget,
    #[serde(serialize_with = "serialize", deserialize_with = "deserialize")]
    right_child: HashOutTarget,
    #[serde(serialize_with = "serialize", deserialize_with = "deserialize")]
    old_rows_tree_hash: HashOutTarget,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ParentCircuit {
    /// Identifier of the block number column
    pub(crate) index_identifier: F,
    /// Block number stored in the old node
    pub(crate) old_index_value: U256,
    /// Minimum block number stored in the subtree rooted in the old node
    pub(crate) old_min: U256,
    /// Maximum block number stored in the subtree rooted in the old node
    pub(crate) old_max: U256,
    /// Hash of the left child of the old node
    pub(crate) old_left_child: HashOut<F>,
    /// Hash of the right child of the old node
    pub(crate) old_right_child: HashOut<F>,
    /// Hash of the rows tree stored in the old node
    pub(crate) old_rows_tree_hash: HashOut<F>,
}

impl ParentCircuit {
    fn build<E: ExtractionPIWrap>(
        b: &mut CBuilder,
        extraction_pi: &[Target],
        rows_tree_pi: &[Target],
    ) -> ParentWires {
        let ttrue = b._true();

        let index_identifier = b.add_virtual_target();
        let [old_index_value, old_min, old_max] = [0; 3].map(|_| b.add_virtual_u256());
        let [old_left_child, old_right_child, old_rows_tree_hash] =
            [0; 3].map(|_| b.add_virtual_hash());

        let extraction_pi = E::PI::from_slice(extraction_pi);
        let rows_tree_pi = row_tree::PublicInputs::<Target>::from_slice(rows_tree_pi);

        let block_number = extraction_pi.primary_index_value();

        // Enforce that the data extracted from the blockchain is the same as the data
        // employed to build the rows tree for this node.
        b.connect_curve_points(extraction_pi.value_set_digest(), rows_tree_pi.rows_digest());

        // Compute the hash of table metadata, to be exposed as public input to prove to
        // the verifier that we extracted the correct storage slots and we place the data
        // in the expected columns of the constructed tree; we add also the identifier
        // of the block number column to the table metadata.
        // metadata_hash = H(extraction_proof.DM || block_id)
        let inputs = extraction_pi
            .metadata_set_digest()
            .to_targets()
            .iter()
            .cloned()
            .chain(iter::once(index_identifier))
            .collect();
        let metadata_hash = b.hash_n_to_hash_no_pad::<CHasher>(inputs).elements;

        // Compute the order-agnostic digest of this node of the block tree.
        // node_digest = HashToInt(H(block_id || block_number)) * rows_tree_proof.DR
        let inputs = iter::once(index_identifier)
            .chain(block_number.iter().cloned())
            .collect();
        let node_digest = compute_index_digest(b, inputs, rows_tree_pi.rows_digest());

        // We recompute the hash of the old node to bind the `old_min` and `old_max`
        // values to the hash of the old tree.
        // H_old = H(left_child || right_child || old_min || old_max || block_id || old_block_number || old_rows_tree_hash)
        let inputs = old_left_child
            .to_targets()
            .into_iter()
            .chain(old_right_child.to_targets())
            .chain(old_min.to_targets())
            .chain(old_max.to_targets())
            .chain(iter::once(index_identifier))
            .chain(old_index_value.to_targets())
            .chain(old_rows_tree_hash.to_targets())
            .collect();
        let h_old = b.hash_n_to_hash_no_pad::<CHasher>(inputs).elements;

        // The old node will be the left child of the new node, so we enforce the BST
        // property over the values stored in the nodes.
        let new_block_num = UInt256Target::from_targets(&block_number);
        let old_max_lt_new_block_num = b.is_less_than_u256(&old_max, &new_block_num);
        b.connect(old_max_lt_new_block_num.target, ttrue.target);

        // Compute hash of the new node
        // node_min = old_min
        // node_max = block_number
        // Since in the index tree for block, the previous node is always a left child, we can
        // hardcode this in the node hash. This is due to the construction  of sbbst, see
        // https://github.com/Lagrange-Labs/ryhope for more information about the  type of tree.
        // H_new = H(H_old || H("") || node_min || node_max || block_id || block_number || rows_tree_proof.H)
        let empty_hash = b.constant_hash(*empty_poseidon_hash()).to_targets();
        let inputs = h_old
            .into_iter()
            .chain(empty_hash)
            .chain(old_min.to_targets()) // node_min
            .chain(block_number.iter().cloned()) // node_max
            .chain(iter::once(index_identifier))
            .chain(block_number.iter().cloned())
            .chain(rows_tree_pi.h.iter().cloned())
            .collect();
        let h_new = b.hash_n_to_hash_no_pad::<CHasher>(inputs).elements;

        // check that the rows tree built is for a merged table iff we extract data from MPT for a merged table
        b.connect(
            rows_tree_pi.is_merge_case().target,
            extraction_pi.is_merge_case().target,
        );

        // Register the public inputs.
        PublicInputs::new(
            &h_new,
            &h_old,
            &old_min.to_targets(), // node_min
            &block_number,         // node_max
            &block_number,
            &extraction_pi.commitment(),
            &extraction_pi.prev_commitment(),
            &metadata_hash,
            &node_digest.to_targets(),
        )
        .register(b);

        ParentWires {
            index_identifier,
            old_index_value,
            old_min,
            old_max,
            left_child: old_left_child,
            right_child: old_right_child,
            old_rows_tree_hash,
        }
    }

    /// Assign the wires.
    fn assign(&self, pw: &mut PartialWitness<F>, wires: &ParentWires) {
        pw.set_target(wires.index_identifier, self.index_identifier);
        [
            (&wires.old_index_value, self.old_index_value),
            (&wires.old_min, self.old_min),
            (&wires.old_max, self.old_max),
        ]
        .into_iter()
        .for_each(|(t, v)| pw.set_u256_target(t, v));
        [
            (wires.left_child, self.old_left_child),
            (wires.right_child, self.old_right_child),
            (wires.old_rows_tree_hash, self.old_rows_tree_hash),
        ]
        .into_iter()
        .for_each(|(t, v)| pw.set_hash_target(t, v));
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct RecursiveParentWires<E: ExtractionPIWrap> {
    parent_wires: ParentWires,
    extraction_verifier: RecursiveCircuitsVerifierTarget<D>,
    rows_tree_verifier: RecursiveCircuitsVerifierTarget<D>,
    _e: PhantomData<E>,
}

#[derive(Clone, Debug)]
pub(crate) struct RecursiveParentInput {
    pub(crate) witness: ParentCircuit,
    pub(crate) extraction_proof: ProofWithVK,
    pub(crate) rows_tree_proof: ProofWithVK,
    pub(crate) extraction_set: RecursiveCircuits<F, C, D>,
    pub(crate) rows_tree_set: RecursiveCircuits<F, C, D>,
}
impl<E: ExtractionPIWrap> CircuitLogicWires<F, D, 0> for RecursiveParentWires<E>
where
    [(); E::PI::TOTAL_LEN]:,
    [(); <H as Hasher<F>>::HASH_SIZE]:,
{
    // Final extraction circuit set + rows tree circuit set
    type CircuitBuilderParams = (RecursiveCircuits<F, C, D>, RecursiveCircuits<F, C, D>);

    type Inputs = RecursiveParentInput;

    const NUM_PUBLIC_INPUTS: usize = PublicInputs::<Target>::TOTAL_LEN;

    fn circuit_logic(
        builder: &mut CircuitBuilder<F, D>,
        _verified_proofs: [&ProofWithPublicInputsTarget<D>; 0],
        builder_parameters: Self::CircuitBuilderParams,
    ) -> Self {
        const ROWS_TREE_IO: usize = row_tree::PublicInputs::<Target>::TOTAL_LEN;

        let extraction_verifier =
            RecursiveCircuitsVerifierGagdet::<F, C, D, { E::PI::TOTAL_LEN }>::new(
                default_config(),
                &builder_parameters.0,
            );
        let extraction_verifier = extraction_verifier.verify_proof_in_circuit_set(builder);
        let extraction_pi =
            extraction_verifier.get_public_input_targets::<F, { E::PI::TOTAL_LEN }>();

        let rows_tree_verifier = RecursiveCircuitsVerifierGagdet::<F, C, D, ROWS_TREE_IO>::new(
            default_config(),
            &builder_parameters.1,
        );
        let rows_tree_verifier = rows_tree_verifier.verify_proof_in_circuit_set(builder);
        let rows_tree_pi = rows_tree_verifier.get_public_input_targets::<F, ROWS_TREE_IO>();

        let parent_wires = ParentCircuit::build::<E>(builder, extraction_pi, rows_tree_pi);

        RecursiveParentWires {
            parent_wires,
            extraction_verifier,
            rows_tree_verifier,
            _e: PhantomData,
        }
    }

    fn assign_input(&self, inputs: Self::Inputs, pw: &mut PartialWitness<F>) -> Result<()> {
        inputs.witness.assign(pw, &self.parent_wires);

        let (proof, vd) = inputs.extraction_proof.into();
        self.extraction_verifier
            .set_target(pw, &inputs.extraction_set, &proof, &vd)?;

        let (proof, vd) = inputs.rows_tree_proof.into();
        self.rows_tree_verifier
            .set_target(pw, &inputs.rows_tree_set, &proof, &vd)
    }
}

#[cfg(test)]
mod tests {
    use crate::block_tree::{
        leaf::tests::{compute_expected_hash, compute_expected_set_digest},
        tests::{TestPIField, TestPITargets},
    };

    use super::{
        super::tests::{random_extraction_pi, random_rows_tree_pi},
        *,
    };
    use mp2_common::{
        poseidon::H,
        utils::{Fieldable, ToFields},
    };
    use mp2_test::{
        circuit::{run_circuit, UserCircuit},
        utils::random_vector,
    };
    use plonky2::{
        field::types::Sample, hash::hash_types::NUM_HASH_OUT_ELTS, plonk::config::Hasher,
    };
    use plonky2_ecgfp5::curve::curve::Point;
    use rand::{thread_rng, Rng};

    #[derive(Clone, Debug)]
    struct TestParentCircuit<'a> {
        c: ParentCircuit,
        extraction_pi: &'a [F],
        rows_tree_pi: &'a [F],
    }

    impl UserCircuit<F, D> for TestParentCircuit<'_> {
        // Parent node wires + extraction public inputs + rows tree public inputs
        type Wires = (ParentWires, Vec<Target>, Vec<Target>);

        fn build(b: &mut CBuilder) -> Self::Wires {
            let extraction_pi = b.add_virtual_targets(TestPITargets::TOTAL_LEN);
            let rows_tree_pi = b.add_virtual_targets(row_tree::PublicInputs::<Target>::TOTAL_LEN);

            let parent_wires =
                ParentCircuit::build::<TestPITargets>(b, &extraction_pi, &rows_tree_pi);

            (parent_wires, extraction_pi, rows_tree_pi)
        }

        fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
            self.c.assign(pw, &wires.0);

            assert_eq!(wires.1.len(), TestPITargets::TOTAL_LEN);
            pw.set_target_arr(&wires.1, self.extraction_pi);

            assert_eq!(wires.2.len(), row_tree::PublicInputs::<Target>::TOTAL_LEN);
            pw.set_target_arr(&wires.2, self.rows_tree_pi);
        }
    }

    #[test]
    fn test_block_index_parent_circuit() {
        let mut rng = thread_rng();

        let index_identifier = rng.gen::<u32>().to_field();
        let [old_index_value, old_min, old_max] =
            [0; 3].map(|_| U256::from_limbs(rng.gen::<[u64; 4]>()));
        let [left_child, right_child, old_rows_tree_hash] =
            [0; 3].map(|_| HashOut::from_vec(random_vector::<u32>(NUM_HASH_OUT_ELTS).to_fields()));

        let row_digest = Point::sample(&mut rng).to_weierstrass().to_fields();
        let extraction_pi =
            &random_extraction_pi(&mut rng, old_max + U256::from(1), &row_digest, true);
        let rows_tree_pi = &random_rows_tree_pi(&mut rng, &row_digest, true);

        let test_circuit = TestParentCircuit {
            c: ParentCircuit {
                index_identifier,
                old_index_value,
                old_min,
                old_max,
                old_left_child: left_child,
                old_right_child: right_child,
                old_rows_tree_hash,
            },
            extraction_pi,
            rows_tree_pi,
        };

        let proof = run_circuit::<F, D, C, _>(test_circuit);
        let pi = PublicInputs::from_slice(&proof.public_inputs);
        let extraction_pi = TestPIField::from_slice(extraction_pi);
        let rows_tree_pi = row_tree::PublicInputs::from_slice(rows_tree_pi);

        let empty_hash = empty_poseidon_hash().elements;
        let block_number = extraction_pi.block_number_raw();

        // Check old hash
        let h_old = {
            let inputs: Vec<_> = left_child
                .to_fields()
                .into_iter()
                .chain(right_child.to_fields())
                .chain(old_min.to_fields())
                .chain(old_max.to_fields())
                .chain(iter::once(index_identifier))
                .chain(old_index_value.to_fields())
                .chain(old_rows_tree_hash.to_fields())
                .collect();
            let exp_hash = H::hash_no_pad(&inputs).elements;

            assert_eq!(pi.h_old, exp_hash);

            exp_hash
        };
        // Check new hash
        {
            let inputs: Vec<_> = h_old
                .iter()
                .cloned()
                .chain(empty_hash)
                .chain(old_min.to_fields())
                .chain(block_number.iter().cloned())
                .chain(iter::once(index_identifier))
                .chain(block_number.iter().cloned())
                .chain(rows_tree_pi.h.iter().cloned())
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
            assert_eq!(pi.max, block_number);
        }
        // Check block number
        {
            assert_eq!(pi.block_number, block_number);
        }
        // Check block hash
        {
            assert_eq!(pi.block_hash, extraction_pi.block_hash_raw());
        }
        // Check previous block hash
        {
            assert_eq!(pi.prev_block_hash, extraction_pi.prev_block_hash_raw());
        }
        // Check metadata hash
        {
            let exp_hash = compute_expected_hash(&extraction_pi, index_identifier);

            assert_eq!(pi.metadata_hash, exp_hash.elements);
        }
        // Check new node digest
        {
            let exp_digest =
                compute_expected_set_digest(index_identifier, block_number.to_vec(), rows_tree_pi);

            assert_eq!(pi.new_value_set_digest_point(), exp_digest.to_weierstrass());
        }
    }
}
