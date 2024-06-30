//! Block Index APIs

use super::{
    leaf::{LeafCircuit, RecursiveLeafInput, RecursiveLeafWires},
    membership::{MembershipCircuit, MembershipWires},
    parent::{ParentCircuit, RecursiveParentInput, RecursiveParentWires},
    PublicInputs,
};
use anyhow::Result;
use ethers::types::U256;
use mp2_common::{default_config, proof::ProofWithVK, C, D, F};
use plonky2::hash::hash_types::HashOut;
use recursion_framework::{
    circuit_builder::{CircuitWithUniversalVerifier, CircuitWithUniversalVerifierBuilder},
    framework::{prepare_recursive_circuit_for_circuit_set, RecursiveCircuits},
};
use serde::{Deserialize, Serialize};

/// A wrapper around the serialized proof and the corresponding circuit set.
type ProofWithCircuitSet = (Vec<u8>, RecursiveCircuits<F, C, D>);

/// CircuitInput is a wrapper around the different specialized circuits that can
/// be used to prove a node recursively.
#[derive(Serialize, Deserialize)]
pub enum CircuitInput {
    Leaf {
        witness: LeafCircuit,
        extraction_proof: ProofWithCircuitSet,
        rows_tree_proof: ProofWithCircuitSet,
    },
    Parent {
        witness: ParentCircuit,
        extraction_proof: ProofWithCircuitSet,
        rows_tree_proof: ProofWithCircuitSet,
    },
    Membership {
        witness: MembershipCircuit,
        right_child_proof: Vec<u8>,
    },
}

impl CircuitInput {
    /// Create a circuit input for proving a leaf node.
    pub fn new_leaf(
        block_id: F,
        extraction_proof: Vec<u8>,
        rows_tree_proof: Vec<u8>,
        extraction_circuit_set: &RecursiveCircuits<F, C, D>,
        rows_tree_circuit_set: &RecursiveCircuits<F, C, D>,
    ) -> Self {
        Self::Leaf {
            witness: LeafCircuit { block_id },
            extraction_proof: (extraction_proof, extraction_circuit_set.clone()),
            rows_tree_proof: (rows_tree_proof, rows_tree_circuit_set.clone()),
        }
    }

    /// Create a circuit input for proving a parent node.
    pub fn new_parent(
        block_id: F,
        old_block_number: U256,
        old_min: U256,
        old_max: U256,
        left_child: HashOut<F>,
        right_child: HashOut<F>,
        old_rows_tree_hash: HashOut<F>,
        extraction_proof: Vec<u8>,
        rows_tree_proof: Vec<u8>,
        extraction_circuit_set: &RecursiveCircuits<F, C, D>,
        rows_tree_circuit_set: &RecursiveCircuits<F, C, D>,
    ) -> Self {
        CircuitInput::Parent {
            witness: ParentCircuit {
                block_id,
                old_block_number,
                old_min,
                old_max,
                left_child,
                right_child,
                old_rows_tree_hash,
            },
            extraction_proof: (extraction_proof, extraction_circuit_set.clone()),
            rows_tree_proof: (rows_tree_proof, rows_tree_circuit_set.clone()),
        }
    }

    /// Create a circuit input for proving a membership node of 1 child.
    pub fn new_membership(
        block_id: F,
        block_number: U256,
        old_min: U256,
        old_max: U256,
        left_child: HashOut<F>,
        rows_tree_hash: HashOut<F>,
        right_child_proof: Vec<u8>,
    ) -> Self {
        CircuitInput::Membership {
            witness: MembershipCircuit {
                block_id,
                block_number,
                old_min,
                old_max,
                left_child,
                rows_tree_hash,
            },
            right_child_proof,
        }
    }
}

/// Main struct holding the different circuit parameters for each of the circuits defined here.
#[derive(Serialize, Deserialize)]
pub struct PublicParameters {
    leaf: CircuitWithUniversalVerifier<F, C, D, 0, RecursiveLeafWires>,
    parent: CircuitWithUniversalVerifier<F, C, D, 0, RecursiveParentWires>,
    membership: CircuitWithUniversalVerifier<F, C, D, 1, MembershipWires>,
    set: RecursiveCircuits<F, C, D>,
}

const BLOCK_INDEX_IO_LEN: usize = PublicInputs::<F>::TOTAL_LEN;

/// Number of circuits in the set
/// 1 leaf + 1 parent + 1 membership
const CIRCUIT_SET_SIZE: usize = 3;

impl PublicParameters {
    /// Generates the circuit parameters for the circuits.
    pub fn build(
        extraction_set: &RecursiveCircuits<F, C, D>,
        rows_tree_set: &RecursiveCircuits<F, C, D>,
    ) -> Self {
        let config = default_config();
        let builder = CircuitWithUniversalVerifierBuilder::<F, D, BLOCK_INDEX_IO_LEN>::new::<C>(
            config,
            CIRCUIT_SET_SIZE,
        );

        // Build the circuits.
        let leaf = builder.build_circuit((extraction_set.clone(), rows_tree_set.clone()));
        let parent = builder.build_circuit((extraction_set.clone(), rows_tree_set.clone()));
        let membership = builder.build_circuit(());

        // Build the circuit set.
        let circuits = vec![
            prepare_recursive_circuit_for_circuit_set(&leaf),
            prepare_recursive_circuit_for_circuit_set(&parent),
            prepare_recursive_circuit_for_circuit_set(&membership),
        ];
        let set = RecursiveCircuits::<F, C, D>::new(circuits);

        PublicParameters {
            leaf,
            parent,
            membership,
            set,
        }
    }

    /// Generate the proof by the circuit input.
    pub fn generate_proof(&self, input: CircuitInput) -> Result<Vec<u8>> {
        match input {
            CircuitInput::Leaf {
                witness,
                extraction_proof,
                rows_tree_proof,
            } => self.generate_leaf_proof(witness, extraction_proof, rows_tree_proof),
            CircuitInput::Parent {
                witness,
                extraction_proof,
                rows_tree_proof,
            } => self.generate_parent_proof(witness, extraction_proof, rows_tree_proof),
            CircuitInput::Membership {
                witness,
                right_child_proof,
            } => self.generate_membership_proof(witness, right_child_proof),
        }
    }

    fn generate_leaf_proof(
        &self,
        witness: LeafCircuit,
        extraction_proof: ProofWithCircuitSet,
        rows_tree_proof: ProofWithCircuitSet,
    ) -> Result<Vec<u8>> {
        let (proof, extraction_set) = extraction_proof;
        let extraction_proof = ProofWithVK::deserialize(&proof)?;
        let (proof, rows_tree_set) = rows_tree_proof;
        let rows_tree_proof = ProofWithVK::deserialize(&proof)?;

        let leaf = RecursiveLeafInput {
            witness,
            extraction_proof,
            rows_tree_proof,
            extraction_set,
            rows_tree_set,
        };
        let proof = self.set.generate_proof(&self.leaf, [], [], leaf)?;
        ProofWithVK::from((proof, self.leaf.circuit_data().verifier_only.clone())).serialize()
    }

    fn generate_parent_proof(
        &self,
        witness: ParentCircuit,
        extraction_proof: ProofWithCircuitSet,
        rows_tree_proof: ProofWithCircuitSet,
    ) -> Result<Vec<u8>> {
        let (proof, extraction_set) = extraction_proof;
        let extraction_proof = ProofWithVK::deserialize(&proof)?;
        let (proof, rows_tree_set) = rows_tree_proof;
        let rows_tree_proof = ProofWithVK::deserialize(&proof)?;

        let parent = RecursiveParentInput {
            witness,
            extraction_proof,
            rows_tree_proof,
            extraction_set,
            rows_tree_set,
        };
        let proof = self.set.generate_proof(&self.parent, [], [], parent)?;
        ProofWithVK::from((proof, self.parent.circuit_data().verifier_only.clone())).serialize()
    }

    fn generate_membership_proof(
        &self,
        witness: MembershipCircuit,
        child_proof: Vec<u8>,
    ) -> Result<Vec<u8>> {
        let (child_proof, child_vk) = ProofWithVK::deserialize(&child_proof)?.into();
        let proof =
            self.set
                .generate_proof(&self.membership, [child_proof], [&child_vk], witness)?;
        ProofWithVK::from((proof, self.membership.circuit_data().verifier_only.clone())).serialize()
    }
}

#[cfg(test)]
mod tests {
    use super::{
        super::{
            tests::{random_block_index_pi, random_extraction_pi, random_rows_tree_pi},
            PublicInputs,
        },
        *,
    };
    use crate::row_tree;
    use mp2_common::{
        poseidon::{empty_poseidon_hash, hash_to_int_value, H},
        utils::{Fieldable, ToFields},
    };
    use mp2_test::utils::random_vector;
    use mp2_v1::final_extraction;
    use plonky2::{
        field::types::{Field, Sample},
        hash::hash_types::NUM_HASH_OUT_ELTS,
        plonk::{
            circuit_data::VerifierOnlyCircuitData, config::Hasher, proof::ProofWithPublicInputs,
        },
    };
    use plonky2_ecgfp5::curve::{curve::Point, scalar_field::Scalar};
    use rand::{rngs::ThreadRng, thread_rng, Rng};
    use recursion_framework::framework_testing::TestingRecursiveCircuits;
    use std::iter;

    const EXTRACTION_IO_LEN: usize = final_extraction::PublicInputs::<F>::TOTAL_LEN;
    const ROWS_TREE_IO_LEN: usize = row_tree::PublicInputs::<F>::TOTAL_LEN;

    struct TestBuilder {
        params: PublicParameters,
        extraction_set: TestingRecursiveCircuits<F, C, D, EXTRACTION_IO_LEN>,
        rows_tree_set: TestingRecursiveCircuits<F, C, D, ROWS_TREE_IO_LEN>,
    }

    impl TestBuilder {
        fn new() -> Result<Self> {
            let extraction_set = TestingRecursiveCircuits::<F, C, D, EXTRACTION_IO_LEN>::default();
            let rows_tree_set = TestingRecursiveCircuits::<F, C, D, ROWS_TREE_IO_LEN>::default();
            let params = PublicParameters::build(
                extraction_set.get_recursive_circuit_set(),
                rows_tree_set.get_recursive_circuit_set(),
            );

            Ok(Self {
                params,
                extraction_set,
                rows_tree_set,
            })
        }

        fn generate_extraction_proof(
            &self,
            rng: &mut ThreadRng,
            block_number: U256,
            value_digest: &[F],
        ) -> Result<ProofWithVK> {
            let pi = random_extraction_pi(rng, block_number, &value_digest);

            let proof = self
                .extraction_set
                .generate_input_proofs::<1>([pi.try_into().unwrap()])?;
            let vk = self.extraction_set.verifier_data_for_input_proofs::<1>()[0].clone();
            Ok(ProofWithVK::from((proof[0].clone(), vk)))
        }

        fn generate_rows_tree_proof(
            &self,
            rng: &mut ThreadRng,
            row_digest: &[F],
        ) -> Result<ProofWithVK> {
            let pi = random_rows_tree_pi(rng, &row_digest);

            let proof = self
                .rows_tree_set
                .generate_input_proofs::<1>([pi.try_into().unwrap()])?;
            let vk = self.rows_tree_set.verifier_data_for_input_proofs::<1>()[0].clone();

            Ok(ProofWithVK::from((proof[0].clone(), vk)))
        }
    }

    #[test]
    fn test_block_index_api() -> Result<()> {
        let b = TestBuilder::new()?;

        let mut rng = thread_rng();
        let block_id = rng.gen::<u32>().to_field();

        log::info!("Generating a dummy proof of left child");
        let block_number = 100.into();
        let left_child_pi =
            random_block_index_pi(&mut rng, block_number, block_number, block_number);
        let left_child_pi = PublicInputs::from_slice(&left_child_pi);

        log::info!("Generating a leaf proof of right child");
        let block_number = block_number + 1;
        let right_child_proof = generate_leaf_proof(&b, &mut rng, block_id, block_number)?;
        let right_child_pi = PublicInputs::from_slice(&right_child_proof.proof.public_inputs);

        log::info!("Generating the parent proof");
        generate_parent_proof(
            &b,
            &mut rng,
            block_id,
            block_number + 1,
            block_number,
            block_number,
            block_number,
            left_child_pi.new_hash_value(),
            right_child_pi.new_hash_value(),
        )?;

        log::info!("Generating the membership proof");
        generate_membership_proof(
            &b,
            &mut rng,
            block_id,
            block_number - 1,
            block_number,
            block_number,
            left_child_pi.new_hash_value(),
            right_child_proof,
        )?;

        Ok(())
    }

    fn generate_leaf_proof(
        b: &TestBuilder,
        rng: &mut ThreadRng,
        block_id: F,
        block_number: U256,
    ) -> Result<ProofWithVK> {
        let row_digest = Point::sample(rng).to_weierstrass().to_fields();
        let extraction_proof = b.generate_extraction_proof(rng, block_number, &row_digest)?;
        let rows_tree_proof = b.generate_rows_tree_proof(rng, &row_digest)?;
        let extraction_pi =
            final_extraction::PublicInputs::from_slice(&extraction_proof.proof.public_inputs);
        let rows_tree_pi = row_tree::PublicInputs::from_slice(&rows_tree_proof.proof.public_inputs);

        let input = CircuitInput::new_leaf(
            block_id,
            extraction_proof.serialize()?,
            rows_tree_proof.serialize()?,
            b.extraction_set.get_recursive_circuit_set(),
            b.rows_tree_set.get_recursive_circuit_set(),
        );

        let proof = b.params.generate_proof(input)?;
        let proof = ProofWithVK::deserialize(&proof).unwrap();
        let pi = PublicInputs::from_slice(&proof.proof.public_inputs);

        let empty_hash = empty_poseidon_hash();
        let block_number = extraction_pi.block_number_raw();

        // Check new hash
        {
            let inputs: Vec<_> = empty_hash
                .elements
                .iter()
                .chain(empty_hash.elements.iter())
                .chain(block_number) // node_min
                .chain(block_number) // node_max
                .chain(iter::once(&block_id))
                .chain(block_number)
                .chain(rows_tree_pi.h)
                .cloned()
                .collect();
            let exp_hash = H::hash_no_pad(&inputs);

            assert_eq!(pi.h_new, exp_hash.elements);
        }
        // Check old hash
        {
            assert_eq!(pi.h_old, empty_hash.elements);
        }
        // Check minimum block number
        {
            assert_eq!(pi.min, block_number);
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
            let inputs: Vec<_> = extraction_pi
                .digest_metadata_raw()
                .iter()
                .cloned()
                .chain(iter::once(block_id))
                .collect();
            let exp_hash = H::hash_no_pad(&inputs);

            assert_eq!(pi.m, exp_hash.elements);
        }
        // Check new node digest
        {
            let inputs: Vec<_> = iter::once(block_id)
                .chain(block_number.iter().cloned())
                .collect();
            let hash = H::hash_no_pad(&inputs);
            let int = hash_to_int_value(hash);
            let scalar = Scalar::from_noncanonical_biguint(int);
            let point = rows_tree_pi.rows_digest_field();
            let point = Point::decode(point.encode()).unwrap();
            let exp_digest = point * scalar;

            assert_eq!(pi.new_node_digest_point(), exp_digest.to_weierstrass());
        }

        Ok(proof)
    }

    fn generate_parent_proof(
        b: &TestBuilder,
        rng: &mut ThreadRng,
        block_id: F,
        block_number: U256,
        old_block_number: U256,
        old_min: U256,
        old_max: U256,
        left_child: HashOut<F>,
        right_child: HashOut<F>,
    ) -> Result<ProofWithVK> {
        let row_digest = Point::sample(rng).to_weierstrass().to_fields();
        let extraction_proof = b.generate_extraction_proof(rng, block_number, &row_digest)?;
        let rows_tree_proof = b.generate_rows_tree_proof(rng, &row_digest)?;
        let extraction_pi =
            final_extraction::PublicInputs::from_slice(&extraction_proof.proof.public_inputs);
        let rows_tree_pi = row_tree::PublicInputs::from_slice(&rows_tree_proof.proof.public_inputs);

        let old_rows_tree_hash =
            HashOut::from_vec(random_vector::<u32>(NUM_HASH_OUT_ELTS).to_fields());
        let input = CircuitInput::new_parent(
            block_id,
            old_block_number,
            old_min,
            old_max,
            left_child,
            right_child,
            old_rows_tree_hash,
            extraction_proof.serialize()?,
            rows_tree_proof.serialize()?,
            b.extraction_set.get_recursive_circuit_set(),
            b.rows_tree_set.get_recursive_circuit_set(),
        );

        let proof = b.params.generate_proof(input)?;
        let proof = ProofWithVK::deserialize(&proof).unwrap();
        let pi = PublicInputs::from_slice(&proof.proof.public_inputs);

        let empty_hash = empty_poseidon_hash().elements;
        let block_number = extraction_pi.block_number_raw();

        // Check old hash
        let h_old = {
            let inputs: Vec<_> = left_child
                .elements
                .into_iter()
                .chain(right_child.elements)
                .chain(old_min.to_fields())
                .chain(old_max.to_fields())
                .chain(iter::once(block_id))
                .chain(old_block_number.to_fields())
                .chain(old_rows_tree_hash.elements)
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
                .chain(iter::once(block_id))
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
            let inputs: Vec<_> = extraction_pi
                .digest_metadata_raw()
                .iter()
                .cloned()
                .chain(iter::once(block_id))
                .collect();
            let exp_hash = H::hash_no_pad(&inputs);

            assert_eq!(pi.m, exp_hash.elements);
        }
        // Check new node digest
        {
            let inputs: Vec<_> = iter::once(block_id)
                .chain(block_number.iter().cloned())
                .collect();
            let hash = H::hash_no_pad(&inputs);
            let int = hash_to_int_value(hash);
            let scalar = Scalar::from_noncanonical_biguint(int);
            let point = rows_tree_pi.rows_digest_field();
            let point = Point::decode(point.encode()).unwrap();
            let exp_digest = point * scalar;

            assert_eq!(pi.new_node_digest_point(), exp_digest.to_weierstrass());
        }

        Ok(proof)
    }

    fn generate_membership_proof(
        b: &TestBuilder,
        rng: &mut ThreadRng,
        block_id: F,
        block_number: U256,
        old_min: U256,
        old_max: U256,
        left_child: HashOut<F>,
        right_child_proof: ProofWithVK,
    ) -> Result<ProofWithVK> {
        let child_pi = PublicInputs::from_slice(&right_child_proof.proof.public_inputs);
        let right_child_proof = right_child_proof.serialize()?;

        let rows_tree_hash = HashOut::from_vec(random_vector::<u32>(NUM_HASH_OUT_ELTS).to_fields());
        let input = CircuitInput::new_membership(
            block_id,
            block_number,
            old_min,
            old_max,
            left_child,
            rows_tree_hash,
            right_child_proof,
        );

        let proof = b.params.generate_proof(input)?;
        let proof = ProofWithVK::deserialize(&proof).unwrap();
        let pi = PublicInputs::from_slice(&proof.proof.public_inputs);

        // Check old hash
        {
            let inputs: Vec<_> = left_child
                .elements
                .iter()
                .chain(child_pi.h_old)
                .cloned()
                .chain(old_min.to_fields())
                .chain(old_max.to_fields())
                .chain(iter::once(block_id))
                .chain(block_number.to_fields())
                .chain(rows_tree_hash.elements)
                .collect();
            let exp_hash = H::hash_no_pad(&inputs).elements;

            assert_eq!(pi.h_old, exp_hash);

            exp_hash
        };
        // Check new hash
        {
            let inputs: Vec<_> = left_child
                .elements
                .iter()
                .chain(child_pi.h_new)
                .cloned()
                .chain(old_min.to_fields())
                .chain(child_pi.max.iter().cloned())
                .chain(iter::once(block_id))
                .chain(block_number.to_fields())
                .chain(rows_tree_hash.elements)
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
            assert_eq!(pi.m, child_pi.m);
        }
        // Check new node digest
        {
            assert_eq!(pi.new_node_digest, child_pi.new_node_digest);
        }

        Ok(proof)
    }
}
