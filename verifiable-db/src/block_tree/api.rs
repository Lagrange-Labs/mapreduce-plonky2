//! Block Index APIs

use crate::extraction::{ExtractionPI, ExtractionPIWrap};

use super::{
    leaf::{LeafCircuit, RecursiveLeafInput, RecursiveLeafWires},
    membership::{MembershipCircuit, MembershipWires},
    parent::{ParentCircuit, RecursiveParentInput, RecursiveParentWires},
    PublicInputs,
};
use alloy::primitives::U256;
use anyhow::Result;
use mp2_common::{default_config, poseidon::H, proof::ProofWithVK, types::HashOutput, C, D, F};
use plonky2::{
    field::types::Field,
    hash::hash_types::HashOut,
    plonk::config::{GenericHashOut, Hasher},
};
use recursion_framework::{
    circuit_builder::{CircuitWithUniversalVerifier, CircuitWithUniversalVerifierBuilder},
    framework::{prepare_recursive_circuit_for_circuit_set, RecursiveCircuits},
};
use serde::{Deserialize, Serialize};

/// CircuitInput is a wrapper around the different specialized circuits that can
/// be used to prove a node recursively.
#[derive(Serialize, Deserialize)]
pub enum CircuitInput {
    Leaf {
        witness: LeafCircuit,
        extraction_proof: Vec<u8>,
        rows_tree_proof: Vec<u8>,
    },
    Parent {
        witness: ParentCircuit,
        extraction_proof: Vec<u8>,
        rows_tree_proof: Vec<u8>,
    },
    Membership {
        witness: MembershipCircuit,
        right_child_proof: Vec<u8>,
    },
}

impl CircuitInput {
    /// Create a circuit input for proving a leaf node.
    pub fn new_leaf(block_id: u64, extraction_proof: Vec<u8>, rows_tree_proof: Vec<u8>) -> Self {
        Self::Leaf {
            witness: LeafCircuit {
                index_identifier: F::from_canonical_u64(block_id),
            },
            extraction_proof,
            rows_tree_proof,
        }
    }

    /// Create a circuit input for proving a parent node.
    #[allow(clippy::too_many_arguments)]
    pub fn new_parent(
        block_id: u64,
        old_block_number: U256,
        old_min: U256,
        old_max: U256,
        old_left_child: &HashOutput,
        old_right_child: &HashOutput,
        old_rows_tree_hash: &HashOutput,
        extraction_proof: Vec<u8>,
        rows_tree_proof: Vec<u8>,
    ) -> Self {
        CircuitInput::Parent {
            witness: ParentCircuit {
                index_identifier: F::from_canonical_u64(block_id),
                old_index_value: old_block_number,
                old_min,
                old_max,
                old_left_child: HashOut::<F>::from_bytes(old_left_child.into()),
                old_right_child: HashOut::<F>::from_bytes(old_right_child.into()),
                old_rows_tree_hash: HashOut::<F>::from_bytes(old_rows_tree_hash.into()),
            },
            extraction_proof,
            rows_tree_proof,
        }
    }

    /// Create a circuit input for proving a membership node of 1 child.
    pub fn new_membership(
        index_identifier: u64,
        index_value: U256,
        old_min: U256,
        old_max: U256,
        left_child: &HashOutput,
        rows_tree_hash: &HashOutput,
        right_child_proof: Vec<u8>,
    ) -> Self {
        CircuitInput::Membership {
            witness: MembershipCircuit {
                index_identifier: F::from_canonical_u64(index_identifier),
                index_value,
                old_min,
                old_max,
                left_child: HashOut::<F>::from_bytes(left_child.into()),
                rows_tree_hash: HashOut::<F>::from_bytes(rows_tree_hash.into()),
            },
            right_child_proof,
        }
    }
}

/// Main struct holding the different circuit parameters for each of the circuits defined here.
#[derive(Serialize, Deserialize)]
#[serde(bound = "")]
pub struct PublicParameters<E: ExtractionPIWrap>
where
    [(); E::PI::TOTAL_LEN]:,
{
    leaf: CircuitWithUniversalVerifier<F, C, D, 0, RecursiveLeafWires<E>>,
    parent: CircuitWithUniversalVerifier<F, C, D, 0, RecursiveParentWires<E>>,
    membership: CircuitWithUniversalVerifier<F, C, D, 1, MembershipWires>,
    set: RecursiveCircuits<F, C, D>,
}

const BLOCK_INDEX_IO_LEN: usize = PublicInputs::<F>::TOTAL_LEN;

/// Number of circuits in the set
/// 1 leaf + 1 parent + 1 membership
const CIRCUIT_SET_SIZE: usize = 3;

impl<E> PublicParameters<E>
where
    E: ExtractionPIWrap,
    [(); E::PI::TOTAL_LEN]:,
    [(); <H as Hasher<F>>::HASH_SIZE]:,
{
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

    pub fn set_vk(&self) -> &RecursiveCircuits<F, C, D> {
        &self.set
    }

    /// Generate the proof by the circuit input.
    /// The extraction set comes from the parameters of extracting the value, for example from the
    /// blockchain
    /// The row set comes from the parameters  used to generate the proofs at the row tree level
    pub fn generate_proof(
        &self,
        input: CircuitInput,
        extraction_set: &RecursiveCircuits<F, C, D>,
        row_set: &RecursiveCircuits<F, C, D>,
    ) -> Result<Vec<u8>> {
        match input {
            CircuitInput::Leaf {
                witness,
                extraction_proof,
                rows_tree_proof,
            } => self.generate_leaf_proof(
                witness,
                extraction_proof,
                rows_tree_proof,
                extraction_set,
                row_set,
            ),
            CircuitInput::Parent {
                witness,
                extraction_proof,
                rows_tree_proof,
            } => self.generate_parent_proof(
                witness,
                extraction_proof,
                rows_tree_proof,
                extraction_set,
                row_set,
            ),
            CircuitInput::Membership {
                witness,
                right_child_proof,
            } => self.generate_membership_proof(witness, right_child_proof),
        }
    }

    fn generate_leaf_proof(
        &self,
        witness: LeafCircuit,
        extraction_proof: Vec<u8>,
        rows_tree_proof: Vec<u8>,
        extraction_set: &RecursiveCircuits<F, C, D>,
        rows_tree_set: &RecursiveCircuits<F, C, D>,
    ) -> Result<Vec<u8>> {
        let extraction_proof = ProofWithVK::deserialize(&extraction_proof)?;
        let rows_tree_proof = ProofWithVK::deserialize(&rows_tree_proof)?;

        let leaf = RecursiveLeafInput {
            witness,
            extraction_proof,
            rows_tree_proof,
            extraction_set: extraction_set.clone(),
            rows_tree_set: rows_tree_set.clone(),
        };
        let proof = self.set.generate_proof(&self.leaf, [], [], leaf)?;
        ProofWithVK::from((proof, self.leaf.circuit_data().verifier_only.clone())).serialize()
    }

    fn generate_parent_proof(
        &self,
        witness: ParentCircuit,
        extraction_proof: Vec<u8>,
        rows_tree_proof: Vec<u8>,
        extraction_set: &RecursiveCircuits<F, C, D>,
        rows_tree_set: &RecursiveCircuits<F, C, D>,
    ) -> Result<Vec<u8>> {
        let extraction_proof = ProofWithVK::deserialize(&extraction_proof)?;
        let rows_tree_proof = ProofWithVK::deserialize(&rows_tree_proof)?;

        let parent = RecursiveParentInput {
            witness,
            extraction_proof,
            rows_tree_proof,
            extraction_set: extraction_set.clone(),
            rows_tree_set: rows_tree_set.clone(),
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
    use crate::{
        block_tree::{
            compute_final_digest,
            leaf::tests::{compute_expected_hash, compute_expected_set_digest},
        },
        extraction, row_tree,
    };
    use mp2_common::{
        poseidon::{empty_poseidon_hash, H},
        utils::{Fieldable, ToFields},
    };
    use mp2_test::utils::random_vector;
    use plonky2::{
        field::types::{PrimeField64, Sample},
        hash::hash_types::NUM_HASH_OUT_ELTS,
        iop::target::Target,
        plonk::config::Hasher,
    };
    use rand::{rngs::ThreadRng, thread_rng, Rng};
    use recursion_framework::framework_testing::TestingRecursiveCircuits;
    use std::iter;

    const EXTRACTION_IO_LEN: usize = extraction::test::PublicInputs::<F>::TOTAL_LEN;
    const ROWS_TREE_IO_LEN: usize = row_tree::PublicInputs::<F>::total_len();

    struct TestBuilder<E>
    where
        E: ExtractionPIWrap,
        [(); E::PI::TOTAL_LEN]:,
    {
        params: PublicParameters<E>,
        extraction_set: TestingRecursiveCircuits<F, C, D, EXTRACTION_IO_LEN>,
        rows_tree_set: TestingRecursiveCircuits<F, C, D, ROWS_TREE_IO_LEN>,
    }

    impl<E> TestBuilder<E>
    where
        E: ExtractionPIWrap,
        [(); E::PI::TOTAL_LEN]:,
        [(); <H as Hasher<F>>::HASH_SIZE]:,
    {
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
            is_merge_case: bool,
        ) -> Result<ProofWithVK> {
            let pi = random_extraction_pi(rng, block_number, value_digest, is_merge_case);

            let proof = self
                .extraction_set
                .generate_input_proofs::<1>([pi.try_into().unwrap()])?;
            let vk = self.extraction_set.verifier_data_for_input_proofs::<1>()[0].clone();
            Ok(ProofWithVK::from((proof[0].clone(), vk)))
        }

        fn generate_rows_tree_proof(
            &self,
            rng: &mut ThreadRng,
            is_merge_case: bool,
        ) -> Result<ProofWithVK> {
            let pi = random_rows_tree_pi(rng, is_merge_case);

            let proof = self
                .rows_tree_set
                .generate_input_proofs::<1>([pi.try_into().unwrap()])?;
            let vk = self.rows_tree_set.verifier_data_for_input_proofs::<1>()[0].clone();

            Ok(ProofWithVK::from((proof[0].clone(), vk)))
        }

        fn generate_leaf_proof(
            &self,
            rng: &mut ThreadRng,
            block_id: F,
            block_number: U256,
        ) -> Result<ProofWithVK> {
            let rows_tree_proof = self.generate_rows_tree_proof(rng, true)?;
            let rows_tree_pi =
                row_tree::PublicInputs::from_slice(&rows_tree_proof.proof.public_inputs);
            let final_digest = compute_final_digest(true, &rows_tree_pi)
                .to_weierstrass()
                .to_fields();
            let extraction_proof =
                self.generate_extraction_proof(rng, block_number, &final_digest, true)?;
            let extraction_pi =
                extraction::test::PublicInputs::from_slice(&extraction_proof.proof.public_inputs);

            let input = CircuitInput::new_leaf(
                block_id.to_canonical_u64(),
                extraction_proof.serialize()?,
                rows_tree_proof.serialize()?,
            );

            let proof = self.params.generate_proof(
                input,
                self.extraction_set.get_recursive_circuit_set(),
                self.rows_tree_set.get_recursive_circuit_set(),
            )?;
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
                let exp_hash = compute_expected_hash(&extraction_pi, block_id);
                assert_eq!(pi.metadata_hash, exp_hash.elements);
            }
            // Check new node digest
            {
                let exp_digest = compute_expected_set_digest(
                    true,
                    block_id,
                    block_number.to_vec(),
                    rows_tree_pi,
                );
                assert_eq!(pi.new_value_set_digest_point(), exp_digest.to_weierstrass());
            }

            Ok(proof)
        }

        #[allow(clippy::too_many_arguments)]
        fn generate_parent_proof(
            &self,
            rng: &mut ThreadRng,
            block_id: F,
            block_number: U256,
            old_block_number: U256,
            old_min: U256,
            old_max: U256,
            left_child: HashOut<F>,
            right_child: HashOut<F>,
        ) -> Result<ProofWithVK> {
            let rows_tree_proof = self.generate_rows_tree_proof(rng, false)?;
            let rows_tree_pi =
                row_tree::PublicInputs::from_slice(&rows_tree_proof.proof.public_inputs);
            let final_digest = compute_final_digest(false, &rows_tree_pi)
                .to_weierstrass()
                .to_fields();
            let extraction_proof =
                self.generate_extraction_proof(rng, block_number, &final_digest, false)?;
            let extraction_pi =
                extraction::test::PublicInputs::from_slice(&extraction_proof.proof.public_inputs);

            let old_rows_tree_hash =
                HashOut::from_vec(random_vector::<u32>(NUM_HASH_OUT_ELTS).to_fields());
            let input = CircuitInput::new_parent(
                block_id.to_canonical_u64(),
                old_block_number,
                old_min,
                old_max,
                &left_child.to_bytes().try_into().unwrap(),
                &right_child.to_bytes().try_into().unwrap(),
                &old_rows_tree_hash.to_bytes().try_into().unwrap(),
                extraction_proof.serialize()?,
                rows_tree_proof.serialize()?,
            );

            let proof = self.params.generate_proof(
                input,
                self.extraction_set.get_recursive_circuit_set(),
                self.rows_tree_set.get_recursive_circuit_set(),
            )?;
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
                let exp_hash = compute_expected_hash(&extraction_pi, block_id);
                assert_eq!(pi.metadata_hash, exp_hash.elements);
            }
            // Check new node digest
            {
                let exp_digest = compute_expected_set_digest(
                    false,
                    block_id,
                    block_number.to_vec(),
                    rows_tree_pi,
                );
                assert_eq!(pi.new_value_set_digest_point(), exp_digest.to_weierstrass());
            }

            Ok(proof)
        }

        fn generate_membership_proof(
            &self,
            index_identifier: F,
            index_number: U256,
            old_min: U256,
            old_max: U256,
            left_child: HashOut<F>,
            right_child_proof: ProofWithVK,
        ) -> Result<ProofWithVK> {
            let child_pi = PublicInputs::from_slice(&right_child_proof.proof.public_inputs);
            let right_child_proof = right_child_proof.serialize()?;

            let rows_tree_hash = HashOut::rand();
            let input = CircuitInput::new_membership(
                index_identifier.to_canonical_u64(),
                index_number,
                old_min,
                old_max,
                &left_child.to_bytes().try_into().unwrap(),
                &rows_tree_hash.to_bytes().try_into().unwrap(),
                right_child_proof,
            );

            let proof = self.params.generate_proof(
                input,
                self.extraction_set.get_recursive_circuit_set(),
                self.rows_tree_set.get_recursive_circuit_set(),
            )?;
            let proof = ProofWithVK::deserialize(&proof).unwrap();
            let pi = PublicInputs::from_slice(&proof.proof.public_inputs);

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
                    .chain(index_number.to_fields())
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
                    .chain(index_number.to_fields())
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

            Ok(proof)
        }
    }

    #[test]
    fn test_block_index_api() -> Result<()> {
        let b = TestBuilder::<crate::extraction::test::PublicInputs<Target>>::new()?;

        let mut rng = thread_rng();
        let block_id = rng.gen::<u32>().to_field();

        log::info!("Generating a dummy proof of left child");
        let block_number: U256 = U256::from(100);
        let left_child_pi =
            random_block_index_pi(&mut rng, block_number, block_number, block_number);
        let left_child_pi = PublicInputs::from_slice(&left_child_pi);

        log::info!("Generating a leaf proof of right child");
        let block_number = block_number + U256::from(1);
        let right_child_proof = b.generate_leaf_proof(&mut rng, block_id, block_number)?;
        let right_child_pi = PublicInputs::from_slice(&right_child_proof.proof.public_inputs);

        log::info!("Generating the parent proof");
        b.generate_parent_proof(
            &mut rng,
            block_id,
            block_number + U256::from(1),
            block_number,
            block_number,
            block_number,
            left_child_pi.new_merkle_hash_field(),
            right_child_pi.new_merkle_hash_field(),
        )?;

        log::info!("Generating the membership proof");
        b.generate_membership_proof(
            block_id,
            block_number - U256::from(1),
            block_number,
            block_number,
            left_child_pi.new_merkle_hash_field(),
            right_child_proof,
        )?;

        Ok(())
    }
}
