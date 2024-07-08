use anyhow::Result;
use mp2_common::{default_config, proof::ProofWithVK, C, D, F};
use plonky2::hash::hash_types::HashOut;
use recursion_framework::{
    circuit_builder::{CircuitWithUniversalVerifier, CircuitWithUniversalVerifierBuilder},
    framework::{prepare_recursive_circuit_for_circuit_set, RecursiveCircuits},
};
use serde::{Deserialize, Serialize};

use super::circuit::{DummyCircuit, DummyWires, RecursiveIVCInput, RecursiveIVCWires};

pub enum CircuitInput {
    FirstProof {
        dummy: DummyCircuit,
        block_proof: Vec<u8>,
    },
    SubsequentProof {
        block_proof: Vec<u8>,
        prev_proof: Vec<u8>,
    },
}

impl CircuitInput {
    pub fn new_first_input(block_proof: Vec<u8>) -> Result<Self> {
        let p = ProofWithVK::deserialize(&block_proof)?;
        let pi = crate::block_tree::PublicInputs::<F>::from_slice(&p.proof.public_inputs);
        let block_hash = pi.prev_block_hash_fields();
        let md = pi.metadata_hash();
        let z0 = pi.min_block_number()?;
        Ok(Self::FirstProof {
            dummy: DummyCircuit {
                block_hash,
                metadata_hash: HashOut::try_from(md)?,
                z0,
            },
            block_proof,
        })
    }

    pub fn new_subsequent_input(block_proof: Vec<u8>, prev_proof: Vec<u8>) -> Result<Self> {
        Ok(Self::SubsequentProof {
            block_proof,
            prev_proof,
        })
    }
}

#[derive(Serialize, Deserialize)]
pub struct PublicParameters {
    ivc: CircuitWithUniversalVerifier<F, C, D, 1, RecursiveIVCWires>,
    dummy: CircuitWithUniversalVerifier<F, C, D, 0, DummyWires>,
    set: RecursiveCircuits<F, C, D>,
}

impl PublicParameters {
    pub fn build(block_set: &RecursiveCircuits<F, C, D>) -> PublicParameters {
        let config = default_config();
        const CIRCUIT_SET_SIZE: usize = 2;
        const IVC_NUM_IO: usize = super::NUM_IO;
        let builder = CircuitWithUniversalVerifierBuilder::<F, D, IVC_NUM_IO>::new::<C>(
            config,
            CIRCUIT_SET_SIZE,
        );
        let ivc = builder.build_circuit(block_set.clone());
        let dummy = builder.build_circuit(());
        let circuits = vec![
            prepare_recursive_circuit_for_circuit_set(&ivc),
            prepare_recursive_circuit_for_circuit_set(&dummy),
        ];
        let set = RecursiveCircuits::<F, C, D>::new(circuits);
        PublicParameters { dummy, ivc, set }
    }

    pub fn generate_proof(
        &self,
        input: CircuitInput,
        block_set: &RecursiveCircuits<F, C, D>,
    ) -> Result<Vec<u8>> {
        let (prev_proof, vd, block_proof) = match input {
            CircuitInput::FirstProof { dummy, block_proof } => {
                let dummy_proof = self.set.generate_proof(&self.dummy, [], [], dummy)?;
                (
                    dummy_proof,
                    self.dummy.circuit_data().verifier_only.clone(),
                    block_proof,
                )
            }
            CircuitInput::SubsequentProof {
                block_proof,
                prev_proof,
            } => {
                let prev_proof = ProofWithVK::deserialize(&prev_proof)?;
                (
                    prev_proof.proof,
                    self.ivc.circuit_data().verifier_only.clone(),
                    block_proof,
                )
            }
        };
        let block_proof = ProofWithVK::deserialize(&block_proof)?;
        let input = RecursiveIVCInput {
            block_proof,
            block_set: block_set.clone(),
        };
        let proof = self
            .set
            .generate_proof(&self.ivc, [prev_proof], [&vd], input)?;
        ProofWithVK::from((proof, self.ivc.circuit_data().verifier_only.clone())).serialize()
    }
}

#[cfg(test)]
mod test {

    use super::*;
    use anyhow::Result;
    use ethers::types::U256;
    use mp2_common::{
        keccak::PACKED_HASH_LEN,
        poseidon::empty_poseidon_hash,
        utils::{FromFields, ToFields},
        C, D, F,
    };
    use mp2_test::utils::random_vector;
    use plonky2::field::types::Sample;
    use plonky2_ecgfp5::curve::curve::Point;
    use rand::{thread_rng, Rng};
    use recursion_framework::framework_testing::TestingRecursiveCircuits;

    use crate::ivc::circuit::BLOCK_IO;

    #[test]
    fn ivc_api() -> Result<()> {
        let block_set = TestingRecursiveCircuits::<F, C, D, BLOCK_IO>::default();
        let params = PublicParameters::build(block_set.get_recursive_circuit_set());

        let first_block_number = U256(thread_rng().gen::<[u64; 4]>());
        let min = first_block_number;
        let max = first_block_number;
        let block_number = first_block_number;
        // can't use "random_block_index_pi" here since we need to generate an empty hash and empty
        // digest
        let h_old = empty_poseidon_hash().to_fields();
        let h_new = HashOut::<F>::rand().to_fields();
        let metadata_set_hash = HashOut::<F>::rand().to_fields();
        let value_digest = Point::rand().to_fields();
        let [minf, maxf, bnf] = [min, max, block_number].map(|u| u.to_fields());
        let [block_hash, prev_block_hash] =
            [0; 2].map(|_| random_vector::<u32>(PACKED_HASH_LEN).to_fields());
        let first_block_pi = crate::block_tree::PublicInputs::new(
            &h_new,
            &h_old,
            &minf,
            &maxf,
            &bnf,
            &block_hash,
            &prev_block_hash,
            &metadata_set_hash,
            &value_digest,
        )
        .to_vec();
        println!("generating random block proof");
        let first_block_proof =
            block_set.generate_input_proofs::<1>([first_block_pi.clone().try_into().unwrap()])?;
        let first_block_proof = ProofWithVK::from((
            first_block_proof[0].clone(),
            block_set.verifier_data_for_input_proofs::<1>()[0].clone(),
        ));
        let input = CircuitInput::new_first_input(first_block_proof.serialize()?)?;
        println!("generating first ivc proof");
        let first_ivc_proof_buff =
            params.generate_proof(input, block_set.get_recursive_circuit_set())?;
        println!("checking first ivc proof");
        let (first_ivc_proof, _) = ProofWithVK::deserialize(&first_ivc_proof_buff)?.into();
        {
            let block_pi = crate::block_tree::PublicInputs::from_slice(&first_block_pi);
            let ivc_pi = crate::ivc::PublicInputs::<F>::from_slice(&first_ivc_proof.public_inputs);
            assert_eq!(
                ivc_pi.merkle_root_hash_fields(),
                block_pi.new_merkle_hash_field(),
            );
            assert_eq!(ivc_pi.metadata_hash(), block_pi.metadata_hash(),);
            // same value digest
            assert_eq!(
                ivc_pi.value_set_digest_point(),
                block_pi.new_value_set_digest_point(),
            );
            assert_eq!(ivc_pi.z0_u256(), min);
            assert_eq!(ivc_pi.zi_u256(), min);
            assert_eq!(ivc_pi.block_hash_fields(), block_pi.block_hash());
        }

        println!("Generating second block proof");
        let h_old = h_new;
        let h_new = HashOut::<F>::rand().to_fields();
        let next_block_number = (first_block_number + U256::one()).to_fields();
        let prev_block_hash = block_hash;
        let next_block_hash = random_vector::<u32>(PACKED_HASH_LEN).to_fields();
        let next_value_digest = Point::rand().to_fields();

        let second_block_pi = crate::block_tree::PublicInputs::new(
            &h_new,
            &h_old,
            &minf,
            &next_block_number,
            &next_block_number,
            &next_block_hash,
            &prev_block_hash,
            &metadata_set_hash,
            &next_value_digest,
        )
        .to_vec();
        let second_block_proof =
            block_set.generate_input_proofs::<1>([second_block_pi.clone().try_into().unwrap()])?;
        let second_block_proof = ProofWithVK::from((
            second_block_proof[0].clone(),
            block_set.verifier_data_for_input_proofs::<1>()[0].clone(),
        ));
        println!("Generating second IVC proof");
        let second_input = CircuitInput::new_subsequent_input(
            second_block_proof.serialize()?,
            first_ivc_proof_buff,
        )?;
        let second_ivc_proof =
            params.generate_proof(second_input, block_set.get_recursive_circuit_set())?;
        let (second_ivc_proof, _) = ProofWithVK::deserialize(&second_ivc_proof)?.into();
        {
            let block_pi = crate::block_tree::PublicInputs::from_slice(&second_block_pi);
            let ivc_pi = crate::ivc::PublicInputs::<F>::from_slice(&second_ivc_proof.public_inputs);
            assert_eq!(
                ivc_pi.merkle_root_hash_fields(),
                block_pi.new_merkle_hash_field(),
            );
            assert_eq!(ivc_pi.metadata_hash(), block_pi.metadata_hash(),);
            // the two digest should be added together from first proof
            let exp_digest =
                Point::from_fields(&next_value_digest) + Point::from_fields(&value_digest);
            assert_eq!(ivc_pi.value_set_digest_point(), exp_digest.to_weierstrass(),);
            assert_eq!(ivc_pi.z0_u256(), min);
            assert_eq!(ivc_pi.zi_u256(), U256::from_fields(&next_block_number));
            assert_eq!(ivc_pi.block_hash_fields(), block_pi.block_hash());
        }
        Ok(())
    }
}
