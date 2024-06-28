use anyhow::{bail, Result};
use ethers::types::U256;
use mp2_common::{default_config, proof::ProofWithVK, C, D, F};
use recursion_framework::{
    circuit_builder::{CircuitWithUniversalVerifier, CircuitWithUniversalVerifierBuilder},
    framework::{prepare_recursive_circuit_for_circuit_set, RecursiveCircuits},
};

use crate::cells_tree;

use super::{
    full_node::FullNodeCircuit,
    leaf::{self, LeafCircuit},
    partial_node::PartialNodeCircuit,
    IndexTuple,
};

pub struct Parameters {
    leaf: CircuitWithUniversalVerifier<F, C, D, 0, leaf::RecursiveLeafWires>,
    row_set: RecursiveCircuits<F, C, D>,
}

const ROW_IO_LEN: usize = super::public_inputs::TOTAL_LEN;
const CELL_IO_LEN: usize = cells_tree::PublicInputs::<F>::TOTAL_LEN;

impl Parameters {
    pub fn build(cells_set: &RecursiveCircuits<F, C, D>) -> Self {
        // TODO
        const ROW_CIRCUIT_SET_SIZE: usize = 2;
        let builder = CircuitWithUniversalVerifierBuilder::<F, D, ROW_IO_LEN>::new::<C>(
            default_config(),
            ROW_CIRCUIT_SET_SIZE,
        );

        let leaf_circuit = builder.build_circuit(cells_set.clone());
        let circuits = vec![prepare_recursive_circuit_for_circuit_set(&leaf_circuit)];
        let circuit_set = RecursiveCircuits::<F, C, D>::new(circuits);
        Self {
            leaf: leaf_circuit,
            row_set: circuit_set,
        }
    }

    pub fn generate_proof(&self, input: CircuitInput) -> Result<Vec<u8>> {
        match input {
            CircuitInput::Leaf {
                witness,
                cells_proof,
                cells_set,
            } => self.generate_leaf_proof(witness, cells_proof, cells_set),
            _ => bail!("unsupported yet"),
        }
    }

    fn generate_leaf_proof(
        &self,
        witness: LeafCircuit,
        cells_proof: Vec<u8>,
        cells_set: RecursiveCircuits<F, C, D>,
    ) -> Result<Vec<u8>> {
        let cells_proof = ProofWithVK::deserialize(&cells_proof)?;
        let leaf = leaf::RecursiveLeafInput {
            witness,
            cells_proof,
            cells_set,
        };
        let proof = self.row_set.generate_proof(&self.leaf, [], [], leaf)?;
        ProofWithVK::new(proof, self.leaf.circuit_data().verifier_only.clone()).serialize()
    }
}

/// Enum holding all the inputs necessary to generate
/// rows tree related proofs
enum CircuitInput {
    Leaf {
        witness: leaf::LeafCircuit,
        cells_proof: Vec<u8>,
        cells_set: RecursiveCircuits<F, C, D>,
    },
    //Full(FullNodeInput),
    //Partial(PartialNodeCircuit),
}

impl CircuitInput {
    fn leaf(
        identifier: F,
        value: U256,
        cells_proof: Vec<u8>,
        cells_set: &RecursiveCircuits<F, C, D>,
    ) -> Result<Self> {
        let circuit = LeafCircuit::new(IndexTuple::new(identifier, value));
        Ok(CircuitInput::Leaf {
            witness: circuit,
            cells_proof,
            cells_set: cells_set.clone(),
        })
    }
    //pub fn full(
    //    identifier: F,
    //    value: U256,
    //    left_proof: Vec<u8>,
    //    right_proof: Vec<u8>,
    //    cells_proof: Vec<u8>,
    //) -> Result<Self> {
    //    let left = ProofWithVK::deserialize(&left_proof)?;
    //    let right = ProofWithVK::deserialize(&right_proof)?;
    //    let cells = ProofWithVK::deserialize(&cells_proof)?;
    //    let circuit = FullNodeCircuit::from(IndexTuple::new(identifier, value));
    //    Ok(CircuitInput::Full(FullNodeInput {
    //        witness: circuit,
    //        left,
    //        right,
    //        cells,
    //    }))
    //}
    //pub fn partial(
    //    identifier: F,
    //    value: U256,
    //    is_child_left: bool,
    //    child_proof: Vec<u8>,
    //    cells_proof: Vec<u8>,
    //) -> Result<Self> {
    //    let child = ProofWithVK::deserialize(&child_proof)?;
    //    let cells = ProofWithVK::deserialize(&cells_proof)?;
    //    let tuple = IndexTuple::new(identifier, value);
    //    let witness = PartialNodeCircuit::new(tuple, is_child_left);
    //    Ok(CircuitInput::Partial(PartialNodeInput {
    //        witness,
    //        child,
    //        cells,
    //    }))
    //}
}

pub struct FullNodeInput {
    witness: FullNodeCircuit,
    left: ProofWithVK,
    right: ProofWithVK,
    cells: ProofWithVK,
}

pub struct PartialNodeInput {
    witness: PartialNodeCircuit,
    child: ProofWithVK,
    cells: ProofWithVK,
}

#[cfg(test)]
mod test {
    use crate::row_tree::public_inputs::PublicInputs;

    use super::*;
    use mp2_common::{
        group_hashing::map_to_curve_point,
        poseidon::{empty_poseidon_hash, H},
        utils::ToFields,
        F,
    };
    use plonky2::{field::types::Sample, hash::hash_types::HashOut, plonk::config::Hasher};
    use plonky2_ecgfp5::curve::curve::Point;
    use rand::{thread_rng, Rng};
    use recursion_framework::framework_testing::TestingRecursiveCircuits;

    #[test]
    fn test_recursive_leaf_generation() -> Result<()> {
        let testing_framework = TestingRecursiveCircuits::<F, C, D, CELL_IO_LEN>::default();
        let params = Parameters::build(testing_framework.get_recursive_circuit_set());

        // generate row tree leaf input
        let mut rng = thread_rng();
        let value = U256::from(rng.gen::<[u8; 32]>());
        let identifier = F::rand();

        // generate cells tree input and fake proof
        let cells_hash = HashOut::rand().to_fields();
        let cells_digest = Point::rand().to_weierstrass().to_fields();
        let cells_pi = cells_tree::PublicInputs::new(&cells_hash, &cells_digest).to_vec();

        let cells_proof =
            testing_framework.generate_input_proofs::<1>([cells_pi.clone().try_into().unwrap()])?;
        let cells_proof_vk = ProofWithVK::new(
            cells_proof[0].clone(),
            testing_framework.verifier_data_for_input_proofs::<1>()[0].clone(),
        );
        let cells_pi = cells_tree::PublicInputs::from_slice(&cells_pi);
        //  generate row leaf proof
        let input = CircuitInput::leaf(
            identifier,
            value,
            cells_proof_vk.serialize()?,
            testing_framework.get_recursive_circuit_set(),
        )?;

        let proof = params.generate_proof(input)?;
        let pi = ProofWithVK::deserialize(&proof)
            .unwrap()
            .proof
            .public_inputs;
        let pi = PublicInputs::from_slice(&pi);
        let tuple = IndexTuple::new(identifier, value);
        {
            let empty_hash = empty_poseidon_hash();
            // H(left_child_hash,right_child_hash,min,max,index_identifier,index_value,cells_tree_hash)
            let inputs: Vec<_> = empty_hash
                .to_fields()
                .iter()
                .chain(empty_hash.to_fields().iter())
                .chain(tuple.index_value.to_fields().iter())
                .chain(tuple.index_value.to_fields().iter())
                .chain(tuple.to_fields().iter())
                .chain(cells_pi.h_raw().iter())
                .cloned()
                .collect();
            let exp_hash = H::hash_no_pad(&inputs);
            assert_eq!(pi.root_hash_hashout(), exp_hash);
        }
        {
            let inner = map_to_curve_point(&tuple.to_fields());
            let cells_point = Point::decode(cells_pi.digest_point().encode()).unwrap();
            assert_eq!(
                cells_point.to_weierstrass().to_fields(),
                cells_pi.digest_point().to_fields()
            );
            let result_inner = inner + cells_point;
            let result = map_to_curve_point(&result_inner.to_weierstrass().to_fields());
            assert_eq!(pi.rows_digest_field(), result.to_weierstrass());
        }
        Ok(())
    }
}
