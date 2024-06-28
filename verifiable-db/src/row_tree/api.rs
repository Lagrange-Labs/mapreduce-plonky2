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
    use super::*;
    use mp2_common::F;
    use plonky2::field::types::Sample;
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
        let cells_pi = (0..CELL_IO_LEN).map(|_| F::rand()).collect::<Vec<_>>();

        let cells_proof =
            testing_framework.generate_input_proofs::<1>([cells_pi.try_into().unwrap()])?;
        let cells_proof_vk = ProofWithVK::new(
            cells_proof[0].clone(),
            testing_framework.verifier_data_for_input_proofs::<1>()[0].clone(),
        );
        //  generate row leaf proof
        let input = CircuitInput::leaf(
            identifier,
            value,
            cells_proof_vk.serialize()?,
            testing_framework.get_recursive_circuit_set(),
        )?;

        let proof = params.generate_proof(input)?;
        Ok(())
    }
}
