use anyhow::Result;
use plonky2::plonk::{
    circuit_data::CircuitConfig,
    config::{GenericConfig, PoseidonGoldilocksConfig},
};
use recursion_framework::{
    circuit_builder::{CircuitWithUniversalVerifier, CircuitWithUniversalVerifierBuilder},
    framework::{RecursiveCircuitInfo, RecursiveCircuits},
};
use serde::{Deserialize, Serialize};

use crate::api::{ProofWithVK, C, D, F};

use super::{
    inner_node::{NodeCircuit, NodeWires},
    leaf::{LeafCircuit, LeafWires},
    PublicInputs,
};

const STORAGE_CIRCUIT_SET_SIZE: usize = 2;
const NUM_IO: usize = PublicInputs::<F>::TOTAL_LEN;

pub enum Inputs {
    Leaf(LeafCircuit),
    Node(NodeInputs),
}

pub struct NodeInputs {
    left: Vec<u8>,
    right: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
pub struct PublicParameters {
    leaf_circuit: CircuitWithUniversalVerifier<F, C, D, 0, LeafWires>,
    node_circuit: CircuitWithUniversalVerifier<F, C, D, 2, NodeWires>,
    set: RecursiveCircuits<F, C, D>,
}

impl PublicParameters {
    pub fn build() -> Self {
        let config = CircuitConfig::standard_recursion_config();
        let circuit_builder = CircuitWithUniversalVerifierBuilder::<F, D, NUM_IO>::new::<C>(
            config,
            STORAGE_CIRCUIT_SET_SIZE,
        );
        let leaf_circuit = circuit_builder.build_circuit::<C, 0, LeafWires>(());
        let node_circuit = circuit_builder.build_circuit::<C, 2, NodeWires>(());

        let mut circuits_set = vec![
            leaf_circuit.get_verifier_data().circuit_digest,
            node_circuit.get_verifier_data().circuit_digest,
        ];

        let set = RecursiveCircuits::new_from_circuit_digests(circuits_set);
        Self {
            leaf_circuit,
            node_circuit,
            set,
        }
    }

    pub fn generate_proof(&self, inputs: Inputs) -> Result<Vec<u8>> {
        match inputs {
            Inputs::Leaf(leaf) => {
                let proof = self.set.generate_proof(&self.leaf_circuit, [], [], leaf)?;
                ProofWithVK {
                    proof,
                    vk: self.leaf_circuit.get_verifier_data().clone(),
                }
                .serialize()
            }
            Inputs::Node(node) => {
                let left = ProofWithVK::deserialize(&node.left)?;
                let right = ProofWithVK::deserialize(&node.right)?;
                let proof = self.set.generate_proof(
                    &self.node_circuit,
                    [left.proof, right.proof],
                    [&left.vk, &right.vk],
                    NodeCircuit {},
                )?;
                ProofWithVK {
                    proof,
                    vk: self.node_circuit.get_verifier_data().clone(),
                }
                .serialize()
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::eth::left_pad32;
    use crate::storage::lpn::leaf::LeafCircuit;
    use crate::storage::lpn::KEY_SIZE;
    use crate::storage::lpn::LEAF_SIZE;
    use plonky2::plonk::circuit_builder::CircuitBuilder;
    use plonky2::plonk::circuit_data::CircuitConfig;
    use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
    use plonky2::plonk::proof::ProofWithPublicInputs;
    use recursion_framework::circuit_builder::CircuitWithUniversalVerifierBuilder;

    #[test]
    fn test_public_parameters() {
        let gen_input = |k: &'_ str, v: &'_ str| -> ([u8; KEY_SIZE], [u8; LEAF_SIZE]) {
            let kb = left_pad32(k.as_bytes());
            let vb = left_pad32(v.as_bytes());
            (kb.try_into().unwrap(), vb.try_into().unwrap())
        };
        let (k1, v1) = gen_input("deadbeef", "0badf00d");
        let (k2, v2) = gen_input("0badf00d", "deedbaaf");
        let params = PublicParameters::build();
        let p1 = params
            .generate_proof(Inputs::Leaf(LeafCircuit { key: k1, value: v1 }))
            .unwrap();
        let p2 = params
            .generate_proof(Inputs::Leaf(LeafCircuit { key: k2, value: v2 }))
            .unwrap();
        params
            .generate_proof(Inputs::Node(NodeInputs {
                left: p1,
                right: p2,
            }))
            .unwrap();
    }
}
