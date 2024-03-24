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

use crate::api::{default_config, ProofWithVK, C, D, F};

use super::{
    inner_node::{NodeCircuit, NodeWires},
    leaf::{LeafCircuit, LeafWires},
    PublicInputs,
};

const STORAGE_CIRCUIT_SET_SIZE: usize = 2;
const NUM_IO: usize = PublicInputs::<F>::TOTAL_LEN;

/// Inputs to the storage database related circuits (specifically for mapping)
pub enum Input {
    Leaf(LeafCircuit),
    Node(NodeInputs),
}

/// The inputs for proving an intermediate node in the storage database
/// for mapping.
pub struct NodeInputs {
    left: Vec<u8>,
    right: Vec<u8>,
}

impl NodeInputs {
    /// Construct an instance of `NodeInputs` from 2 child proofs
    pub fn new(left_proof: Vec<u8>, right_proof: Vec<u8>) -> Self {
        Self {
            left: left_proof,
            right: right_proof,
        }
    }
}

/// Parameters containing the public information for proving both leaves and nodes
/// of the storage database
#[derive(Serialize, Deserialize)]
pub struct PublicParameters {
    leaf_circuit: CircuitWithUniversalVerifier<F, C, D, 0, LeafWires>,
    node_circuit: CircuitWithUniversalVerifier<F, C, D, 2, NodeWires>,
    set: RecursiveCircuits<F, C, D>,
}

impl PublicParameters {
    /// Build the public parameters for the storage database related circuits
    pub fn build() -> Self {
        let config = default_config();
        let circuit_builder = CircuitWithUniversalVerifierBuilder::<F, D, NUM_IO>::new::<C>(
            config,
            STORAGE_CIRCUIT_SET_SIZE,
        );
        let leaf_circuit = circuit_builder.build_circuit::<C, 0, LeafWires>(());
        let node_circuit = circuit_builder.build_circuit::<C, 2, NodeWires>(());

        let circuits_set = vec![
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

    /// Generate a proof for a leaf or node in the storage database and returns its
    /// serialized form.
    pub fn generate_proof(&self, inputs: Input) -> Result<Vec<u8>> {
        match inputs {
            Input::Leaf(leaf) => {
                let proof = self.set.generate_proof(&self.leaf_circuit, [], [], leaf)?;
                ProofWithVK {
                    proof,
                    vk: self.leaf_circuit.get_verifier_data().clone(),
                }
                .serialize()
            }
            Input::Node(node) => {
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
    /// Get the set of circuits related to the storage database in LPN
    pub(crate) fn get_lpn_circuit_set(&self) -> &RecursiveCircuits<F, C, D> {
        &self.set
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::eth::left_pad32;
    use crate::storage::lpn::leaf::LeafCircuit;
    use crate::storage::lpn::KEY_SIZE;
    use crate::storage::lpn::LEAF_SIZE;

    #[test]
    fn test_public_parameters() {
        let gen_input = |k: &'_ str, v: &'_ str| -> ([u8; KEY_SIZE], [u8; LEAF_SIZE]) {
            let kb = left_pad32(k.as_bytes());
            let vb = left_pad32(v.as_bytes());
            (kb, vb)
        };
        let (k1, v1) = gen_input("deadbeef", "0badf00d");
        let (k2, v2) = gen_input("0badf00d", "deedbaaf");
        let params = PublicParameters::build();
        let p1 = params
            .generate_proof(Input::Leaf(LeafCircuit {
                mapping_key: k1,
                mapping_value: v1,
            }))
            .unwrap();
        let p2 = params
            .generate_proof(Input::Leaf(LeafCircuit {
                mapping_key: k2,
                mapping_value: v2,
            }))
            .unwrap();
        let proof = params
            .generate_proof(Input::Node(NodeInputs {
                left: p1,
                right: p2,
            }))
            .unwrap();
        let p = ProofWithVK::deserialize(&proof).unwrap();
        params.node_circuit.circuit_data().verify(p.proof).unwrap();
    }
}
