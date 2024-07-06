//! Cells Tree Construction APIs

use super::{
    empty_node::{EmptyNodeCircuit, EmptyNodeWires},
    full_node::{FullNodeCircuit, FullNodeWires},
    leaf::{LeafCircuit, LeafWires},
    partial_node::{PartialNodeCircuit, PartialNodeWires},
    public_inputs::PublicInputs,
};
use crate::api::CellNode;
use anyhow::Result;
use ethers::prelude::U256;
use mp2_common::{
    default_config,
    proof::{ProofInputSerialized, ProofWithVK},
    C, D, F,
};
use recursion_framework::{
    circuit_builder::{CircuitWithUniversalVerifier, CircuitWithUniversalVerifierBuilder},
    framework::{RecursiveCircuitInfo, RecursiveCircuits},
};
use serde::{Deserialize, Serialize};
use std::array;

type LeafInput = LeafCircuit;
type ChildInput = ProofInputSerialized<CellNode>;

/// CircuitInput is a wrapper around the different specialized circuits that can
/// be used to prove a node recursively.
#[derive(Serialize, Deserialize)]
pub enum CircuitInput {
    Leaf(LeafInput),
    FullNode(ChildInput),
    PartialNode(ChildInput),
}

impl CircuitInput {
    /// Create a circuit input for proving a leaf node.
    pub fn new_leaf(identifier: F, value: U256) -> Self {
        CircuitInput::Leaf(LeafCircuit { identifier, value })
    }

    /// Create a circuit input for proving a full node of 2 children.
    pub fn new_full_node(identifier: F, value: U256, child_proofs: [Vec<u8>; 2]) -> Self {
        CircuitInput::FullNode(new_child_input(identifier, value, child_proofs.to_vec()))
    }

    /// Create a circuit input for proving a partial node of 1 child.
    pub fn new_partial_node(identifier: F, value: U256, child_proof: Vec<u8>) -> Self {
        CircuitInput::PartialNode(new_child_input(identifier, value, vec![child_proof]))
    }
}

/// Create a new child input.
fn new_child_input(
    identifier: F,
    value: U256,
    serialized_child_proofs: Vec<Vec<u8>>,
) -> ChildInput {
    ChildInput {
        input: CellNode { identifier, value },
        serialized_child_proofs,
    }
}

/// Main struct holding the different circuit parameters for each of the circuits defined here.
#[derive(Serialize, Deserialize)]
pub struct PublicParameters {
    leaf: CircuitWithUniversalVerifier<F, C, D, 0, LeafWires>,
    full_node: CircuitWithUniversalVerifier<F, C, D, 2, FullNodeWires>,
    partial_node: CircuitWithUniversalVerifier<F, C, D, 1, PartialNodeWires>,
    empty_node: CircuitWithUniversalVerifier<F, C, D, 0, EmptyNodeWires>,
    set: RecursiveCircuits<F, C, D>,
    empty_node_proof: ProofWithVK,
}

/// Public API employed to build the circuits, which are returned in serialized form.
pub fn build_circuits_params() -> PublicParameters {
    PublicParameters::build()
}

const NUM_IO: usize = PublicInputs::<F>::TOTAL_LEN;

/// Number of circuits in the set
/// 1 leaf + 1 full node + 1 partial node + 1 empty node
const CIRCUIT_SET_SIZE: usize = 4;

impl PublicParameters {
    /// Generates the circuit parameters for the circuits.
    fn build() -> Self {
        let config = default_config();
        let builder =
            CircuitWithUniversalVerifierBuilder::<F, D, NUM_IO>::new::<C>(config, CIRCUIT_SET_SIZE);

        let leaf = builder.build_circuit(());
        let full_node = builder.build_circuit(());
        let partial_node = builder.build_circuit(());
        let empty_node = builder.build_circuit(());

        let set = RecursiveCircuits::new_from_circuit_digests(vec![
            leaf.get_verifier_data().circuit_digest,
            full_node.get_verifier_data().circuit_digest,
            partial_node.get_verifier_data().circuit_digest,
            empty_node.get_verifier_data().circuit_digest,
        ]);

        // Generate the proof for the empty node. It could be reused.
        let proof = set
            .generate_proof(&empty_node, [], [], EmptyNodeCircuit)
            .unwrap();
        let empty_node_proof = ProofWithVK::from((proof, empty_node.get_verifier_data().clone()));

        PublicParameters {
            leaf,
            full_node,
            partial_node,
            empty_node,
            set,
            empty_node_proof,
        }
    }

    pub fn vk_set(&self) -> &RecursiveCircuits<F, C, D> {
        &self.set
    }
    pub fn generate_proof(&self, circuit_type: CircuitInput) -> Result<Vec<u8>> {
        let set = &self.set;

        let proof_with_vk = match circuit_type {
            CircuitInput::Leaf(leaf) => {
                let proof = set.generate_proof(&self.leaf, [], [], leaf)?;
                (proof, self.leaf.get_verifier_data().clone())
            }
            CircuitInput::FullNode(node) => {
                let child_proofs = node.get_child_proofs()?;
                assert_eq!(
                    child_proofs.len(),
                    2,
                    "Must have two children in this full node input"
                );
                let (child_pis, child_vks): (Vec<_>, Vec<_>) =
                    child_proofs.into_iter().map(|p| (p.proof, p.vk)).unzip();
                let proof = set.generate_proof(
                    &self.full_node,
                    child_pis.try_into().unwrap(),
                    array::from_fn(|i| &child_vks[i]),
                    FullNodeCircuit {
                        identifier: node.input.identifier,
                        value: node.input.value,
                    },
                )?;
                (proof, self.full_node.get_verifier_data().clone())
            }
            CircuitInput::PartialNode(node) => {
                let mut child_proofs = node.get_child_proofs()?;
                assert_eq!(
                    child_proofs.len(),
                    1,
                    "Must have one child in this partial node input"
                );
                let (child_proof, child_vk) = child_proofs.pop().unwrap().into();
                let proof = set.generate_proof(
                    &self.partial_node,
                    [child_proof],
                    [&child_vk],
                    PartialNodeCircuit {
                        identifier: node.input.identifier,
                        value: node.input.value,
                    },
                )?;
                (proof, self.partial_node.get_verifier_data().clone())
            }
        };

        ProofWithVK::from(proof_with_vk).serialize()
    }

    /// Get the proof of an empty node.
    pub(crate) fn empty_node_proof(&self) -> &ProofWithVK {
        &self.empty_node_proof
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mp2_common::{
        group_hashing::{add_curve_point, map_to_curve_point},
        poseidon::{empty_poseidon_hash, H},
        utils::{Endianness, Fieldable, ToFields},
    };
    use plonky2::plonk::config::Hasher;
    use plonky2_ecgfp5::curve::curve::{Point, WeierstrassPoint};
    use rand::{thread_rng, Rng};
    use serial_test::serial;
    use std::iter;

    #[test]
    #[serial]
    fn test_cells_tree_api() {
        // Build the parameters.
        let params = build_circuits_params();

        // Generate a leaf proof.
        let leaf = generate_leaf_proof(&params);

        // Generate an empty node proof.
        let empty_node_proof = generate_empty_node_proof(&params);

        // Generate a full node proof.
        let full_node_proof = generate_full_node_proof(&params, [leaf, empty_node_proof]);

        // Generate a partial node proof.
        let _partial_node_proof = generate_partial_node_proof(&params, full_node_proof);
    }

    fn generate_leaf_proof(params: &PublicParameters) -> Vec<u8> {
        // Build the circuit input.
        let mut rng = thread_rng();
        let identifier = rng.gen::<u32>().to_field();
        let value = U256(rng.gen::<[u64; 4]>());
        let value_fields = value.to_fields();
        let input = CircuitInput::new_leaf(identifier, value);

        // Generate proof.
        let proof = params.generate_proof(input).unwrap();

        // Check the public inputs.
        let pi = ProofWithVK::deserialize(&proof)
            .unwrap()
            .proof
            .public_inputs;
        let pi = PublicInputs::from_slice(&pi);
        {
            let empty_hash = empty_poseidon_hash();
            let inputs: Vec<_> = empty_hash
                .elements
                .iter()
                .cloned()
                .chain(empty_hash.elements)
                .chain(iter::once(identifier))
                .chain(value_fields.clone())
                .collect();
            // TODO: Fix to employ the same hash method in the ryhope tree library.
            let exp_hash = H::hash_no_pad(&inputs);

            assert_eq!(pi.h, exp_hash.elements);
        }
        {
            let inputs: Vec<_> = iter::once(identifier).chain(value_fields).collect();
            let exp_digest = map_to_curve_point(&inputs).to_weierstrass();

            assert_eq!(pi.digest_point(), exp_digest);
        }

        proof
    }

    fn generate_empty_node_proof(params: &PublicParameters) -> Vec<u8> {
        // Get the proof.
        let proof = params.empty_node_proof().serialize().unwrap();

        // Check the public inputs.
        let pi = ProofWithVK::deserialize(&proof)
            .unwrap()
            .proof
            .public_inputs;
        let pi = PublicInputs::from_slice(&pi);
        {
            let empty_hash = empty_poseidon_hash();
            assert_eq!(pi.h, empty_hash.elements);
        }
        {
            assert_eq!(pi.digest_point(), WeierstrassPoint::NEUTRAL);
        }

        proof
    }

    fn generate_full_node_proof(params: &PublicParameters, child_proofs: [Vec<u8>; 2]) -> Vec<u8> {
        // Parse the child public inputs.
        let child_pis: Vec<_> = child_proofs
            .iter()
            .map(|proof| {
                ProofWithVK::deserialize(&proof)
                    .unwrap()
                    .proof
                    .public_inputs
            })
            .collect();
        let child_pis: Vec<_> = child_pis
            .iter()
            .map(|pi| PublicInputs::from_slice(&pi))
            .collect();

        // Build the circuit input.
        let mut rng = thread_rng();
        let identifier = rng.gen::<u32>().to_field();
        let value = U256(rng.gen::<[u64; 4]>());
        let packed_value = value.to_fields();
        let input = CircuitInput::new_full_node(identifier, value, child_proofs);

        // Generate proof.
        let proof = params.generate_proof(input).unwrap();

        // Check the public inputs.
        let pi = ProofWithVK::deserialize(&proof)
            .unwrap()
            .proof
            .public_inputs;
        let pi = PublicInputs::from_slice(&pi);
        {
            let inputs: Vec<_> = child_pis[0]
                .h_raw()
                .iter()
                .chain(child_pis[1].h_raw())
                .cloned()
                .chain(iter::once(identifier))
                .chain(packed_value.clone())
                .collect();
            // TODO: Fix to employ the same hash method in the ryhope tree library.
            let exp_hash = H::hash_no_pad(&inputs);

            assert_eq!(pi.h, exp_hash.elements);
        }
        {
            let child_digests: Vec<_> = child_pis
                .iter()
                .map(|pi| Point::decode(pi.digest_point().encode()).unwrap())
                .collect();
            let inputs: Vec<_> = iter::once(identifier).chain(packed_value).collect();
            let exp_digest = map_to_curve_point(&inputs);
            let exp_digest =
                add_curve_point(&[exp_digest, child_digests[0], child_digests[1]]).to_weierstrass();

            assert_eq!(pi.digest_point(), exp_digest);
        }

        proof
    }

    fn generate_partial_node_proof(params: &PublicParameters, child_proof: Vec<u8>) -> Vec<u8> {
        // Parse the child public inputs.
        let child_pi = ProofWithVK::deserialize(&child_proof)
            .unwrap()
            .proof
            .public_inputs;
        let child_pi = PublicInputs::from_slice(&child_pi);

        // Build the circuit input.
        let mut rng = thread_rng();
        let identifier = rng.gen::<u32>().to_field();
        let value = U256(rng.gen::<[u64; 4]>());
        let packed_value = value.to_fields();
        let input = CircuitInput::new_partial_node(identifier, value, child_proof);

        // Generate proof.
        let proof = params.generate_proof(input).unwrap();

        // Check the public inputs.
        let pi = ProofWithVK::deserialize(&proof)
            .unwrap()
            .proof
            .public_inputs;
        let pi = PublicInputs::from_slice(&pi);
        {
            let empty_hash = empty_poseidon_hash();
            let inputs: Vec<_> = child_pi
                .h_raw()
                .iter()
                .cloned()
                .chain(empty_hash.elements)
                .chain(iter::once(identifier))
                .chain(packed_value.clone())
                .collect();
            // TODO: Fix to employ the same hash method in the ryhope tree library.
            let exp_hash = H::hash_no_pad(&inputs);

            assert_eq!(pi.h, exp_hash.elements);
        }
        {
            let child_digest = Point::decode(child_pi.digest_point().encode()).unwrap();
            let inputs: Vec<_> = iter::once(identifier).chain(packed_value).collect();
            let exp_digest = map_to_curve_point(&inputs);
            let exp_digest = add_curve_point(&[exp_digest, child_digest]).to_weierstrass();

            assert_eq!(pi.digest_point(), exp_digest);
        }

        proof
    }
}
