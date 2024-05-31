use mp2_common::{types::GFp, C, D, F};
use recursion_framework::{
    circuit_builder::{CircuitWithUniversalVerifier, CircuitWithUniversalVerifierBuilder},
    framework::{RecursiveCircuitInfo, RecursiveCircuits},
};
use serde::{Deserialize, Serialize};

use crate::{
    api::{default_config, InputNode, ProofInputSerialized, ProofWithVK},
    length_extraction::{BranchLengthCircuit, ExtensionLengthCircuit},
};

use super::{
    BranchLengthWires, ExtensionLengthWires, LeafLengthCircuit, LeafLengthWires, PublicInputs,
};

type ExtensionInput = ProofInputSerialized<InputNode>;
type BranchInput = ProofInputSerialized<InputNode>;

/// CircuitInput is a wrapper around the different specialized circuits that can
/// be used to prove a MPT node recursively.
#[derive(Serialize, Deserialize)]
pub enum LengthCircuitInput {
    Branch(BranchInput),
    Extension(ExtensionInput),
    Leaf(LeafLengthCircuit),
}

impl LengthCircuitInput {
    /// Creates a new circuit input instance for proving the length extraction of a branch MPT node.
    pub fn new_branch(node: Vec<u8>, child_proof: Vec<u8>) -> Self {
        Self::Branch(ExtensionInput {
            input: InputNode { node },
            serialized_child_proofs: vec![child_proof],
        })
    }

    /// Creates a new circuit input instance for proving the length extraction of an extension MPT node.
    pub fn new_extension(node: Vec<u8>, child_proof: Vec<u8>) -> Self {
        Self::Extension(ExtensionInput {
            input: InputNode { node },
            serialized_child_proofs: vec![child_proof],
        })
    }

    /// Creates a new circuit input instance for proving the length extraction of a leaf MPT node.
    pub fn new_leaf(length_slot: u8, node: Vec<u8>, variable_slot: u8) -> Self {
        Self::Leaf(LeafLengthCircuit::new(length_slot, node, variable_slot))
    }
}

/// Length extraction MPT circuits.
///
/// Unlocks the usage with the recursion framwork.
#[derive(Debug, Serialize, Deserialize)]
pub struct PublicParameters {
    branch: CircuitWithUniversalVerifier<F, C, D, 1, BranchLengthWires>,
    extension: CircuitWithUniversalVerifier<F, C, D, 1, ExtensionLengthWires>,
    leaf: CircuitWithUniversalVerifier<F, C, D, 0, LeafLengthWires>,
    set: RecursiveCircuits<F, C, D>,
}

impl PublicParameters {
    /// Number of public inputs used in the circuits.
    pub const NUM_PUBLIC_INPUTS: usize = PublicInputs::<GFp>::TOTAL_LEN;

    /// Number of circuit variants.
    pub const CIRCUIT_SET_SIZE: usize = 3;

    /// Generates the circuit parameters for the MPT circuits.
    pub fn build() -> Self {
        let config = default_config();
        let circuit_builder = CircuitWithUniversalVerifierBuilder::<
            F,
            D,
            { Self::NUM_PUBLIC_INPUTS },
        >::new::<C>(config, Self::CIRCUIT_SET_SIZE);

        log::debug!("Building MPT length extraction leaf circuit...");

        let leaf = circuit_builder.build_circuit(());

        log::debug!("Building MPT length extraction extension circuit...");

        let extension = circuit_builder.build_circuit(());

        log::debug!("Building MPT length extraction branch circuit...");

        let branch = circuit_builder.build_circuit(());

        log::debug!("Building MPT length extraction recursive circuit set...");

        let set = RecursiveCircuits::new_from_circuit_digests(vec![
            leaf.get_verifier_data().circuit_digest,
            extension.get_verifier_data().circuit_digest,
            branch.get_verifier_data().circuit_digest,
        ]);

        log::debug!("Build of MPT length extraction circuits completed.");

        Self {
            branch,
            extension,
            leaf,
            set,
        }
    }

    /// Generates a serialized proof via [ProofWithVK::serialize].
    pub fn generate_proof(&self, circuit: LengthCircuitInput) -> anyhow::Result<Vec<u8>> {
        let set = &self.set;

        let proof_and_vk = match circuit {
            LengthCircuitInput::Branch(c) => {
                log::debug!("Generating a MPT length extraction branch proof...");

                let mut proofs = c.get_child_proofs()?;

                anyhow::ensure!(proofs.len() == 1, "the proof arity is 1");

                let (child_proof, child_vk) = proofs.remove(0).into();
                let proof = set.generate_proof(
                    &self.branch,
                    [child_proof],
                    [&child_vk],
                    BranchLengthCircuit::new(c.input.node),
                )?;

                (proof, self.branch.get_verifier_data().clone())
            }
            LengthCircuitInput::Extension(c) => {
                log::debug!("Generating a MPT length extraction extension proof...");

                let mut proofs = c.get_child_proofs()?;

                anyhow::ensure!(proofs.len() == 1, "the proof arity is 1");

                let (child_proof, child_vk) = proofs.remove(0).into();
                let proof = set.generate_proof(
                    &self.extension,
                    [child_proof],
                    [&child_vk],
                    ExtensionLengthCircuit::new(c.input.node),
                )?;

                (proof, self.extension.get_verifier_data().clone())
            }
            LengthCircuitInput::Leaf(c) => {
                log::debug!("Generating a MPT length extraction leaf proof...");

                let proof = set.generate_proof(&self.leaf, [], [], c)?;

                (proof, self.leaf.get_verifier_data().clone())
            }
        };

        log::debug!("MPT length extraction proof generated, serializing...");

        // TODO we might not need the VK serialized with the proof as it might live elsewhere as
        // static data.
        let proof = ProofWithVK::from(proof_and_vk).serialize()?;

        log::debug!("MPT length extraction proof serialized.");

        Ok(proof)
    }
}

#[cfg(test)]
mod tests {
    use mp2_common::{
        types::GFp,
        utils::{convert_u8_to_u32_slice, keccak256},
    };
    use plonky2::field::types::Field;

    use crate::{
        api::ProofWithVK,
        length_extraction::{tests::PudgyState, PublicInputs},
    };

    use super::{LengthCircuitInput, PublicParameters};

    #[test]
    fn length_extraction_api_works() {
        let PudgyState {
            slot,
            length,
            variable_slot,
            dm,
            key,
            mut pointer,
            mut proof,
            ..
        } = PudgyState::new();
        let params = PublicParameters::build();

        // Leaf extraction

        let node = proof.pop().unwrap();
        let leaf_circuit = LengthCircuitInput::new_leaf(slot, node.clone(), variable_slot);
        let mut child_proof = params.generate_proof(leaf_circuit).unwrap();

        let lp = ProofWithVK::deserialize(&child_proof).unwrap();
        let pis = lp.proof.public_inputs;
        let pi = PublicInputs::from_slice(&pis[..PublicInputs::<GFp>::TOTAL_LEN]);

        let root: Vec<_> = convert_u8_to_u32_slice(&keccak256(&node))
            .into_iter()
            .map(GFp::from_canonical_u32)
            .collect();

        assert_eq!(pi.length(), &GFp::from_canonical_u32(length));
        assert_eq!(pi.root_hash(), &root);
        assert_eq!(pi.mpt_key(), &key);
        assert_eq!(pi.metadata_point(), dm);
        assert_eq!(pi.mpt_key_pointer(), &pointer);

        // Branch extraction

        while let Some(node) = proof.pop() {
            pointer -= GFp::ONE;

            let root: Vec<_> = convert_u8_to_u32_slice(&keccak256(&node))
                .into_iter()
                .map(GFp::from_canonical_u32)
                .collect();

            let branch_circuit = LengthCircuitInput::new_branch(node, child_proof);

            child_proof = params.generate_proof(branch_circuit).unwrap();

            let lp = ProofWithVK::deserialize(&child_proof).unwrap();
            let pis = lp.proof.public_inputs;
            let pi = PublicInputs::from_slice(&pis[..PublicInputs::<GFp>::TOTAL_LEN]);

            assert_eq!(pi.length(), &GFp::from_canonical_u32(length));
            assert_eq!(pi.root_hash(), &root);
            assert_eq!(pi.mpt_key(), &key);
            assert_eq!(pi.metadata_point(), dm);
            assert_eq!(pi.mpt_key_pointer(), &pointer);
        }
    }
}
