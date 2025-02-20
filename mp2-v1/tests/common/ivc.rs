use super::{
    context::TestContext,
    proof_storage::{IndexProofIdentifier, ProofKey, ProofStorage},
};

use mp2_common::{proof::ProofWithVK, types::HashOutput, F};
use mp2_v1::{
    api,
    indexing::block::{get_previous_epoch, BlockPrimaryIndex, MerkleIndexTree},
};
use plonky2::{hash::hash_types::HashOut, plonk::config::GenericHashOut};

use verifiable_db::ivc::PublicInputs;

impl TestContext {
    pub async fn prove_ivc(
        &mut self,
        bn: BlockPrimaryIndex,
        root_proof_key: IndexProofIdentifier<BlockPrimaryIndex>,
        index_tree: &MerkleIndexTree,
        expected_metadata_hash: &HashOutput,
    ) -> anyhow::Result<()> {
        // load the block proof of the current block
        let index_root_key = ProofKey::Index(root_proof_key);
        let root_proof = self
            .storage
            .get_proof_exact(&index_root_key)
            .expect("index tree proof is not stored");
        // Now we search for the previous IVC proof
        let input =
            if let Some(previous_proof) = self.get_previous_ivc_proof(bn, index_tree).await? {
                verifiable_db::ivc::CircuitInput::new_subsequent_input(root_proof, previous_proof)
            } else {
                verifiable_db::ivc::CircuitInput::new_first_input(root_proof)
            }
            .expect("unable to create ivc circuit inputs");

        let ivc_proof = self
            .b
            .bench("indexing::ivc", || {
                api::generate_proof(self.params(), api::CircuitInput::IVC(input))
            })
            .expect("unable to create ivc proof");
        let proof = ProofWithVK::deserialize(&ivc_proof)?;
        let ivc_pi = PublicInputs::from_slice(&proof.proof().public_inputs);
        // check metadata hash
        assert_eq!(
            ivc_pi.metadata_hash(),
            &HashOut::<F>::from_bytes(expected_metadata_hash.into()).to_vec(),
        );
        self.storage
            .store_proof(ProofKey::IVC(bn), ivc_proof)
            .expect("unable to store new ivc proof");
        Ok(())
    }

    async fn get_previous_ivc_proof(
        &mut self,
        bn: BlockPrimaryIndex,
        index_tree: &MerkleIndexTree,
    ) -> anyhow::Result<Option<Vec<u8>>> {
        // We check to see if bn - 1 has an exisiting proof, if it does we use that one.
        // If it did not we call `get_previous_epoch`, if this erros then we should return None and
        // we are in the case where this is the first IVC proof for this table.

        if let Ok(proof) = self.storage.get_proof_exact(&ProofKey::IVC(bn - 1)) {
            Ok(Some(proof))
        } else {
            match get_previous_epoch(index_tree, bn).await {
                Ok(inner) => match inner {
                    Some(key) => Ok(Some(self.storage.get_proof_exact(&ProofKey::IVC(key))?)),
                    None => Ok(None),
                },
                Err(_) => Ok(None),
            }
        }
    }
}
