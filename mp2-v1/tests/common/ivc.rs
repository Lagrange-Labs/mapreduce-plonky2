use super::{
    context::TestContext,
    proof_storage::{IndexProofIdentifier, ProofKey, ProofStorage},
    table::TableID,
};
use anyhow::anyhow;
use mp2_common::{proof::ProofWithVK, types::HashOutput, F};
use mp2_v1::{
    api,
    indexing::block::{get_previous_epoch, BlockPrimaryIndex, EpochError, MerkleIndexTree},
};
use plonky2::{hash::hash_types::HashOut, plonk::config::GenericHashOut};
use ryhope::storage::RoEpochKvStorage;
use verifiable_db::ivc::PublicInputs;

impl TestContext {
    pub async fn prove_ivc(
        &mut self,
        table_id: &TableID,
        bn: BlockPrimaryIndex,
        index_tree: &MerkleIndexTree,
        expected_metadata_hash: &HashOutput,
    ) -> anyhow::Result<()> {
        // First we check the previous epoch, if this errors with `EpochError::NotFound` then
        // we are in the case where the table had no entries added for this block and so
        // we should handle it accordingly.
        let res = get_previous_epoch(index_tree, bn).await;

        let input = match res {
            Ok(previous_block) => {
                // load the block proof of the current block
                let root_key = index_tree.root().await?.unwrap();
                let index_root_key = ProofKey::Index(IndexProofIdentifier {
                    table: table_id.clone(),
                    tree_key: root_key,
                });
                let root_proof = self
                    .storage
                    .get_proof_exact(&index_root_key)
                    .expect("index tree proof is not stored");
                if previous_block.is_some() {
                    // Here we check to see if the last block that was inserted is the index tree
                    let previous_ivc_key = ProofKey::IVC(bn - 1);
                    let previous_proof = self.storage.get_proof_exact(&previous_ivc_key)?;
                    verifiable_db::ivc::CircuitInput::new_subsequent_input(
                        root_proof,
                        previous_proof,
                    )
                } else {
                    verifiable_db::ivc::CircuitInput::new_first_input(root_proof)
                }
                .expect("unable to create ivc circuit inputs")
            }
            Err(e) => {
                if let EpochError::NotFound(_) = e {
                    let index_root_key = ProofKey::Index(IndexProofIdentifier {
                        table: table_id.clone(),
                        tree_key: bn,
                    });
                    let root_proof = self
                        .storage
                        .get_proof_exact(&index_root_key)
                        .expect("index tree proof is not stored");
                    // The previous block number is the current epoch rather confusingly
                    let prev_bn = index_tree.current_epoch().await? as usize;
                    let previous_ivc_key = ProofKey::IVC(prev_bn);
                    let previous_proof = self.storage.get_proof_exact(&previous_ivc_key)?;
                    verifiable_db::ivc::CircuitInput::new_subsequent_input(
                        root_proof,
                        previous_proof,
                    )
                    .expect("unable to create ivc circuit inputs")
                } else {
                    return Err(anyhow!(
                        "Got an error when fetching previous epoch: {:?}",
                        e
                    ));
                }
            }
        };

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
}
