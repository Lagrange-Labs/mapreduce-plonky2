use super::{
    context::TestContext,
    proof_storage::{IndexProofIdentifier, ProofKey, ProofStorage},
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
        bn: BlockPrimaryIndex,
        root_proof_key: IndexProofIdentifier<BlockPrimaryIndex>,
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
                let index_root_key = ProofKey::Index(root_proof_key);
                let root_proof = self
                    .storage
                    .get_proof_exact(&index_root_key)
                    .expect("index tree proof is not stored");
                if let Some(previous_block_number) = previous_block {
                    // Here we check to see if the last block that was inserted is the index tree
                    let previous_ivc_key =
                        self.get_previous_ivc_proof_key(previous_block_number)?;
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
                    let index_root_key = ProofKey::Index(root_proof_key);
                    let root_proof = self
                        .storage
                        .get_proof_exact(&index_root_key)
                        .expect("index tree proof is not stored");
                    // The previous block number is the current epoch rather confusingly
                    let prev_bn = index_tree.current_epoch().await? as usize;
                    let initial_epoch = index_tree.initial_epoch().await as usize;

                    if prev_bn != initial_epoch {
                        let previous_ivc_key = self.get_previous_ivc_proof_key(prev_bn)?;
                        let previous_proof = self.storage.get_proof_exact(&previous_ivc_key)?;
                        verifiable_db::ivc::CircuitInput::new_subsequent_input(
                            root_proof,
                            previous_proof,
                        )
                        .expect("unable to create ivc circuit inputs")
                    } else {
                        verifiable_db::ivc::CircuitInput::new_first_input(root_proof)
                            .expect("unable to create ivc circuit inputs")
                    }
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

    fn get_previous_ivc_proof_key(
        &mut self,
        previous_block_number: usize,
    ) -> anyhow::Result<ProofKey> {
        let mut last_block_number = previous_block_number;

        while let Ok(prev_proof) = self
            .storage
            .get_proof_exact(&ProofKey::IVC(last_block_number + 1))
        {
            let proof = ProofWithVK::deserialize(&prev_proof)?;
            let ivc_pi = PublicInputs::from_slice(&proof.proof().public_inputs);

            // The block number is a u64 and the U256 is little endian encoded so we need the last one.
            last_block_number = ivc_pi.zi_u256().as_limbs()[0] as usize;
        }

        Ok(ProofKey::IVC(last_block_number))
    }
}
