use super::{
    context::TestContext,
    index_tree::MerkleIndexTree,
    proof_storage::{IndexProofIdentifier, ProofKey, ProofStorage},
    table::TableID,
};
use anyhow::Result;
use mp2_common::{proof::ProofWithVK, types::HashOutput, F};
use mp2_v1::{api, indexing::block::BlockPrimaryIndex};
use plonky2::{hash::hash_types::HashOut, plonk::config::GenericHashOut};
use verifiable_db::{block_tree, ivc::PublicInputs};

impl TestContext {
    pub async fn prove_ivc(
        &mut self,
        table_id: &TableID,
        bn: BlockPrimaryIndex,
        index_tree: &MerkleIndexTree,
        expected_metadata_hash: &HashOutput,
    ) -> Result<()> {
        // load the block proof of the current block
        let root_key = index_tree.root().await.unwrap();
        let index_root_key = ProofKey::Index(IndexProofIdentifier {
            table: table_id.clone(),
            tree_key: root_key,
        });
        let root_proof = self
            .storage
            .get_proof_exact(&index_root_key)
            .expect("index tree proof is not stored");
        // load the previous IVC proof if there is one
        // we simply can try to load from the storage at block -1
        // TODO: generalize that to a better more generic method for any index tree
        let previous_ivc_key = ProofKey::IVC(bn - 1);
        let input = match self.storage.get_proof_exact(&previous_ivc_key) {
            Ok(previous_proof) => {
                // Check the input previous proof and block proof.
                {
                    let [prev_proof, block_proof] = [&previous_proof, &root_proof]
                        .map(|proof| ProofWithVK::deserialize(proof).unwrap());
                    let prev_pi = PublicInputs::from_slice(&prev_proof.proof.public_inputs);
                    let block_pi =
                        block_tree::PublicInputs::from_slice(&block_proof.proof.public_inputs);
                    assert_eq!(
                        prev_pi.block_hash_fields(),
                        block_pi.prev_block_hash_fields(),
                    );
                    assert_eq!(
                        prev_pi.merkle_root_hash_fields(),
                        block_pi.old_merkle_hash_field(),
                    );
                    assert_eq!(prev_pi.z0_u256(), block_pi.min_block_number().unwrap());
                    assert_eq!(prev_pi.metadata_hash(), block_pi.metadata_hash());
                }
                verifiable_db::ivc::CircuitInput::new_subsequent_input(root_proof, previous_proof)
            }
            Err(_) => verifiable_db::ivc::CircuitInput::new_first_input(root_proof),
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
}
