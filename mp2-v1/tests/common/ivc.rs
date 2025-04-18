use super::{
    context::TestContext,
    proof_storage::{IndexProofIdentifier, ProofKey, ProofStorage},
    table::TableID,
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
        table_id: &TableID,
        bn: BlockPrimaryIndex,
        index_tree: &MerkleIndexTree,
        provable_data_commitment: bool,
        expected_metadata_hash: &HashOutput,
        expected_root_of_trust: HashOutput,
    ) -> anyhow::Result<()> {
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
        // load the previous IVC proof if there is one
        // we simply can try to load from the storage at block -1
        // TODO: generalize that to a better more generic method for any index tree
        let previous_block = get_previous_epoch(index_tree, bn).await?;
        let input = if let Some(prev_bn) = previous_block {
            let previous_ivc_key = ProofKey::IVC(prev_bn);
            let previous_proof = self.storage.get_proof_exact(&previous_ivc_key)?;
            verifiable_db::ivc::CircuitInput::new_subsequent_input(
                provable_data_commitment,
                root_proof,
                previous_proof,
            )
        } else {
            verifiable_db::ivc::CircuitInput::new_first_input(provable_data_commitment, root_proof)
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
        // check root of trust
        assert_eq!(ivc_pi.block_hash_output(), expected_root_of_trust,);
        self.storage
            .store_proof(ProofKey::IVC(bn), ivc_proof)
            .expect("unable to store new ivc proof");
        Ok(())
    }
}
