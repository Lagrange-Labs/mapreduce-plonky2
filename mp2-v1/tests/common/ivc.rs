use super::{
    context::TestContext,
    index_tree::MerkleIndexTree,
    proof_storage::{IndexProofIdentifier, ProofKey, ProofStorage},
    table::TableID,
};
use mp2_common::{proof::ProofWithVK, types::HashOutput, F};
use mp2_v1::{api, indexing::block::BlockPrimaryIndex};
use plonky2::{hash::hash_types::HashOut, plonk::config::GenericHashOut};
use verifiable_db::ivc::PublicInputs;

impl TestContext {
    pub async fn prove_ivc(
        &mut self,
        table_id: &TableID,
        bn: BlockPrimaryIndex,
        index_tree: &MerkleIndexTree,
        expected_metadata_hash: &HashOutput,
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
        let previous_ivc_key = ProofKey::IVC(bn - 1);
        let input = match self.storage.get_proof_exact(&previous_ivc_key) {
            Ok(previous_proof) => {
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
