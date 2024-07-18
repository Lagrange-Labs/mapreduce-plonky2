use super::{
    context::TestContext,
    index_tree::{IndexTree, MerkleIndexTree},
    proof_storage::{BlockPrimaryIndex, IndexProofIdentifier, ProofKey, ProofStorage},
    TestCase,
};
use anyhow::Result;
use mp2_v1::api;
use ryhope::tree::TreeTopology;

impl<P: ProofStorage> TestContext<P> {
    pub async fn prove_ivc(&mut self, case: &TestCase, index_tree: &MerkleIndexTree) -> Result<()> {
        let bn = self.block_number().await as BlockPrimaryIndex;
        // load the block proof of the current block
        let table_id = case.table_id();
        let root_key = index_tree.root().unwrap();
        let index_root_key = ProofKey::Index(IndexProofIdentifier {
            table: table_id,
            tree_key: root_key,
        });
        let root_proof = self
            .storage
            .get_proof(&index_root_key)
            .expect("index tree proof is not stored");
        // load the previous IVC proof if there is one
        // we simply can try to load from the storage at block -1
        let previous_ivc_key = ProofKey::IVC(bn - 1);
        let input = match self.storage.get_proof(&previous_ivc_key) {
            Ok(previous_proof) => {
                verifiable_db::ivc::CircuitInput::new_subsequent_input(root_proof, previous_proof)
            }
            Err(_) => verifiable_db::ivc::CircuitInput::new_first_input(root_proof),
        }
        .expect("unable to create ivc circuit inputs");
        let ivc_proof = api::generate_proof(self.params(), api::CircuitInput::IVC(input))
            .expect("unable to create ivc proof");
        self.storage
            .store_proof(ProofKey::IVC(bn), ivc_proof)
            .expect("unable to store new ivc proof");
        Ok(())
    }
}
