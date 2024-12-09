//! Implementations of the traits found in [`crate::indexing::planner::ports::input`].

use mp2_common::eth::ReceiptProofInfo;

use super::input::Extractable;

impl Extractable for ReceiptProofInfo {
    fn to_path(&self) -> Vec<Vec<u8>> {
        self.mpt_proof.clone()
    }
}
