//! Public inputs for Block Insertion circuits

use std::array::from_fn as create_array;

use crate::{CBuilder, F};
use alloy::primitives::U256;
use mp2_common::{
    keccak::PACKED_HASH_LEN,
    public_inputs::{PublicInputCommon, PublicInputRange},
    types::CURVE_TARGET_LEN,
    u256::{self, UInt256Target},
    utils::{FromFields, FromTargets, ToTargets},
};
use plonky2::{
    hash::hash_types::{HashOut, HashOutTarget, NUM_HASH_OUT_ELTS},
    iop::target::Target,
};
use plonky2_ecgfp5::{curve::curve::WeierstrassPoint, gadgets::curve::CurveTarget};

// Block Insertion public inputs:
// `H_new : [4]F` - Hash of the tree after insertion of the current block
// `H_old : [4]F` - Hash of the tree constructed so far
// `min : F[8]` - Minimum block number found among the nodes in the subtree rooted in the current node
// `max : F[8]` - Maximum block number found among the nodes in the subtree rooted in the current node
// `block_number : [8]F` - Block number being inserted, represented as a u256 with 8 32-bit limbs in big-endian order
// `block_hash : [8]F` - Block header of the block being inserted
// `prev_block_hash : [8]F` - Block header of the last inserted block in the old tree
// `M : [4]F` - Metadata hash for the data related to this block extracted from the blockchain; this is the same as the metadata digest computed by extraction circuits, but wrapped in a hash since it is more efficient to be propagated as a public input
// `new_node_digest : Digest[F]` - Order-agnostic digest of the new inserted node, to be employed in case we want to later build a generic index tree with a different index than the block number
const H_NEW_RANGE: PublicInputRange = 0..NUM_HASH_OUT_ELTS;
const H_OLD_RANGE: PublicInputRange = H_NEW_RANGE.end..H_NEW_RANGE.end + NUM_HASH_OUT_ELTS;
const MIN_RANGE: PublicInputRange = H_OLD_RANGE.end..H_OLD_RANGE.end + u256::NUM_LIMBS;
const MAX_RANGE: PublicInputRange = MIN_RANGE.end..MIN_RANGE.end + u256::NUM_LIMBS;
const BLOCK_NUMBER_RANGE: PublicInputRange = MAX_RANGE.end..MAX_RANGE.end + u256::NUM_LIMBS;
const BLOCK_HASH_RANGE: PublicInputRange =
    BLOCK_NUMBER_RANGE.end..BLOCK_NUMBER_RANGE.end + PACKED_HASH_LEN;
const PREV_BLOCK_HASH_RANGE: PublicInputRange =
    BLOCK_HASH_RANGE.end..BLOCK_HASH_RANGE.end + PACKED_HASH_LEN;
const METADATA_HASH_RANGE: PublicInputRange =
    PREV_BLOCK_HASH_RANGE.end..PREV_BLOCK_HASH_RANGE.end + NUM_HASH_OUT_ELTS;
const NEW_NODE_DIGEST_RANGE: PublicInputRange =
    METADATA_HASH_RANGE.end..METADATA_HASH_RANGE.end + CURVE_TARGET_LEN;

/// Public inputs for Cells Tree Construction
#[derive(Clone, Debug)]
pub struct PublicInputs<'a, T> {
    pub(crate) h_new: &'a [T],
    pub(crate) h_old: &'a [T],
    pub(crate) min: &'a [T],
    pub(crate) max: &'a [T],
    pub(crate) block_number: &'a [T],
    pub(crate) block_hash: &'a [T],
    pub(crate) prev_block_hash: &'a [T],
    pub(crate) metadata_hash: &'a [T],
    pub(crate) new_node_digest: &'a [T],
}

impl PublicInputCommon for PublicInputs<'_, Target> {
    const RANGES: &'static [PublicInputRange] = &[
        H_NEW_RANGE,
        H_OLD_RANGE,
        MIN_RANGE,
        MAX_RANGE,
        BLOCK_NUMBER_RANGE,
        BLOCK_HASH_RANGE,
        PREV_BLOCK_HASH_RANGE,
        METADATA_HASH_RANGE,
        NEW_NODE_DIGEST_RANGE,
    ];

    fn register_args(&self, cb: &mut CBuilder) {
        cb.register_public_inputs(self.h_new);
        cb.register_public_inputs(self.h_old);
        cb.register_public_inputs(self.min);
        cb.register_public_inputs(self.max);
        cb.register_public_inputs(self.block_number);
        cb.register_public_inputs(self.block_hash);
        cb.register_public_inputs(self.prev_block_hash);
        cb.register_public_inputs(self.metadata_hash);
        cb.register_public_inputs(self.new_node_digest);
    }
}

impl PublicInputs<'_, F> {
    /// Get the new Merkle tree root hash value.
    pub fn new_merkle_hash_field(&self) -> HashOut<F> {
        self.h_new.try_into().unwrap()
    }

    pub fn old_merkle_hash_field(&self) -> HashOut<F> {
        self.h_old.try_into().unwrap()
    }

    pub fn block_hash(&self) -> [F; PACKED_HASH_LEN] {
        create_array(|i| self.block_hash[i])
    }

    pub fn prev_block_hash_fields(&self) -> [F; PACKED_HASH_LEN] {
        create_array(|i| self.prev_block_hash[i])
    }

    /// Get the new node digest point.
    pub fn new_value_set_digest_point(&self) -> WeierstrassPoint {
        WeierstrassPoint::from_fields(self.new_node_digest)
    }

    pub fn min_block_number(&self) -> anyhow::Result<U256> {
        Ok(U256::from_fields(self.min))
    }
}

impl PublicInputs<'_, Target> {
    /// Get the new Merkle root hash target.
    pub fn new_merkle_hash_target(&self) -> HashOutTarget {
        self.h_new.try_into().unwrap()
    }

    /// Get the previous Merkle root hash target.
    pub fn old_merkle_hash(&self) -> HashOutTarget {
        self.h_old.try_into().unwrap()
    }

    /// Get the new node digest target.
    pub fn new_value_set_digest(&self) -> CurveTarget {
        CurveTarget::from_targets(self.new_node_digest)
    }

    pub fn index_value(&self) -> UInt256Target {
        UInt256Target::from_targets(self.block_number)
    }

    pub fn min_value(&self) -> UInt256Target {
        UInt256Target::from_targets(self.min)
    }

    pub fn prev_block_hash(&self) -> Vec<Target> {
        self.prev_block_hash.to_targets()
    }
    pub fn current_block_hash(&self) -> Vec<Target> {
        self.block_hash.to_targets()
    }
}

impl<'a, T: Copy> PublicInputs<'a, T> {
    /// Total length of the public inputs
    pub(crate) const TOTAL_LEN: usize = NEW_NODE_DIGEST_RANGE.end;

    /// Create a new public inputs.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        h_new: &'a [T],
        h_old: &'a [T],
        min: &'a [T],
        max: &'a [T],
        index_value: &'a [T],
        commitment: &'a [T],
        prev_commitment: &'a [T],
        metadata_hash: &'a [T],
        new_node_digest: &'a [T],
    ) -> Self {
        assert_eq!(h_new.len(), H_NEW_RANGE.len());
        assert_eq!(h_old.len(), H_OLD_RANGE.len());
        assert_eq!(min.len(), MIN_RANGE.len());
        assert_eq!(max.len(), MAX_RANGE.len());
        assert_eq!(index_value.len(), BLOCK_NUMBER_RANGE.len());
        assert_eq!(commitment.len(), BLOCK_HASH_RANGE.len());
        assert_eq!(prev_commitment.len(), BLOCK_HASH_RANGE.len());
        assert_eq!(metadata_hash.len(), METADATA_HASH_RANGE.len());
        assert_eq!(new_node_digest.len(), NEW_NODE_DIGEST_RANGE.len());
        Self {
            h_new,
            h_old,
            min,
            max,
            block_number: index_value,
            block_hash: commitment,
            prev_block_hash: prev_commitment,
            metadata_hash,
            new_node_digest,
        }
    }
    /// Create from a slice.
    pub fn from_slice(pi: &'a [T]) -> Self {
        assert!(pi.len() >= Self::TOTAL_LEN);

        Self {
            h_new: &pi[H_NEW_RANGE],
            h_old: &pi[H_OLD_RANGE],
            min: &pi[MIN_RANGE],
            max: &pi[MAX_RANGE],
            block_number: &pi[BLOCK_NUMBER_RANGE],
            block_hash: &pi[BLOCK_HASH_RANGE],
            prev_block_hash: &pi[PREV_BLOCK_HASH_RANGE],
            metadata_hash: &pi[METADATA_HASH_RANGE],
            new_node_digest: &pi[NEW_NODE_DIGEST_RANGE],
        }
    }

    /// Combine to a vector.
    pub fn to_vec(&self) -> Vec<T> {
        self.h_new
            .iter()
            .chain(self.h_old)
            .chain(self.min)
            .chain(self.max)
            .chain(self.block_number)
            .chain(self.block_hash)
            .chain(self.prev_block_hash)
            .chain(self.metadata_hash)
            .chain(self.new_node_digest)
            .cloned()
            .collect()
    }
    pub fn metadata_hash(&self) -> &[T] {
        self.metadata_hash
    }
}

#[cfg(test)]
mod tests {
    use crate::block_tree::tests::random_block_index_pi;

    use super::*;
    use crate::{C, D, F};
    use mp2_test::circuit::{run_circuit, UserCircuit};
    use plonky2::iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    };
    use rand::{thread_rng, Rng};

    #[derive(Clone, Debug)]
    struct TestPICircuit<'a> {
        exp_pi: &'a [F],
    }

    impl UserCircuit<F, D> for TestPICircuit<'_> {
        type Wires = Vec<Target>;

        fn build(b: &mut CBuilder) -> Self::Wires {
            let pi = b.add_virtual_targets(PublicInputs::<Target>::TOTAL_LEN);
            PublicInputs::from_slice(&pi).register(b);

            pi
        }

        fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
            pw.set_target_arr(wires, self.exp_pi);
        }
    }

    #[test]
    fn test_block_insertion_public_inputs() {
        let mut rng = thread_rng();

        let [min, max, block_number] = [0; 3].map(|_| U256::from_limbs(rng.gen::<[u64; 4]>()));
        let exp_pi = random_block_index_pi(&mut rng, min, max, block_number).to_vec();

        let test_circuit = TestPICircuit { exp_pi: &exp_pi };
        let proof = run_circuit::<F, D, C, _>(test_circuit);

        assert_eq!(&proof.public_inputs, &exp_pi);
        assert_eq!(exp_pi.len(), super::PublicInputs::<Target>::TOTAL_LEN);
    }
}
