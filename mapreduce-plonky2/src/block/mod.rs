//! This circuit proves the correct updating of the block tree. There're steps
//! on how to prove the correct construction:
//! - Prove the sequentiality property of the last block inserted.
//! - Prove we include the new block right after the previous block inserted.
//! - Prove the append-only property, that we keep appending blocks without
//!   deletion and modification.

mod public_inputs;

use crate::state::PublicInputs as LeafInputs;
use plonky2::{
    field::extension::Extendable,
    hash::{
        hash_types::{HashOut, HashOutTarget, RichField},
        merkle_proofs::MerkleProofTarget,
        poseidon::PoseidonHash,
    },
    iop::{
        target::{BoolTarget, Target},
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::circuit_builder::CircuitBuilder,
};
use plonky2_crypto::u32::arithmetic_u32::CircuitBuilderU32;
use plonky2_crypto::u32::arithmetic_u32::U32Target;
use public_inputs::PublicInputs;
use std::array;

/// Block tree wires
pub struct BlockTreeWires<const DEPTH: usize>
where
    [(); DEPTH - 1]:,
{
    /// The flag identified if the new leaf is the first inserted block
    is_first: BoolTarget,
    /// The index of new leaf is given by its little-endian bits. It corresponds
    /// to the plonky2 [verify_merkle_proof argument](https://github.com/0xPolygonZero/plonky2/blob/62ffe11a984dbc0e6fe92d812fa8da78b7ba73c7/plonky2/src/hash/merkle_proofs.rs#L98).
    leaf_index_bits: [BoolTarget; DEPTH - 1],
    /// The path starts from the sibling of new leaf (block), and the parent's
    /// siblings at each level, till to the root. It corresponds to the plonky2
    /// [MerkleProofTarget](https://github.com/0xPolygonZero/plonky2/blob/62ffe11a984dbc0e6fe92d812fa8da78b7ba73c7/plonky2/src/hash/merkle_proofs.rs#L37).
    path: [HashOutTarget; DEPTH],
}

/// Block tree circuit used to prove the correct updating of the block tree
#[derive(Clone, Debug)]
pub struct BlockTreeCircuit<F, const DEPTH: usize>
where
    F: RichField,
{
    /// The flag identified if the current is the first inserted block
    is_first: bool,
    /// The new leaf index is equal to `new_block_number - first_block_number`.
    /// It's decomposed to bits which represents if new leaf is the left or
    /// right child at each level, so we know the corresponding siblings
    /// (if left or right) in path. It corresponds to the plonky2
    /// [verify_merkle_proof argument](https://github.com/0xPolygonZero/plonky2/blob/62ffe11a984dbc0e6fe92d812fa8da78b7ba73c7/plonky2/src/hash/merkle_proofs.rs#L44).
    leaf_index: usize,
    /// The path starts from the sibling of new leaf (block), and the parent's
    /// siblings at each level, till to the root. It corresonds to the plonky2
    /// [MerkleProof](https://github.com/0xPolygonZero/plonky2/blob/62ffe11a984dbc0e6fe92d812fa8da78b7ba73c7/plonky2/src/hash/merkle_proofs.rs#L21).
    path: [HashOut<F>; DEPTH],
}

impl<F, const DEPTH: usize> BlockTreeCircuit<F, DEPTH>
where
    F: RichField,
    [(); DEPTH - 1]:,
{
    pub fn new(is_first: bool, leaf_index: usize, path: [HashOut<F>; DEPTH]) -> Self {
        Self {
            is_first,
            leaf_index,
            path,
        }
    }

    /// Build for the circuit. The arguments are:
    /// - prev_pi: Previous outputs of this circuit
    /// - new_leaf_pi: Public inputs of the new leaf (block)
    // New block tree leaf (state root public inputs)
    pub fn build<const D: usize>(
        cb: &mut CircuitBuilder<F, D>,
        prev_pi: &[Target],
        new_leaf_pi: &[Target],
    ) -> BlockTreeWires<DEPTH>
    where
        F: Extendable<D>,
    {
        // Wrap the public inputs.
        let prev_pi = PublicInputs::from(prev_pi);
        let new_leaf_pi = LeafInputs::from(new_leaf_pi);

        // Initialize the targets in wires.
        let is_first = cb.add_virtual_bool_target_safe();
        let leaf_index_bits = array::from_fn(|_| cb.add_virtual_bool_target_safe());
        let path = array::from_fn(|_| cb.add_virtual_hash());

        // Verify the previous outputs and the new leaf (block) public inputs.
        verify_proofs(cb, &prev_pi, &new_leaf_pi, &leaf_index_bits, is_first);

        // Verify both the old and new roots of the block tree which are
        // calculated from the leaves sequentially.
        verify_append_only(cb, &prev_pi, &new_leaf_pi, &leaf_index_bits, &path);

        let wires = BlockTreeWires {
            is_first,
            leaf_index_bits,
            path,
        };

        // Register the public inputs.
        PublicInputs::register(
            cb,
            &prev_pi.init_root(),
            path.last().unwrap(),
            prev_pi.first_block_number(),
            new_leaf_pi.block_number(),
            &new_leaf_pi.block_header(),
        );

        wires
    }

    /// Assign the wires.
    pub fn assign(&self, pw: &mut PartialWitness<F>, wires: &BlockTreeWires<DEPTH>) {
        pw.set_bool_target(wires.is_first, self.is_first);

        // Split the leaf index into a list of bits, which represents if the new
        // leaf is the left or right child at each level. It corresponds the
        // circuit function `split_le`. Reference the plonky2
        // [verify_merkle_proof_to_cap](https://github.com/0xPolygonZero/plonky2/blob/62ffe11a984dbc0e6fe92d812fa8da78b7ba73c7/plonky2/src/hash/merkle_proofs.rs#L54C8-L54C34).
        let mut index = self.leaf_index;
        for i in 0..DEPTH - 1 {
            let bit = index & 1;
            index >>= 1;
            pw.set_bool_target(wires.leaf_index_bits[i], bit == 1);
        }

        wires
            .path
            .into_iter()
            .zip(self.path)
            .for_each(|(t, v)| pw.set_hash_target(t, v));
    }
}

/// Verify the previous outputs and the new leaf (block) public inputs.
fn verify_proofs<F: RichField + Extendable<D>, const D: usize>(
    cb: &mut CircuitBuilder<F, D>,
    prev_pi: &PublicInputs<Target>,
    new_leaf_pi: &LeafInputs<Target>,
    leaf_index_bits: &[BoolTarget],
    is_first: BoolTarget,
) {
    let first_block_num = prev_pi.first_block_number();
    let prev_block_num = prev_pi.block_number();
    let new_block_num = new_leaf_pi.block_number();

    // Check the previous block header.
    prev_pi
        .block_header()
        .enforce_equal(cb, &new_leaf_pi.prev_block_header());

    // Check `prev_block_number + 1 == new_block_number`.
    let one = cb.one_u32();
    let (exp_block_num, overflow) = cb.add_u32(prev_block_num, one);
    cb.assert_zero_u32(overflow);
    cb.connect_u32(exp_block_num, new_block_num);

    // Check the sequentiality as
    // `first_block_number + leaf_index = new_block_number`.
    let leaf_index = cb.le_sum(leaf_index_bits.iter());
    let (exp_block_num, overflow) = cb.add_u32(first_block_num, U32Target(leaf_index));
    cb.assert_zero_u32(overflow);
    cb.connect_u32(exp_block_num, new_block_num);

    // Check that the first block number of previous proof is set accordingly to
    // the new one if this is the first block inserted to the block tree.
    let exp_first_block_num = cb.select(is_first, new_block_num.0, first_block_num.0);
    cb.connect(exp_first_block_num, first_block_num.0);
}

/// Verify both the old and new roots of the block tree which are calculated
/// from the leaves sequentially.
fn verify_append_only<F: RichField + Extendable<D>, const D: usize>(
    cb: &mut CircuitBuilder<F, D>,
    prev_pi: &PublicInputs<Target>,
    new_leaf_pi: &LeafInputs<Target>,
    leaf_index_bits: &[BoolTarget],
    path: &[HashOutTarget],
) {
    // Get the old and new roots.
    let old_root = prev_pi.root();
    let (new_root, siblings) = path.split_last().unwrap();

    // Construct the Merkle proof.
    let siblings = siblings.to_vec();
    let merkle_proof = MerkleProofTarget { siblings };

    // Get the new leaf data.
    let leaf_data = leaf_data(cb, new_leaf_pi);

    // Verify the new leaf is present at the given index in Merkle tree with the new root.
    cb.verify_merkle_proof::<PoseidonHash>(leaf_data, leaf_index_bits, *new_root, &merkle_proof);

    // Verify the leaf is empty at the given index in Merkle tree with the old root.
    cb.verify_merkle_proof::<PoseidonHash>(vec![], leaf_index_bits, old_root, &merkle_proof);
}

/// Get the leaf data from public inputs.
fn leaf_data<F: RichField + Extendable<D>, const D: usize>(
    cb: &mut CircuitBuilder<F, D>,
    leaf_pi: &LeafInputs<Target>,
) -> Vec<Target> {
    let state_root = leaf_pi.root().elements;
    let block_number = leaf_pi.block_number().0;
    let block_header = leaf_pi.block_header().arr.map(|u32_target| u32_target.0);

    // Join as [state_root, block_number, block_header].
    state_root
        .into_iter()
        .chain([block_number])
        .chain(block_header)
        .collect()
}
