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
use public_inputs::PublicInputs;
use std::array;

/// Block tree wires
pub struct BlockTreeWires<const MAX_DEPTH: usize>
where
    [(); MAX_DEPTH + 1]:,
{
    /// The index of new leaf is given by its little-endian bits. It corresponds
    /// to the plonky2 [verify_merkle_proof argument](https://github.com/0xPolygonZero/plonky2/blob/62ffe11a984dbc0e6fe92d812fa8da78b7ba73c7/plonky2/src/hash/merkle_proofs.rs#L98).
    leaf_index_bits: [BoolTarget; MAX_DEPTH],
    /// The path starts from the sibling of new leaf (block), and the parent's
    /// siblings at each level, till to the root. It corresponds to the plonky2
    /// [MerkleProofTarget](https://github.com/0xPolygonZero/plonky2/blob/62ffe11a984dbc0e6fe92d812fa8da78b7ba73c7/plonky2/src/hash/merkle_proofs.rs#L37).
    // The +1 is because it includes the root as well in the path.
    path: [HashOutTarget; MAX_DEPTH + 1],
}

/// Block tree circuit used to prove the correct updating of the block tree
#[derive(Clone, Debug)]
pub struct BlockTreeCircuit<F, const MAX_DEPTH: usize>
where
    F: RichField,
    [(); MAX_DEPTH + 1]:,
{
    /// The new leaf index is equal to `new_block_number - first_block_number`,
    /// it's zero for the first inserted block. It's decomposed to bits which
    /// represents if new leaf is the left or right child at each level, and we
    /// could know the corresponding siblings (if left or right) in path. It
    /// corresponds to the plonky2 [verify_merkle_proof argument](https://github.com/0xPolygonZero/plonky2/blob/62ffe11a984dbc0e6fe92d812fa8da78b7ba73c7/plonky2/src/hash/merkle_proofs.rs#L44).
    leaf_index: usize,
    /// The path starts from the sibling of new leaf (block), and the parent's
    /// siblings at each level, till to the root. It corresonds to the plonky2
    /// [MerkleProof](https://github.com/0xPolygonZero/plonky2/blob/62ffe11a984dbc0e6fe92d812fa8da78b7ba73c7/plonky2/src/hash/merkle_proofs.rs#L21).
    path: [HashOut<F>; MAX_DEPTH + 1],
}

impl<F, const MAX_DEPTH: usize> BlockTreeCircuit<F, MAX_DEPTH>
where
    F: RichField,
    [(); MAX_DEPTH + 1]:,
{
    pub fn new(leaf_index: usize, path: [HashOut<F>; MAX_DEPTH + 1]) -> Self {
        Self { leaf_index, path }
    }

    /// Build for the circuit. The arguments are:
    /// - prev_pi: Previous outputs of Merkle tree (the current circuit). It's a
    ///   dummy proof if the new leaf is the first inserted block, the dummy
    ///   proof must be set as `first_block_number = new_block_number` and
    ///   `block_number = new_block_number - 1`.
    /// - new_leaf_pi: Public inputs of the new leaf (state root).
    pub fn build<const D: usize>(
        cb: &mut CircuitBuilder<F, D>,
        prev_pi: &[Target],
        new_leaf_pi: &[Target],
    ) -> BlockTreeWires<MAX_DEPTH>
    where
        F: Extendable<D>,
    {
        // Wrap the public inputs.
        let prev_pi = PublicInputs::from(prev_pi);
        let new_leaf_pi = LeafInputs::from(new_leaf_pi);

        // Initialize the targets in wires.
        let leaf_index_bits = array::from_fn(|_| cb.add_virtual_bool_target_safe());
        let path = array::from_fn(|_| cb.add_virtual_hash());

        // Verify the previous outputs and the new leaf (block) public inputs.
        verify_proofs(cb, &prev_pi, &new_leaf_pi, &leaf_index_bits);

        // Verify both the old and new roots of the block tree which are
        // calculated from the leaves sequentially.
        verify_append_only(cb, &prev_pi, &new_leaf_pi, &leaf_index_bits, &path);

        let wires = BlockTreeWires {
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
    pub fn assign(&self, pw: &mut PartialWitness<F>, wires: &BlockTreeWires<MAX_DEPTH>) {
        // Split the leaf index into a list of bits, which represents if the new
        // leaf is the left or right child at each level. It corresponds the
        // circuit function `split_le`. Reference the plonky2
        // [verify_merkle_proof_to_cap](https://github.com/0xPolygonZero/plonky2/blob/62ffe11a984dbc0e6fe92d812fa8da78b7ba73c7/plonky2/src/hash/merkle_proofs.rs#L54).
        let mut index = self.leaf_index;
        for i in 0..MAX_DEPTH {
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
) {
    // Check the previous block header.
    prev_pi
        .block_header()
        .enforce_equal(cb, &new_leaf_pi.prev_block_header());

    let first_block_num = prev_pi.first_block_number();
    let prev_block_num = prev_pi.block_number();
    let new_block_num = new_leaf_pi.block_number();

    // The new leaf is the first inserted block if leaf index is zero.
    let zero = cb.zero();
    let leaf_index = cb.le_sum(leaf_index_bits.iter());
    let is_first = cb.is_equal(leaf_index, zero);

    // Check the sequentiality as
    // `first_block_number + leaf_index = new_block_number`.
    let exp_block_num = cb.add(first_block_num.0, leaf_index);
    cb.connect(exp_block_num, new_block_num.0);

    // Check `prev_block_number + 1 == new_block_number`.
    let one = cb.one();
    let exp_block_num = cb.add(prev_block_num.0, one);
    cb.connect(exp_block_num, new_block_num.0);

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        benches::init_logging,
        circuit::{test::run_circuit, UserCircuit},
        keccak::PACKED_HASH_LEN,
        utils::test::random_vector,
    };
    use anyhow::Result;
    use plonky2::{
        field::types::Field,
        hash::{
            hash_types::NUM_HASH_OUT_ELTS, merkle_proofs::verify_merkle_proof,
            merkle_proofs::MerkleProof, merkle_tree::MerkleTree,
        },
        plonk::config::{GenericConfig, PoseidonGoldilocksConfig},
    };
    use rand::{thread_rng, Rng};

    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    /// Test circuit
    #[derive(Clone, Debug)]
    struct TestCircuit<const MAX_DEPTH: usize>
    where
        [(); MAX_DEPTH + 1]:,
    {
        prev_pi: Vec<F>,
        new_leaf_pi: Vec<F>,
        c: BlockTreeCircuit<F, MAX_DEPTH>,
    }

    impl<const MAX_DEPTH: usize> UserCircuit<F, D> for TestCircuit<MAX_DEPTH>
    where
        [(); MAX_DEPTH + 1]:,
    {
        type Wires = (Vec<Target>, Vec<Target>, BlockTreeWires<MAX_DEPTH>);

        fn build(cb: &mut CircuitBuilder<F, D>) -> Self::Wires {
            let prev_pi = cb.add_virtual_targets(PublicInputs::<Target>::TOTAL_LEN);
            let new_leaf_pi = cb.add_virtual_targets(LeafInputs::<Target>::TOTAL_LEN);

            let wires = BlockTreeCircuit::build(cb, &prev_pi, &new_leaf_pi);

            (prev_pi, new_leaf_pi, wires)
        }

        fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
            pw.set_target_arr(&wires.0, &self.prev_pi);
            pw.set_target_arr(&wires.1, &self.new_leaf_pi);

            self.c.assign(pw, &wires.2);
        }
    }

    /// Test the block-tree circuit for inserting the first block to an empty
    /// tree (is_first = true).
    #[test]
    fn test_block_tree_circuit_for_first_block() {
        const MAX_DEPTH: usize = 4;

        test_circuit::<MAX_DEPTH>(0);
    }

    /// Test the block-tree circuit for inserting the block at a random leaf
    /// index, the previous leaves have already been inserted before.
    #[test]
    fn test_block_tree_circuit_for_random_leaf_index() {
        const MAX_DEPTH: usize = 4;

        let leaf_count = 1 << MAX_DEPTH;

        // Generate a random leaf index.
        let mut rng = thread_rng();
        let leaf_index = rng.gen_range(1..leaf_count);

        test_circuit::<MAX_DEPTH>(leaf_index);
    }

    /// Run the test circuit with a specified new leaf index.
    fn test_circuit<const MAX_DEPTH: usize>(leaf_index: usize)
    where
        [(); MAX_DEPTH + 1]:,
    {
        init_logging();

        // Generate the all leaves, the new leaf is specified at given index.
        let first_block_num = thread_rng().gen_range(1..10_000);
        let leaves = generate_all_leaves::<MAX_DEPTH>(first_block_num, leaf_index);

        // Cache the previous and new leaf data.
        let leaf_data = leaves[leaf_index].clone();
        let prev_leaf_index = leaf_index.checked_sub(1).unwrap_or_default();
        let prev_leaf_data = leaves[prev_leaf_index].clone();

        // Generate the old root without the new leaf.
        let mut old_leaves = leaves.clone();
        old_leaves[leaf_index] = vec![];
        let old_root = merkle_root(old_leaves);

        // Generate the new path (till to the new root).
        let path = merkle_path(leaf_index, leaves);

        // Verify the path, old and new roots (out of circuit).
        let (new_root, siblings) = path.split_last().unwrap();
        let siblings = siblings.to_vec();
        let merkle_proof = MerkleProof { siblings };
        verify_merkle_proof::<_, PoseidonHash>(vec![], leaf_index, old_root.clone(), &merkle_proof)
            .unwrap();
        verify_merkle_proof::<_, PoseidonHash>(
            leaf_data.clone(),
            leaf_index,
            *new_root,
            &merkle_proof,
        )
        .unwrap();

        // Generate the previous public inputs of Merkle tree.
        let prev_pi =
            tree_inputs::<MAX_DEPTH>(leaf_index == 0, first_block_num, &prev_leaf_data, old_root);

        // Generate the public inputs of the new leaf.
        let new_leaf_pi = new_leaf_inputs(&leaf_data, &prev_pi);

        // Get the expected outputs.
        let exp_outputs = expected_outputs(&prev_pi, &new_leaf_pi, path.last().unwrap());

        // Run the circuit.
        let test_circuit = TestCircuit::<MAX_DEPTH> {
            c: BlockTreeCircuit::new(leaf_index, path),
            prev_pi,
            new_leaf_pi,
        };
        let proof = run_circuit::<F, D, C, _>(test_circuit);

        // Verify the outputs.
        assert_eq!(exp_outputs, proof.public_inputs);
    }

    /// Generate the all leaves of a Merkle tree, the new leaf (block) is
    /// specified at the given index.
    fn generate_all_leaves<const MAX_DEPTH: usize>(
        first_block_num: usize,
        leaf_index: usize,
    ) -> Vec<Vec<F>> {
        let leaf_count = 1 << MAX_DEPTH;
        assert!(leaf_index < leaf_count);

        (0..leaf_count)
            .map(|i| {
                if i <= leaf_index {
                    rand_leaf_data(first_block_num + i)
                } else {
                    vec![]
                }
            })
            .collect()
    }

    /// Generate the Merkle root from leaves.
    fn merkle_root(leaves: Vec<Vec<F>>) -> HashOut<F> {
        // Construct the Merkle tree.
        let tree = MerkleTree::<_, PoseidonHash>::new(leaves, 0);
        assert_eq!(tree.cap.0.len(), 1, "Merkle tree must have one root");

        tree.cap.0[0]
    }

    /// Generate the Merkle path from leaves.
    fn merkle_path<const MAX_DEPTH: usize>(
        leaf_index: usize,
        leaves: Vec<Vec<F>>,
    ) -> [HashOut<F>; MAX_DEPTH + 1] {
        // Construct the Merkle tree.
        let tree = MerkleTree::<F, PoseidonHash>::new(leaves, 0);
        assert_eq!(tree.cap.0.len(), 1, "Merkle tree must have one root");

        // Generate the siblings at the each level (without root).
        let merkle_proof = tree.prove(leaf_index);
        let mut path = merkle_proof.siblings;

        // Append the root to the path.
        path.push(tree.cap.0[0]);

        path.try_into().unwrap()
    }

    /// Generate the public inputs of Merkle tree (the current circuit).
    fn tree_inputs<const MAX_DEPTH: usize>(
        is_dummy: bool,
        first_block_num: usize,
        leaf_data: &[F],
        root: HashOut<F>,
    ) -> Vec<F> {
        // All leaves are empty for the init root.
        let init_root = merkle_root(generate_all_leaves::<MAX_DEPTH>(first_block_num, 0));

        // [state_root, block_number, block_header]
        assert_eq!(leaf_data.len(), NUM_HASH_OUT_ELTS + 1 + PACKED_HASH_LEN);
        let block_header = leaf_data[NUM_HASH_OUT_ELTS + 1..].to_vec();

        // The block number is set to `first_block_number - 1` for dummy proofs.
        let first_block_num = F::from_canonical_usize(first_block_num);
        let block_num = if is_dummy {
            leaf_data[NUM_HASH_OUT_ELTS]
        } else {
            first_block_num - F::ONE
        };

        // [init_root, root, first_block_number, block_number, block_header]
        init_root
            .elements
            .into_iter()
            .chain(root.elements)
            .chain([first_block_num, block_num])
            .chain(block_header)
            .collect()
    }

    /// Generate the public inputs of new Merkle leaf (state root).
    fn new_leaf_inputs(leaf_data: &[F], prev_pi: &[F]) -> Vec<F> {
        // [state_root, block_number, block_header]
        assert_eq!(leaf_data.len(), NUM_HASH_OUT_ELTS + 1 + PACKED_HASH_LEN);
        let state_root = &leaf_data[..NUM_HASH_OUT_ELTS];
        let block_num = leaf_data[NUM_HASH_OUT_ELTS];
        let block_header = &leaf_data[NUM_HASH_OUT_ELTS + 1..];

        let prev_pi = PublicInputs::from(prev_pi);
        let prev_block_header = prev_pi.block_header_data();

        // [state_root, block_header, block_number, prev_block_header]
        state_root
            .iter()
            .chain(block_header)
            .chain(&[block_num])
            .chain(prev_block_header)
            .cloned()
            .collect()
    }

    /// Get the expected outputs.
    fn expected_outputs(prev_pi: &[F], new_leaf_pi: &[F], new_root: &HashOut<F>) -> Vec<F> {
        let prev_pi = PublicInputs::from(prev_pi);
        let new_leaf_pi = LeafInputs::from(new_leaf_pi);

        // [init_root, root, first_block_number, block_number, block_header]
        prev_pi
            .init_root_data()
            .iter()
            .cloned()
            .chain(new_root.elements)
            .chain([
                prev_pi.first_block_number_data(),
                new_leaf_pi.block_number_data(),
            ])
            .chain(new_leaf_pi.block_header_data().iter().cloned())
            .collect()
    }

    /// Generate the random leaf data.
    fn rand_leaf_data(block_num: usize) -> Vec<F> {
        // Generate as [state_root, block_number, block_header].
        let mut data: Vec<_> = random_vector(NUM_HASH_OUT_ELTS + 1 + PACKED_HASH_LEN)
            .into_iter()
            .map(F::from_canonical_usize)
            .collect();

        // Set the block number.
        data[NUM_HASH_OUT_ELTS] = F::from_canonical_usize(block_num);

        data
    }
}
