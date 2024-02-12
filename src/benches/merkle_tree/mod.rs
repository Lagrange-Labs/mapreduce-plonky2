//! This module tests for a Merkle Tree with recursive proofs.

use crate::{
    circuit::{CyclicCircuit, PCDCircuit},
    merkle_tree::{DigestTreeCircuit, MerkleNode, MerkleTree},
};
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};

mod canonical_hashing;

/// The degree of circuit builder and generic configuration
const D: usize = 2;

/// Generic configuration
type C = PoseidonGoldilocksConfig;

/// Base field
type F = <C as GenericConfig<D>>::F;

/// Prove and generate proofs for all Merkle tree leaves.
fn prove_all_leaves<O, U, const ARITY: usize>(
    circuit: &CyclicCircuit<F, C, D, U, ARITY>,
    tree: &mut MerkleTree<F, C, D, O>,
) where
    U: PCDCircuit<F, D, ARITY> + DigestTreeCircuit<O>,
    O: Clone,
{
    // Iterate all Merkle tree leaves to generate proofs and save to the nodes.
    tree.all_leaves()
        .iter_mut()
        .enumerate()
        .for_each(|(i, leaf)| {
            if let MerkleNode::Leaf(value, _, proof_result) = leaf {
                println!("[+] Proving leaf {} with value {:?}", i, value);
                // Generate the proof.
                let proof = circuit.prove_init(U::new_leaf(value.clone())).unwrap().0;

                // Verify the proof for test.
                circuit
                    .verify_proof(proof.clone())
                    .expect("Failed to verify proof");

                // Save proof to the node for further using when proving parent
                // branch.
                *proof_result = Some(proof);
            } else {
                panic!("Must be a leaf of tree");
            }
        });
}

/// Prove and generate proofs for all Merkle tree branches from lowest levels to
/// high recursively. It should be complete until proving the root.
fn prove_branches_recursive<O, U, const ARITY: usize>(
    circuit: &CyclicCircuit<F, C, D, U, ARITY>,
    tree: &mut MerkleTree<F, C, D, O>,
) where
    U: PCDCircuit<F, D, ARITY> + DigestTreeCircuit<O>,
    O: Clone,
{
    // Prove branches from lowest levels to high.
    let max_level = tree.max_level();
    (0..max_level).rev().for_each(|level| {
        // Get branches at the specified level.
        tree.branches_at_level(level)
            .iter_mut()
            .enumerate()
            .for_each(|(i, branch)| {
                if let MerkleNode::Branch(children, .., proof_result) = branch {
                    println!("[+] Proving branch {} at level {}", i, level);
                    // The children have already been proved before, since we
                    // process from lowest to high.
                    let inputs: Vec<_> =
                        children.iter().map(|node| node.output().clone()).collect();
                    let last_proofs = core::array::from_fn(|i| {
                        children.get(i).map(|c| c.proof().clone().unwrap())
                    });

                    // Generate the proof.
                    let proof = circuit
                        .prove_step(U::new_branch(inputs), &last_proofs)
                        .unwrap()
                        .0;

                    // Verify the proof for test.
                    circuit
                        .verify_proof(proof.clone())
                        .expect("Failed to verify proof");

                    // Save proof to the node for further using when proving parent
                    // branch.
                    *proof_result = Some(proof);
                } else {
                    panic!("Must be a branch of tree");
                }
            });
    });
}
