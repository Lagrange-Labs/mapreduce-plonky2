//! This module implements a Merkle Tree with recursive proofs that handle a
//! maximum number of children proofs. It is meant as a fallback in case group
//! hashing does not work as expected. Specifically, this tree allows to prove
//! it contains the same set of leaves than another MPT tree without requiring
//! order agnostic canonical hashing. The downside is that it requires the
//! structure to mimick exactly the same as the MPT one. It still gains on the
//! avoidance of RLP and keccak, but keeps the extra cost of verifying a maximum
//! number of proofs.

use super::{prove_all_leaves, prove_branches_recursive, C, D, F};
use crate::{
    benches::init_logging,
    circuit::{CyclicCircuit, UserCircuit},
    merkle_tree::{DigestArityCircuit, MerkleLeafValue, MerkleNode, MerkleTree},
    utils::read_le_u32,
};
use plonky2::{
    field::types::Field,
    hash::{hash_types::HashOut, hashing::hash_n_to_hash_no_pad, poseidon::PoseidonPermutation},
    plonk::circuit_builder::CircuitBuilder,
};
use rand::Rng;

/// The maximum child number of a Merkle tree branch
const ARITY: usize = 4;

/// The Merkle tree and node types
type Tree = MerkleTree<F, C, D, HashOut<F>>;
type Node = MerkleNode<F, C, D, HashOut<F>>;

/// The user circuit and recursive circuit
type TestCircuit = DigestArityCircuit<F, D, ARITY>;
type RecursiveCircuit = CyclicCircuit<F, C, D, TestCircuit, ARITY>;

/// Benchmark and test the canonical hashing circuit.
#[test]
fn test_canonical_hashing_circuit() {
    init_logging();

    // Initialize the recursive circuit and testing Merkle tree.
    let circuit = recursive_circuit();
    let mut tree = merkle_tree();

    // Prove the Merkle tree from the lowest leaves to high branches until root,
    // for example we have the below Merkle tree:
    //
    // root
    // |   \
    // |    \
    // v1    branch
    //       |  \  \
    //       |   \  \
    //       v2  v3  v4
    //
    // The proving process should be:
    // . The four leaves have values of v1, v2, v3 and v4.
    // . `prove_all_leaves` function proves and generates Poseidon hashes for
    //   leaves as H(v1), H(v2), H(v3) and H(v4).
    // . `prove_branches_recursive` function generates Poseidon hashes for all
    //   branches recursively. There is only one branch in this Merkle tree. It
    //   should be H(H(v2) || H(v3) || H(v4)).
    // . `prove_branches_recursive` function generates Poseidon hash for the
    //   root finially. It should be H(H(v1) || H(H(v2) || H(v3) || H(v4))).
    prove_all_leaves(&circuit, &mut tree);
    prove_branches_recursive(&circuit, &mut tree);
}

/// Create a cyclic circuit for proving recursively.
fn recursive_circuit() -> RecursiveCircuit {
    let padder = |b: &mut CircuitBuilder<F, D>| {
        TestCircuit::build(b);

        14
    };

    RecursiveCircuit::new(padder)
}

/// Create a Merkle tree with testing branches and leaves.
fn merkle_tree() -> Tree {
    let [v1, v2, v3, v4] = [0; 4].map(|_| rand_leaf());
    let branch = new_branch(vec![v2, v3, v4]);

    let root = new_branch(vec![v1, branch]);

    Tree::new(root)
}

/// Create a branch of Merkle tree by child nodes.
fn new_branch(children: Vec<Node>) -> Node {
    assert!(children.len() > 0 && children.len() <= ARITY);

    // Flatten the child hash values and calculate hash for this branch.
    let inputs: Vec<_> = children
        .iter()
        .flat_map(|node| node.output().elements)
        .collect();
    let hash = hash_n_to_hash_no_pad::<F, PoseidonPermutation<F>>(&inputs);

    Node::Branch(children, hash, None)
}

/// Create a leaf of Merkle tree by value.
fn new_leaf(value: MerkleLeafValue) -> Node {
    // Convert the value of u8 array to u32, then convert to field.
    let inputs: Vec<_> = value
        .chunks(4)
        .into_iter()
        .map(|mut chunk| {
            let u32_num = read_le_u32(&mut chunk);
            F::from_canonical_u32(u32_num)
        })
        .collect();

    let hash = hash_n_to_hash_no_pad::<F, PoseidonPermutation<F>>(&inputs);

    Node::Leaf(value, hash, None)
}

/// Create a leaf of Merkle tree by random value.
fn rand_leaf() -> Node {
    new_leaf(rand::thread_rng().gen::<[u8; 32]>())
}
