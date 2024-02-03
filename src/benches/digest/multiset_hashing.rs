//! Multiset hashing circuit benchmark and test with Merkle tree.

use super::{prove_all_leaves, prove_branches_recursive, C, D, F};
use crate::{
    benches::init_logging,
    circuit::{CyclicCircuit, UserCircuit},
    digest::{
        hash_to_field_point_value, MerkleLeafValue, MerkleNode, MerkleTree, MultisetHashingCircuit,
        MultisetHashingPointValue,
    },
    utils::read_le_u32,
};
use plonky2::{
    field::types::Field,
    hash::{hashing::hash_n_to_m_no_pad, poseidon::PoseidonPermutation},
    plonk::circuit_builder::CircuitBuilder,
};
use rand::Rng;

/// The Merkle tree for testing multiset hashing is a binary tree.
const ARITY: usize = 2;

/// The extension degree, it's different with generic configuration degree (D).
const N: usize = 5;

/// The Merkle tree types
type Value = MultisetHashingPointValue<F, N>;
type Tree = MerkleTree<F, C, D, Value>;
type Node = MerkleNode<F, C, D, Value>;

/// The user circuit and recursive circuit
type TestCircuit = MultisetHashingCircuit<F, D, N>;
type RecursiveCircuit = CyclicCircuit<F, C, D, TestCircuit, ARITY>;

/// Benchmark and test the multiset hashing circuit.
#[ignore]
#[test]
fn test_multiset_hashing_circuit() {
    init_logging();

    // Initialize the recursive circuit and testing Merkle tree.
    let circuit = recursive_circuit();
    let mut tree = merkle_tree();

    // Prove the Merkle tree (binary tree) from lowest leaves to high branches
    // until root, for example we have the below Merkle tree:
    //
    //          root
    //          /  \
    //         /    \
    //   branch1    branch2
    //    /  \       /  \
    //   /    \     /    \
    // v1     v2   v3     v4
    //
    // The proving process should be:
    // . The four leaves have values of v1, v2, v3 and v4.
    // . `prove_all_leaves` function proves and generates Poseidon hashes for
    //   leaves as H(v1), H(v2), H(v3) and H(v4), then converts each hash value
    //   to an extension point as (X, Y).
    // . `prove_branches_recursive` function adds the extension points of two
    //   children as its value for all branches recursively. There're two
    //   branches in this Merkle tree. The value of branch1 should be
    //   (X1 + X2, Y1 + Y2), and branch2 should be (X3 + X4, Y3 + Y4).
    // . `prove_branches_recursive` function calculates the extension point for
    //   the root finially. It should be (X1 + X2 + X3 + X4, Y1 + Y2 + Y3 + Y4).
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

/// Create a Merkle tree (binary tree) with testing branches and leaves.
fn merkle_tree() -> Tree {
    let [v1, v2, v3, v4] = [0; 4].map(|_| rand_leaf());
    let branch1 = new_branch(vec![v1, v2]);
    let branch2 = new_branch(vec![v3, v4]);

    let root = new_branch(vec![branch1, branch2]);

    MerkleTree::new(root)
}

/// Create a branch of Merkle tree by child nodes.
fn new_branch(children: Vec<Node>) -> Node {
    assert!(children.len() > 0 && children.len() <= ARITY);

    // Add the child extension points as the value of this branch.
    let addition = children
        .iter()
        .fold(Value::default(), |acc, node| &acc + node.output());

    Node::Branch(children, addition, None)
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

    // Calculate the Poseidon hash and output N values of base field.
    let hash: [F; N] = hash_n_to_m_no_pad::<F, PoseidonPermutation<F>>(&inputs, N)
        .try_into()
        .unwrap();

    // Convert the hash to an extension point.
    let point = hash_to_field_point_value(hash);

    Node::Leaf(value, point, None)
}

/// Create a leaf of Merkle tree by random value.
fn rand_leaf() -> Node {
    new_leaf(rand::thread_rng().gen::<[u8; 32]>())
}
