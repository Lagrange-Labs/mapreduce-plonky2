//! Multiset hashing circuit benchmark and test with Merkle tree.

use super::{prove_all_leaves, prove_branches_recursive, C, D, F};
use crate::{
    benches::init_logging,
    circuit::{CyclicCircuit, UserCircuit},
    digest::{
        MerkleLeafValue, MerkleNode, MerkleTree, MultisetHashingCircuit, ECGFP5_EXT_DEGREE as N,
    },
    map_to_curve::ToCurvePoint,
    utils::read_le_u32,
};
use plonky2::{
    field::{
        extension::{quintic::QuinticExtension, FieldExtension},
        types::Field,
    },
    hash::{hashing::hash_n_to_m_no_pad, poseidon::PoseidonPermutation},
    plonk::circuit_builder::CircuitBuilder,
};
use plonky2_ecgfp5::curve::curve::Point;
use rand::Rng;

/// The maximum child number of a Merkle tree branch
const ARITY: usize = 4;

/// The Merkle tree types
type Tree = MerkleTree<F, C, D, Point>;
type Node = MerkleNode<F, C, D, Point>;

/// The user circuit and recursive circuit
type TestCircuit = MultisetHashingCircuit<F, D, ARITY>;
type RecursiveCircuit = CyclicCircuit<F, C, D, TestCircuit, ARITY>;

/// Benchmark and test the multiset hashing circuit.
#[test]
fn test_multiset_hashing_circuit() {
    init_logging();

    // Initialize the recursive circuit and testing Merkle tree.
    let circuit = recursive_circuit();
    let mut tree = merkle_tree();

    // Prove the Merkle tree from lowest leaves to high branches until root, for
    // example we have the below Merkle tree (binary tree for testing):
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
    //   to a curve point P.
    // . `prove_branches_recursive` function adds the curve points of children
    //   as its value for all branches recursively. There're two branches in
    //   this Merkle tree. The value of branch1 should be `curve_add(P1, P2)`,
    //   and branch2 should be `curve_add(P3, P4)`.
    // . `prove_branches_recursive` function calculates the curve point value of
    //   the root finially. It should be `curve_add(P1, P2, P3, P4)`.
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
    let branch1 = new_branch(vec![v1, v2]);
    let branch2 = new_branch(vec![v3, v4]);

    let root = new_branch(vec![branch1, branch2]);

    MerkleTree::new(root)
}

/// Create a branch of Merkle tree by child nodes.
fn new_branch(children: Vec<Node>) -> Node {
    assert!((1..=ARITY).contains(&children.len()));

    // Calculate the curve point addition for children of branch.
    // <https://github.com/Lagrange-Labs/plonky2-ecgfp5/blob/08feaa03a006923fa721f2f5a26578d13bc25fa6/src/curve/curve.rs#L709>
    let addition = children
        .iter()
        .map(|node| node.output())
        .cloned()
        .reduce(|acc, point| acc + point)
        .unwrap();

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

    // Convert the hash to a curve point.
    let point = QuinticExtension::from_basefield_array(hash).map_to_curve_point();

    Node::Leaf(value, point, None)
}

/// Create a leaf of Merkle tree by random value.
fn rand_leaf() -> Node {
    new_leaf(rand::thread_rng().gen::<[u8; 32]>())
}
