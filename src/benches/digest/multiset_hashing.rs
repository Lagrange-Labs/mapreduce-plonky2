//! Multiset hashing circuit benchmark and test with Merkle tree.

use crate::{
    benches::init_logging,
    circuit::{CyclicCircuit, UserCircuit},
    digest::{
        DigestTreeCircuit, MerkleLeafValue, MerkleNode, MerkleTree, MultisetHashingCircuit,
        MultisetHashingPointValue, MultisetHashingConfig,
    },
    utils::read_le_u32,
};
use plonky2::{
    field::types::Field,
    hash::{hashing::hash_n_to_hash_no_pad, poseidon::PoseidonPermutation},
    plonk::{circuit_builder::CircuitBuilder, config::GenericConfig},
};
use rand::Rng;

/// The Merkle tree for testing multiset hashing is a binary tree.
const ARITY: usize = 2;

/// Degree, config and field types.
const D: usize = 5;
type C = MultisetHashingConfig;
type F = <C as GenericConfig<D>>::F;

/// Merkle tree and node types.
type Tree = MerkleTree<F, C, D, MultisetHashingPointValue<F, D>>;
type Node = MerkleNode<F, C, D, MultisetHashingPointValue<F, D>>;

/// The circuit to test and recursive circuit.
type TestCircuit = MultisetHashingCircuit<F, D>;
type RecursiveCircuit = CyclicCircuit<F, C, D, TestCircuit, ARITY>;

/// Benchmark and test the multiset hashing circuit.
// #[test]
fn test_multiset_hashing_circuit() {
    init_logging();

    // Initialize the recursive circuit and testing Merkle tree.
    let circuit = recursive_circuit();
    let mut tree = merkle_tree();

    // Prove this binary tree from lowest leaves to high branches until root,
    // For example we have the below tree:
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
    //   leaves as H(v1), H(v2), H(v3) and H(v4), then ...
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

    MerkleTree::new(root)
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

/// Prove and generate Poseidon hash for all Merkle tree leaves.
fn prove_all_leaves(circuit: &RecursiveCircuit, tree: &mut Tree) {
    // Iterate all Merkle tree leaves to generate proofs and save to the nodes.
    tree.all_leaves()
        .iter_mut()
        .enumerate()
        .for_each(|(i, leaf)| {
            if let MerkleNode::Leaf(value, _, proof_result) = leaf {
                println!("[+] Proving leaf {} with value {:?}", i, value);
                // Generate the proof.
                let proof = circuit
                    .prove_init(TestCircuit::new_leaf(value.clone()))
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
                panic!("Must be a leaf of tree");
            }
        });
}

/// Prove and generate Poseidon hash for all Merkle tree branches from lowest
/// levels to high recursively. It should be finished until proving the root.
fn prove_branches_recursive(circuit: &RecursiveCircuit, tree: &mut Tree) {
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
                    let inputs = children.iter().map(|node| node.output().elements).collect();

                    // Children are always arranged from left to right, there are
                    // only real proofs then followed by dummy ones. For example
                    // cannot be `[real, dummy, dummy, real]`.
                    //let mut last_proofs: Vec<_> =
                    //    children.iter().map(|node| node.proof().clone()).collect();

                    let last_proofs = core::array::from_fn(|i| {
                        if i < children.len() {
                            children[i].proof().clone()
                        } else {
                            None
                        }
                    });

                    // Generate the proof.
                    let proof = circuit
                        .prove_step(TestCircuit::new_branch(inputs), &last_proofs)
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
