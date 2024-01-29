//! Digest circuit benchmark and test with the Merkle tree.

use crate::{
    circuit::{CyclicCircuit, UserCircuit},
    digest::DigestCircuit,
};
use ethers::types::U256;
use plonky2::{
    field::{extension::Extendable, types::Field},
    hash::{
        hash_types::{HashOut, RichField},
        hashing::hash_n_to_hash_no_pad,
        poseidon::PoseidonPermutation,
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        config::{GenericConfig, PoseidonGoldilocksConfig},
        proof::ProofWithPublicInputs,
    },
};
use rand::Rng;
use std::iter;

use super::init_logging;

const D: usize = 2;

/// Set this constant to identify each Merkle tree branch has ARITY children at
/// maximum.
const ARITY: usize = 4;

type C = PoseidonGoldilocksConfig;
type F = <C as GenericConfig<D>>::F;
type U = DigestCircuit<F, D, ARITY>;

/// Benchmark and test the digest circuit.
#[test]
fn test_digest_circuit() {
    init_logging();
    let circuit = cyclic_circuit();
    let mut tree = merkle_tree();

    // Prove the Merkle tree from the lowest leaves to high branches until root,
    // For example we have the below Merkle tree:
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
fn cyclic_circuit() -> CyclicCircuit<F, C, D, U, ARITY> {
    let padder = |b: &mut CircuitBuilder<F, D>| {
        U::build(b);

        14
    };

    CyclicCircuit::<F, C, D, U, ARITY>::new(padder)
}

/// Create a Merkle tree with testing branches and leaves.
fn merkle_tree() -> MerkleTree<F, C, D> {
    let [v1, v2, v3, v4] = [0; 4].map(|_| rand_leaf());
    let branch = MerkleNode::new_branch(vec![v2, v3, v4]);

    let root = MerkleNode::new_branch(vec![v1, branch]);

    MerkleTree::new(root)
}

/// Create a Merkle tree leaf with random value.
fn rand_leaf() -> MerkleNode<F, C, D> {
    MerkleNode::new_leaf(U256(rand::thread_rng().gen::<[u64; 4]>()))
}

/// Prove and generate Poseidon hash for all Merkle tree leaves.
fn prove_all_leaves(circuit: &CyclicCircuit<F, C, D, U, ARITY>, tree: &mut MerkleTree<F, C, D>) {
    // Iterate all Merkle tree leaves to generate proofs and save to the nodes.
    tree.all_leaves()
        .iter_mut()
        .enumerate()
        .for_each(|(i, leaf)| {
            if let MerkleNode::Leaf(value, _, proof_result) = leaf {
                println!("[+] Proving leaf {} with value {:?}", i, value);
                // Generate the proof.
                let inputs = value.0.map(F::from_canonical_u64).to_vec();
                let proof = circuit.prove_init(U::new(inputs)).unwrap().0;

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
fn prove_branches_recursive(
    circuit: &CyclicCircuit<F, C, D, U, ARITY>,
    tree: &mut MerkleTree<F, C, D>,
) {
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
                    let inputs = children
                        .iter()
                        .flat_map(|node| node.hash().elements)
                        .collect();

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
                    let proof = circuit.prove_step(U::new(inputs), &last_proofs).unwrap().0;

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

/// Merkle tree structure
#[derive(Clone, Debug)]
struct MerkleTree<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    /// The root of Merkle tree
    root: MerkleNode<F, C, D>,
    /// Maximum level of Merkle tree and level starts from zero
    max_level: u64,
}

impl MerkleTree<F, C, D> {
    /// Create a Merkle tree by the root node.
    pub fn new(root: MerkleNode<F, C, D>) -> Self {
        let max_level = root.max_level(0);
        Self { root, max_level }
    }

    /// Return the root.
    pub fn root(&self) -> &MerkleNode<F, C, D> {
        &self.root
    }

    /// Return the maximum level of Merkle tree.
    pub fn max_level(&self) -> u64 {
        self.max_level
    }

    /// Return the all leaves.
    pub fn all_leaves(&mut self) -> Vec<&mut MerkleNode<F, C, D>> {
        self.root.all_leaves()
    }

    /// Return the all branches without leaves at the specified level.
    pub fn branches_at_level(&mut self, level: u64) -> Vec<&mut MerkleNode<F, C, D>> {
        self.root.branches_at_level(level)
    }
}

/// Merkle node structure
#[derive(Clone, Debug)]
enum MerkleNode<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    /// A Merkle tree branch including child nodes, hash and proof of this node
    Branch(
        Vec<Self>,
        HashOut<F>,
        Option<ProofWithPublicInputs<F, C, D>>,
    ),
    /// A Merkle tree leaf including value, hash and proof of this node
    Leaf(U256, HashOut<F>, Option<ProofWithPublicInputs<F, C, D>>),
}

impl MerkleNode<F, C, D> {
    /// Create a branch by child nodes.
    pub fn new_branch(children: Vec<Self>) -> Self {
        assert!(children.len() > 0 && children.len() <= ARITY);

        // Flatten the child hash values and calculate hash for this branch.
        let inputs: Vec<_> = children
            .iter()
            .flat_map(|node| node.hash().elements)
            .collect();
        let hash = hash_n_to_hash_no_pad::<F, PoseidonPermutation<F>>(&inputs);

        Self::Branch(children, hash, None)
    }

    /// Create a leaf by value.
    pub fn new_leaf(value: U256) -> Self {
        // Flatten the value and calculate hash.
        let inputs: Vec<_> = value.0.into_iter().map(F::from_canonical_u64).collect();
        let hash = hash_n_to_hash_no_pad::<F, PoseidonPermutation<F>>(&inputs);

        Self::Leaf(value, hash, None)
    }

    /// Get the maximum level of this node, and it starts from zero.
    pub fn max_level(&self, current: u64) -> u64 {
        match self {
            Self::Branch(children, ..) => {
                // Calculate the maximum level recursively.
                let current = current + 1;
                children.iter().map(|n| n.max_level(current)).max().unwrap()
            }
            Self::Leaf(..) => current,
        }
    }

    /// Get the all leaf nodes.
    pub fn all_leaves(&mut self) -> Vec<&mut MerkleNode<F, C, D>> {
        match self {
            Self::Branch(children, ..) => {
                // Get the leaves recursively.
                children.iter_mut().flat_map(|n| n.all_leaves()).collect()
            }
            Self::Leaf(..) => vec![self],
        }
    }

    /// Get branches at the specified level.
    pub fn branches_at_level(&mut self, current: u64) -> Vec<&mut MerkleNode<F, C, D>> {
        // Return this branch directly if the current level is zero.
        if current == 0 {
            if let Self::Branch(..) = self {
                return vec![self];
            }
        }

        match self {
            Self::Branch(children, ..) => {
                // Get the branches recursively.
                let current = current - 1;
                children
                    .iter_mut()
                    .flat_map(|n| n.branches_at_level(current))
                    .collect()
            }
            Self::Leaf(..) => vec![],
        }
    }

    /// Get the hash value of this node.
    pub fn hash(&self) -> &HashOut<F> {
        match self {
            Self::Branch(_, hash, ..) => hash,
            Self::Leaf(_, hash, ..) => hash,
        }
    }

    /// Get the proof of this node.
    pub fn proof(&self) -> &Option<ProofWithPublicInputs<F, C, D>> {
        match self {
            Self::Branch(.., proof) => proof,
            Self::Leaf(.., proof) => proof,
        }
    }
}
