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
    plonk::config::{GenericConfig, PoseidonGoldilocksConfig},
    plonk::{circuit_builder::CircuitBuilder, proof::ProofWithPublicInputs},
};
use rand::Rng;
use std::iter;

const D: usize = 2;
const ARITY: usize = 16;

type C = PoseidonGoldilocksConfig;
type F = <C as GenericConfig<D>>::F;
type U = DigestCircuit<F, D, ARITY>;

#[test]
fn test_digest_circuit() {
    let circuit = cyclic_circuit();
    let mut tree = merkle_tree();

    prove_all_leaves(&circuit, &mut tree);
    prove_branches_recursive(&circuit, &mut tree);
}

fn cyclic_circuit() -> CyclicCircuit<F, C, D, U, ARITY> {
    let padder = |b: &mut CircuitBuilder<F, D>| {
        U::build(b);

        ARITY
    };

    CyclicCircuit::<F, C, D, U, ARITY>::new(padder)
}

fn merkle_tree() -> MerkleTree<F, C, D> {
    let [v1, v2, v3, v4] = [0; 4].map(|_| rand_leaf());
    let branch = MerkleNode::new_branch(vec![v2, v3, v4]);

    let root = MerkleNode::new_branch(vec![v1, branch]);

    MerkleTree::new(root)
}

fn rand_leaf() -> MerkleNode<F, C, D> {
    MerkleNode::new_leaf(U256(rand::thread_rng().gen::<[u64; 4]>()))
}

fn prove_all_leaves(circuit: &CyclicCircuit<F, C, D, U, ARITY>, tree: &mut MerkleTree<F, C, D>) {
    tree.all_leaves().iter_mut().for_each(|leaf| {
        if let MerkleNode::Leaf(value, _, proof_result) = leaf {
            let inputs = value.0.map(F::from_canonical_u64).to_vec();
            let proof = circuit.prove_init(U::new(inputs)).unwrap().0;

            circuit
                .verify_proof(proof.clone())
                .expect("Failed to verify proof");

            *proof_result = Some(proof);
        } else {
            panic!("Must be a leaf of tree");
        }
    });
}

fn prove_branches_recursive(
    circuit: &CyclicCircuit<F, C, D, U, ARITY>,
    tree: &mut MerkleTree<F, C, D>,
) {
    let max_level = tree.max_level();
    (0..max_level).rev().into_iter().for_each(|level| {
        tree.branches_at_level(level).iter_mut().for_each(|branch| {
            if let MerkleNode::Branch(children, .., proof_result) = branch {
                let inputs = children
                    .iter()
                    .flat_map(|node| node.hash().elements)
                    .collect();

                let mut last_proofs: Vec<_> =
                    children.iter().map(|node| node.proof().clone()).collect();
                last_proofs.extend(
                    iter::repeat(last_proofs.last().unwrap().clone())
                        .take(ARITY - last_proofs.len()),
                );
                let last_proofs = last_proofs.try_into().unwrap();

                let proof = circuit.prove_step(U::new(inputs), &last_proofs).unwrap().0;
                circuit
                    .verify_proof(proof.clone())
                    .expect("Failed to verify proof");

                *proof_result = Some(proof);
            } else {
                panic!("Must be a branch of tree");
            }
        });
    });
}

#[derive(Clone, Debug)]
struct MerkleTree<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    root: MerkleNode<F, C, D>,
    max_level: u64,
}

impl MerkleTree<F, C, D> {
    pub fn new(root: MerkleNode<F, C, D>) -> Self {
        let max_level = root.max_level(0);
        Self { root, max_level }
    }

    pub fn root(&self) -> &MerkleNode<F, C, D> {
        &self.root
    }

    pub fn max_level(&self) -> u64 {
        self.max_level
    }

    // Return all leaves.
    pub fn all_leaves(&mut self) -> Vec<&mut MerkleNode<F, C, D>> {
        self.root.all_leaves()
    }

    // Return branches without leaves at the specified level.
    pub fn branches_at_level(&mut self, level: u64) -> Vec<&mut MerkleNode<F, C, D>> {
        self.root.branches_at_level(level)
    }
}

#[derive(Clone, Debug)]
enum MerkleNode<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    // children, hash and proof
    Branch(
        Vec<Self>,
        HashOut<F>,
        Option<ProofWithPublicInputs<F, C, D>>,
    ),
    // value and proof
    Leaf(U256, HashOut<F>, Option<ProofWithPublicInputs<F, C, D>>),
}

impl MerkleNode<F, C, D> {
    pub fn new_branch(children: Vec<Self>) -> Self {
        assert!(children.len() > 0 && children.len() <= ARITY);

        let inputs: Vec<_> = children
            .iter()
            .flat_map(|node| node.hash().elements)
            .collect();
        let hash = hash_n_to_hash_no_pad::<F, PoseidonPermutation<F>>(&inputs);

        Self::Branch(children, hash, None)
    }

    pub fn new_leaf(value: U256) -> Self {
        let inputs: Vec<_> = value.0.into_iter().map(F::from_canonical_u64).collect();
        let hash = hash_n_to_hash_no_pad::<F, PoseidonPermutation<F>>(&inputs);

        Self::Leaf(value, hash, None)
    }

    pub fn max_level(&self, current: u64) -> u64 {
        match self {
            Self::Branch(children, ..) => {
                let current = current + 1;
                children.iter().map(|n| n.max_level(current)).max().unwrap()
            }
            Self::Leaf(..) => current,
        }
    }

    pub fn all_leaves(&mut self) -> Vec<&mut MerkleNode<F, C, D>> {
        match self {
            Self::Branch(children, ..) => {
                children.iter_mut().flat_map(|n| n.all_leaves()).collect()
            }
            Self::Leaf(..) => vec![self],
        }
    }

    pub fn branches_at_level(&mut self, current: u64) -> Vec<&mut MerkleNode<F, C, D>> {
        if current == 0 {
            if let Self::Branch(..) = self {
                return vec![self];
            }
        }

        match self {
            Self::Branch(children, ..) => {
                let current = current - 1;
                children
                    .iter_mut()
                    .flat_map(|n| n.branches_at_level(current))
                    .collect()
            }
            Self::Leaf(..) => vec![],
        }
    }

    pub fn hash(&self) -> &HashOut<F> {
        match self {
            Self::Branch(_, hash, ..) => hash,
            Self::Leaf(_, hash, ..) => hash,
        }
    }

    pub fn proof(&self) -> &Option<ProofWithPublicInputs<F, C, D>> {
        match self {
            Self::Branch(.., proof) => proof,
            Self::Leaf(.., proof) => proof,
        }
    }
}
