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
    let mut tree = digest_tree();

    prove_all_leaves(&circuit, &mut tree);
    prove_branches_recursive(&circuit, &mut tree);
}

fn cyclic_circuit() -> CyclicCircuit<F, C, D, U, ARITY> {
    let padder = |b: &mut CircuitBuilder<F, D>| {
        U::build(b);

        // TODO: return right gate number.
        16
    };

    CyclicCircuit::<F, C, D, U, ARITY>::new(padder)
}

fn digest_tree() -> DigestTree<F, C, D> {
    let [v1, v2, v3, v4] = [0; 4].map(|_| rand_leaf());
    let branch = DigestNode::new_branch(vec![v2, v3, v4]);

    let root = DigestNode::new_branch(vec![v1, branch]);

    DigestTree::new(root)
}

fn rand_leaf() -> DigestNode<F, C, D> {
    DigestNode::new_leaf(U256(rand::thread_rng().gen::<[u64; 4]>()))
}

fn prove_all_leaves(circuit: &CyclicCircuit<F, C, D, U, ARITY>, tree: &mut DigestTree<F, C, D>) {
    tree.all_leaves().iter_mut().for_each(|leaf| {
        if let DigestNode::Leaf(value, _, proof_result) = leaf {
            let inputs = value.0.map(F::from_canonical_u64).to_vec();
            *proof_result = Some(circuit.prove_init(U::new(inputs)).unwrap().0);
        } else {
            panic!("Must be a leaf of tree");
        }
    });
}

fn prove_branches_recursive(
    circuit: &CyclicCircuit<F, C, D, U, ARITY>,
    tree: &mut DigestTree<F, C, D>,
) {
    let max_level = tree.max_level();
    (0..max_level).rev().into_iter().for_each(|level| {
        tree.branches_at_level(level).iter_mut().for_each(|branch| {
            if let DigestNode::Branch(children, .., proof) = branch {
                let inputs_proofs = children
                    .iter()
                    .map(|node| (node.hash().elements, node.proof().clone().unwrap()))
                    .collect();

                *proof = Some(prove_once(circuit, inputs_proofs));
            } else {
                panic!("Must be a branch of tree");
            }
        });
    });
}

fn prove_once(
    circuit: &CyclicCircuit<F, C, D, U, ARITY>,
    inputs_proofs: Vec<([F; 4], ProofWithPublicInputs<F, C, D>)>,
) -> ProofWithPublicInputs<F, C, D> {
    let (inputs, proofs): (Vec<_>, Vec<_>) = inputs_proofs.into_iter().unzip();
    let inputs = inputs.into_iter().flatten().collect();

    let dummy_n = ARITY - proofs.len();
    let proofs: [Option<ProofWithPublicInputs<F, C, D>>; ARITY] = proofs
        .into_iter()
        .map(Some)
        .chain(std::iter::repeat(None).take(dummy_n))
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();

    let proof = circuit.prove_step(U::new(inputs), &proofs).unwrap().0;
    circuit
        .verify_proof(proof.clone())
        .expect("Failed to verify proof");

    proof
}

#[derive(Clone, Debug)]
struct DigestTree<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    root: DigestNode<F, C, D>,
    max_level: u64,
}

impl DigestTree<F, C, D> {
    pub fn new(root: DigestNode<F, C, D>) -> Self {
        let max_level = root.max_level(0);
        Self { root, max_level }
    }

    pub fn root(&self) -> &DigestNode<F, C, D> {
        &self.root
    }

    pub fn max_level(&self) -> u64 {
        self.max_level
    }

    // Return all leaves.
    pub fn all_leaves(&mut self) -> Vec<&mut DigestNode<F, C, D>> {
        self.root.all_leaves()
    }

    // Return branches without leaves at the specified level.
    pub fn branches_at_level(&mut self, level: u64) -> Vec<&mut DigestNode<F, C, D>> {
        self.root.branches_at_level(level)
    }
}

#[derive(Clone, Debug)]
enum DigestNode<F, C, const D: usize>
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

impl DigestNode<F, C, D> {
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

    pub fn all_leaves(&mut self) -> Vec<&mut DigestNode<F, C, D>> {
        match self {
            Self::Branch(children, ..) => {
                children.iter_mut().flat_map(|n| n.all_leaves()).collect()
            }
            Self::Leaf(..) => vec![self],
        }
    }

    pub fn branches_at_level(&mut self, current: u64) -> Vec<&mut DigestNode<F, C, D>> {
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
