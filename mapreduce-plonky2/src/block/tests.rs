use crate::{
    api::ProofWithVK,
    array::Array,
    benches::init_logging,
    block::{
        empty_merkle_root, leaf_data, BlockTreeCircuitInputs, BlockTreeInputs, Inputs, Parameters,
        NUM_IO, NUM_STATE_PUBLIC_INPUTS,
    },
    circuit::{test::run_circuit, UserCircuit},
    keccak::{HASH_LEN, PACKED_HASH_LEN},
    state::StateInputs,
    types::HashOutput,
    utils::{convert_u8_to_u32_slice, test::random_vector},
};
use plonky2::{
    field::{
        goldilocks_field::GoldilocksField,
        types::{Field, Sample},
    },
    hash::{
        hash_types::{HashOut, HashOutTarget, NUM_HASH_OUT_ELTS},
        merkle_proofs::{verify_merkle_proof, MerkleProof},
        merkle_tree::MerkleTree,
        poseidon::PoseidonHash,
    },
    iop::{
        target::{BoolTarget, Target},
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        config::{GenericConfig, GenericHashOut, Hasher, PoseidonGoldilocksConfig},
    },
};
use rand::{thread_rng, Rng};
use recursion_framework::{
    framework_testing::TestingRecursiveCircuits,
    serialization::circuit_data_serialization::SerializableRichField,
};

use super::{public_inputs::PublicInputs, BlockTreeCircuit, BlockTreeWires};

/// Generate the Merkle root from leaves.
fn merkle_root<F: SerializableRichField<D>, const D: usize>(leaves: Vec<Vec<F>>) -> HashOut<F> {
    // Construct the Merkle tree.
    let tree = MerkleTree::<_, PoseidonHash>::new(leaves, 0);
    assert_eq!(tree.cap.0.len(), 1, "Merkle tree must have one root");

    tree.cap.0[0]
}

/// Returns the hash in bytes of the leaf of the block tree. It takes as parameters
/// the block number, the block header in bytes and the state root in bytes.
/// The block header is the one coming from the block chain. The state root is the one
/// created by the LPN state logic.
pub fn block_leaf_hash(
    block_number: u32,
    block_header: &HashOutput,
    state_root: &HashOutput,
) -> HashOutput {
    let bh = convert_u8_to_u32_slice(block_header);
    let sr = HashOut::from_bytes(state_root);
    let f_slice = std::iter::once(block_number)
        .chain(bh)
        .map(GoldilocksField::from_canonical_u32)
        .chain(sr.elements)
        .collect::<Vec<_>>();
    assert!(f_slice.len() != 8, "f_slice must NOT be of length 8");
    let hash_f = PoseidonHash::hash_no_pad(&f_slice);
    hash_f.to_bytes().try_into().unwrap()
}

const D: usize = 2;
type C = PoseidonGoldilocksConfig;
type F = <C as GenericConfig<D>>::F;

/// Test circuit
#[derive(Clone, Debug)]
struct TestCircuit<const MAX_DEPTH: usize> {
    is_first: bool,
    prev_pi: Vec<F>,
    new_leaf_pi: Vec<F>,
    c: BlockTreeCircuit<F, MAX_DEPTH>,
}

impl<const MAX_DEPTH: usize> UserCircuit<F, D> for TestCircuit<MAX_DEPTH> {
    type Wires = (
        BoolTarget,
        Vec<Target>,
        Vec<Target>,
        BlockTreeWires<MAX_DEPTH>,
    );

    fn build(cb: &mut CircuitBuilder<F, D>) -> Self::Wires {
        let is_first = cb.add_virtual_bool_target_safe();
        let prev_pi = cb.add_virtual_targets(PublicInputs::<Target>::TOTAL_LEN);
        let new_leaf_pi = cb.add_virtual_targets(StateInputs::<Target>::TOTAL_LEN);

        let wires = BlockTreeCircuit::build(cb, &prev_pi, &new_leaf_pi);

        // Check is_first flag.
        cb.connect(is_first.target, wires.is_first.target);

        (is_first, prev_pi, new_leaf_pi, wires)
    }

    fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
        pw.set_bool_target(wires.0, self.is_first);
        pw.set_target_arr(&wires.1, &self.prev_pi);
        pw.set_target_arr(&wires.2, &self.new_leaf_pi);

        self.c.assign(pw, &wires.3);
    }
}

#[test]
fn test_block_tree_circuit_parameters() {
    init_logging();

    const MAX_DEPTH: usize = 26;

    let testing_framework = TestingRecursiveCircuits::<F, C, D, NUM_STATE_PUBLIC_INPUTS>::default();
    let params = Parameters::<MAX_DEPTH>::build(testing_framework.get_recursive_circuit_set());
    println!("ivc circuit: {}", params.ivc_circuit.wrapped_circuit_size());

    let first_block_num = thread_rng().gen_range(1..10_000);
    let leaf_index = 0;
    let prev_pi: [F; NUM_IO] = std::array::from_fn(|_| F::rand());

    let gen_input = |leaf_index: usize, leaves: Vec<Vec<F>>, prev_pi: &[F]| {
        let leaf_data = leaves[leaf_index].clone();

        let (root, path) = merkle_root_path(leaf_index, leaves);
        let new_leaf_pi = new_leaf_inputs(&leaf_data, prev_pi);
        let new_leaf_proof = testing_framework
            .generate_input_proofs::<1>([new_leaf_pi.try_into().unwrap()])
            .unwrap();
        let new_leaf_proof = (
            new_leaf_proof[0].clone(),
            testing_framework.verifier_data_for_input_proofs::<1>()[0].clone(),
        )
            .into();

        (root, path, new_leaf_proof)
    };
    let mut leaves = generate_all_leaves::<MAX_DEPTH>(first_block_num, leaf_index);
    let (root, path, new_leaf_proof) = gen_input(leaf_index, leaves.clone(), prev_pi.as_slice());
    let inputs = Inputs::First(BlockTreeInputs {
        block_tree: BlockTreeCircuit::new(leaf_index, root, path),
        new_leaf_proof,
        state_circuit_set: testing_framework.get_recursive_circuit_set().clone(),
    });
    let proof = params.generate_proof(inputs).unwrap();

    params.verify_proof(&proof).unwrap();

    let leaf_index = leaf_index + 1;
    leaves[leaf_index] = rand_leaf_data(first_block_num + 1);
    let previous_proof = ProofWithVK::deserialize(&proof).unwrap();
    let (proof, _) = (&previous_proof).into();
    let prev_pi = Parameters::<MAX_DEPTH>::block_tree_public_inputs(proof);

    let (root, path, new_leaf_proof) = gen_input(leaf_index, leaves, prev_pi);

    let inputs = Inputs::Subsequent(BlockTreeCircuitInputs {
        base_inputs: BlockTreeInputs {
            block_tree: BlockTreeCircuit::new(leaf_index, root, path),
            new_leaf_proof,
            state_circuit_set: testing_framework.get_recursive_circuit_set().clone(),
        },
        previous_proof,
    });

    let proof = params.generate_proof(inputs).unwrap();

    params.verify_proof(&proof).unwrap();
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
fn test_circuit<const MAX_DEPTH: usize>(leaf_index: usize) -> Vec<GoldilocksField> {
    init_logging();

    // The new leaf is the first inserted block if leaf index is zero.
    let is_first = leaf_index == 0;

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
    let old_root = merkle_root::<F, D>(old_leaves);

    // Generate the new root and path (siblings without root).
    let (new_root, path) = merkle_root_path(leaf_index, leaves);

    // Verify the path, old and new roots (out of circuit).
    verify_merkle_proof::<_, PoseidonHash>(vec![], leaf_index, old_root.clone(), &path).unwrap();
    verify_merkle_proof::<_, PoseidonHash>(leaf_data.clone(), leaf_index, new_root, &path).unwrap();

    // Generate the previous public inputs of Merkle tree.
    let prev_pi = tree_inputs::<MAX_DEPTH>(is_first, first_block_num, &prev_leaf_data, old_root);

    // Generate the public inputs of the new leaf.
    let new_leaf_pi = new_leaf_inputs(&leaf_data, &prev_pi);

    // Get the expected outputs.
    let exp_outputs = expected_outputs(&prev_pi, &new_leaf_pi, &new_root);

    // Run the circuit.
    let test_circuit = TestCircuit::<MAX_DEPTH> {
        is_first,
        prev_pi,
        new_leaf_pi,
        c: BlockTreeCircuit::new(leaf_index, new_root, path),
    };
    let proof = run_circuit::<F, D, C, _>(test_circuit);

    // Verify the outputs.
    assert_eq!(exp_outputs, proof.public_inputs);
    exp_outputs
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

/// Generate the Merkle root and path (siblings without root) from leaves.
fn merkle_root_path(
    leaf_index: usize,
    leaves: Vec<Vec<F>>,
) -> (HashOut<F>, MerkleProof<F, PoseidonHash>) {
    // Construct the Merkle tree.
    let tree = MerkleTree::<F, PoseidonHash>::new(leaves, 0);
    assert_eq!(tree.cap.0.len(), 1, "Merkle tree must have one root");

    let root = tree.cap.0[0];

    // Generate the siblings at the each level (without root).
    let path = tree.prove(leaf_index);

    (root, path)
}

/// Generate the public inputs of Merkle tree (the current circuit).
fn tree_inputs<const MAX_DEPTH: usize>(
    is_dummy: bool,
    first_block_num: usize,
    leaf_data: &[F],
    root: HashOut<F>,
) -> Vec<F> {
    // All leaves are empty for the init root.
    let init_root = empty_merkle_root::<F, D, MAX_DEPTH>();

    // [block_number, block_header, state_root]
    assert_eq!(leaf_data.len(), 1 + PACKED_HASH_LEN + NUM_HASH_OUT_ELTS);
    let block_header = leaf_data[1..1 + PACKED_HASH_LEN].to_vec();

    // The block number is set to `first_block_number - 1` for dummy proofs.
    let first_block_num = F::from_canonical_usize(first_block_num);
    let block_num = if is_dummy {
        first_block_num - F::ONE
    } else {
        leaf_data[0]
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
    // [block_number, block_header, state_root]
    assert_eq!(leaf_data.len(), 1 + PACKED_HASH_LEN + NUM_HASH_OUT_ELTS);
    let block_num = leaf_data[0];
    let block_header = &leaf_data[1..1 + PACKED_HASH_LEN];
    let state_root = &leaf_data[1 + PACKED_HASH_LEN..];

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
    let new_leaf_pi = StateInputs::from_slice(new_leaf_pi);

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
    // Generate as [block_number, block_header, state_root].
    let mut data: Vec<_> = random_vector(1 + PACKED_HASH_LEN + NUM_HASH_OUT_ELTS)
        .into_iter()
        .map(F::from_canonical_usize)
        .collect();

    // Set the block number.
    data[0] = F::from_canonical_usize(block_num);

    data
}

#[test]
fn test_hash_leaf() {
    let block_number = thread_rng().gen_range(1..10_000);
    let block_header = random_vector::<u8>(HASH_LEN).try_into().unwrap();
    let state_root = HashOut {
        elements: GoldilocksField::rand_vec(NUM_HASH_OUT_ELTS)
            .try_into()
            .unwrap(),
    };

    let expected = block_leaf_hash(
        block_number,
        &block_header,
        &state_root.to_bytes().try_into().unwrap(),
    );
    let expected_f = HashOut::<GoldilocksField>::from_bytes(&expected);

    let mut pi = Vec::new();
    // state root
    pi.extend(&state_root.elements);
    // block header from blockchain in packed format
    pi.extend(
        convert_u8_to_u32_slice(&block_header)
            .into_iter()
            .map(F::from_canonical_u32),
    );
    // block number in u32 format
    pi.push(F::from_canonical_u32(block_number));
    // previous block hash - useless in this case but still
    pi.extend(GoldilocksField::rand_vec(PACKED_HASH_LEN));
    let circuit = TestCircuit {
        expected: expected_f,
        state_inputs: pi,
    };

    run_circuit::<GoldilocksField, 2, C, _>(circuit);

    #[derive(Clone, Debug)]
    struct TestCircuit {
        expected: HashOut<GoldilocksField>,
        state_inputs: Vec<F>,
    }

    impl UserCircuit<GoldilocksField, 2> for TestCircuit {
        type Wires = (
            Array<Target, { StateInputs::<Target>::TOTAL_LEN }>,
            HashOutTarget,
        );

        fn build(c: &mut CircuitBuilder<GoldilocksField, 2>) -> Self::Wires {
            let state_pi = Array::<Target, _>::new(c);
            let pi = StateInputs::from_slice(&state_pi.arr);
            let preimage = leaf_data(c, &pi);
            let out_target = c.hash_n_to_hash_no_pad::<PoseidonHash>(preimage);
            let exp_target = c.add_virtual_hash();
            c.connect_hashes(out_target, exp_target);
            (state_pi, exp_target)
        }

        fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
            // assign the inputs
            wires
                .0
                .assign(pw, &self.state_inputs.clone().try_into().unwrap());
            // assign the expect hash output
            pw.set_hash_target(wires.1, self.expected);
        }
    }
}
