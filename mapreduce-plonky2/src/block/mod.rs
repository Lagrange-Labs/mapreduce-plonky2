//! This circuit proves the correct updating of the block tree. There're steps
//! on how to prove the correct construction:
//! - Prove the sequentiality property of the last block inserted.
//! - Prove we include the new block right after the previous block inserted.
//! - Prove the append-only property, that we keep appending blocks without
//!   deletion and modification.

pub mod public_inputs;
pub use public_inputs::PublicInputs;

use crate::{
    api::{default_config, ProofWithVK},
    keccak::PACKED_HASH_LEN,
    state::{self, StateInputs},
    types::HashOutput,
    utils::{convert_u8_to_u32_slice, hash_two_to_one, IntTargetWriter},
    verifier_gadget,
};
use anyhow::Result;
use plonky2::{
    field::{
        extension::Extendable,
        goldilocks_field::GoldilocksField,
        types::{Field, PrimeField64},
    },
    hash::{
        hash_types::{HashOut, HashOutTarget, RichField},
        merkle_proofs::{MerkleProof, MerkleProofTarget},
        merkle_tree::MerkleTree,
        poseidon::PoseidonHash,
    },
    iop::{
        target::{BoolTarget, Target},
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::VerifierOnlyCircuitData,
        config::{GenericHashOut, Hasher},
        proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget},
    },
};
use recursion_framework::{
    circuit_builder::{
        public_input_targets, CircuitLogicWires, CircuitWithUniversalVerifier,
        CircuitWithUniversalVerifierBuilder,
    },
    framework::{
        prepare_recursive_circuit_for_circuit_set, RecursiveCircuits,
        RecursiveCircuitsVerifierGagdet, RecursiveCircuitsVerifierTarget,
    },
    serialization::{
        circuit_data_serialization::SerializableRichField, deserialize, deserialize_array,
        serialize, serialize_array,
    },
};
use serde::{Deserialize, Serialize};
use std::array;

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

/// Returns the hash in bytes of the node of the block tree.
/// NOTE: this method does NOT use the domain separation tag, since the circuit uses the native merkle gadget
/// from plonky2. As long as it's the only one, it is fine.
/// TODO: maybe refactor circuit to use our own?
pub fn block_node_hash(left: HashOutput, right: HashOutput) -> HashOutput {
    hash_two_to_one::<GoldilocksField, PoseidonHash>(left, right)
}
#[derive(Serialize, Deserialize)]
/// Block tree wires to assign
pub struct BlockTreeWires<const MAX_DEPTH: usize> {
    #[serde(serialize_with = "serialize", deserialize_with = "deserialize")]
    /// The flag identifies if this is the first block inserted to the tree.
    is_first: BoolTarget,
    #[serde(
        serialize_with = "serialize_array",
        deserialize_with = "deserialize_array"
    )]
    /// The index of new leaf is given by its little-endian bits. It corresponds
    /// to the plonky2 [verify_merkle_proof argument](https://github.com/0xPolygonZero/plonky2/blob/62ffe11a984dbc0e6fe92d812fa8da78b7ba73c7/plonky2/src/hash/merkle_proofs.rs#L98).
    leaf_index_bits: [BoolTarget; MAX_DEPTH],
    #[serde(serialize_with = "serialize", deserialize_with = "deserialize")]
    /// The new root of this Merkle tree
    root: HashOutTarget,
    #[serde(serialize_with = "serialize", deserialize_with = "deserialize")]
    /// The path starts from the sibling of new leaf, and the parent's siblings
    /// at each level. The root is not included. It corresponds to the plonky2
    /// [MerkleProofTarget](https://github.com/0xPolygonZero/plonky2/blob/62ffe11a984dbc0e6fe92d812fa8da78b7ba73c7/plonky2/src/hash/merkle_proofs.rs#L37).
    path: MerkleProofTarget,
}

/// Block tree circuit used to prove the correct updating of the block tree
#[derive(Clone, Debug)]
pub struct BlockTreeCircuit<F, const MAX_DEPTH: usize>
where
    F: RichField,
{
    /// The new leaf index is equal to `new_block_number - first_block_number`,
    /// it's zero for the first inserted block. It's decomposed to bits which
    /// represents if new leaf is the left or right child at each level, and we
    /// could know the corresponding siblings (if left or right) in path. It
    /// corresponds to the plonky2 [verify_merkle_proof argument](https://github.com/0xPolygonZero/plonky2/blob/62ffe11a984dbc0e6fe92d812fa8da78b7ba73c7/plonky2/src/hash/merkle_proofs.rs#L44).
    leaf_index: usize,
    /// The new root of this Merkle tree
    root: HashOut<F>,
    /// The path starts from the sibling of new leaf, and the parent's siblings
    /// at each level. The root is not included. It corresonds to the plonky2
    /// [MerkleProof](https://github.com/0xPolygonZero/plonky2/blob/62ffe11a984dbc0e6fe92d812fa8da78b7ba73c7/plonky2/src/hash/merkle_proofs.rs#L21).
    path: MerkleProof<F, PoseidonHash>,
}

impl<F, const MAX_DEPTH: usize> BlockTreeCircuit<F, MAX_DEPTH>
where
    F: RichField,
{
    pub fn new(leaf_index: usize, root: HashOutput, siblings: Vec<HashOutput>) -> Self {
        let root = HashOut::from_bytes(&root);
        let siblings = siblings
            .into_iter()
            .map(|s| HashOut::from_bytes(&s))
            .collect();
        let mp = MerkleProof { siblings };
        Self::new_from(leaf_index, root, mp)
    }

    pub fn new_from(
        leaf_index: usize,
        root: HashOut<F>,
        path: MerkleProof<F, PoseidonHash>,
    ) -> Self {
        Self {
            leaf_index,
            root,
            path,
        }
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
        let new_state_pi = StateInputs::from_slice(new_leaf_pi);

        // Initialize the targets in wires.
        let leaf_index_bits = array::from_fn(|_| cb.add_virtual_bool_target_safe());
        let root = cb.add_virtual_hash();
        let path = MerkleProofTarget {
            siblings: cb.add_virtual_hashes(MAX_DEPTH),
        };

        // The new leaf is the first inserted block if leaf index is zero.
        let zero = cb.zero();
        let leaf_index = cb.le_sum(leaf_index_bits.iter());
        let is_first = cb.is_equal(leaf_index, zero);

        // Verify the previous outputs and the new leaf (block) public inputs.
        verify_proofs(cb, &prev_pi, &new_state_pi, leaf_index, is_first);

        // Verify both the old and new roots of the block tree which are
        // calculated from the leaves sequentially.
        verify_append_only(cb, &prev_pi, &new_state_pi, &leaf_index_bits, &root, &path);

        let wires = BlockTreeWires {
            is_first,
            leaf_index_bits,
            root,
            path,
        };

        // Register the public inputs.
        PublicInputs::register(
            cb,
            &prev_pi.init_root(),
            &root,
            prev_pi.first_block_number(),
            new_state_pi.block_number(),
            &new_state_pi.block_header(),
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

        pw.set_hash_target(wires.root, self.root);

        wires
            .path
            .siblings
            .iter()
            .zip(&self.path.siblings)
            .for_each(|(t, v)| pw.set_hash_target(*t, *v));
    }
}

/// Verify the previous outputs and the new leaf (block) public inputs.
fn verify_proofs<F: RichField + Extendable<D>, const D: usize>(
    cb: &mut CircuitBuilder<F, D>,
    prev_pi: &PublicInputs<Target>,
    new_state_pi: &StateInputs<Target>,
    leaf_index: Target,
    is_first: BoolTarget,
) {
    // Check the previous block header.
    prev_pi
        .original_block_header()
        .enforce_equal(cb, &new_state_pi.prev_block_header());

    let first_block_num = prev_pi.first_block_number();
    let prev_block_num = prev_pi.block_number();
    let new_block_num = new_state_pi.block_number();

    // Check `first_block_number + leaf_index = new_block_number`.
    let exp_block_num = cb.add(first_block_num.0, leaf_index);
    cb.connect(exp_block_num, new_block_num.0);

    // Check `prev_block_number + 1 == new_block_number`.
    let one = cb.one();
    let exp_block_num = cb.add(prev_block_num.0, one);
    cb.connect(exp_block_num, new_block_num.0);

    // Check the previous root is equal to the init root if the new leaf is the
    // first inserted block.
    let init_root = prev_pi.init_root();
    let prev_root = prev_pi.root();
    init_root
        .elements
        .into_iter()
        .zip(prev_root.elements)
        .for_each(|(init_element, prev_element)| {
            let exp_element = cb.select(is_first, init_element, prev_element);
            cb.connect(exp_element, prev_element);
        });
}

/// Verify both the old and new roots of the block tree which are calculated
/// from the leaves sequentially.
fn verify_append_only<F: RichField + Extendable<D>, const D: usize>(
    cb: &mut CircuitBuilder<F, D>,
    prev_pi: &PublicInputs<Target>,
    new_state_pi: &StateInputs<Target>,
    leaf_index_bits: &[BoolTarget],
    new_root: &HashOutTarget,
    path: &MerkleProofTarget,
) {
    let old_root = prev_pi.root();

    // Get the new leaf data.
    let leaf_data = leaf_data(cb, new_state_pi);

    // Verify the new leaf is present at the given index in Merkle tree with the new root.
    cb.verify_merkle_proof::<PoseidonHash>(leaf_data, leaf_index_bits, *new_root, path);

    // Verify the leaf is empty at the given index in Merkle tree with the old root.
    cb.verify_merkle_proof::<PoseidonHash>(vec![], leaf_index_bits, old_root, path);
}

/// Get the leaf data from public inputs.
fn leaf_data<F: RichField + Extendable<D>, const D: usize>(
    cb: &mut CircuitBuilder<F, D>,
    leaf_pi: &StateInputs<Target>,
) -> Vec<Target> {
    let state_root = leaf_pi.root().elements;
    let block_number = leaf_pi.block_number().0;
    let block_header = leaf_pi.block_header().arr.map(|u32_target| u32_target.0);

    // mimick block_leaf_hash
    std::iter::once(block_number)
        .chain(block_header)
        .chain(state_root)
        .collect()
}

type F = crate::api::F;
type C = crate::api::C;
const D: usize = crate::api::D;
const NUM_IO: usize = PublicInputs::<Target>::TOTAL_LEN;
const NUM_STATE_PUBLIC_INPUTS: usize = StateInputs::<Target>::TOTAL_LEN;
// number of public inputs for IVC block DB circuit; it has one additional
// public input with respect to the public inputs of `BlockTreeCircuit`,
// which is employed to determine whether the proof being verified is a proof
// previously generated for the IVC circuit or for a dummy circuit.
// In particular, dummy circuit will always generate proofs where this
// additional public input value is set to 1, while IVC proofs will have
// this public input value set to 0.
pub(crate) const NUM_IVC_PUBLIC_INPUTS: usize = NUM_IO + 1;
/// This data strcuture contains the input values related to the additional
/// logic enforced in the block tree IVC circuit besides recursive verification
/// of  previously generated IVC proof
struct BlockTreeInputs<const MAX_DEPTH: usize> {
    block_tree: BlockTreeCircuit<F, MAX_DEPTH>,
    new_leaf_proof: ProofWithVK,
    state_circuit_set: RecursiveCircuits<F, C, D>,
}

#[derive(Serialize, Deserialize)]
/// Wires for the IVC circuit proving the insertion of a new block in the block DB tree
struct BlockTreeRecursiveWires<const MAX_DEPTH: usize, const D: usize> {
    block_tree: BlockTreeWires<MAX_DEPTH>,
    state_verifier: RecursiveCircuitsVerifierTarget<D>,
}

impl<const MAX_DEPTH: usize> CircuitLogicWires<F, D, 1> for BlockTreeRecursiveWires<MAX_DEPTH, D>
where
    [(); <PoseidonHash as Hasher<F>>::HASH_SIZE]:,
    [(); NUM_IVC_PUBLIC_INPUTS]:,
{
    type CircuitBuilderParams = RecursiveCircuits<F, C, D>;

    type Inputs = BlockTreeInputs<MAX_DEPTH>;

    const NUM_PUBLIC_INPUTS: usize = NUM_IVC_PUBLIC_INPUTS;

    fn circuit_logic(
        builder: &mut CircuitBuilder<F, D>,
        verified_proofs: [&ProofWithPublicInputsTarget<D>; 1],
        builder_parameters: Self::CircuitBuilderParams,
    ) -> Self {
        let verifier_gadget =
            RecursiveCircuitsVerifierGagdet::<F, C, D, NUM_STATE_PUBLIC_INPUTS>::new(
                default_config(),
                &builder_parameters,
            );
        let state_verifier_wires = verifier_gadget.verify_proof_in_circuit_set(builder);
        let new_leaf_pi =
            state_verifier_wires.get_public_input_targets::<F, NUM_STATE_PUBLIC_INPUTS>();
        let (prev_pi, is_dummy) = Self::public_input_targets(&verified_proofs[0]).split_at(NUM_IO);
        assert_eq!(prev_pi.len(), NUM_IO);
        assert_eq!(is_dummy.len(), 1);
        let block_tree_wires = BlockTreeCircuit::build(builder, prev_pi, new_leaf_pi);
        // check that if `is_first == true`, then the `verified_proof` is a dummy one
        builder.connect(block_tree_wires.is_first.target, is_dummy[0]);
        // register public input stating that this is not a dummy proof
        let zero = builder.zero();
        builder.register_public_input(zero);
        Self {
            block_tree: block_tree_wires,
            state_verifier: state_verifier_wires,
        }
    }

    fn assign_input(&self, inputs: Self::Inputs, pw: &mut PartialWitness<F>) -> Result<()> {
        inputs.block_tree.assign(pw, &self.block_tree);
        let (proof, vd) = (&inputs.new_leaf_proof).into();
        self.state_verifier
            .set_target(pw, &inputs.state_circuit_set, proof, vd)
    }
}

#[derive(Serialize, Deserialize)]
/// Wires for the circuit employed to generate the dummy proofs being recursively verified in place
/// of a real one when generating the proof of insertion of the first block in the block tree DB
struct DummyCircuitWires<const MAX_DEPTH: usize> {
    pi: [Target; NUM_IO],
}

struct DummyCircuitInputs {
    first_block_number: F,
    parent_hash: [F; PACKED_HASH_LEN],
}

impl<const MAX_DEPTH: usize> CircuitLogicWires<F, D, 0> for DummyCircuitWires<MAX_DEPTH> {
    type CircuitBuilderParams = ();

    type Inputs = DummyCircuitInputs;

    const NUM_PUBLIC_INPUTS: usize = NUM_IVC_PUBLIC_INPUTS;

    fn circuit_logic(
        builder: &mut CircuitBuilder<F, D>,
        _verified_proofs: [&ProofWithPublicInputsTarget<D>; 0],
        _builder_parameters: Self::CircuitBuilderParams,
    ) -> Self {
        let pi = builder.add_virtual_public_input_arr::<NUM_IO>();
        // register a public input telling that this is a dummy proof
        let one = builder.one();
        builder.register_public_input(one);
        Self { pi }
    }

    fn assign_input(&self, inputs: Self::Inputs, pw: &mut PartialWitness<F>) -> Result<()> {
        // compute input values
        let empty_root = empty_merkle_root::<F, D, MAX_DEPTH>();
        let public_inputs = PublicInputs::from(&self.pi);
        pw.set_hash_target(public_inputs.init_root(), empty_root);
        // when inserting the first block the block DB tree empty, so the last root is set to
        // `empty_root` too
        pw.set_hash_target(public_inputs.root(), empty_root);
        pw.set_target(
            public_inputs.first_block_number().0,
            inputs.first_block_number,
        );
        // set `block_number` and `block_header` public inputs in order to satisfy constraints imposed
        // by block DB circuit for the first block being inserted
        pw.set_target(
            public_inputs.block_number().0,
            inputs.first_block_number - F::ONE,
        );
        public_inputs
            .original_block_header()
            .assign(pw, &inputs.parent_hash);

        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
/// Parameters representing the circuits employed to build the block tree DB
pub(crate) struct Parameters<const MAX_DEPTH: usize> {
    dummy: CircuitWithUniversalVerifier<F, C, D, 0, DummyCircuitWires<MAX_DEPTH>>,
    ivc_circuit: CircuitWithUniversalVerifier<F, C, D, 1, BlockTreeRecursiveWires<MAX_DEPTH, D>>,
    set: RecursiveCircuits<F, C, D>,
}

impl<const MAX_DEPTH: usize> Parameters<MAX_DEPTH>
where
    [(); <PoseidonHash as Hasher<F>>::HASH_SIZE]:,
{
    /// Build parameters for circuits related to the construction of the block DB tree
    pub(crate) fn build(state_circuit_set: &RecursiveCircuits<F, C, D>) -> Self {
        const IVC_CIRCUIT_SET_SIZE: usize = 2;
        let builder = CircuitWithUniversalVerifierBuilder::<F, D, NUM_IVC_PUBLIC_INPUTS>::new::<C>(
            default_config(),
            IVC_CIRCUIT_SET_SIZE,
        );
        let dummy = builder.build_circuit(());
        let ivc_circuit = builder.build_circuit(state_circuit_set.clone());

        // It's okay to use the circuit set mechanism here since the prover can not give a dummy proof after the first
        // block insertion because the regular circuit checks if it's the first insertion or not and sets a flag accordingly.
        // that flag should be false after the first insertion, always, while the dummy circuit always expose 1.
        let circuits = vec![
            prepare_recursive_circuit_for_circuit_set(&dummy),
            prepare_recursive_circuit_for_circuit_set(&ivc_circuit),
        ];

        let circuit_set = RecursiveCircuits::<F, C, D>::new(circuits);

        Self {
            dummy,
            ivc_circuit,
            set: circuit_set,
        }
    }

    /// Generate a proof block tree DB circuit employing the circuit parameters found in  `self`
    pub(crate) fn generate_proof(&self, input: Inputs<MAX_DEPTH>) -> Result<Vec<u8>> {
        match input {
            Inputs::First(input) => {
                // in this case we need to first generate a dummy proof with the
                // correct public inputs in order to generate the IVC proof of insertion
                // of the first block in the block tree DB
                let (leaf_proof, _) = (&input.new_leaf_proof).into();

                let leaf_pi =
                    StateInputs::from_slice(state::lpn::api::Parameters::public_inputs(leaf_proof));
                let dummy_proof_inputs = DummyCircuitInputs {
                    first_block_number: leaf_pi.block_number_data(),
                    parent_hash: leaf_pi.prev_block_header_data().try_into().unwrap(),
                };
                let dummy_proof =
                    self.set
                        .generate_proof(&self.dummy, [], [], dummy_proof_inputs)?;
                let previous_proof =
                    (dummy_proof, self.dummy.circuit_data().verifier_only.clone()).into();
                let inputs = Inputs::Subsequent(BlockTreeCircuitInputs {
                    base_inputs: input,
                    previous_proof,
                });
                self.generate_proof(inputs)
            }
            Inputs::Subsequent(input) => {
                let (block_tree_inputs, prev_proof) = input.into();
                let (input_proof, input_vd) = prev_proof.into();
                let proof = self.set.generate_proof(
                    &self.ivc_circuit,
                    [input_proof],
                    [&input_vd],
                    block_tree_inputs,
                )?;
                ProofWithVK::from((proof, self.ivc_circuit.circuit_data().verifier_only.clone()))
                    .serialize()
            }
        }
    }

    /// Verify proof generated by `generate_proof` method
    pub(crate) fn verify_proof(&self, proof: &[u8]) -> Result<()> {
        let proof = ProofWithVK::deserialize(proof)?;
        let (proof, _) = proof.into();
        self.ivc_circuit.circuit_data().verify(proof)
    }
    /// Get the public inputs corresponding to the block tree circuit logic from a proof generated
    /// by the IVC block tree circuit
    pub(crate) fn block_tree_public_inputs(proof: &ProofWithPublicInputs<F, C, D>) -> &[F] {
        &CircuitWithUniversalVerifier::<F, C, D, 1, BlockTreeRecursiveWires<MAX_DEPTH, D>>::public_inputs(&proof)[..NUM_IO]
    }

    /// Get the public input targets corresponding to the block tree circuit logic from a proof target
    /// rerpesenting a proof generated by the IVC block tree circuit
    pub(crate) fn block_tree_public_input_targets(
        proof: &ProofWithPublicInputsTarget<D>,
    ) -> &[Target] {
        public_input_targets::<F, D, NUM_IO>(proof)
    }

    pub(crate) fn get_block_db_circuit_set(&self) -> &RecursiveCircuits<F, C, D> {
        &self.set
    }

    pub(crate) fn get_block_db_vk(&self) -> &VerifierOnlyCircuitData<C, D> {
        &self.ivc_circuit.circuit_data().verifier_only
    }
}

/// This data structure contains all the inputs necessary to generate a proof for
/// the block tree IVC circuit. These are the internal structs with the deserialized inputs
/// from the public API.
struct BlockTreeCircuitInputs<const MAX_DEPTH: usize> {
    base_inputs: BlockTreeInputs<MAX_DEPTH>,
    previous_proof: ProofWithVK,
}

impl<const MAX_DEPTH: usize> Into<(BlockTreeInputs<MAX_DEPTH>, ProofWithVK)>
    for BlockTreeCircuitInputs<MAX_DEPTH>
{
    fn into(self) -> (BlockTreeInputs<MAX_DEPTH>, ProofWithVK) {
        (self.base_inputs, self.previous_proof)
    }
}

/// Wrapper to represent inputs for block tree IVC proofs
pub(crate) enum Inputs<const MAX_DEPTH: usize> {
    /// inputs to generate the first IVC proof, which doesn't verify a previously generated
    /// IVC proof
    First(BlockTreeInputs<MAX_DEPTH>),
    /// Inputs to generate a generic IVC proof, which recursively verify a previously generated
    /// IVC proof
    Subsequent(BlockTreeCircuitInputs<MAX_DEPTH>),
}

impl<const MAX_DEPTH: usize> Inputs<MAX_DEPTH> {
    /// Instantiate a new instance of `Inputs` containing inputs to generate the IVC proof for the
    /// first block being inserted in the DB
    pub(crate) fn input_for_first_block(
        input: BaseCircuitInput<MAX_DEPTH>,
        state_circuit_set: &RecursiveCircuits<F, C, D>,
    ) -> Result<Self> {
        Ok(Self::First(BlockTreeInputs {
            block_tree: input.block_tree,
            new_leaf_proof: ProofWithVK::deserialize(&input.new_leaf_proof)?,
            state_circuit_set: state_circuit_set.clone(),
        }))
    }

    /// Instantiate a new instance of `Inputs` containing inputs to generate the IVC proof for any
    /// new block being inserted in the DB (expect for the first one)
    pub(crate) fn input_for_new_block(
        input: RecursiveCircuitInput<MAX_DEPTH>,
        state_circuit_set: &RecursiveCircuits<F, C, D>,
    ) -> Result<Self> {
        Ok(Self::Subsequent(BlockTreeCircuitInputs {
            base_inputs: BlockTreeInputs {
                block_tree: input.base_inputs.block_tree,
                new_leaf_proof: ProofWithVK::deserialize(&input.base_inputs.new_leaf_proof)?,
                state_circuit_set: state_circuit_set.clone(),
            },
            previous_proof: ProofWithVK::deserialize(&input.previous_proof)?,
        }))
    }
}
/// `BaseCircuitInput` contains the inputs to be provided to the public APIs in order to generate
/// a proof for the insertion of the first block in the block tree DB
pub struct BaseCircuitInput<const MAX_DEPTH: usize> {
    block_tree: BlockTreeCircuit<F, MAX_DEPTH>,
    new_leaf_proof: Vec<u8>,
}
/// `RecursiveCircuitInput` contains the input to be provided to the public APIs in order to
/// generate a proof for the insertion of a new block (except for the first one) in the
/// block tree DB
pub struct RecursiveCircuitInput<const MAX_DEPTH: usize> {
    base_inputs: BaseCircuitInput<MAX_DEPTH>,
    previous_proof: Vec<u8>,
}

/// `CircuitInput` represents the inputs that need to be provided to the public APIs in order
/// to generate a proof of insertion in the block tree DB
pub enum CircuitInput<const MAX_DEPTH: usize> {
    /// inputs to generate the first IVC proof, which doesn't verify a previously generated
    /// IVC proof
    First(BaseCircuitInput<MAX_DEPTH>),
    /// Inputs to generate a generic IVC proof, which recursively verify a previously generated
    /// IVC proof
    Subsequent(RecursiveCircuitInput<MAX_DEPTH>),
}

impl<const MAX_DEPTH: usize> CircuitInput<MAX_DEPTH> {
    /// Instantiate a new instance of `CircuitInput` containing inputs to generate the IVC proof for the
    /// first block being inserted in the DB
    pub fn input_for_first_block(
        block_tree: BlockTreeCircuit<F, MAX_DEPTH>,
        new_leaf_proof: Vec<u8>,
    ) -> Self {
        Self::First(BaseCircuitInput {
            block_tree,
            new_leaf_proof,
        })
    }
    /// Instantiate a new instance of `CircuitInput` containing inputs to generate the IVC proof for any
    /// new block being inserted in the DB (expect for the first one)
    pub fn input_for_new_block(
        block_tree: BlockTreeCircuit<F, MAX_DEPTH>,
        new_leaf_proof: Vec<u8>,
        previous_proof: Vec<u8>,
    ) -> Self {
        Self::Subsequent(RecursiveCircuitInput {
            base_inputs: BaseCircuitInput {
                block_tree,
                new_leaf_proof,
            },
            previous_proof,
        })
    }
}

pub(crate) fn empty_merkle_root<
    F: SerializableRichField<D>,
    const D: usize,
    const MAX_DEPTH: usize,
>() -> HashOut<F> {
    (0..MAX_DEPTH).fold(HashOut::<F>::from_partial(&vec![]), |hash, _| {
        PoseidonHash::two_to_one(hash, hash)
    })
}

/// Generate the Merkle root from leaves.
fn merkle_root<F: SerializableRichField<D>, const D: usize>(leaves: Vec<Vec<F>>) -> HashOut<F> {
    // Construct the Merkle tree.
    let tree = MerkleTree::<_, PoseidonHash>::new(leaves, 0);
    assert_eq!(tree.cap.0.len(), 1, "Merkle tree must have one root");

    tree.cap.0[0]
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::{
        array::Array,
        benches::init_logging,
        circuit::{test::run_circuit, UserCircuit},
        keccak::{HASH_LEN, PACKED_HASH_LEN},
        utils::test::random_vector,
    };
    use plonky2::{
        field::types::{Field, Sample},
        hash::{
            hash_types::NUM_HASH_OUT_ELTS, merkle_proofs::verify_merkle_proof,
            merkle_tree::MerkleTree,
        },
        plonk::config::{GenericConfig, PoseidonGoldilocksConfig},
    };
    use rand::{thread_rng, Rng};
    use recursion_framework::framework_testing::TestingRecursiveCircuits;

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

        let testing_framework =
            TestingRecursiveCircuits::<F, C, D, NUM_STATE_PUBLIC_INPUTS>::default();
        let params = Parameters::<MAX_DEPTH>::build(testing_framework.get_recursive_circuit_set());
        println!("ivc circuit: {}", params.ivc_circuit.wrapped_circuit_size());

        let first_block_num = thread_rng().gen_range(1..10_000);
        let leaf_index = 0;
        let prev_pi: [F; NUM_IO] = array::from_fn(|_| F::rand());

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
        let (root, path, new_leaf_proof) =
            gen_input(leaf_index, leaves.clone(), prev_pi.as_slice());
        let inputs = Inputs::First(BlockTreeInputs {
            block_tree: BlockTreeCircuit::new_from(leaf_index, root, path),
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
                block_tree: BlockTreeCircuit::new_from(leaf_index, root, path),
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
        verify_merkle_proof::<_, PoseidonHash>(vec![], leaf_index, old_root.clone(), &path)
            .unwrap();
        verify_merkle_proof::<_, PoseidonHash>(leaf_data.clone(), leaf_index, new_root, &path)
            .unwrap();

        // Generate the previous public inputs of Merkle tree.
        let prev_pi =
            tree_inputs::<MAX_DEPTH>(is_first, first_block_num, &prev_leaf_data, old_root);

        // Generate the public inputs of the new leaf.
        let new_leaf_pi = new_leaf_inputs(&leaf_data, &prev_pi);

        // Get the expected outputs.
        let exp_outputs = expected_outputs(&prev_pi, &new_leaf_pi, &new_root);

        // Run the circuit.
        let test_circuit = TestCircuit::<MAX_DEPTH> {
            is_first,
            prev_pi,
            new_leaf_pi,
            c: BlockTreeCircuit::new_from(leaf_index, new_root, path),
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
}
