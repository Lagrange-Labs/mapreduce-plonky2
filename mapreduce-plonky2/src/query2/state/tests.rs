use crate::{query2::state::StateCircuitInputs, types::MAPPING_KEY_LEN, utils::convert_u8_to_u32_slice};
use std::{array, iter, ops::Add, process::Output};

use ethers::types::Address;
use itertools::Itertools;
use plonky2::{
    field::{goldilocks_field::GoldilocksField, types::Field},
    hash::{
        hash_types::{HashOut, RichField, NUM_HASH_OUT_ELTS},
        hashing::hash_n_to_hash_no_pad,
        poseidon::PoseidonPermutation,
    },
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{circuit_builder::CircuitBuilder, config::PoseidonGoldilocksConfig},
};
use plonky2::field::types::Sample;
use rand::{rngs::StdRng, Rng, RngCore, SeedableRng};
use recursion_framework::{framework::RecursiveCircuits, framework_testing::TestingRecursiveCircuits};
use serial_test::serial;

use crate::{
    array::Array,
    circuit::{test::run_circuit, UserCircuit},
    query2::{
        block::BlockPublicInputs, storage::public_inputs::PublicInputs as StorageInputs, EWord,
        PackedSCAddress,
    },
};

use super::StateWires;
use anyhow::Result;

const DEPTH: usize = 3;
type PublicInputs<'a> = BlockPublicInputs<'a, GoldilocksField>;
type StateCircuit<const DEPTH: usize> = super::StateCircuit<DEPTH, GoldilocksField>;

fn random_address(rng: &mut StdRng) -> Address {
    let mut address = Address::zero();
    rng.fill_bytes(&mut address.as_bytes_mut());
    address
}

pub(crate) fn run_state_circuit<'a>(seed: u64) -> ([u8; MAPPING_KEY_LEN], Vec<GoldilocksField>) {
    let rng = &mut StdRng::seed_from_u64(seed);
    run_state_circuit_with_slot_and_addresses(
        seed, 
        rng.next_u32(), 
        rng.next_u32(),
        random_address(rng),
        random_address(rng),
    )
}

pub(crate) fn run_state_circuit_with_slot_and_addresses<'a>(
    seed: u64,
    slot_length: u32,
    mapping_slot: u32,
    sc_address: Address,
    user_address: Address,
) -> ([u8; MAPPING_KEY_LEN], Vec<GoldilocksField>) {
    let (mapping_key, inputs) = StorageInputs::inputs_from_seed_and_owner(seed, user_address);
    let storage_pi = StorageInputs::from_slice(&inputs);
    let circuit =
        TestStateCircuit::<DEPTH>::new_from_slot_and_addr(seed, slot_length, mapping_slot, sc_address, &storage_pi);
    let proof = run_circuit::<_, _, PoseidonGoldilocksConfig, _>(circuit.clone());
    let pi = BlockPublicInputs::<'_, GoldilocksField>::from(proof.public_inputs.as_slice());
    assert_eq!(pi.block_number(), circuit.block_number);
    assert_eq!(pi.range(), GoldilocksField::ONE);
    assert_eq!(pi.root(), circuit.root);
    assert_eq!(
        pi.smart_contract_address(),
        &circuit.smart_contract_address.arr
    );
    assert_eq!(pi.mapping_slot(), circuit.mapping_slot);
    assert_eq!(pi.mapping_slot_length(), circuit.length_slot);

    let (x, y, f) = storage_pi.digest_raw();
    assert_eq!(&pi.digest().x.0, &x);
    assert_eq!(&pi.digest().y.0, &y);
    assert!(if f.is_zero() {
        !pi.digest().is_inf
    } else {
        pi.digest().is_inf
    });

    (mapping_key, proof.public_inputs.to_owned())
}

#[derive(Debug, Clone)]
pub struct TestProvenanceWires {
    storage: Vec<Target>,
    provenance: StateWires,
}

#[derive(Debug, Clone)]
pub struct TestStateCircuit<const DEPTH: usize> {
    storage_values: Vec<GoldilocksField>,
    c: StateCircuit<DEPTH>,
    block_number: GoldilocksField,
    root: HashOut<GoldilocksField>,
    smart_contract_address: PackedSCAddress<GoldilocksField>,
    mapping_slot: GoldilocksField,
    length_slot: GoldilocksField,
}

impl<const DEPTH: usize> TestStateCircuit<DEPTH> {
    pub fn new_from_seed(seed: u64, storage: &StorageInputs<GoldilocksField>) -> Self {
        let rng = &mut StdRng::seed_from_u64(seed);
        Self::new_from_slot_and_addr(
            seed, 
            rng.next_u32(), 
            rng.next_u32(), 
            random_address(rng),
            storage
        )
    }

    pub fn new_from_slot_and_addr(
        seed: u64,
        length_slot: u32,
        mapping_slot: u32,
        smart_contract_address: Address,
        storage: &StorageInputs<GoldilocksField>,
    ) -> Self {
        let rng = &mut StdRng::seed_from_u64(seed);

        let mut smart_contract_address = PackedSCAddress::try_from(
            convert_u8_to_u32_slice(smart_contract_address.as_fixed_bytes())
            .into_iter()
            .map(|val| F::from_canonical_u32(val))
            .collect_vec()
        ).unwrap();

        let mapping_slot = GoldilocksField::from_canonical_u32(mapping_slot);
        let length_slot = GoldilocksField::from_canonical_u32(length_slot);
        let block_number = GoldilocksField::from_canonical_u32(rng.next_u32());

        let siblings: Vec<_> = (0..DEPTH)
            .map(|_| {
                let mut s = HashOut::default();
                s.elements
                    .iter_mut()
                    .for_each(|l| *l = GoldilocksField::from_canonical_u32(rng.next_u32()));
                s
            })
            .collect();

        let positions: Vec<_> = (0..DEPTH).map(|_| rng.next_u32() & 1 == 1).collect();

        // FIXME use crate::state::lpn::state_leaf_hash
        let preimage: Vec<_> = smart_contract_address
            .arr
            .iter()
            .chain(iter::once(&mapping_slot))
            .chain(iter::once(&length_slot))
            .chain(storage.root_raw().iter())
            .copied()
            .collect();

        let mut state_root = hash_n_to_hash_no_pad::<
            GoldilocksField,
            PoseidonPermutation<GoldilocksField>,
        >(preimage.as_slice());

        for i in 0..DEPTH {
            let (left, right) = if positions[i] {
                (siblings[i].clone(), state_root.clone())
            } else {
                (state_root.clone(), siblings[i].clone())
            };

            let mut preimage = left.elements.to_vec();
            preimage.extend_from_slice(&right.elements);

            state_root = hash_n_to_hash_no_pad::<
                GoldilocksField,
                PoseidonPermutation<GoldilocksField>,
            >(preimage.as_slice());
        }

        let mut block_hash = Array::<GoldilocksField, 8>::default();

        block_hash
            .arr
            .iter_mut()
            .for_each(|h| *h = GoldilocksField::from_canonical_u32(rng.next_u32()));

        let mut preimage = vec![block_number];
        preimage.extend_from_slice(&block_hash.arr);
        preimage.extend_from_slice(&state_root.elements);

        let block_leaf_hash = hash_n_to_hash_no_pad::<
            GoldilocksField,
            PoseidonPermutation<GoldilocksField>,
        >(preimage.as_slice());

        let c = StateCircuit::new(
            smart_contract_address.clone(),
            mapping_slot,
            length_slot,
            block_number,
            state_root,
            siblings,
            positions,
            block_hash,
        );

        Self {
            storage_values: storage.inputs.to_vec(),
            c,
            block_number,
            root: block_leaf_hash,
            smart_contract_address,
            mapping_slot,
            length_slot,
        }
    }
}

impl<const DEPTH: usize> UserCircuit<GoldilocksField, 2> for TestStateCircuit<DEPTH> {
    type Wires = TestProvenanceWires;

    fn build(b: &mut CircuitBuilder<GoldilocksField, 2>) -> Self::Wires {
        let targets = b.add_virtual_targets(StorageInputs::<()>::TOTAL_LEN);
        let storage = StorageInputs::from_slice(&targets);
        let provenance = StateCircuit::<DEPTH>::build(b, &storage);

        TestProvenanceWires {
            storage: targets,
            provenance,
        }
    }

    fn prove(&self, pw: &mut PartialWitness<GoldilocksField>, wires: &Self::Wires) {
        wires
            .storage
            .iter()
            .zip(self.storage_values.iter())
            .for_each(|(&w, &v)| pw.set_target(w, v));

        self.c.assign(pw, &wires.provenance);
    }
}

#[test]
fn prove_and_verify_state_circuit() {
    let pi = run_state_circuit(0xdead);
}

impl<'a, F: RichField> BlockPublicInputs<'a, F> {
    pub fn values_from_seed(seed: u64) -> [F; Self::total_len()] {
        let rng = &mut StdRng::seed_from_u64(seed);

        array::from_fn(|_| F::from_canonical_u32(rng.next_u32()))
    }
}

type F = crate::api::F;
type C = crate::api::C;
const D: usize = crate::api::D;
type StateParameters = super::Parameters;
const NUM_STORAGE_INPUTS: usize = StorageInputs::<Target>::TOTAL_LEN;


pub(crate) fn generate_inputs_for_state_circuit(
        params: &StateParameters, 
        testing_framework: &TestingRecursiveCircuits<F, C, D, NUM_STORAGE_INPUTS>,
        seed: u64,
        length_slot: Option<u32>,
        mapping_slot: Option<u32>,
        smart_contract_address: Option<Address>,
        user_address: Option<Address>,
    ) -> StateCircuitInputs {
        let rng = &mut StdRng::seed_from_u64(seed);
        let length_slot = if let Some(slot) = length_slot {
            slot
        } else {
            rng.next_u32()
        };
        let mapping_slot = if let Some(slot) = mapping_slot {
            slot
        } else {
            rng.next_u32()
        };
        let smart_contract_address = if let Some(address) = smart_contract_address {
            address
        } else {
            random_address(rng)
        };
        let user_address = if let Some(address) = user_address {
            address
        } else {
            random_address(rng)
        };
        let (_, storage_pi) = StorageInputs::inputs_from_seed_and_owner(seed, user_address);
        
        let storage_proof = (
            testing_framework.generate_input_proofs([storage_pi.clone()]).unwrap()[0].clone(),
            testing_framework.verifier_data_for_input_proofs::<1>()[0].clone(),
        ).into();

        let state_circuit = TestStateCircuit::new_from_slot_and_addr(
            seed, 
            length_slot,
            mapping_slot,
            smart_contract_address,
            &StorageInputs::from(storage_pi.as_slice())).c;
        
        StateCircuitInputs::new(
                state_circuit,
                storage_proof,
                testing_framework.get_recursive_circuit_set(),
        )
    }

#[test]
#[serial]
fn test_state_circuit_parameters() {
    let testing_framework = TestingRecursiveCircuits::<F, C, D, NUM_STORAGE_INPUTS>::default();

    let params = StateParameters::build(testing_framework.get_recursive_circuit_set());
    
    let inputs = generate_inputs_for_state_circuit(&params, &testing_framework, 42, None, None, None, None);

    let proof = params.generate_proof(
        testing_framework.get_recursive_circuit_set(),
        inputs 
        ).unwrap();

    params.verify_proof(&proof).unwrap();
}
