use crate::types::MAPPING_KEY_LEN;
use std::{array, iter, process::Output};

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
use rand::{rngs::StdRng, RngCore, SeedableRng};

use crate::{
    array::Array,
    circuit::{test::run_circuit, UserCircuit},
    query2::{
        aggregation::AggregationPublicInputs,
        storage::public_inputs::PublicInputs as StorageInputs, EWord, PackedSCAddress,
    },
};

use super::StateWires;

const DEPTH: usize = 3;
type PublicInputs<'a> = AggregationPublicInputs<'a, GoldilocksField>;
type StateCircuit = super::StateCircuit<DEPTH, GoldilocksField>;

pub(crate) fn run_state_circuit<'a>(seed: u64) -> ([u8; MAPPING_KEY_LEN], Vec<GoldilocksField>) {
    let rng = &mut StdRng::seed_from_u64(seed);
    run_state_circuit_with_slot(seed, rng.next_u32(), rng.next_u32())
}

pub(crate) fn run_state_circuit_with_slot<'a>(
    seed: u64,
    slot_length: u32,
    mapping_slot: u32,
) -> ([u8; MAPPING_KEY_LEN], Vec<GoldilocksField>) {
    let (mapping_key, inputs) = StorageInputs::inputs_from_seed(seed);
    let storage_pi = StorageInputs::from_slice(&inputs);
    let circuit =
        TestStateCircuit::from_seed_and_slot(seed, slot_length, mapping_slot, &storage_pi);
    let proof = run_circuit::<_, _, PoseidonGoldilocksConfig, _>(circuit.clone());
    let pi = AggregationPublicInputs::<'_, GoldilocksField>::from(proof.public_inputs.as_slice());
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
pub struct TestStateCircuit {
    storage_values: Vec<GoldilocksField>,
    c: StateCircuit,
    block_number: GoldilocksField,
    root: HashOut<GoldilocksField>,
    smart_contract_address: PackedSCAddress<GoldilocksField>,
    mapping_slot: GoldilocksField,
    length_slot: GoldilocksField,
}

impl TestStateCircuit {
    pub fn from_seed(seed: u64, storage: &StorageInputs<GoldilocksField>) -> Self {
        let rng = &mut StdRng::seed_from_u64(seed);
        Self::from_seed_and_slot(seed, rng.next_u32(), rng.next_u32(), storage)
    }

    pub fn from_seed_and_slot(
        seed: u64,
        length_slot: u32,
        mapping_slot: u32,
        storage: &StorageInputs<GoldilocksField>,
    ) -> Self {
        let rng = &mut StdRng::seed_from_u64(seed);

        let mut smart_contract_address = PackedSCAddress::default();
        smart_contract_address
            .arr
            .iter_mut()
            .for_each(|l| *l = GoldilocksField::from_canonical_u32(rng.next_u32()));

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

impl UserCircuit<GoldilocksField, 2> for TestStateCircuit {
    type Wires = TestProvenanceWires;

    fn build(b: &mut CircuitBuilder<GoldilocksField, 2>) -> Self::Wires {
        let targets = b.add_virtual_targets(StorageInputs::<()>::TOTAL_LEN);
        let storage = StorageInputs::from_slice(&targets);
        let provenance = StateCircuit::build(b, &storage);

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

impl<'a, F: RichField> AggregationPublicInputs<'a, F> {
    pub fn values_from_seed(seed: u64) -> [F; Self::total_len()] {
        let rng = &mut StdRng::seed_from_u64(seed);

        array::from_fn(|_| F::from_canonical_u32(rng.next_u32()))
    }
}