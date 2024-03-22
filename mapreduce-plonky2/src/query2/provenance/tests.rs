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
        storage::public_inputs::PublicInputs as StorageInputs, Address,
    },
};

use super::ProvenanceWires;

const DEPTH: usize = 3;
const TEST_L: usize = 4;
type PublicInputs<'a, const L: usize> = AggregationPublicInputs<'a, GoldilocksField, L>;
type ProvenanceCircuit<const L: usize> = super::ProvenanceCircuit<DEPTH, L, GoldilocksField>;

pub(crate) fn run_provenance_circuit<'a, const L: usize>(
    seed: u64,
) -> AggregationPublicInputs<'a, GoldilocksField, L> {
    let values = StorageInputs::values_from_seed(seed);
    let storage_pi = StorageInputs::from_slice(&values);
    let circuit = TestProvenanceCircuit::<L>::from_seed(seed, &storage_pi);
    let proof = run_circuit::<_, _, PoseidonGoldilocksConfig, _>(circuit.clone());
    let pi = PublicInputs::from(proof.public_inputs.as_slice());
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
    assert!(if f.is_one() {
        pi.digest().is_inf
    } else {
        !pi.digest().is_inf
    });

    pi
}

#[derive(Debug, Clone)]
struct TestProvenanceWires {
    storage: Vec<Target>,
    provenance: ProvenanceWires,
}

#[derive(Debug, Clone)]
pub struct TestProvenanceCircuit<const L: usize> {
    storage_values: Vec<GoldilocksField>,
    c: ProvenanceCircuit<L>,
    block_number: GoldilocksField,
    root: HashOut<GoldilocksField>,
    block_number_min: GoldilocksField,
    block_number_max: GoldilocksField,
    smart_contract_address: Address<GoldilocksField>,
    mapping_slot: GoldilocksField,
    length_slot: GoldilocksField,
}

impl<const L: usize> TestProvenanceCircuit<L> {
    pub fn from_seed(seed: u64, storage: &StorageInputs<GoldilocksField>) -> Self {
        let rng = &mut StdRng::seed_from_u64(seed);

        let mut smart_contract_address = Address::default();
        smart_contract_address
            .arr
            .iter_mut()
            .for_each(|l| *l = GoldilocksField::from_canonical_u32(rng.next_u32()));

        let mapping_slot = GoldilocksField::from_canonical_u32(rng.next_u32());
        let length_slot = GoldilocksField::from_canonical_u32(rng.next_u32());
        let block_number = GoldilocksField::from_canonical_u32(rng.next_u32());
        let block_number_min = GoldilocksField::from_canonical_u32(rng.next_u32());
        let block_number_max = GoldilocksField::from_canonical_u32(rng.next_u32());

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

        let c = ProvenanceCircuit::<L>::new(
            smart_contract_address.clone(),
            mapping_slot,
            length_slot,
            block_number,
            block_number_min,
            block_number_max,
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
            block_number_min,
            block_number_max,
            smart_contract_address,
            mapping_slot,
            length_slot,
        }
    }
}

impl<const L: usize> UserCircuit<GoldilocksField, 2> for TestProvenanceCircuit<L> {
    type Wires = TestProvenanceWires;

    fn build(b: &mut CircuitBuilder<GoldilocksField, 2>) -> Self::Wires {
        let targets = b.add_virtual_targets(StorageInputs::<()>::TOTAL_LEN);
        let storage = StorageInputs::from_slice(&targets);
        let provenance = ProvenanceCircuit::<L>::build(b, &storage);

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
fn prove_and_verify_provenance_circuit() {
    let pi = run_provenance_circuit::<10>(0xdead);
}

impl<'a, F: RichField, const L: usize> AggregationPublicInputs<'a, F, L> {
    pub fn values_from_seed(seed: u64) -> [F; Self::total_len()] {
        let rng = &mut StdRng::seed_from_u64(seed);

        array::from_fn(|_| F::from_canonical_u32(rng.next_u32()))
    }
}
