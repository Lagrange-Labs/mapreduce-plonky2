use std::{array, iter, process::Output};

use plonky2::{
    field::{goldilocks_field::GoldilocksField, types::Field},
    hash::{
        hash_types::{HashOut, RichField},
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
    group_hashing,
    keccak::OutputHash,
    query2::{storage::public_inputs::PublicInputs as StorageInputs, Address},
};

use super::ProvenanceWires;

const DEPTH: usize = 3;
type PublicInputs<'a> = super::PublicInputs<'a, GoldilocksField>;
type ProvenanceCircuit = super::ProvenanceCircuit<DEPTH, GoldilocksField>;

#[test]
fn prove_and_verify_provenance_circuit() {
    let seed = 0xdead;
    let values = StorageInputs::values_from_seed(seed);
    let storage_pi = StorageInputs::from_slice(&values);
    let circuit = TestProvenanceCircuit::from_seed(seed, &storage_pi);
    let proof = run_circuit::<_, _, PoseidonGoldilocksConfig, _>(circuit.clone());
    let pi = PublicInputs::from_slice(proof.public_inputs.as_slice());

    assert_eq!(pi.block_number_data(), circuit.block_number);
    assert_eq!(pi.range_data(), circuit.range);
    assert_eq!(pi.root_data(), &circuit.root.elements);
    assert_eq!(pi.block_number_min_data(), circuit.block_number_min);
    assert_eq!(pi.block_number_max_data(), circuit.block_number_max);
    assert_eq!(pi.block_number_max_data(), circuit.block_number_max);
    assert_eq!(
        pi.smart_contract_address_data(),
        &circuit.smart_contract_address.arr
    );
    assert_eq!(pi.mapping_slot_data(), circuit.mapping_slot);
    assert_eq!(pi.length_slot_data(), circuit.length_slot);

    let (x, y, f) = storage_pi.digest_raw();
    assert_eq!(&pi.digest_data()[0..group_hashing::N], &x);
    assert_eq!(
        &pi.digest_data()[group_hashing::N..2 * group_hashing::N],
        &y
    );
    assert_eq!(&pi.digest_data()[2 * group_hashing::N], &f);
}

impl<'a, T: Copy + Default> super::PublicInputs<'a, T> {
    /// Writes the parts of the public inputs into the provided target array.
    pub fn parts_into_values(
        values: &mut [T; PublicInputs::TOTAL_LEN],
        b: &[T; PublicInputs::B_LEN],
        r: &[T; PublicInputs::R_LEN],
        c: &[T; PublicInputs::C_LEN],
        b_min: &[T; PublicInputs::B_MIN_LEN],
        b_max: &[T; PublicInputs::B_MAX_LEN],
        a: &[T; PublicInputs::A_LEN],
        x: &[T; PublicInputs::X_LEN],
        m: &[T; PublicInputs::M_LEN],
        s: &[T; PublicInputs::S_LEN],
        d: &[T; PublicInputs::D_LEN],
    ) {
        values[Self::B_IDX..Self::B_IDX + Self::B_LEN].copy_from_slice(b);
        values[Self::R_IDX..Self::R_IDX + Self::R_LEN].copy_from_slice(r);
        values[Self::C_IDX..Self::C_IDX + Self::C_LEN].copy_from_slice(c);
        values[Self::B_MIN_IDX..Self::B_MIN_IDX + Self::B_MIN_LEN].copy_from_slice(b_min);
        values[Self::B_MAX_IDX..Self::B_MAX_IDX + Self::B_MAX_LEN].copy_from_slice(b_max);
        values[Self::A_IDX..Self::A_IDX + Self::A_LEN].copy_from_slice(a);
        values[Self::X_IDX..Self::X_IDX + Self::X_LEN].copy_from_slice(x);
        values[Self::M_IDX..Self::M_IDX + Self::M_LEN].copy_from_slice(m);
        values[Self::S_IDX..Self::S_IDX + Self::S_LEN].copy_from_slice(s);
        values[Self::D_IDX..Self::D_IDX + Self::D_LEN].copy_from_slice(d);
    }
}

impl<'a, F: RichField> super::PublicInputs<'a, F> {
    pub fn values_from_seed(seed: u64) -> [F; PublicInputs::TOTAL_LEN] {
        let rng = &mut StdRng::seed_from_u64(seed);

        let b = array::from_fn(|_| F::from_canonical_u32(rng.next_u32()));
        let r = array::from_fn(|_| F::from_canonical_u32(rng.next_u32()));
        let c = array::from_fn(|_| F::from_canonical_u32(rng.next_u32()));
        let b_min = array::from_fn(|_| F::from_canonical_u32(rng.next_u32()));
        let b_max = array::from_fn(|_| F::from_canonical_u32(rng.next_u32()));
        let a = array::from_fn(|_| F::from_canonical_u32(rng.next_u32()));
        let x = array::from_fn(|_| F::from_canonical_u32(rng.next_u32()));
        let m = array::from_fn(|_| F::from_canonical_u32(rng.next_u32()));
        let s = array::from_fn(|_| F::from_canonical_u32(rng.next_u32()));
        let d = array::from_fn(|_| F::from_canonical_u32(rng.next_u32()));

        let mut values = array::from_fn(|_| F::ZERO);
        Self::parts_into_values(&mut values, &b, &r, &c, &b_min, &b_max, &a, &x, &m, &s, &d);

        values
    }
}

#[derive(Debug, Clone)]
struct TestProvenanceWires {
    storage: Vec<Target>,
    provenance: ProvenanceWires,
}

#[derive(Debug, Clone)]
struct TestProvenanceCircuit {
    storage_values: Vec<GoldilocksField>,
    c: ProvenanceCircuit,
    block_number: GoldilocksField,
    range: GoldilocksField,
    root: HashOut<GoldilocksField>,
    block_number_min: GoldilocksField,
    block_number_max: GoldilocksField,
    smart_contract_address: Address<GoldilocksField>,
    mapping_slot: GoldilocksField,
    length_slot: GoldilocksField,
}

impl TestProvenanceCircuit {
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
        let range = GoldilocksField::ONE;

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

        let mut block_hash = Array::default();

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

        let c = ProvenanceCircuit::new(
            smart_contract_address.clone(),
            mapping_slot,
            length_slot,
            block_number,
            block_number_min,
            block_number_max,
            range,
            state_root,
            siblings,
            positions,
            block_hash,
        );

        Self {
            storage_values: storage.inputs.to_vec(),
            c,
            block_number,
            range,
            root: block_leaf_hash,
            block_number_min,
            block_number_max,
            smart_contract_address,
            mapping_slot,
            length_slot,
        }
    }
}

impl UserCircuit<GoldilocksField, 2> for TestProvenanceCircuit {
    type Wires = TestProvenanceWires;

    fn build(b: &mut CircuitBuilder<GoldilocksField, 2>) -> Self::Wires {
        let targets = b.add_virtual_targets(StorageInputs::<()>::TOTAL_LEN);
        let storage = StorageInputs::from_slice(&targets);
        let provenance = ProvenanceCircuit::build(b, &storage);

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
