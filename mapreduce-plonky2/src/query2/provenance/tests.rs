use std::iter;

use ethers::types::Address;
use plonky2::plonk::config::GenericHashOut;
use plonky2::{
    field::{
        goldilocks_field::GoldilocksField,
        types::{Field, PrimeField64},
    },
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
    query2::epilogue::{Provenance, PublicInputs as EpilogueInputs},
    state::lpn::state_leaf_hash,
    utils::{convert_u32_fields_to_u8_vec, convert_u8_slice_to_u32_fields},
};

use super::ProvenanceWires;

const L: usize = 2;
const DEPTH: usize = 3;
type PublicInputs<'a> = EpilogueInputs<'a, GoldilocksField, Provenance, L>;
type ProvenanceCircuit = super::ProvenanceCircuit<L, DEPTH, GoldilocksField>;

#[test]
fn prove_and_verify_provenance_circuit() {
    let seed = 0xdead;
    let epilogue_values = PublicInputs::values_from_seed(seed);
    let epilogue = PublicInputs::from_slice(&epilogue_values);
    let circuit = TestProvenanceCircuit::from_seed(seed, &epilogue);
    let block_leaf_hash = circuit.block_leaf_hash;
    let proof = run_circuit::<_, _, PoseidonGoldilocksConfig, _>(circuit);
    let pi = PublicInputs::from_slice(proof.public_inputs.as_slice());

    assert_eq!(pi.block_number_raw(), epilogue.block_number_raw());
    assert_eq!(pi.range_raw(), epilogue.range_raw());
    assert_eq!(pi.root_raw(), &block_leaf_hash.elements);
    assert_eq!(pi.min_block_number_raw(), epilogue.min_block_number_raw());
    assert_eq!(pi.max_block_number_raw(), epilogue.max_block_number_raw());
    assert_eq!(
        pi.smart_contract_address_raw(),
        epilogue.smart_contract_address_raw()
    );
    assert_eq!(pi.user_address_raw(), epilogue.user_address_raw());
    assert_eq!(pi.mapping_slot_raw(), epilogue.mapping_slot_raw());
    assert_eq!(pi.length_slot_raw(), epilogue.length_slot_raw());
}

#[derive(Debug, Clone)]
struct TestProvenanceWires {
    epilogue: Vec<Target>,
    provenance: ProvenanceWires,
}

#[derive(Debug, Clone)]
struct TestProvenanceCircuit {
    epilogue_values: Vec<GoldilocksField>,
    c: ProvenanceCircuit,
    block_leaf_hash: HashOut<GoldilocksField>,
}

impl TestProvenanceCircuit {
    pub fn from_seed(seed: u64, epilogue: &EpilogueInputs<GoldilocksField, Provenance, L>) -> Self {
        let rng = &mut StdRng::seed_from_u64(seed);

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
        let preimage: Vec<_> = epilogue
            .smart_contract_address_raw()
            .iter()
            .chain(iter::once(epilogue.mapping_slot_raw()))
            .chain(iter::once(epilogue.length_slot_raw()))
            .chain(epilogue.root_raw())
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

        let mut preimage = vec![*epilogue.block_number_raw()];
        preimage.extend_from_slice(&block_hash.arr);
        preimage.extend_from_slice(&state_root.elements);

        let block_leaf_hash = hash_n_to_hash_no_pad::<
            GoldilocksField,
            PoseidonPermutation<GoldilocksField>,
        >(preimage.as_slice());

        let c = ProvenanceCircuit::new(state_root, siblings, positions, block_hash);

        Self {
            epilogue_values: epilogue.inputs.to_vec(),
            c,
            block_leaf_hash,
        }
    }
}

impl UserCircuit<GoldilocksField, L> for TestProvenanceCircuit {
    type Wires = TestProvenanceWires;

    fn build(b: &mut CircuitBuilder<GoldilocksField, L>) -> Self::Wires {
        let targets = b.add_virtual_targets(PublicInputs::total_len());
        let epilogue = EpilogueInputs::<Target, Provenance, L>::from_slice(&targets);
        let provenance = super::ProvenanceCircuit::<_, DEPTH, _>::build(b, &epilogue);

        TestProvenanceWires {
            epilogue: targets,
            provenance,
        }
    }

    fn prove(&self, pw: &mut PartialWitness<GoldilocksField>, wires: &Self::Wires) {
        wires
            .epilogue
            .iter()
            .zip(self.epilogue_values.iter())
            .for_each(|(&w, &v)| pw.set_target(w, v));

        self.c.assign(pw, &wires.provenance);
    }
}
