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
use plonky2_ecgfp5::curve::curve::Point;
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
type PublicInputs<'a> = EpilogueInputs<'a, GoldilocksField, Provenance, L>;
type ProvenanceCircuit = super::ProvenanceCircuit<L, GoldilocksField>;

#[test]
fn prove_and_verify_provenance_circuit() {
    let seed = 0xdead;
    let epilogue_values = PublicInputs::values_from_seed(seed);
    let epilogue = PublicInputs::from_slice(&epilogue_values);
    let circuit = TestProvenanceCircuit::from_seed(seed, &epilogue);
    let proof = run_circuit::<_, _, PoseidonGoldilocksConfig, _>(circuit);
    let pi = PublicInputs::from_slice(proof.public_inputs.as_slice());

    assert_eq!(pi.block_number_raw(), epilogue.block_number_raw());
    assert_eq!(pi.range_raw(), epilogue.range_raw());
    //assert_eq!(pi.root_raw(), epilogue.root_raw());
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
}

impl TestProvenanceCircuit {
    pub fn from_seed(seed: u64, epilogue: &EpilogueInputs<GoldilocksField, Provenance, L>) -> Self {
        let rng = &mut StdRng::seed_from_u64(seed);

        let siblings: Vec<_> = (0..L)
            .map(|_| {
                let mut s = HashOut::default();
                s.elements
                    .iter_mut()
                    .for_each(|l| *l = GoldilocksField::from_canonical_u32(rng.next_u32()));
                s
            })
            .collect();

        let positions: Vec<_> = (0..L).map(|_| rng.next_u32() & 1 == 1).collect();

        let address = Address::from_slice(
            &epilogue
                .smart_contract_address_raw()
                .iter()
                .map(|x| x.to_canonical_u64() as u32)
                .flat_map(|x| x.to_le_bytes())
                .collect::<Vec<_>>(),
        );
        let mapping_slot = epilogue.mapping_slot_raw().to_canonical_u64() as u8;
        let length_slot = epilogue.length_slot_raw().to_canonical_u64() as u8;
        let storage_root = HashOut {
            elements: epilogue.root_raw().try_into().unwrap(),
        };

        let state_root = state_leaf_hash(
            address,
            mapping_slot,
            length_slot,
            storage_root.to_bytes().try_into().unwrap(),
        );
        let mut state_root = HashOut::from_bytes(&state_root);

        for i in 0..L {
            let (left, right) = if positions[i] {
                (state_root.clone(), siblings[i].clone())
            } else {
                (siblings[i].clone(), state_root.clone())
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

        let c = ProvenanceCircuit::new(state_root, siblings, positions, block_hash);

        Self {
            epilogue_values: epilogue.inputs.to_vec(),
            c,
        }
    }
}

impl UserCircuit<GoldilocksField, L> for TestProvenanceCircuit {
    type Wires = TestProvenanceWires;

    fn build(b: &mut CircuitBuilder<GoldilocksField, L>) -> Self::Wires {
        let targets = b.add_virtual_targets(PublicInputs::total_len());
        let epilogue = EpilogueInputs::<Target, Provenance, L>::from_slice(&targets);
        let provenance = super::ProvenanceCircuit::build(b, &epilogue);

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
