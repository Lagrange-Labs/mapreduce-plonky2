//! Tests module for the leaf circuit

use std::array;

use ethers::types::Address;
use plonky2::{
    field::{
        goldilocks_field::GoldilocksField,
        types::{Field, PrimeField64},
    },
    hash::{
        hash_types::RichField,
        hash_types::{HashOut, HashOutTarget},
        hashing::hash_n_to_hash_no_pad,
        poseidon::PoseidonPermutation,
    },
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        config::{GenericHashOut, PoseidonGoldilocksConfig},
    },
};
use rand::{rngs::StdRng, RngCore, SeedableRng};

use crate::{
    circuit::{test::run_circuit, UserCircuit},
    state::lpn::state_leaf_hash,
    state::{BlockLinkingInputs, StateInputs},
};

use super::LeafCircuit;

#[test]
fn prove_and_verify_leaf_circuit() {
    let block_linking_values =
        BlockLinkingInputs::<GoldilocksField>::values_from_seed(TestLeafCircuit::PI_SEED);
    let block_linking = BlockLinkingInputs::from_slice(&block_linking_values);

    let preimage = LeafCircuit::node_preimage(&block_linking).collect::<Vec<_>>();
    let root = hash_n_to_hash_no_pad::<_, PoseidonPermutation<_>>(&preimage);
    // ensuring the public method using bytes is returning the same output
    {
        // need to convert the address back to u8 slice
        let address = Address::from_slice(
            &block_linking
                .packed_address()
                .iter()
                .map(|x| x.to_canonical_u64() as u32)
                .flat_map(|x| x.to_le_bytes())
                .collect::<Vec<_>>(),
        );
        let mapping_slot = block_linking.mapping_slot().to_canonical_u64() as u8;
        let length_slot = block_linking.length_slot().to_canonical_u64() as u8;
        // we want bytes
        let storage_root = HashOut {
            elements: block_linking.merkle_root().to_vec().try_into().unwrap(),
        }
        .to_bytes();
        assert_eq!(
            root.to_bytes(),
            state_leaf_hash(
                address,
                mapping_slot,
                length_slot,
                storage_root.try_into().unwrap()
            )
        );
    }

    let circuit = TestLeafCircuit {
        block_linking_values: block_linking_values.to_vec(),
        c: LeafCircuit,
    };
    let proof = run_circuit::<_, _, PoseidonGoldilocksConfig, _>(circuit);
    let pi = StateInputs::from_slice(proof.public_inputs.as_slice());

    assert_eq!(pi.root_data(), root.elements);
    assert_eq!(pi.block_header_data(), block_linking.block_hash());
    assert_eq!(&pi.block_number_data(), block_linking.block_number());
    assert_eq!(pi.prev_block_header_data(), block_linking.prev_block_hash());
}

impl<'a, T: Copy + Default> StateInputs<'a, T> {
    /// Writes the parts of the block liking public inputs into the provided target array.
    pub fn parts_into_values(
        values: &mut [T; StateInputs::<()>::TOTAL_LEN],
        c: &[T; StateInputs::<()>::C_LEN],
        h: &[T; StateInputs::<()>::H_LEN],
        n: &[T; StateInputs::<()>::N_LEN],
        prev_h: &[T; StateInputs::<()>::PREV_H_LEN],
    ) {
        values[Self::C_IDX..Self::C_IDX + Self::C_LEN].copy_from_slice(c);
        values[Self::H_IDX..Self::H_IDX + Self::H_LEN].copy_from_slice(h);
        values[Self::N_IDX..Self::N_IDX + Self::N_LEN].copy_from_slice(n);
        values[Self::PREV_H_IDX..Self::PREV_H_IDX + Self::PREV_H_LEN].copy_from_slice(prev_h);
    }

    pub fn update_root_data(values: &mut [T; StateInputs::<()>::TOTAL_LEN], data: &[T]) {
        values[Self::C_IDX..Self::C_IDX + Self::C_LEN].copy_from_slice(data);
    }
}

impl<'a, F: RichField> StateInputs<'a, F> {
    pub fn values_from_seed(seed: u64) -> [F; StateInputs::<()>::TOTAL_LEN] {
        let rng = &mut StdRng::seed_from_u64(seed);

        let c = array::from_fn(|_| F::from_canonical_u32(rng.next_u32()));
        let h = array::from_fn(|_| F::from_canonical_u32(rng.next_u32()));
        let n = array::from_fn(|_| F::from_canonical_u32(rng.next_u32()));
        let prev_h = array::from_fn(|_| F::from_canonical_u32(rng.next_u32()));

        let mut values = array::from_fn(|_| F::ZERO);
        Self::parts_into_values(&mut values, &c, &h, &n, &prev_h);

        values
    }

    pub fn update_root_data_from_seed(values: &mut [F; StateInputs::<()>::TOTAL_LEN], seed: u64) {
        let rng = &mut StdRng::seed_from_u64(seed);
        let c: [F; StateInputs::<()>::C_LEN] =
            array::from_fn(|_| F::from_canonical_u32(rng.next_u32()));

        Self::update_root_data(values, &c);
    }
}

#[derive(Clone)]
struct TestLeafWires {
    block_linking: Vec<Target>,
}

#[derive(Clone, Debug)]
struct TestLeafCircuit {
    block_linking_values: Vec<GoldilocksField>,
    c: LeafCircuit,
}

impl TestLeafCircuit {
    const PI_SEED: u64 = 0xbeef;
}

impl UserCircuit<GoldilocksField, 2> for TestLeafCircuit {
    type Wires = TestLeafWires;

    fn build(b: &mut CircuitBuilder<GoldilocksField, 2>) -> Self::Wires {
        let targets = b.add_virtual_targets(BlockLinkingInputs::<()>::TOTAL_LEN);
        let block_linking = BlockLinkingInputs::from_slice(&targets);
        LeafCircuit::build(b, &block_linking);

        TestLeafWires {
            block_linking: targets.clone(),
        }
    }

    fn prove(&self, pw: &mut PartialWitness<GoldilocksField>, wires: &Self::Wires) {
        let block_linking = BlockLinkingInputs::from_slice(&wires.block_linking);

        self.block_linking_values
            .iter()
            .zip(block_linking.inner.iter())
            .for_each(|(&v, &t)| pw.set_target(t, v));
    }
}
