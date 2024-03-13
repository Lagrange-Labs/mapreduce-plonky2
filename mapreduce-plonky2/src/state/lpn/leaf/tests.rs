//! Tests module for the leaf circuit

use ethers::types::Address;
use plonky2::{
    field::{
        goldilocks_field::GoldilocksField,
        types::{Field, PrimeField64},
    },
    hash::{
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

use crate::{
    circuit::{test::run_circuit, UserCircuit},
    state::{
        lpn::leaf::{state_leaf_hash, PublicInputs, STATE_LEAF_DST},
        BlockLinkingPublicInputs,
    },
};

use super::LeafCircuit;

#[test]
fn prove_and_verify_leaf_circuit() {
    let block_linking_values = BlockLinkingPublicInputs::values_from_seed(TestLeafCircuit::PI_SEED);
    let block_linking = BlockLinkingPublicInputs::from_slice(&block_linking_values);

    let preimage = LeafCircuit::node_preimage(
        GoldilocksField::from_canonical_u8(STATE_LEAF_DST),
        &block_linking,
    )
    .collect::<Vec<_>>();
    println!("test preimage: {:?}", preimage);
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
    let pi = PublicInputs::from_slice(proof.public_inputs.as_slice());

    assert_eq!(pi.root_data(), root.elements);
    assert_eq!(pi.block_header_data(), block_linking.block_hash());
    assert_eq!(&pi.block_number_data(), block_linking.block_number());
    assert_eq!(pi.prev_block_header_data(), block_linking.prev_block_hash());
}

#[derive(Clone)]
struct TestLeafWires {
    block_linking: Vec<Target>,
    root: HashOutTarget,
}

#[derive(Clone)]
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
        let targets = b.add_virtual_targets(BlockLinkingPublicInputs::<()>::TOTAL_LEN);
        let block_linking = BlockLinkingPublicInputs::from_slice(&targets);
        let root = LeafCircuit::build(b, &block_linking);

        TestLeafWires {
            block_linking: targets.clone(),
            root,
        }
    }

    fn prove(&self, pw: &mut PartialWitness<GoldilocksField>, wires: &Self::Wires) {
        let block_linking = BlockLinkingPublicInputs::from_slice(&wires.block_linking);

        self.block_linking_values
            .iter()
            .zip(block_linking.inner.iter())
            .for_each(|(&v, &t)| pw.set_target(t, v));
    }
}
