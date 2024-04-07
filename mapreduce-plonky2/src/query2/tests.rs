use crate::{
    block::empty_merkle_root,
    circuit::test::run_circuit,
    keccak::PACKED_HASH_LEN,
    query2::{
        revelation::RevelationPublicInputs, state::tests::run_state_circuit_with_slot_and_addresses,
    },
    types::MAPPING_KEY_LEN,
    utils::convert_u8_to_u32_slice,
};
use ethers::types::Address;
use itertools::Itertools;
use plonky2::{
    field::{
        goldilocks_field::GoldilocksField,
        types::{Field, PrimeField64},
    },
    hash::{hashing::hash_n_to_hash_no_pad, poseidon::PoseidonPermutation},
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        config::{GenericConfig, PoseidonGoldilocksConfig},
    },
};

use crate::{block::public_inputs::PublicInputs as BlockDBPublicInputs, circuit::UserCircuit};

use super::{
    block::{
        full_node::{FullNodeCircuit, FullNodeWires},
        partial_node::{PartialNodeCircuit, PartialNodeWires},
        BlockPublicInputs as BlockQueryPublicInputs,
    },
    revelation::circuit::{RevelationCircuit, RevelationWires},
};

const D: usize = 2;
type C = PoseidonGoldilocksConfig;
type F = <C as GenericConfig<D>>::F;

#[derive(Debug, Clone)]
struct FullNodeCircuitValidator<'a> {
    validated: FullNodeCircuit,
    children: &'a [BlockQueryPublicInputs<'a, F>; 2],
}

impl UserCircuit<GoldilocksField, D> for FullNodeCircuitValidator<'_> {
    type Wires = (FullNodeWires, [Vec<Target>; 2]);

    fn build(c: &mut CircuitBuilder<GoldilocksField, D>) -> Self::Wires {
        let child_inputs = [
            c.add_virtual_targets(BlockQueryPublicInputs::<Target>::total_len()),
            c.add_virtual_targets(BlockQueryPublicInputs::<Target>::total_len()),
        ];
        let children_io = std::array::from_fn(|i| {
            BlockQueryPublicInputs::<Target>::from(child_inputs[i].as_slice())
        });
        let wires = FullNodeCircuit::build(c, children_io);
        (wires, child_inputs)
    }

    fn prove(&self, pw: &mut PartialWitness<GoldilocksField>, wires: &Self::Wires) {
        pw.set_target_arr(&wires.1[0], self.children[0].inputs);
        pw.set_target_arr(&wires.1[1], self.children[1].inputs);
        self.validated.assign(pw, &wires.0);
    }
}

#[derive(Clone, Debug)]
struct PartialNodeCircuitValidator<'a> {
    validated: PartialNodeCircuit,
    child_proof: BlockQueryPublicInputs<'a, F>,
}
impl UserCircuit<F, D> for PartialNodeCircuitValidator<'_> {
    type Wires = (PartialNodeWires, Vec<Target>);

    fn build(c: &mut CircuitBuilder<F, D>) -> Self::Wires {
        let child_to_prove_pi =
            c.add_virtual_targets(BlockQueryPublicInputs::<Target>::total_len());
        let child_to_prove_io =
            BlockQueryPublicInputs::<Target>::from(child_to_prove_pi.as_slice());
        let wires = PartialNodeCircuit::build(c, &child_to_prove_io);

        (wires, child_to_prove_pi.try_into().unwrap())
    }

    fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
        pw.set_target_arr(&wires.1, self.child_proof.inputs);
        self.validated.assign(pw, &wires.0);
    }
}

#[derive(Clone, Debug)]
struct RevelationCircuitValidator<'a, const L: usize, const MAX_DEPTH: usize> {
    validated: RevelationCircuit<L>,
    db_proof: BlockDBPublicInputs<'a, F>,
    root_proof: BlockQueryPublicInputs<'a, F>,
}
impl<const L: usize, const MAX_DEPTH: usize> UserCircuit<F, D>
    for RevelationCircuitValidator<'_, L, MAX_DEPTH>
{
    type Wires = (RevelationWires<L>, Vec<Target>, Vec<Target>);

    fn build(c: &mut CircuitBuilder<F, D>) -> Self::Wires {
        let db_proof_io = c.add_virtual_targets(BlockDBPublicInputs::<Target>::TOTAL_LEN);
        let db_proof_pi = BlockDBPublicInputs::<Target>::from(db_proof_io.as_slice());

        let root_proof_io = c.add_virtual_targets(BlockQueryPublicInputs::<Target>::total_len());
        let root_proof_pi = BlockQueryPublicInputs::<Target>::from(root_proof_io.as_slice());

        let wires = RevelationCircuit::<L>::build::<MAX_DEPTH>(c, db_proof_pi, root_proof_pi);
        (wires, db_proof_io, root_proof_io)
    }

    fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
        pw.set_target_arr(&wires.1, self.db_proof.proof_inputs);
        pw.set_target_arr(&wires.2, self.root_proof.inputs);
        self.validated.assign(pw, &wires.0);
    }
}

const EMPTY_NFT_ID: [u8; MAPPING_KEY_LEN] = [0u8; MAPPING_KEY_LEN];

/// Builds & proves the following tree
///
/// Top-level - PartialInnerCircuit
/// ├── Middle sub-tree - FullInnerNodeCircuit
/// │   ├── LeafCircuit -
/// │   └── LeafCircuit -
/// └── Untouched sub-tree - hash == Poseidon("ernesto")
#[test]
fn test_query2_mini_tree() {
    const L: usize = 4;
    const SLOT_LENGTH: u32 = 9;
    const MAX_DEPTH: usize = 12;
    const MAPPING_SLOT: u32 = 48372;
    let smart_contract_address = Address::random();
    let user_address = Address::random();

    let (left_value, left_leaf_proof_io) = run_state_circuit_with_slot_and_addresses(
        0xdead,
        SLOT_LENGTH,
        MAPPING_SLOT,
        smart_contract_address,
        user_address,
        10
    );
    let (right_value, right_leaf_proof_io) = run_state_circuit_with_slot_and_addresses(
        0xbeef,
        SLOT_LENGTH,
        MAPPING_SLOT,
        smart_contract_address,
        user_address,
        11
    );

    let left_leaf_pi = BlockQueryPublicInputs::<'_, F>::from(left_leaf_proof_io.as_slice());
    let right_leaf_pi = BlockQueryPublicInputs::<'_, F>::from(right_leaf_proof_io.as_slice());

    let middle_proof = run_circuit::<F, D, C, _>(FullNodeCircuitValidator {
        validated: FullNodeCircuit {},
        children: &[left_leaf_pi.clone(), right_leaf_pi.clone()],
    });

    let proved = hash_n_to_hash_no_pad::<F, PoseidonPermutation<_>>(
        &b"ernesto"
            .iter()
            .copied()
            .map(F::from_canonical_u8)
            .collect_vec(),
    );

    let top_proof = run_circuit::<F, D, C, _>(PartialNodeCircuitValidator {
        validated: PartialNodeCircuit::new(proved, false),
        child_proof: BlockQueryPublicInputs::<F>::from(middle_proof.public_inputs.as_slice()),
    });

    let root_proof =
        BlockQueryPublicInputs::<GoldilocksField>::from(top_proof.public_inputs.as_slice());

    let prev_root = empty_merkle_root::<GoldilocksField, 2, MAX_DEPTH>();
    let new_root = root_proof.root().elements;

    // we say we ran the query up to the last block generated in the block db
    let last_block = root_proof.block_number();
    // we say the first block number generated is the last block - the range - some constant
    // i.e. the database have been running for a while before
    let first_block = root_proof.block_number() - root_proof.range() + F::from_canonical_u8(34);
    // A rendom value for the block header
    let block_header: [F; PACKED_HASH_LEN] = std::array::from_fn(F::from_canonical_usize);

    let block_data = BlockDBPublicInputs::from_parts(
        &prev_root.elements,
        &new_root,
        first_block,
        last_block,
        &block_header,
    );
    let db_proof = BlockDBPublicInputs::<F>::from(block_data.as_slice());

    // These are the _query_ min and max range, NOT necessarily the range aggregated
    // we can choose anything as long as they satisfy the constraints when aggregating
    // query_min >= min_block during aggregation
    // query_max <= max_block during aggregation
    let query_min_block_number = root_proof.block_number() - GoldilocksField::ONE;
    let query_max_block_number = root_proof.block_number();

    let num_entries = 2;
    // entries sorted !
    assert!(
        convert_u8_to_u32_slice(&right_value)
            .last()
            .cloned()
            .unwrap()
            < convert_u8_to_u32_slice(&left_value)
                .last()
                .cloned()
                .unwrap()
    );
    let nft_ids = [right_value, left_value, EMPTY_NFT_ID, EMPTY_NFT_ID];
    let packed_nft_ids = nft_ids
        .iter()
        .map(|v| convert_u8_to_u32_slice(v).try_into().unwrap())
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
    let revelation_circuit = RevelationCircuit::<L> {
        packed_keys: packed_nft_ids,
        num_entries,
        query_min_block_number: query_min_block_number.to_canonical_u64() as usize,
        query_max_block_number: query_max_block_number.to_canonical_u64() as usize,
    };

    let final_proof = run_circuit::<F, D, C, _>(RevelationCircuitValidator::<L, MAX_DEPTH> {
        validated: revelation_circuit,
        db_proof,
        root_proof: root_proof.clone(),
    });
    let pi = RevelationPublicInputs::<_, L> {
        inputs: final_proof.public_inputs.as_slice(),
    };

    let padded_address = &left_leaf_pi.user_address();
    let address = &padded_address[padded_address.len() - 5..];
    assert_eq!(pi.user_address(), address);
    let reduced_left_value = convert_u8_to_u32_slice(&left_value)
        .last()
        .cloned()
        .unwrap();
    let reduced_right_value = convert_u8_to_u32_slice(&right_value)
        .last()
        .cloned()
        .unwrap();
    // ordered values
    let exp_values = [reduced_right_value, reduced_left_value, 0, 0];
    let exp_values_f = exp_values
        .into_iter()
        .map(F::from_canonical_u32)
        .collect_vec();
    pi.nft_ids()
        .iter()
        .zip(exp_values_f.iter())
        .for_each(|(a, b)| {
            assert_eq!(a, b);
        });
    pi.block_header()
        .iter()
        .zip(block_header.iter())
        .for_each(|(a, b)| {
            assert_eq!(a, b);
        });
    assert_eq!(pi.min_block_number(), query_min_block_number);
    assert_eq!(pi.max_block_number(), query_max_block_number);
    assert_eq!(pi.range(), root_proof.range());
    assert_eq!(
        pi.smart_contract_address(),
        root_proof.smart_contract_address()
    );
    assert_eq!(pi.mapping_slot(), root_proof.mapping_slot());
    assert_eq!(pi.mapping_slot_length(), root_proof.mapping_slot_length());
    //
}
