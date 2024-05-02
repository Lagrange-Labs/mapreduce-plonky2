use std::fmt::{self, Debug};

use itertools::Itertools;
use plonky2::{
    field::{
        extension::{quintic::QuinticExtension, FieldExtension},
        goldilocks_field::GoldilocksField,
        types::Field,
    },
    hash::hash_types::{HashOut, HashOutTarget, NUM_HASH_OUT_ELTS},
    iop::target::Target,
    plonk::{circuit_builder::CircuitBuilder, config::GenericHashOut},
};
use plonky2_crypto::u32::arithmetic_u32::U32Target;
use plonky2_ecgfp5::{
    curve::curve::WeierstrassPoint,
    gadgets::curve::{CircuitBuilderEcGFp5, CurveTarget},
};
use recursion_framework::{
    circuit_builder::{CircuitWithUniversalVerifier, CircuitWithUniversalVerifierBuilder},
    framework::RecursiveCircuits,
};
use serde::{Deserialize, Serialize};

use crate::{
    api::{default_config, ProofWithVK, C, D, F},
    types::{
        HashOutput, PackedAddressTarget, PackedValueTarget, CURVE_TARGET_LEN, PACKED_ADDRESS_LEN,
        PACKED_VALUE_LEN,
    },
    utils::{convert_point_to_curve_target, convert_slice_to_curve_point},
};

use self::{
    full_node::{FullNodeCircuit, FullNodeWires},
    partial_node::{PartialNodeCircuitInputs, PartialNodeWires},
};

use anyhow::Result;

pub mod full_node;
pub mod partial_node;

pub(crate) const BLOCK_CIRCUIT_SET_SIZE: usize = 3;
pub enum CircuitInput {
    /// left and right children proof
    FullNode((ProofWithVK, ProofWithVK)),
    PartialNode(PartialNodeCircuitInputs),
}

impl CircuitInput {
    pub fn new_full_node(left_proof: Vec<u8>, right_proof: Vec<u8>) -> Result<Self> {
        Ok(Self::FullNode((
            ProofWithVK::deserialize(&left_proof)?,
            ProofWithVK::deserialize(&right_proof)?,
        )))
    }

    pub fn new_partial_node(
        child_proof: Vec<u8>,
        sibling_hash: HashOutput,
        sibling_is_left: bool,
    ) -> Result<Self> {
        Ok(Self::PartialNode(PartialNodeCircuitInputs::new(
            ProofWithVK::deserialize(&child_proof)?,
            HashOut::<F>::from_bytes(sibling_hash.as_slice()),
            sibling_is_left,
        )))
    }
}

pub const NUM_IO: usize = BlockPublicInputs::<Target>::total_len();

#[derive(Serialize, Deserialize)]
pub struct Parameters {
    full_node_circuit: CircuitWithUniversalVerifier<F, C, D, 2, FullNodeWires>,
    partial_node_circuit: CircuitWithUniversalVerifier<F, C, D, 1, PartialNodeWires>,
    circuit_set: RecursiveCircuits<F, C, D>,
}

impl Parameters {
    pub fn build(state_circuit_params: &super::state::Parameters) -> Self {
        let circuit_builder = CircuitWithUniversalVerifierBuilder::<F, D, NUM_IO>::new::<C>(
            default_config(),
            BLOCK_CIRCUIT_SET_SIZE,
        );
        let full_node_circuit = circuit_builder.build_circuit(());
        let partial_node_circuit = circuit_builder.build_circuit(());

        let circuit_digests = vec![
            state_circuit_params
                .circuit_data()
                .verifier_only
                .circuit_digest,
            full_node_circuit
                .circuit_data()
                .verifier_only
                .circuit_digest,
            partial_node_circuit
                .circuit_data()
                .verifier_only
                .circuit_digest,
        ];

        let circuit_set = RecursiveCircuits::new_from_circuit_digests(circuit_digests);

        Self {
            full_node_circuit,
            partial_node_circuit,
            circuit_set,
        }
    }

    pub fn generate_proof(&self, input: CircuitInput) -> Result<Vec<u8>> {
        match input {
            CircuitInput::FullNode((left_proof, right_proof)) => {
                let (left_proof, left_vd) = left_proof.into();
                let (right_proof, right_vd) = right_proof.into();
                let proof = self.circuit_set.generate_proof(
                    &self.full_node_circuit,
                    [left_proof, right_proof],
                    [&left_vd, &right_vd],
                    FullNodeCircuit {},
                )?;
                ProofWithVK::from((
                    proof,
                    self.full_node_circuit.circuit_data().verifier_only.clone(),
                ))
            }
            CircuitInput::PartialNode(input) => {
                let (inputs, child_proof) = input.into();
                let (proof, vd) = child_proof.into();
                let proof = self.circuit_set.generate_proof(
                    &self.partial_node_circuit,
                    [proof],
                    [&vd],
                    inputs,
                )?;
                ProofWithVK::from((
                    proof,
                    self.partial_node_circuit
                        .circuit_data()
                        .verifier_only
                        .clone(),
                ))
            }
        }
        .serialize()
    }

    pub(crate) fn verify_proof(&self, proof: &[u8]) -> Result<()> {
        let proof = ProofWithVK::deserialize(proof)?;
        let (proof, vd) = proof.into();
        let circuit_data = match () {
            () if vd == self.full_node_circuit.circuit_data().verifier_only => {
                Ok(self.full_node_circuit.circuit_data())
            }
            () if vd == self.partial_node_circuit.circuit_data().verifier_only => {
                Ok(self.partial_node_circuit.circuit_data())
            }
            () => Err(anyhow::Error::msg(
                "No circuit found for provided verifier data",
            )),
        }?;
        circuit_data.verify(proof)
    }

    pub(crate) fn get_block_circuit_set(&self) -> &RecursiveCircuits<F, C, D> {
        &self.circuit_set
    }
}

#[derive(Clone, Copy, Debug)]
#[repr(u8)]
pub enum Inputs {
    /// B - block number of the latest block aggregated
    BlockNumber,
    /// R - aggregated range
    Range,
    /// C - Merkle hash of the subtree, or poseidon hash of the leaf
    Root,
    /// A - SMC address in compact packed u32
    SmartContractAddress,
    /// X - onwer's address - treated as generic 32byte value, packed in u32
    UserAddress,
    /// M - mapping slot
    MappingSlot,
    /// S - storage slot length
    StorageSlotLength,
    /// D - aggregated digest
    Digest,
}
const NUM_ELEMENTS: usize = 8;
impl Inputs {
    const SIZES: [usize; NUM_ELEMENTS] = [
        1,
        1,
        NUM_HASH_OUT_ELTS,
        PackedAddressTarget::LEN,
        PACKED_VALUE_LEN,
        1,
        1,
        CURVE_TARGET_LEN,
    ];

    const fn total_len() -> usize {
        Self::SIZES[0]
            + Self::SIZES[1]
            + Self::SIZES[2]
            + Self::SIZES[3]
            + Self::SIZES[4]
            + Self::SIZES[5]
            + Self::SIZES[6]
            + Self::SIZES[7]
    }

    pub const fn len(&self) -> usize {
        let me = *self as u8;
        Self::SIZES[me as usize]
    }

    fn range(&self) -> std::ops::Range<usize> {
        let mut offset = 0;
        let me = *self as u8;
        for i in 0..me {
            offset += Self::SIZES[i as usize];
        }

        offset..offset + Self::SIZES[me as usize]
    }
}

/// On top of the habitual T
#[derive(Clone)]
pub struct BlockPublicInputs<'input, T: Clone> {
    pub inputs: &'input [T],
}

impl<'a, T: Clone + Copy + Debug> Debug for BlockPublicInputs<'a, T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "BlockNumber: {:?}", self.block_number_raw())?;
        writeln!(f, "Range: {:?}", self.range_raw())?;
        writeln!(f, "Root: {:?}", self.root_raw())?;
        writeln!(f, "SC Address: {:?}", self.smart_contract_address_raw())?;
        writeln!(f, "Owner Address: {:?}", self.user_address_raw())?;
        writeln!(f, "Mapping slot: {:?}", self.mapping_slot_raw())?;
        writeln!(
            f,
            "Storage slot length: {:?}",
            self.storage_slot_length_raw()
        )?;
        writeln!(f, "Digest: {:?}", self.digest_raw())
    }
}

impl<'a, T: Clone + Copy> From<&'a [T]> for BlockPublicInputs<'a, T> {
    fn from(inputs: &'a [T]) -> Self {
        assert_eq!(inputs.len(), Self::total_len());
        Self { inputs }
    }
}

impl<'a, T: Clone + Copy> BlockPublicInputs<'a, T> {
    fn block_number_raw(&self) -> &[T] {
        &self.inputs[Inputs::BlockNumber.range()]
    }
    fn range_raw(&self) -> &[T] {
        &self.inputs[Inputs::Range.range()]
    }
    fn root_raw(&self) -> &[T] {
        &self.inputs[Inputs::Root.range()]
    }
    fn smart_contract_address_raw(&self) -> &[T] {
        &self.inputs[Inputs::SmartContractAddress.range()]
    }
    fn user_address_raw(&self) -> &[T] {
        &self.inputs[Inputs::UserAddress.range()]
    }
    fn mapping_slot_raw(&self) -> &[T] {
        &self.inputs[Inputs::MappingSlot.range()]
    }

    pub(crate) fn storage_slot_length_raw(&self) -> &[T] {
        &self.inputs[Inputs::StorageSlotLength.range()]
    }

    fn digest_raw(
        &self,
    ) -> (
        [T; crate::group_hashing::EXTENSION_DEGREE],
        [T; crate::group_hashing::EXTENSION_DEGREE],
        T,
    ) {
        convert_slice_to_curve_point(&self.inputs[Inputs::Digest.range()])
    }

    pub(crate) const fn total_len() -> usize {
        Inputs::total_len()
    }
}

impl<'a> BlockPublicInputs<'a, Target> {
    pub(crate) fn block_number(&self) -> Target {
        self.block_number_raw()[0]
    }

    pub(crate) fn range(&self) -> Target {
        self.range_raw()[0]
    }

    pub(crate) fn root(&self) -> HashOutTarget {
        HashOutTarget {
            elements: self.root_raw().try_into().unwrap(),
        }
    }

    pub(crate) fn smart_contract_address(&self) -> PackedAddressTarget {
        PackedAddressTarget::try_from(
            self.smart_contract_address_raw()
                .iter()
                .map(|&t| U32Target(t))
                .collect_vec(),
        )
        .unwrap()
    }

    pub(crate) fn user_address(&self) -> PackedValueTarget {
        PackedValueTarget::try_from(
            self.user_address_raw()
                .iter()
                .map(|&t| U32Target(t))
                .collect_vec(),
        )
        .unwrap()
    }

    pub(crate) fn mapping_slot(&self) -> Target {
        self.mapping_slot_raw()[0]
    }

    pub(crate) fn digest(&self) -> CurveTarget {
        convert_point_to_curve_target(self.digest_raw())
    }

    pub(crate) fn mapping_slot_length(&self) -> Target {
        self.storage_slot_length_raw()[0]
    }

    pub fn register(
        b: &mut CircuitBuilder<GoldilocksField, 2>,
        block_number: Target,
        range: Target,
        root: &HashOutTarget,
        smc_address: &PackedAddressTarget,
        user_address: &PackedValueTarget,
        mapping_slot: Target,
        mapping_slot_length: Target,
        digest: CurveTarget,
    ) {
        b.register_public_input(block_number);
        b.register_public_input(range);
        b.register_public_inputs(&root.elements);
        smc_address.register_as_public_input(b);
        user_address.register_as_public_input(b);
        b.register_public_input(mapping_slot);
        b.register_public_input(mapping_slot_length);
        b.register_curve_public_input(digest);
    }
}

impl<'a> BlockPublicInputs<'a, GoldilocksField> {
    // Only used for testing.
    pub fn from_parts(
        block_number: GoldilocksField,
        range: GoldilocksField,
        root: HashOut<GoldilocksField>,
        smart_contract_address: &[GoldilocksField; PACKED_ADDRESS_LEN],
        user_address: &[GoldilocksField; PACKED_VALUE_LEN],
        mapping_slot: GoldilocksField,
        storage_slot_length: GoldilocksField,
        digest: WeierstrassPoint,
    ) -> [GoldilocksField; Self::total_len()] {
        let mut inputs = vec![];
        inputs.push(block_number);
        inputs.push(range);
        inputs.extend_from_slice(&root.elements);
        inputs.extend_from_slice(smart_contract_address.as_slice());
        inputs.extend_from_slice(user_address.as_slice());
        inputs.push(mapping_slot);
        inputs.push(storage_slot_length);
        inputs.extend_from_slice(&digest.x.0);
        inputs.extend_from_slice(&digest.y.0);
        inputs.push(GoldilocksField::from_bool(digest.is_inf));
        inputs.try_into().unwrap()
    }
    pub fn block_number(&self) -> GoldilocksField {
        self.block_number_raw()[0]
    }

    pub fn range(&self) -> GoldilocksField {
        self.range_raw()[0]
    }

    pub fn root(&self) -> HashOut<GoldilocksField> {
        HashOut::from_vec(self.root_raw().to_owned())
    }

    pub fn smart_contract_address(&self) -> &[GoldilocksField] {
        self.smart_contract_address_raw()
    }

    pub fn user_address(&self) -> &[GoldilocksField] {
        self.user_address_raw()
    }

    pub fn mapping_slot(&self) -> GoldilocksField {
        self.mapping_slot_raw()[0]
    }

    pub fn digest(&self) -> WeierstrassPoint {
        let (x, y, is_inf) = self.digest_raw();
        WeierstrassPoint {
            x: QuinticExtension::<GoldilocksField>::from_basefield_array(std::array::from_fn::<
                GoldilocksField,
                5,
                _,
            >(|i| x[i])),
            y: QuinticExtension::<GoldilocksField>::from_basefield_array(std::array::from_fn::<
                GoldilocksField,
                5,
                _,
            >(|i| y[i])),
            is_inf: is_inf.is_nonzero(),
        }
    }

    pub(crate) fn mapping_slot_length(&self) -> GoldilocksField {
        self.storage_slot_length_raw()[0]
    }
}

#[cfg(test)]
mod tests {
    use ethers::types::Address;
    use itertools::Itertools;
    use plonky2::field::types::Field;
    use plonky2::plonk::config::GenericHashOut;
    use plonky2::{
        hash::{hashing::hash_n_to_hash_no_pad, poseidon::PoseidonPermutation},
        iop::target::Target,
    };
    use recursion_framework::framework_testing::TestingRecursiveCircuits;
    use serial_test::serial;

    use crate::query2::{
        state::{tests::generate_inputs_for_state_circuit, Parameters as StateParams},
        storage::public_inputs::PublicInputs as StorageInputs,
    };

    type F = crate::api::F;
    type C = crate::api::C;
    const D: usize = crate::api::D;

    #[test]
    #[serial]
    fn test_block_circuit_api() {
        const NUM_STORAGE_INPUTS: usize = StorageInputs::<Target>::TOTAL_LEN;
        const LENGTH_SLOT: u32 = 42;
        const MAPPING_SLOT: u32 = 24;
        let smart_contract_address = Address::random();
        let user_address = Address::random();
        let testing_framework = TestingRecursiveCircuits::<F, C, D, NUM_STORAGE_INPUTS>::default();
        let state_circuit_params =
            StateParams::build(testing_framework.get_recursive_circuit_set());

        let block_circuit_params = super::Parameters::build(&state_circuit_params);

        let left_leaf_io = generate_inputs_for_state_circuit(
            &testing_framework,
            0xdead,
            Some(LENGTH_SLOT),
            Some(MAPPING_SLOT),
            Some(smart_contract_address),
            Some(user_address),
        );

        let right_leaf_io = generate_inputs_for_state_circuit(
            &testing_framework,
            0xbeef,
            Some(LENGTH_SLOT),
            Some(MAPPING_SLOT),
            Some(smart_contract_address),
            Some(user_address),
        );

        let left_leaf_proof = state_circuit_params
            .generate_proof(&block_circuit_params.get_block_circuit_set(), left_leaf_io)
            .unwrap();

        let right_leaf_proof = state_circuit_params
            .generate_proof(&block_circuit_params.get_block_circuit_set(), right_leaf_io)
            .unwrap();

        println!("leaf proofs built");

        let full_node_proof = block_circuit_params
            .generate_proof(
                super::CircuitInput::new_full_node(left_leaf_proof, right_leaf_proof).unwrap(),
            )
            .unwrap();

        block_circuit_params.verify_proof(&full_node_proof).unwrap();

        println!("full node proof built");

        let sibling_hash = hash_n_to_hash_no_pad::<F, PoseidonPermutation<_>>(
            &b"ernesto"
                .iter()
                .copied()
                .map(F::from_canonical_u8)
                .collect_vec(),
        );

        let partial_node_proof = block_circuit_params
            .generate_proof(
                super::CircuitInput::new_partial_node(
                    full_node_proof,
                    sibling_hash.to_bytes().try_into().unwrap(),
                    true,
                )
                .unwrap(),
            )
            .unwrap();

        block_circuit_params
            .verify_proof(&partial_node_proof)
            .unwrap();
    }
}
