use anyhow::Result;
use plonky2::plonk::{
    circuit_data::{CircuitConfig, VerifierOnlyCircuitData},
    config::{GenericConfig, PoseidonGoldilocksConfig},
    proof::ProofWithPublicInputs,
};
use recursion_framework::{
    framework::RecursiveCircuits,
    serialization::{circuit_data_serialization::SerializableRichField, deserialize, serialize},
};
use serde::{Deserialize, Serialize};

pub use crate::storage::{
    self,
    length_extract::{self},
    lpn as lpn_storage, mapping,
};

pub use crate::state::{
    self,
    lpn::{self as lpn_state},
};

use crate::{
    block::Inputs,
    state::{block_linking, lpn::api::ProofInputs},
};

use self::storage::{digest_equal, length_match};
use crate::block;

// TODO: put every references here. remove one from mapping
pub(crate) const D: usize = 2;
pub(crate) type C = PoseidonGoldilocksConfig;
pub(crate) type F = <C as GenericConfig<D>>::F;

/// Set of inputs necessary to generate proofs for each circuit employed in the pre-processing
/// stage of LPN
pub enum CircuitInput<const MAX_DEPTH: usize> {
    /// Input for circuits proving inclusion of entries of a mapping in an MPT
    Mapping(mapping::CircuitInput),
    /// Input for circuit extracting length of a mapping from MPT
    LengthExtract(storage::length_extract::CircuitInput),
    /// Input for circuit building the storage DB of LPN
    Storage(lpn_storage::Input),
    /// Input for circuit binding the proofs for `Mapping` and `LengthExtract` circuits
    LengthMatch(length_match::CircuitInput),
    // Input for circuit binding the proofs for `LengthMatch` and `Storage` circuits
    DigestEqual(digest_equal::CircuitInput),
    /// Input for circuit linking the constructed storage DB to a specific block of the
    /// mainchain
    BlockLinking(block_linking::CircuitInput),
    /// Input for circuit bulding the state DB of LPN
    State(lpn_state::api::CircuitInput),
    /// Input for circuit building the block tree DB of LPN
    BlockDB(block::CircuitInput<MAX_DEPTH>),
}

#[derive(Serialize, Deserialize)]
/// Parameters defining all the circuits employed for the pre-processing stage of LPN
pub struct PublicParameters<const MAX_DEPTH: usize> {
    mapping: mapping::PublicParameters,
    length_extract: length_extract::PublicParameters,
    length_match: length_match::Parameters,
    lpn_storage: lpn_storage::PublicParameters,
    digest_equal: digest_equal::Parameters,
    block_linking: block_linking::PublicParameters,
    lpn_state: lpn_state::api::Parameters,
    block_db: block::Parameters<MAX_DEPTH>,
}

#[derive(Serialize, Deserialize)]
/// This data structure contains some information about the block DB circuit that needs
/// to be exchanged with public parameters for query circuits
pub struct BlockDBCircuitInfo<const MAX_DEPTH: usize> {
    circuit_set: RecursiveCircuits<F, C, D>,
    #[serde(serialize_with = "serialize", deserialize_with = "deserialize")]
    verifier_data: VerifierOnlyCircuitData<C, D>,
}

impl<const MAX_DEPTH: usize> BlockDBCircuitInfo<MAX_DEPTH> {
    pub(crate) fn serialize(&self) -> Result<Vec<u8>> {
        Ok(bincode::serialize(self)?)
    }

    pub(crate) fn deserialize(bytes: &[u8]) -> Result<Self> {
        Ok(bincode::deserialize(bytes)?)
    }

    pub(crate) fn get_block_db_circuit_set(&self) -> &RecursiveCircuits<F, C, D> {
        &self.circuit_set
    }

    pub(crate) fn get_block_db_vk(&self) -> &VerifierOnlyCircuitData<C, D> {
        &self.verifier_data
    }
}

/// Retrieve a common `CircuitConfig` to be employed to generate the parameters for the circuits
/// employed for the pre-processing statge of LPN
pub(crate) fn default_config() -> CircuitConfig {
    CircuitConfig::standard_recursion_config()
}
/// Instantiate the circuits employed for the pre-processing stage of LPN, returning their
/// corresponding parameters
pub fn build_circuits_params<const MAX_DEPTH: usize>() -> PublicParameters<MAX_DEPTH> {
    let mapping = mapping::build_circuits_params();
    let length_extract = length_extract::PublicParameters::build();
    let length_match = length_match::Parameters::build(
        mapping.get_mapping_circuit_set(),
        &length_extract.circuit_data().verifier_data(),
    );
    let lpn_storage = lpn_storage::PublicParameters::build();
    let digest_equal = digest_equal::Parameters::build(
        lpn_storage.get_lpn_circuit_set(),
        &length_match.circuit_data().verifier_data(),
    );
    let block_linking =
        block_linking::PublicParameters::build(&digest_equal.circuit_data().verifier_data());
    let lpn_state = lpn_state::api::Parameters::build(block_linking.circuit_data().verifier_data());
    let block_db = block::Parameters::build(lpn_state.get_lpn_state_circuit_set());
    PublicParameters {
        mapping,
        length_extract,
        length_match,
        lpn_storage,
        digest_equal,
        block_linking,
        lpn_state,
        block_db,
    }
}

/// Generate a proof for a circuit in the set of circuits employed in the pre-processing stage
/// of LPN, employing `CircuitInput` to specify for which circuit the proof should be generated
pub fn generate_proof<const MAX_DEPTH: usize>(
    params: &PublicParameters<MAX_DEPTH>,
    input: CircuitInput<MAX_DEPTH>,
) -> Result<Vec<u8>> {
    match input {
        CircuitInput::Mapping(mapping_input) => {
            mapping::generate_proof(&params.mapping, mapping_input)
        }
        CircuitInput::LengthExtract(length_extract_input) => {
            params.length_extract.generate(length_extract_input)
        }
        CircuitInput::LengthMatch(length_match_input) => {
            let (mapping_proof, length_proof) = length_match_input.try_into()?;
            let length_match_proof = ProofWithVK::from((
                length_proof,
                params.length_extract.circuit_data().verifier_only.clone(),
            ));
            params.length_match.generate_proof(
                params.mapping.get_mapping_circuit_set(),
                &mapping_proof,
                &length_match_proof,
            )
        }
        CircuitInput::Storage(storage_input) => params.lpn_storage.generate_proof(storage_input),
        CircuitInput::DigestEqual(digest_equal_input) => {
            let (lpn_proof, mpt_proof) = digest_equal_input.try_into()?;
            let mpt_proof = ProofWithVK::from((
                mpt_proof,
                params.length_match.circuit_data().verifier_only.clone(),
            ));
            params.digest_equal.generate_proof(
                params.lpn_storage.get_lpn_circuit_set(),
                &lpn_proof,
                &mpt_proof,
            )
        }
        CircuitInput::BlockLinking(block_linking_input) => {
            let storage_proof = ProofWithVK::from((
                block_linking_input.storage_proof.clone(),
                params.digest_equal.circuit_data().verifier_only.clone(),
            ));
            params.block_linking.generate_proof(
                &block_linking_input,
                &params.digest_equal.circuit_data().verifier_only,
            )
        }
        CircuitInput::State(state_input) => {
            let proof_input = match state_input {
                lpn_state::api::CircuitInput::Leaf(leaf_proof) => ProofInputs::from_leaf_input(
                    leaf_proof,
                    &params.block_linking.circuit_data().verifier_only,
                ),
                lpn_state::api::CircuitInput::Node((left, right)) => {
                    ProofInputs::from_node_input(&left, &right)
                }
            }?;
            params.lpn_state.generate_proof(proof_input)
        }
        CircuitInput::BlockDB(block_db_input) => {
            let proof_input = match block_db_input {
                block::CircuitInput::First(input) => Inputs::input_for_first_block(
                    input,
                    params.lpn_state.get_lpn_state_circuit_set(),
                ),
                block::CircuitInput::Subsequent(input) => {
                    Inputs::input_for_new_block(input, params.lpn_state.get_lpn_state_circuit_set())
                }
            }?;
            params.block_db.generate_proof(proof_input)
        }
    }
}
/// Get the information about the block DB circuit that needs to be exchanged with
/// set of parameters for query circuits
pub fn block_db_circuit_info<const MAX_DEPTH: usize>(
    params: &PublicParameters<MAX_DEPTH>,
) -> Result<Vec<u8>> {
    let block_db_info = BlockDBCircuitInfo::<MAX_DEPTH> {
        circuit_set: params.block_db.get_block_db_circuit_set().clone(),
        verifier_data: params.block_db.get_block_db_vk().clone(),
    };
    block_db_info.serialize()
}

/// ProofWithVK is a generic struct holding a child proof and its associated verification key.
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub(crate) struct ProofWithVK {
    pub(crate) proof: ProofWithPublicInputs<F, C, D>,
    #[serde(serialize_with = "serialize", deserialize_with = "deserialize")]
    pub(crate) vk: VerifierOnlyCircuitData<C, D>,
}

impl ProofWithVK {
    pub(crate) fn serialize(&self) -> Result<Vec<u8>> {
        let buff = bincode::serialize(&self)?;
        Ok(buff)
    }

    pub(crate) fn deserialize(buff: &[u8]) -> Result<Self> {
        let s = bincode::deserialize(buff)?;
        Ok(s)
    }

    pub(crate) fn proof(&self) -> &ProofWithPublicInputs<F, C, D> {
        &self.proof
    }

    pub(crate) fn verifier_data(&self) -> &VerifierOnlyCircuitData<C, D> {
        &self.vk
    }
}

impl
    From<(
        ProofWithPublicInputs<F, C, D>,
        VerifierOnlyCircuitData<C, D>,
    )> for ProofWithVK
{
    fn from(
        (proof, vk): (
            ProofWithPublicInputs<F, C, D>,
            VerifierOnlyCircuitData<C, D>,
        ),
    ) -> Self {
        ProofWithVK { proof, vk }
    }
}

pub(crate) fn serialize_proof<
    F: SerializableRichField<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
>(
    proof: &ProofWithPublicInputs<F, C, D>,
) -> Result<Vec<u8>> {
    Ok(bincode::serialize(&proof)?)
}

pub(crate) fn deserialize_proof<
    F: SerializableRichField<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
>(
    bytes: &[u8],
) -> Result<ProofWithPublicInputs<F, C, D>> {
    Ok(bincode::deserialize(bytes)?)
}

impl
    Into<(
        ProofWithPublicInputs<F, C, D>,
        VerifierOnlyCircuitData<C, D>,
    )> for ProofWithVK
{
    fn into(
        self,
    ) -> (
        ProofWithPublicInputs<F, C, D>,
        VerifierOnlyCircuitData<C, D>,
    ) {
        (self.proof, self.vk)
    }
}

impl<'a>
    Into<(
        &'a ProofWithPublicInputs<F, C, D>,
        &'a VerifierOnlyCircuitData<C, D>,
    )> for &'a ProofWithVK
{
    fn into(
        self,
    ) -> (
        &'a ProofWithPublicInputs<F, C, D>,
        &'a VerifierOnlyCircuitData<C, D>,
    ) {
        (self.proof(), self.verifier_data())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use anyhow::Result;
    use plonky2::{
        iop::witness::PartialWitness,
        plonk::{
            circuit_builder::CircuitBuilder,
            circuit_data::{CircuitConfig, CircuitData},
            proof::ProofWithPublicInputs,
        },
    };
    use recursion_framework::{
        circuit_builder::CircuitLogicWires, framework_testing::DummyCircuitWires,
    };

    /// Circuit that does nothing but can be passed as a children proof to some circuit when testing the aggregation
    /// logic. See state/block_linking/mod.rs tests for example.
    pub(crate) struct TestDummyCircuit<const NUM_PUBLIC_INPUTS: usize> {
        data: CircuitData<F, C, D>,
        wires: DummyCircuitWires<NUM_PUBLIC_INPUTS>,
    }

    impl<const NUM_PUBLIC_INPUTS: usize> TestDummyCircuit<NUM_PUBLIC_INPUTS> {
        pub(crate) fn build() -> Self {
            let config = CircuitConfig::standard_recursion_config();
            let mut cb = CircuitBuilder::<F, D>::new(config);
            let wires = DummyCircuitWires::circuit_logic(&mut cb, [], ());
            let data = cb.build::<C>();
            Self { data, wires }
        }

        pub(crate) fn generate_proof(
            &self,
            public_inputs: [F; NUM_PUBLIC_INPUTS],
        ) -> Result<ProofWithPublicInputs<F, C, D>> {
            let mut pw = PartialWitness::<F>::new();
            <DummyCircuitWires<NUM_PUBLIC_INPUTS> as CircuitLogicWires<F, D, 0>>::assign_input(
                &self.wires,
                public_inputs,
                &mut pw,
            )?;
            self.data.prove(pw)
        }

        pub(crate) fn circuit_data(&self) -> &CircuitData<F, C, D> {
            &self.data
        }
    }
}
