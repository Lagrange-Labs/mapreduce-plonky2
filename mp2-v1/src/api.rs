//! Main APIs and related structures

use crate::{
    block_extraction, contract_extraction,
    final_extraction::{self, BaseCircuitProofInputs, SimpleCircuit},
    length_extraction::{self, LengthCircuitInput},
    values_extraction,
};
use anyhow::Result;
use ethers::core::k256::elliptic_curve::rand_core::block;
use mp2_common::{
    serialization::{circuit_data_serialization::SerializableRichField, deserialize, serialize},
    C, D, F,
};
use plonky2::plonk::{
    circuit_builder::CircuitBuilder,
    circuit_data::{CircuitConfig, VerifierCircuitData, VerifierOnlyCircuitData},
    config::{AlgebraicHasher, GenericConfig},
    proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget},
};
use serde::{Deserialize, Serialize};

/// Struct containing the expected input MPT Extension/Branch node
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InputNode {
    pub node: Vec<u8>,
}

/// This data structure allows to specify the inputs for a circuit that needs to
/// recursively verify proofs; the generic type `T` allows to specify the
/// specific inputs of each circuits besides the proofs that need to be
/// recursively verified, while the proofs are serialized in byte format.
#[derive(Serialize, Deserialize)]
pub struct ProofInputSerialized<T> {
    pub input: T,
    pub serialized_child_proofs: Vec<Vec<u8>>,
}

impl<T> ProofInputSerialized<T> {
    /// Deserialize child proofs and return the set of deserialized 'MTPProof`s
    pub fn get_child_proofs(&self) -> anyhow::Result<Vec<ProofWithVK>> {
        self.serialized_child_proofs
            .iter()
            .map(|proof| ProofWithVK::deserialize(proof))
            .collect::<Result<Vec<_>, _>>()
    }
}

/// Set of inputs necessary to generate proofs for each circuit employed in the
/// pre-processing stage of LPN
pub enum CircuitInput {
    /// Contract extraction input
    ContractExtraction(contract_extraction::CircuitInput),
    /// Length extraction input
    LengthExtraction(LengthCircuitInput),
    /// Values extraction input
    ValuesExtraction(values_extraction::CircuitInput),
    /// Block extraction necessary input
    BlockExtraction(block_extraction::CircuitInput),
    /// Final extraction input
    FinalExtraction(final_extraction::CircuitInput),
}

#[derive(Serialize, Deserialize)]
/// Parameters defining all the circuits employed for the pre-processing stage of LPN
pub struct PublicParameters {
    contract_extraction: contract_extraction::PublicParameters,
    length_extraction: length_extraction::PublicParameters,
    values_extraction: values_extraction::PublicParameters,
    block_extraction: block_extraction::PublicParameters,
    final_extraction: final_extraction::PublicParameters,
}

/// Instantiate the circuits employed for the pre-processing stage of LPN,
/// returning their corresponding parameters
pub fn build_circuits_params() -> PublicParameters {
    log::info!("Building contract_extraction parameters...");
    let contract_extraction = contract_extraction::build_circuits_params();
    log::info!("Building length_extraction parameters...");
    let length_extraction = length_extraction::PublicParameters::build();
    log::info!("Building values_extraction parameters...");
    let values_extraction = values_extraction::build_circuits_params();
    log::info!("Building block_extraction parameters...");
    let block_extraction = block_extraction::build_circuits_params();
    log::info!("Building final_extraction parameters...");
    let final_extraction = final_extraction::PublicParameters::build(
        block_extraction.circuit_data().verifier_data(),
        contract_extraction.get_circuit_set(),
        values_extraction.get_circuit_set(),
        length_extraction.get_circuit_set(),
    );
    log::info!("All parameters built!");

    PublicParameters {
        contract_extraction,
        values_extraction,
        length_extraction,
        block_extraction,
        final_extraction,
    }
}

/// Generate a proof for a circuit in the set of circuits employed in the
/// pre-processing stage of LPN, employing `CircuitInput` to specify for which
/// circuit the proof should be generated
pub fn generate_proof(params: &PublicParameters, input: CircuitInput) -> Result<Vec<u8>> {
    match input {
        CircuitInput::ContractExtraction(input) => {
            contract_extraction::generate_proof(&params.contract_extraction, input)
        }
        CircuitInput::LengthExtraction(input) => params.length_extraction.generate_proof(input),
        CircuitInput::ValuesExtraction(input) => {
            values_extraction::generate_proof(&params.values_extraction, input)
        }
        CircuitInput::BlockExtraction(input) => params.block_extraction.generate_proof(input),
        CircuitInput::FinalExtraction(input) => {
            let contract_circuit_set = params.contract_extraction.get_circuit_set();
            let value_circuit_set = params.values_extraction.get_circuit_set();
            match input {
                final_extraction::CircuitInput::Simple(input) => params
                    .final_extraction
                    .generate_simple_proof(input, contract_circuit_set, value_circuit_set),
                final_extraction::CircuitInput::Lengthed(input) => {
                    let length_circuit_set = params.length_extraction.get_circuit_set();
                    params.final_extraction.generate_lengthed_proof(
                        input,
                        contract_circuit_set,
                        value_circuit_set,
                        length_circuit_set,
                    )
                }
            }
        }
    }
}

/// Retrieve a common `CircuitConfig` to be employed to generate the parameters for the circuits
/// employed for the pre-processing statge of LPN
pub(crate) fn default_config() -> CircuitConfig {
    CircuitConfig::standard_recursion_config()
}

/// ProofWithVK is a generic struct holding a child proof and its associated verification key.
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct ProofWithVK {
    pub(crate) proof: ProofWithPublicInputs<F, C, D>,
    #[serde(serialize_with = "serialize", deserialize_with = "deserialize")]
    pub(crate) vk: VerifierOnlyCircuitData<C, D>,
}

impl ProofWithVK {
    pub fn serialize(&self) -> Result<Vec<u8>> {
        let buff = bincode::serialize(&self)?;
        Ok(buff)
    }

    pub fn deserialize(buff: &[u8]) -> Result<Self> {
        let s = bincode::deserialize(buff)?;
        Ok(s)
    }

    pub fn proof(&self) -> &ProofWithPublicInputs<F, C, D> {
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

pub fn serialize_proof<F: SerializableRichField<D>, C: GenericConfig<D, F = F>, const D: usize>(
    proof: &ProofWithPublicInputs<F, C, D>,
) -> Result<Vec<u8>> {
    Ok(bincode::serialize(&proof)?)
}

pub fn deserialize_proof<
    F: SerializableRichField<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
>(
    bytes: &[u8],
) -> Result<ProofWithPublicInputs<F, C, D>> {
    Ok(bincode::deserialize(bytes)?)
}

impl From<ProofWithVK>
    for (
        ProofWithPublicInputs<F, C, D>,
        VerifierOnlyCircuitData<C, D>,
    )
{
    fn from(val: ProofWithVK) -> Self {
        (val.proof, val.vk)
    }
}

impl<'a> From<&'a ProofWithVK>
    for (
        &'a ProofWithPublicInputs<F, C, D>,
        &'a VerifierOnlyCircuitData<C, D>,
    )
{
    fn from(val: &'a ProofWithVK) -> Self {
        (val.proof(), val.verifier_data())
    }
}

/// Recursively verify a proof for a circuit with the given `verifier_data`
pub(crate) fn verify_proof_fixed_circuit<
    F: SerializableRichField<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
>(
    cb: &mut CircuitBuilder<F, D>,
    verifier_data: &VerifierCircuitData<F, C, D>,
) -> ProofWithPublicInputsTarget<D>
where
    C::Hasher: AlgebraicHasher<F>,
{
    let proof = cb.add_virtual_proof_with_pis(&verifier_data.common);
    let vd = cb.constant_verifier_data(&verifier_data.verifier_only);
    cb.verify_proof::<C>(&proof, &vd, &verifier_data.common);
    proof
}

#[cfg(test)]
pub(crate) mod tests {
    use plonky2::{
        field::types::Field,
        iop::{target::Target, witness::WitnessWrite},
    };

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

    // check that the closure $f actually panics, printing $msg as error message if the function
    // did not panic; this macro is employed in tests in place of #[should_panic] to ensure that a
    // panic occurred in the expected function rather than in other parts of the test
    macro_rules! check_panic {
        ($f: expr, $msg: expr) => {{
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe($f));
            assert!(result.is_err(), $msg);
        }};
    }

    pub(crate) use check_panic;

    #[test]
    fn test_verify_proof_with_fixed_circuit() {
        const NUM_IO: usize = 4;
        struct TestCircuit {
            data: CircuitData<F, C, D>,
            pi_targets: [Target; NUM_IO],
        }

        impl TestCircuit {
            fn build(config: CircuitConfig, value: usize) -> Self {
                let mut builder = CircuitBuilder::<F, D>::new(config);
                let val_t = builder.constant(F::from_canonical_usize(value));
                let pi_targets = builder.add_virtual_public_input_arr::<NUM_IO>();
                builder.connect(pi_targets[0], val_t);

                let data = builder.build::<C>();
                TestCircuit { data, pi_targets }
            }

            fn prove(&self, value: usize) -> Result<ProofWithPublicInputs<F, C, D>> {
                let mut pw = PartialWitness::<F>::new();
                let values = [F::from_canonical_usize(value); NUM_IO];
                pw.set_target_arr(&self.pi_targets, &values);
                self.data.prove(pw)
            }
        }

        let config = CircuitConfig::standard_recursion_config();

        let first_test_circuit = TestCircuit::build(config.clone(), 42);
        let second_test_circuit = TestCircuit::build(config.clone(), 24);
        // check that the 2 circuits has the same `CommonCircuitData`, but different `VerifierOnlyCircuitData`
        assert_eq!(
            first_test_circuit.data.common,
            second_test_circuit.data.common
        );
        assert_ne!(
            first_test_circuit.data.verifier_only,
            second_test_circuit.data.verifier_only
        );

        let first_base_proof = first_test_circuit.prove(42).unwrap();
        let second_base_proof = second_test_circuit.prove(24).unwrap();

        struct VerifierCircuit {
            data: CircuitData<F, C, D>,
            proof: ProofWithPublicInputsTarget<D>,
        }

        impl VerifierCircuit {
            fn build(config: CircuitConfig, vd: &VerifierCircuitData<F, C, D>) -> Self {
                let mut builder = CircuitBuilder::<F, D>::new(config);
                let proof = verify_proof_fixed_circuit(&mut builder, vd);
                let data = builder.build::<C>();

                Self { data, proof }
            }

            fn prove(
                &self,
                proof: &ProofWithPublicInputs<F, C, D>,
            ) -> Result<ProofWithPublicInputs<F, C, D>> {
                let mut pw = PartialWitness::<F>::new();
                pw.set_proof_with_pis_target(&self.proof, proof);
                self.data.prove(pw)
            }
        }

        // build verifier circuit for `test_circuit`
        let first_verifier =
            VerifierCircuit::build(config.clone(), &first_test_circuit.data.verifier_data());
        // recursive verification of proof of `test_circuit` should work
        let rec_proof = first_verifier.prove(&first_base_proof).unwrap();
        first_verifier.data.verify(rec_proof).unwrap();

        // verify proof of `second_test_circuit` shouldn't work
        check_panic!(
            || first_verifier.prove(&second_base_proof),
            "successful recursive verification of proof for second circuit with first verifier"
        );

        // check that `second_base_proof` can be verifier by verifier for `second_test_circuit`
        let second_verifier =
            VerifierCircuit::build(config.clone(), &second_test_circuit.data.verifier_data());
        let rec_proof = second_verifier.prove(&second_base_proof).unwrap();
        second_verifier.data.verify(rec_proof).unwrap();

        // verify proof of `test_circuit` shouldn't work
        check_panic!(
            || second_verifier.prove(&first_base_proof),
            "successful recursive verification of proof for second circuit with first verifier"
        );
    }
}
