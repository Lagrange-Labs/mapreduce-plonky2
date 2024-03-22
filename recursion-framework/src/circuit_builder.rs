use plonky2::{
    field::extension::Extendable,
    gates::noop::NoopGate,
    hash::hash_types::RichField,
    iop::{target::Target, witness::PartialWitness},
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData, VerifierOnlyCircuitData},
        config::{AlgebraicHasher, GenericConfig, Hasher},
        proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget},
    },
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::{
    serialization::{
        circuit_data_serialization::SerializableRichField, deserialize, deserialize_long_array,
        serialize, serialize_long_array,
    },
    universal_verifier_gadget::{
        verifier_gadget::{UniversalVerifierBuilder, UniversalVerifierTarget},
        wrap_circuit::WrapCircuit,
        CircuitSet, CircuitSetDigest, CircuitSetTarget,
    },
};

use anyhow::Result;

/// Minimum number of gates for a circuit whose proofs needs to be verified by the universal verifier
pub const MIN_CIRCUIT_SIZE: usize = 64;

/// `CircuitLogicWires` trait must be implemented to specify the additional logic to be enforced in a
/// circuit besides verifying proofs with the universal verifier
pub trait CircuitLogicWires<F: SerializableRichField<D>, const D: usize, const NUM_VERIFIERS: usize>:
    Sized + Serialize + DeserializeOwned
{
    /// Specific input parameters that might be necessary to write the logic of the circuit
    type CircuitBuilderParams: Sized;
    /// Circuit logic specific inputs, which will be employed by the `assign_input` method to fill
    /// witness data from such input values
    type Inputs: Sized;
    /// Number of public inputs of the circuit, excluding the ones reserved by the universal verifier
    /// to expose the digest of the set of admissible circuits that can be verified
    const NUM_PUBLIC_INPUTS: usize;

    /// `circuit_logic` allows to specify an additional logic to be enforced in a circuit besides
    /// verifying proofs with the universal verifier.
    /// It returns an instance of itself, that must contain the wires that will get assigned during proving time.
    fn circuit_logic(
        builder: &mut CircuitBuilder<F, D>,
        verified_proofs: [&ProofWithPublicInputsTarget<D>; NUM_VERIFIERS],
        builder_parameters: Self::CircuitBuilderParams,
    ) -> Self;

    /// `assign_input` allows to specify how to fill the witness variables related to the additional
    /// logic enforced in `circuit_logic`, employing the input data provided in `inputs`
    fn assign_input(&self, inputs: Self::Inputs, pw: &mut PartialWitness<F>) -> Result<()>;

    /// This method, given a `ProofWithPublicInputsTarget` that should represent a proof generated with
    /// a `CircuitWithUniversalVerifier` circuit implementing the additional circuit logid specified by `Self`,
    /// returns the set of `Self::NUM_PUBLIC_INPUTS` targets corresponding to all the public inputs of the
    /// proof except for the ones representing the digest of the circuit set
    fn public_input_targets(proof: &ProofWithPublicInputsTarget<D>) -> &[Target]
    where
        [(); Self::NUM_PUBLIC_INPUTS]:,
    {
        public_input_targets::<F, D, { Self::NUM_PUBLIC_INPUTS }>(proof)
    }
}

/// `CircuitWithUniversalVerifierBuilder` is a data structure that can be employed to build circuits that
/// either employ the universal verifier or whose proofs needs to be verified by a circuit employing the
/// universal verifier
pub struct CircuitWithUniversalVerifierBuilder<
    F: RichField + Extendable<D>,
    const D: usize,
    const NUM_PUBLIC_INPUTS: usize,
> {
    verifier_builder: UniversalVerifierBuilder<F, D, NUM_PUBLIC_INPUTS>,
    config: CircuitConfig,
}

impl<F: SerializableRichField<D>, const D: usize, const NUM_PUBLIC_INPUTS: usize>
    CircuitWithUniversalVerifierBuilder<F, D, NUM_PUBLIC_INPUTS>
{
    /// Instantiate a `CircuitWithUniversalVerifierBuilder` to build circuits with `num_public_inputs`
    /// employing the configuration `config`. Besides verifying proofs, the universal verifier,
    /// which is a fundamental building block of circuits built with such data structure, also checks
    /// that the verifier data employed for proof verification belongs to a set of admissible verifier data;
    /// the size of such a set corresponds to `circuit_set_size`, which must be provided as input.  
    pub fn new<C: GenericConfig<D, F = F> + 'static>(
        config: CircuitConfig,
        circuit_set_size: usize,
    ) -> Self
    where
        C::Hasher: AlgebraicHasher<F>,
        [(); C::Hasher::HASH_SIZE]:,
    {
        let verifier_builder = UniversalVerifierBuilder::new::<C>(config.clone(), circuit_set_size);
        Self {
            verifier_builder,
            config,
        }
    }

    /// `build_circuit` builds a Plonky2 circuit which:
    /// - Verify `NUM_VERIFIERS` proofs employing the universal verifier.
    /// - Execute the custom logic specified by the `CLW` implementation
    /// Note that the output data structure contains also the wrapping circuit necessary to
    /// generate proofs that can be verified recursively with a universal verifier.
    pub fn build_circuit<
        C: GenericConfig<D, F = F>,
        const NUM_VERIFIERS: usize,
        CLW: CircuitLogicWires<F, D, NUM_VERIFIERS>,
    >(
        &self,
        input_parameters: CLW::CircuitBuilderParams,
    ) -> CircuitWithUniversalVerifier<F, C, D, NUM_VERIFIERS, CLW>
    where
        C::Hasher: AlgebraicHasher<F>,
        [(); C::Hasher::HASH_SIZE]:,
    {
        self.build_circuit_internal(&self.config, input_parameters)
    }

    /// Same functionality as `build_circuit`, but employing a custom circuit configuration (provided as input)
    /// to build the circuit
    pub fn build_circuit_with_custom_config<
        C: GenericConfig<D, F = F>,
        const NUM_VERIFIERS: usize,
        CLW: CircuitLogicWires<F, D, NUM_VERIFIERS>,
    >(
        &self,
        custom_config: CircuitConfig,
        input_parameters: CLW::CircuitBuilderParams,
    ) -> CircuitWithUniversalVerifier<F, C, D, NUM_VERIFIERS, CLW>
    where
        C::Hasher: AlgebraicHasher<F>,
        [(); C::Hasher::HASH_SIZE]:,
    {
        self.build_circuit_internal(&custom_config, input_parameters)
    }

    fn build_circuit_internal<
        C: GenericConfig<D, F = F>,
        const NUM_VERIFIERS: usize,
        CLW: CircuitLogicWires<F, D, NUM_VERIFIERS>,
    >(
        &self,
        config: &CircuitConfig,
        input_parameters: CLW::CircuitBuilderParams,
    ) -> CircuitWithUniversalVerifier<F, C, D, NUM_VERIFIERS, CLW>
    where
        C::Hasher: AlgebraicHasher<F>,
        [(); C::Hasher::HASH_SIZE]:,
    {
        let mut builder = CircuitBuilder::<F, D>::new(config.clone());
        let circuit_set_target = CircuitSetTarget::build_target(&mut builder);
        let universal_verifier_targets: [UniversalVerifierTarget<D>; NUM_VERIFIERS] = (0
            ..NUM_VERIFIERS)
            .map(|_| {
                self.verifier_builder
                    .universal_verifier_circuit(&mut builder, &circuit_set_target)
            })
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        let proof_targets = universal_verifier_targets
            .iter()
            .map(|uv_t| uv_t.get_proof_target())
            .collect::<Vec<_>>();
        let circuit_logic_wires = CLW::circuit_logic(
            &mut builder,
            proof_targets.try_into().unwrap(),
            input_parameters,
        );
        // Register the circuit set digest as the last public inputs of the proof. The universal verifier checks that
        // it corresponds to the expect circuit set digest.
        builder.register_public_inputs(circuit_set_target.to_targets().as_slice());

        while builder.num_gates() <= MIN_CIRCUIT_SIZE / 2 {
            builder.add_gate(NoopGate, vec![]);
        }

        let data = builder.build::<C>();

        let wrap_circuit =
            WrapCircuit::build_wrap_circuit(&data.verifier_only, &data.common, &self.config);

        CircuitWithUniversalVerifier::<F, C, D, NUM_VERIFIERS, CLW> {
            universal_verifier_targets,
            circuit_data: data,
            circuit_logic_wires,
            circuit_set_target,
            wrap_circuit,
        }
    }

    pub(crate) fn get_circuit_set_size(&self) -> usize {
        self.verifier_builder.get_circuit_set_size()
    }

    /// This method, given a `ProofWithPublicInputsTarget` that should represent a proof generated with
    /// a circuit built by `Self`, returns the set of targets corresponding to all the public inputs of
    /// the proof except for the ones representing the digest of the circuit set
    pub fn public_input_targets(proof: &ProofWithPublicInputsTarget<D>) -> &[Target] {
        &proof.public_inputs[..NUM_PUBLIC_INPUTS]
    }

    /// This method, given a `ProofWithPublicInputsTarget` that should represent a proof generated with
    /// a circuit built by `Self`, returns the set of targets that represent the digest
    /// of the circuit set exposed as public input by the proof, which might be necessary when the proof
    /// is recursively verified in another circuit
    pub fn circuit_set_targets(proof: &ProofWithPublicInputsTarget<D>) -> &[Target] {
        &proof.public_inputs[NUM_PUBLIC_INPUTS..]
    }
}

/// This method, given a `ProofWithPublicInputsTarget` that should represent a proof generated with
/// a `CircuitWithUniversalVerifier` circuit, returns the set of `NUM_PUBLIC_INPUTS` targets corresponding to
/// all the public inputs of the proof except for the ones representing the digest of the circuit set
pub fn public_input_targets<
    F: SerializableRichField<D>,
    const D: usize,
    const NUM_PUBLIC_INPUTS: usize,
>(
    proof: &ProofWithPublicInputsTarget<D>,
) -> &[Target] {
    CircuitWithUniversalVerifierBuilder::<F, D, NUM_PUBLIC_INPUTS>::public_input_targets(proof)
}

/// This method, given a `ProofWithPublicInputsTarget` that should represent a proof generated with
/// a `CircuitWithUniversalVerifier` circuit, returns the set of targets that represent the digest
/// of the circuit set exposed as public input by the proof, which might be necessary when the proof
/// is recursively verified in another circuit
pub fn circuit_set_targets<
    F: SerializableRichField<D>,
    const D: usize,
    const NUM_PUBLIC_INPUTS: usize,
>(
    proof: &ProofWithPublicInputsTarget<D>,
) -> &[Target] {
    CircuitWithUniversalVerifierBuilder::<F, D, NUM_PUBLIC_INPUTS>::circuit_set_targets(proof)
}

/// `CircuitWithUniversalVerifier` is a data structure representing a circuit containing `NUM_VERIFIERS`
/// instances of the universal verifier altogether with the additional logic specified by the specific
/// `CLW` implementor
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(bound = "")]
pub struct CircuitWithUniversalVerifier<
    F: SerializableRichField<D>,
    C: GenericConfig<D, F = F> + 'static,
    const D: usize,
    const NUM_VERIFIERS: usize,
    CLW: CircuitLogicWires<F, D, NUM_VERIFIERS>,
> where
    C::Hasher: AlgebraicHasher<F>,
{
    #[serde(
        serialize_with = "serialize_long_array",
        deserialize_with = "deserialize_long_array"
    )]
    universal_verifier_targets: [UniversalVerifierTarget<D>; NUM_VERIFIERS],
    #[serde(serialize_with = "serialize", deserialize_with = "deserialize")]
    circuit_data: CircuitData<F, C, D>,
    circuit_logic_wires: CLW,
    circuit_set_target: CircuitSetTarget,
    wrap_circuit: WrapCircuit<F, C, D>,
}

impl<
        F: SerializableRichField<D>,
        C: GenericConfig<D, F = F>,
        const D: usize,
        const NUM_VERIFIERS: usize,
        CLW: CircuitLogicWires<F, D, NUM_VERIFIERS>,
    > CircuitWithUniversalVerifier<F, C, D, NUM_VERIFIERS, CLW>
where
    C::Hasher: AlgebraicHasher<F>,
    [(); C::Hasher::HASH_SIZE]:,
{
    /// Generate a proof for this instance of a `CircuitWithUniversalVerifier, employing the provided inputs
    /// to compute the witness data necessary to generate the proof. More specifically:
    /// - `input_proofs` and `input_verifier_data` are employed as inputs to the `NUM_VERIFIERS` instances of
    ///   of the universal verfier
    /// - `circuit_set` is employed to compute the witness necessary to prove that each `input_verifier_data`
    ///   belongs to the set of admissible circuits to be verified with this circuit, whose digest is a public
    ///   input of the circuit
    /// - `custom_inputs` are employed as inputs to fill witness data related to the additional logic being
    ///   enforced besides verifying the `NUM_VERIFIERS` proofs with the universal verifier
    /// Note that this function will output a proof of the wrapping circuit, which can be directly
    /// recursively verified with the universal verifier. This method is publicly exposed through the
    /// `generate_proof` method of `RecursiveCircuits` data structure
    pub(crate) fn generate_proof(
        &self,
        input_proofs: [ProofWithPublicInputs<F, C, D>; NUM_VERIFIERS],
        input_verifier_data: [&VerifierOnlyCircuitData<C, D>; NUM_VERIFIERS],
        circuit_set: &CircuitSet<F, C, D>,
        custom_inputs: CLW::Inputs,
    ) -> Result<ProofWithPublicInputs<F, C, D>> {
        let mut pw = PartialWitness::<F>::new();
        for i in 0..NUM_VERIFIERS {
            self.universal_verifier_targets.as_ref()[i].set_target(
                &mut pw,
                circuit_set,
                &input_proofs[i],
                input_verifier_data[i],
            )?;
        }
        self.circuit_logic_wires
            .assign_input(custom_inputs, &mut pw)?;

        self.circuit_set_target
            .set_target(&mut pw, &CircuitSetDigest::from(circuit_set));

        let base_proof = self.circuit_data.prove(pw)?;

        self.wrap_circuit.wrap_proof(base_proof)
    }

    /// Returns a reference to the `CircuitData` of the wrapping circuit, that is the circuit whose proofs
    /// can be directly verified recursively by the universal verifier
    pub fn circuit_data(&self) -> &CircuitData<F, C, D> {
        self.wrap_circuit.final_proof_circuit_data()
    }

    /// This method returns the number of gates of the wrapped circuit, that is the circuit whose proofs
    /// are recursively verified by the wrapping circuit; this is mostly intended to let the caller learn
    /// the size of the wrapped circuit, given that the final wrapping circuit, which is the one whose
    /// `CircuitData` are accessbiel through the `circuit_data` method has a fixed size  
    pub fn wrapped_circuit_size(&self) -> usize {
        self.circuit_data.common.degree()
    }

    /// This method, given a proof generated with by `Self` circuit, returns the public inputs
    /// of the proof except for the ones representing the digest of the circuit set
    pub fn public_inputs(proof: &ProofWithPublicInputs<F, C, D>) -> &[F] {
        &proof.public_inputs[..CLW::NUM_PUBLIC_INPUTS]
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::{
        array, cmp,
        iter::{once, repeat},
        marker::PhantomData,
    };

    use plonky2::{
        gates::gate::Gate,
        hash::{hash_types::NUM_HASH_OUT_ELTS, poseidon::PoseidonHash},
        iop::{target::Target, witness::WitnessWrite},
        plonk::config::PoseidonGoldilocksConfig,
    };

    use plonky2_monolith::{gates::monolith::MonolithGate, monolith_hash::MonolithHash};

    use crate::serialization::{
        circuit_data_serialization::SerializableRichField, deserialize_array, serialize_array,
    };

    use super::*;

    use serial_test::serial;

    pub(crate) const NUM_PUBLIC_INPUTS_TEST_CIRCUITS: usize = NUM_HASH_OUT_ELTS;

    pub(crate) type LeafCircuitWires<F, const INPUT_SIZE: usize> =
        LeafCircuitWithCustomHasherWires<F, INPUT_SIZE, PoseidonHash>;

    #[derive(Serialize, Deserialize)]
    pub(crate) struct LeafCircuitWithCustomHasherWires<
        F: RichField,
        const INPUT_SIZE: usize,
        H: AlgebraicHasher<F>,
    > {
        #[serde(
            serialize_with = "serialize_array",
            deserialize_with = "deserialize_array"
        )]
        inputs: [Target; INPUT_SIZE],
        generator: Target,
        _f: PhantomData<F>,
        _h: PhantomData<H>,
    }

    impl<
            'a,
            F: SerializableRichField<D>,
            const D: usize,
            const NUM_VERIFIERS: usize,
            const INPUT_SIZE: usize,
            H: AlgebraicHasher<F>,
        > CircuitLogicWires<F, D, NUM_VERIFIERS>
        for LeafCircuitWithCustomHasherWires<F, INPUT_SIZE, H>
    {
        /*
        - First parameter specifies the number of hashes to be performed
        - Second one is a flag to specify how the input payload of each hash is computed
        */
        type CircuitBuilderParams = (usize, bool);

        type Inputs = ([F; INPUT_SIZE], F);

        const NUM_PUBLIC_INPUTS: usize = NUM_PUBLIC_INPUTS_TEST_CIRCUITS;

        fn circuit_logic(
            builder: &mut CircuitBuilder<F, D>,
            _verified_proofs: [&ProofWithPublicInputsTarget<D>; NUM_VERIFIERS],
            builder_parameters: Self::CircuitBuilderParams,
        ) -> Self {
            let inputs = builder.add_virtual_target_arr::<INPUT_SIZE>();
            let generator = builder.add_virtual_target();
            let mut state = inputs.to_vec();
            let mut generated = generator;
            for _ in 0..builder_parameters.0 {
                let hash_input = {
                    let hash_input_iter = state.into_iter().chain(once(generated));
                    if builder_parameters.1 {
                        hash_input_iter.rev().collect::<Vec<_>>()
                    } else {
                        hash_input_iter.collect::<Vec<_>>()
                    }
                };
                state = builder
                    .hash_n_to_hash_no_pad::<H>(hash_input)
                    .elements
                    .to_vec();
                generated = builder.mul(generated, generator)
            }

            builder.register_public_inputs(state.as_slice());

            Self {
                inputs,
                generator,
                _f: PhantomData::default(),
                _h: PhantomData::default(),
            }
        }

        fn assign_input(&self, inputs: Self::Inputs, pw: &mut PartialWitness<F>) -> Result<()> {
            pw.set_target_arr(self.inputs.as_ref(), inputs.0.as_slice());
            pw.set_target(self.generator, inputs.1);

            Ok(())
        }
    }
    #[derive(Serialize, Deserialize)]
    pub(crate) struct RecursiveCircuitWires<const INPUT_SIZE: usize> {
        #[serde(
            serialize_with = "serialize_array",
            deserialize_with = "deserialize_array"
        )]
        to_be_hashed_payload: [Target; INPUT_SIZE],
    }

    impl<
            'a,
            F: SerializableRichField<D>,
            const D: usize,
            const NUM_VERIFIERS: usize,
            const INPUT_SIZE: usize,
        > CircuitLogicWires<F, D, NUM_VERIFIERS> for RecursiveCircuitWires<INPUT_SIZE>
    {
        type CircuitBuilderParams = ();
        type Inputs = [F; INPUT_SIZE];
        const NUM_PUBLIC_INPUTS: usize = NUM_PUBLIC_INPUTS_TEST_CIRCUITS;

        fn circuit_logic(
            builder: &mut CircuitBuilder<F, D>,
            verified_proofs: [&ProofWithPublicInputsTarget<D>; NUM_VERIFIERS],
            _: Self::CircuitBuilderParams,
        ) -> Self {
            let to_be_hashed_payload = builder.add_virtual_target_arr::<INPUT_SIZE>();
            let hash_input = verified_proofs
                .into_iter()
                .flat_map(|pt| public_input_targets::<F, D, NUM_PUBLIC_INPUTS_TEST_CIRCUITS>(pt))
                .chain(to_be_hashed_payload.iter())
                .cloned()
                .collect::<Vec<_>>();
            let state = builder.hash_n_to_hash_no_pad::<PoseidonHash>(hash_input);
            builder.register_public_inputs(state.elements.as_slice());

            Self {
                to_be_hashed_payload,
            }
        }

        fn assign_input(&self, inputs: Self::Inputs, pw: &mut PartialWitness<F>) -> Result<()> {
            pw.set_target_arr(self.to_be_hashed_payload.as_ref(), inputs.as_slice());

            Ok(())
        }
    }

    fn test_circuit_with_universal_verifier<
        F: SerializableRichField<D>,
        C: GenericConfig<D, F = F> + 'static,
        const D: usize,
        const NUM_VERIFIERS: usize,
        H: AlgebraicHasher<F>,
    >(
        config: Option<CircuitConfig>,
    ) where
        C::Hasher: AlgebraicHasher<F>,
        [(); C::Hasher::HASH_SIZE]:,
    {
        const INPUT_SIZE: usize = 8;
        const NUM_PUBLIC_INPUTS: usize = NUM_PUBLIC_INPUTS_TEST_CIRCUITS;
        let std_config = CircuitConfig::standard_recursion_config();
        let circuit_builder = CircuitWithUniversalVerifierBuilder::<F, D, NUM_PUBLIC_INPUTS>::new::<
            C,
        >(std_config.clone(), 2);
        let leaf_circuit = if let Some(custom_config) = config {
            circuit_builder.build_circuit_with_custom_config::<C, 0, LeafCircuitWithCustomHasherWires<F, INPUT_SIZE, H>>(custom_config, (1usize << 12, false))
        } else {
            circuit_builder
                .build_circuit::<C, 0, LeafCircuitWithCustomHasherWires<F, INPUT_SIZE, H>>((
                    1usize << 7,
                    false,
                ))
        };
        println!(
            "leaf circuit built: {}",
            leaf_circuit.wrapped_circuit_size()
        );

        let recursive_circuit = circuit_builder
            .build_circuit::<C, NUM_VERIFIERS, RecursiveCircuitWires<INPUT_SIZE>>(());

        let circuit_set = CircuitSet::<F, C, D>::build_circuit_set(vec![
            leaf_circuit.circuit_data().verifier_only.circuit_digest,
            recursive_circuit
                .circuit_data()
                .verifier_only
                .circuit_digest,
        ]);

        let circuit_set_digest = CircuitSetDigest::from(&circuit_set);

        let base_proofs = (0..2 * NUM_VERIFIERS - 1)
            .map(|_| {
                let inputs = array::from_fn(|_| F::rand());
                leaf_circuit.generate_proof([], [], &circuit_set, (inputs, F::rand()))
            })
            .collect::<Result<Vec<_>>>()
            .unwrap();

        let recursive_circuits_input = array::from_fn(|_| F::rand());
        let rec_proof = recursive_circuit
            .generate_proof(
                base_proofs[..NUM_VERIFIERS].to_vec().try_into().unwrap(),
                [&leaf_circuit.circuit_data().verifier_only; NUM_VERIFIERS],
                &circuit_set,
                recursive_circuits_input,
            )
            .unwrap();

        assert_eq!(
            &rec_proof.public_inputs[NUM_PUBLIC_INPUTS..],
            circuit_set_digest.flatten().as_slice()
        );

        recursive_circuit
            .circuit_data()
            .verify(rec_proof.clone())
            .unwrap();

        let recursive_circuits_input = array::from_fn(|_| F::rand());
        let input_proofs = base_proofs
            .into_iter()
            .skip(NUM_VERIFIERS)
            .chain(once(rec_proof))
            .collect::<Vec<_>>();
        let input_vd = repeat(&leaf_circuit.circuit_data().verifier_only)
            .take(NUM_VERIFIERS - 1)
            .chain(once(&recursive_circuit.circuit_data().verifier_only))
            .collect::<Vec<_>>();
        let rec_proof = recursive_circuit
            .generate_proof(
                input_proofs.try_into().unwrap(),
                input_vd.try_into().unwrap(),
                &circuit_set,
                recursive_circuits_input,
            )
            .unwrap();

        assert_eq!(
            &rec_proof.public_inputs[NUM_PUBLIC_INPUTS..],
            circuit_set_digest.flatten().as_slice()
        );

        recursive_circuit.circuit_data().verify(rec_proof).unwrap();
    }

    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    fn generate_config_for_monolith() -> CircuitConfig {
        let needed_wires = cmp::max(
            MonolithGate::<F, D>::new().num_wires(),
            CircuitConfig::standard_recursion_config().num_wires,
        );
        CircuitConfig {
            num_wires: needed_wires,
            num_routed_wires: needed_wires,
            ..CircuitConfig::standard_recursion_config()
        }
    }

    #[test]
    #[serial]
    fn test_circuit_with_one_universal_verifier() {
        test_circuit_with_universal_verifier::<F, C, D, 1, PoseidonHash>(None);
    }

    #[test]
    #[serial]
    fn test_circuit_with_two_universal_verifier() {
        test_circuit_with_universal_verifier::<F, C, D, 2, PoseidonHash>(None);
    }

    #[test]
    #[serial]
    fn test_circuit_with_three_universal_verifier() {
        test_circuit_with_universal_verifier::<F, C, D, 3, PoseidonHash>(None);
    }

    #[test]
    #[serial]
    fn test_circuit_with_four_universal_verifier() {
        test_circuit_with_universal_verifier::<F, C, D, 4, PoseidonHash>(None);
    }

    #[test]
    #[serial]
    fn test_circuit_with_five_universal_verifier() {
        test_circuit_with_universal_verifier::<F, C, D, 5, PoseidonHash>(None);
    }

    #[test]
    #[serial]
    fn test_circuit_with_lookup_gates() {
        env_logger::init();
        // To employ `MonolithHash` we need a custom circuit configuration
        let config = generate_config_for_monolith();
        test_circuit_with_universal_verifier::<F, C, D, 2, MonolithHash>(Some(config));
    }
}
