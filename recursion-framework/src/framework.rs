use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOut, RichField},
    iop::{target::Target, witness::PartialWitness},
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, VerifierCircuitTarget, VerifierOnlyCircuitData},
        config::{AlgebraicHasher, GenericConfig, Hasher},
        proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget},
    },
};
use serde::{Deserialize, Serialize};

use crate::{
    circuit_builder::{public_input_targets, CircuitLogicWires, CircuitWithUniversalVerifier},
    serialization::circuit_data_serialization::SerializableRichField,
    universal_verifier_gadget::{
        verifier_gadget::{UniversalVerifierBuilder, UniversalVerifierTarget},
        CircuitSet, CircuitSetDigest, CircuitSetTarget,
    },
};

use anyhow::Result;

/// This trait is employed to fetch the `VerifierOnlyCircuitData` of a circuit, which is needed to verify
/// a proof with the universal verifier
pub trait RecursiveCircuitInfo<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    /// Returns a reference to the `VerifierOnlyCircuitData` of the circuit implementing this trait
    fn get_verifier_data(&self) -> &VerifierOnlyCircuitData<C, D>;
}

/// `RecursivecircuitInfo` trait is automatically implemented for any `CircuitWithUniversalVerifier`
/// and for `&CircuitWithUniversalVerifier`
impl<F, C, const D: usize, const NUM_VERIFIERS: usize, CLW> RecursiveCircuitInfo<F, C, D>
    for CircuitWithUniversalVerifier<F, C, D, NUM_VERIFIERS, CLW>
where
    F: SerializableRichField<D>,
    C: GenericConfig<D, F = F>,
    C::Hasher: AlgebraicHasher<F>,
    [(); C::Hasher::HASH_SIZE]:,
    CLW: CircuitLogicWires<F, D, NUM_VERIFIERS>,
{
    fn get_verifier_data(&self) -> &VerifierOnlyCircuitData<C, D> {
        &self.circuit_data().verifier_only
    }
}

impl<F, C, const D: usize, T> RecursiveCircuitInfo<F, C, D> for &T
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    T: RecursiveCircuitInfo<F, C, D>,
{
    fn get_verifier_data(&self) -> &VerifierOnlyCircuitData<C, D> {
        (*self).get_verifier_data()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(bound = "")]
/// `RecursiveCircuits` is a data structure employed to generate proofs for a given set of circuits,
/// which are basically instances of `CircuitWithUniversalVerifier`
pub struct RecursiveCircuits<
    F: SerializableRichField<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
> {
    circuit_set: CircuitSet<F, C, D>,
}

impl<F: SerializableRichField<D>, C: GenericConfig<D, F = F> + 'static, const D: usize>
    RecursiveCircuits<F, C, D>
where
    C::Hasher: AlgebraicHasher<F>,
    [(); C::Hasher::HASH_SIZE]:,
{
    /// Instantiate a `RecursiveCircuits` data structure employing the list of circuits provided as input
    pub fn new(circuits: Vec<Box<dyn RecursiveCircuitInfo<F, C, D> + '_>>) -> Self {
        let circuit_digests = circuits
            .into_iter()
            .map(|circuit| circuit.as_ref().get_verifier_data().circuit_digest)
            .collect::<Vec<_>>();
        Self::new_from_circuit_digests(circuit_digests)
    }

    /// Internal function used to initialize `Self` from a set of `circuit_digests`
    pub fn new_from_circuit_digests(circuit_digests: Vec<HashOut<F>>) -> Self {
        Self {
            circuit_set: CircuitSet::build_circuit_set(circuit_digests),
        }
    }

    /// Generate a proof for the `CircuitWithUniversalVerifier` `circuit`, employing the provided inputs to fill
    /// the witness data necessary to generate the proofs. More specifically:
    /// - `input_proofs` contains the proofs to be verified by the `NUM_VERIFIERS` instances of the universal verifier in `circuit`,
    ///   and `input_verifier_data` contains the corrisponding verifier data
    /// - `custom_inputs` contains the input necessary to fill the witness data related to the additional logic being
    ///   enforced in the circuit besides verifying the `NUM_VERIFIERS` proofs with the universal verifier
    /// Note that this function will already output a proof that can be directly recursively verified with the
    /// universal verifier
    pub fn generate_proof<
        const NUM_VERIFIERS: usize,
        CLW: CircuitLogicWires<F, D, NUM_VERIFIERS>,
    >(
        &self,
        circuit: &CircuitWithUniversalVerifier<F, C, D, NUM_VERIFIERS, CLW>,
        input_proofs: [ProofWithPublicInputs<F, C, D>; NUM_VERIFIERS],
        input_verifier_data: [&VerifierOnlyCircuitData<C, D>; NUM_VERIFIERS],
        custom_inputs: CLW::Inputs,
    ) -> Result<ProofWithPublicInputs<F, C, D>> {
        circuit.generate_proof(
            input_proofs,
            input_verifier_data,
            &self.circuit_set,
            custom_inputs,
        )
    }

    /// Get the digest of the circuit set as a list of field elements, which should be equal to
    /// the list of public inputs corresponding to the circuit set digest in the generated proofs
    pub fn get_circuit_set_digest(&self) -> CircuitSetDigest<F, C, D> {
        CircuitSetDigest::from(&self.circuit_set)
    }
}

/// This method should be called on each base circuit to be included in the sets of circuits that is
/// provided as input to the `build_circuit` method of the `RecursionCircuit` trait.
/// In particular, this method allows to convert the base circuit to a data structure that fulfills
/// the trait bounds expected for circuits in the input set by the `build_circuit` method
pub fn prepare_recursive_circuit_for_circuit_set<
    'a,
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
>(
    circuit: impl RecursiveCircuitInfo<F, C, D> + 'a,
) -> Box<dyn RecursiveCircuitInfo<F, C, D> + 'a> {
    Box::new(circuit)
}

/// Targets instantiated by the `RecursiveCircuitsVerifierGadget` which needs to be assigned with a
/// witness value by the prover
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct RecursiveCircuitsVerifierTarget<const D: usize>(UniversalVerifierTarget<D>);

impl<const D: usize> RecursiveCircuitsVerifierTarget<D> {
    /// Assign witness values to the targets in `self`, employing the following input data:
    /// - `recursive_circuits_set`: set of recursive circuits bounded to the `RecursiveCircuitsVerifierGadget`
    ///   that instantiated the targets in `self`
    /// - `proof`: proof to be verified
    /// - `verifier_data`: verifier data of the circuit employed to generate `proof`
    pub fn set_target<F: SerializableRichField<D>, C: GenericConfig<D, F = F>>(
        &self,
        pw: &mut PartialWitness<F>,
        recursive_circuits_set: &RecursiveCircuits<F, C, D>,
        proof: &ProofWithPublicInputs<F, C, D>,
        verifier_data: &VerifierOnlyCircuitData<C, D>,
    ) -> Result<()>
    where
        C::Hasher: AlgebraicHasher<F>,
        [(); C::Hasher::HASH_SIZE]:,
    {
        self.0.set_target(
            pw,
            &recursive_circuits_set.circuit_set,
            proof,
            verifier_data,
        )
    }

    /// Returns a set of targets corresponding to the public inputs of the proof being recursively
    /// verified
    pub fn get_public_input_targets<F: SerializableRichField<D>, const NUM_PUBLIC_INPUTS: usize>(
        &self,
    ) -> &[Target] {
        let pt = self.0.get_proof_target();
        public_input_targets::<F, D, NUM_PUBLIC_INPUTS>(pt)
    }
}
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(bound = "")]
/// `RecursiveCircuitsVerifierGadget` is a gadget that can be employed in circuits that need to verify proofs generated
/// with the `RecursiveCircuits` framework. This data structure is instantiated in order to add the verifier for such
/// proofs to an existing circuit, employing the methods provided by the data structure.
pub struct RecursiveCircuitsVerifierGagdet<
    F: SerializableRichField<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
    const NUM_PUBLIC_INPUTS: usize,
> {
    gadget_builder: UniversalVerifierBuilder<F, D, NUM_PUBLIC_INPUTS>,
    recursive_circuits: RecursiveCircuits<F, C, D>,
}

impl<
        F: SerializableRichField<D>,
        C: GenericConfig<D, F = F> + 'static,
        const D: usize,
        const NUM_PUBLIC_INPUTS: usize,
    > RecursiveCircuitsVerifierGagdet<F, C, D, NUM_PUBLIC_INPUTS>
{
    /// Instantiate the `RecursiveCircuitsVerifierGadget` to verify proofs generated with `recursive_circuits_set` employing
    /// the 'config` circuit configuration`
    pub fn new(config: CircuitConfig, recursive_circuits_set: &RecursiveCircuits<F, C, D>) -> Self
    where
        C::Hasher: AlgebraicHasher<F>,
        [(); C::Hasher::HASH_SIZE]:,
    {
        let circuit_set_size = recursive_circuits_set.circuit_set.circuit_set_size();
        let gadget_builder =
            UniversalVerifierBuilder::<F, D, NUM_PUBLIC_INPUTS>::new(config, circuit_set_size);
        Self {
            gadget_builder,
            recursive_circuits: recursive_circuits_set.clone(),
        }
    }

    /// Gadget to verify a proof generated with the `RecursiveCircuits` framework for any circuit in the set
    /// of recursive circuits bounded to 'self` (i.e., the `recursive_circuits_set` employed to instantiate `self`)
    pub fn verify_proof_in_circuit_set(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> RecursiveCircuitsVerifierTarget<D>
    where
        C::Hasher: AlgebraicHasher<F>,
        [(); C::Hasher::HASH_SIZE]:,
    {
        let circuit_set_target = CircuitSetTarget::from_circuit_set_digest(
            builder,
            self.recursive_circuits.get_circuit_set_digest(),
        );
        RecursiveCircuitsVerifierTarget(
            self.gadget_builder
                .universal_verifier_circuit(builder, &circuit_set_target),
        )
    }

    /// Gadget to verify a proof generated with the 'RecursiveCircuits` framework for a specific circuit
    /// `fixed_circuit` belonging to the set of recursive circuits bounded to `self`
    pub fn verify_proof_fixed_circuit_in_circuit_set(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        fixed_circuit: &VerifierOnlyCircuitData<C, D>,
    ) -> ProofWithPublicInputsTarget<D>
    where
        C::Hasher: AlgebraicHasher<F>,
        [(); C::Hasher::HASH_SIZE]:,
    {
        let circuit_set_target = CircuitSetTarget::from_circuit_set_digest(
            builder,
            self.recursive_circuits.get_circuit_set_digest(),
        );
        let verifier_data = VerifierCircuitTarget {
            constants_sigmas_cap: builder.constant_merkle_cap(&fixed_circuit.constants_sigmas_cap),
            circuit_digest: builder.constant_hash(fixed_circuit.circuit_digest),
        };
        let proof = self
            .gadget_builder
            .verify_proof_for_universal_verifier::<C>(builder, &verifier_data);
        UniversalVerifierBuilder::<F, D, NUM_PUBLIC_INPUTS>::check_circuit_set_equality(
            builder,
            &circuit_set_target,
            &proof,
        );
        proof
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::array;
    use std::marker::PhantomData;

    use plonky2::field::types::Sample;
    use plonky2::iop::witness::WitnessWrite;
    use plonky2::plonk::{circuit_data::CircuitConfig, config::PoseidonGoldilocksConfig};
    use rstest::{fixture, rstest};
    use serial_test::serial;

    use crate::circuit_builder::tests::NUM_PUBLIC_INPUTS_TEST_CIRCUITS;
    use crate::circuit_builder::{
        tests::{LeafCircuitWires, RecursiveCircuitWires},
        CircuitWithUniversalVerifierBuilder,
    };
    use crate::serialization::circuit_data_serialization::SerializableRichField;
    use crate::serialization::{deserialize, serialize};

    use super::*;

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

    pub(crate) const NUM_PUBLIC_INPUTS_VERIFIER_CIRCUITS: usize = 0;

    /// Circuit employing the `RecursiveCircuitsVerifierGadget` to recursively verify a proof generated
    /// for any circuit belonging to a given set of circuits
    #[derive(Serialize, Deserialize)]
    pub(crate) struct VerifierCircuitWires<
        C: GenericConfig<D>,
        const D: usize,
        const NUM_PUBLIC_INPUTS: usize,
    > {
        targets: RecursiveCircuitsVerifierTarget<D>,
        c: PhantomData<C>,
    }

    impl<
            F: SerializableRichField<D>,
            C: GenericConfig<D, F = F> + 'static,
            const D: usize,
            const NUM_PUBLIC_INPUTS: usize,
        > CircuitLogicWires<F, D, 0> for VerifierCircuitWires<C, D, NUM_PUBLIC_INPUTS>
    where
        C::Hasher: AlgebraicHasher<F>,
        [(); C::Hasher::HASH_SIZE]:,
    {
        type CircuitBuilderParams = RecursiveCircuitsVerifierGagdet<F, C, D, NUM_PUBLIC_INPUTS>;

        type Inputs = (
            RecursiveCircuits<F, C, D>,
            ProofWithPublicInputs<F, C, D>,
            VerifierOnlyCircuitData<C, D>,
        );

        const NUM_PUBLIC_INPUTS: usize = NUM_PUBLIC_INPUTS_VERIFIER_CIRCUITS;

        fn circuit_logic(
            builder: &mut CircuitBuilder<F, D>,
            _verified_proofs: [&ProofWithPublicInputsTarget<D>; 0],
            builder_parameters: Self::CircuitBuilderParams,
        ) -> Self {
            Self {
                targets: builder_parameters.verify_proof_in_circuit_set(builder),
                c: PhantomData::<C>::default(),
            }
        }

        fn assign_input(&self, inputs: Self::Inputs, pw: &mut PartialWitness<F>) -> Result<()> {
            self.targets.set_target(pw, &inputs.0, &inputs.1, &inputs.2)
        }
    }

    /// Circuit employing the `RecursiveCircuitsVerifierGadget` to recursively verify a proof generated
    /// by a fixed circuit belonging to a given set of circuits
    #[derive(Serialize, Deserialize)]
    pub(crate) struct VerifierCircuitFixedWires<
        C: GenericConfig<D>,
        const D: usize,
        const NUM_PUBLIC_INPUTS: usize,
    > {
        #[serde(serialize_with = "serialize", deserialize_with = "deserialize")]
        targets: ProofWithPublicInputsTarget<D>,
        c: PhantomData<C>,
    }

    impl<
            F: SerializableRichField<D>,
            C: GenericConfig<D, F = F> + 'static,
            const D: usize,
            const NUM_PUBLIC_INPUTS: usize,
        > CircuitLogicWires<F, D, 0> for VerifierCircuitFixedWires<C, D, NUM_PUBLIC_INPUTS>
    where
        C::Hasher: AlgebraicHasher<F>,
        [(); C::Hasher::HASH_SIZE]:,
    {
        type CircuitBuilderParams = (
            RecursiveCircuitsVerifierGagdet<F, C, D, NUM_PUBLIC_INPUTS>,
            VerifierOnlyCircuitData<C, D>,
        );

        type Inputs = ProofWithPublicInputs<F, C, D>;

        const NUM_PUBLIC_INPUTS: usize = NUM_PUBLIC_INPUTS_VERIFIER_CIRCUITS;

        fn circuit_logic(
            builder: &mut CircuitBuilder<F, D>,
            _verified_proofs: [&ProofWithPublicInputsTarget<D>; 0],
            builder_parameters: Self::CircuitBuilderParams,
        ) -> Self {
            Self {
                targets: builder_parameters
                    .0
                    .verify_proof_fixed_circuit_in_circuit_set(builder, &builder_parameters.1),
                c: PhantomData::<C>::default(),
            }
        }

        fn assign_input(&self, inputs: Self::Inputs, pw: &mut PartialWitness<F>) -> Result<()> {
            pw.set_proof_with_pis_target(&self.targets, &inputs);

            Ok(())
        }
    }

    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    // data structure to test the `RecursiveCircuits` framework and its serialization/deserialization
    #[derive(Serialize, Deserialize)]
    #[serde(bound = "")]
    struct TestRecursiveCircuits<
        F: SerializableRichField<D>,
        C: GenericConfig<D, F = F> + 'static,
        const D: usize,
        const INPUT_SIZE: usize,
    >
    where
        C::Hasher: AlgebraicHasher<F>,
    {
        leaf_circuit: CircuitWithUniversalVerifier<F, C, D, 0, LeafCircuitWires<F, INPUT_SIZE>>,
        recursive_circuit_one:
            CircuitWithUniversalVerifier<F, C, D, 1, RecursiveCircuitWires<INPUT_SIZE>>,
        recursive_circuit_two:
            CircuitWithUniversalVerifier<F, C, D, 2, RecursiveCircuitWires<INPUT_SIZE>>,
        recursive_circuit_three:
            CircuitWithUniversalVerifier<F, C, D, 3, RecursiveCircuitWires<INPUT_SIZE>>,
        recursive_circuit_four:
            CircuitWithUniversalVerifier<F, C, D, 4, RecursiveCircuitWires<INPUT_SIZE>>,
        framework: RecursiveCircuits<F, C, D>,
    }

    impl<
            F: SerializableRichField<D>,
            C: GenericConfig<D, F = F> + 'static,
            const D: usize,
            const INPUT_SIZE: usize,
        > TestRecursiveCircuits<F, C, D, INPUT_SIZE>
    where
        C::Hasher: AlgebraicHasher<F>,
        [(); C::Hasher::HASH_SIZE]:,
    {
        fn new() -> Self {
            const CIRCUIT_SET_SIZE: usize = 5;
            let config = CircuitConfig::standard_recursion_config();

            const NUM_PUBLIC_INPUTS: usize = NUM_PUBLIC_INPUTS_TEST_CIRCUITS;
            let circuit_builder =
                CircuitWithUniversalVerifierBuilder::<F, D, NUM_PUBLIC_INPUTS>::new::<C>(
                    config,
                    CIRCUIT_SET_SIZE,
                );

            let leaf_circuit = circuit_builder
                .build_circuit::<C, 0, LeafCircuitWires<F, INPUT_SIZE>>((1usize << 12, false));

            let recursive_circuit_one =
                circuit_builder.build_circuit::<C, 1, RecursiveCircuitWires<INPUT_SIZE>>(());

            let recursive_circuit_two =
                circuit_builder.build_circuit::<C, 2, RecursiveCircuitWires<INPUT_SIZE>>(());

            let recursive_circuit_three =
                circuit_builder.build_circuit::<C, 3, RecursiveCircuitWires<INPUT_SIZE>>(());

            let recursive_circuit_four =
                circuit_builder.build_circuit::<C, 4, RecursiveCircuitWires<INPUT_SIZE>>(());

            let circuits = vec![
                prepare_recursive_circuit_for_circuit_set(&leaf_circuit),
                prepare_recursive_circuit_for_circuit_set(&recursive_circuit_one),
                prepare_recursive_circuit_for_circuit_set(&recursive_circuit_two),
                prepare_recursive_circuit_for_circuit_set(&recursive_circuit_three),
                prepare_recursive_circuit_for_circuit_set(&recursive_circuit_four),
            ];

            let recursive_framework = RecursiveCircuits::new(circuits);

            Self {
                leaf_circuit,
                recursive_circuit_one,
                recursive_circuit_two,
                recursive_circuit_three,
                recursive_circuit_four,
                framework: recursive_framework,
            }
        }

        fn run_test(&self) {
            const NUM_PUBLIC_INPUTS: usize = NUM_PUBLIC_INPUTS_TEST_CIRCUITS;
            let base_proofs = (0..7)
                .map(|_| {
                    let inputs = array::from_fn(|_| F::rand());
                    self.framework
                        .generate_proof(&self.leaf_circuit, [], [], (inputs, F::rand()))
                })
                .collect::<Result<Vec<_>>>()
                .unwrap();

            let leaf_circuit_vd = self.leaf_circuit.get_verifier_data();

            let recursive_circuits_input = array::from_fn(|_| F::rand());
            let rec_proof_1 = self
                .framework
                .generate_proof(
                    &self.recursive_circuit_four,
                    base_proofs[..4].to_vec().try_into().unwrap(),
                    [leaf_circuit_vd; 4],
                    recursive_circuits_input,
                )
                .unwrap();

            assert_eq!(
                &rec_proof_1.public_inputs[NUM_PUBLIC_INPUTS..],
                self.framework.get_circuit_set_digest().flatten().as_slice()
            );

            let recursive_circuits_input = array::from_fn(|_| F::rand());
            let rec_proof_2 = self
                .framework
                .generate_proof(
                    &self.recursive_circuit_three,
                    base_proofs[4..].to_vec().try_into().unwrap(),
                    [leaf_circuit_vd; 3],
                    recursive_circuits_input,
                )
                .unwrap();

            assert_eq!(
                &rec_proof_2.public_inputs[NUM_PUBLIC_INPUTS..],
                self.framework.get_circuit_set_digest().flatten().as_slice()
            );

            let recursive_circuits_input = array::from_fn(|_| F::rand());
            let rec_proof = self
                .framework
                .generate_proof(
                    &self.recursive_circuit_two,
                    [rec_proof_1, rec_proof_2],
                    [
                        self.recursive_circuit_four.get_verifier_data(),
                        self.recursive_circuit_three.get_verifier_data(),
                    ],
                    recursive_circuits_input,
                )
                .unwrap();

            assert_eq!(
                &rec_proof.public_inputs[NUM_PUBLIC_INPUTS..],
                self.framework.get_circuit_set_digest().flatten().as_slice()
            );

            let recursive_circuits_input = array::from_fn(|_| F::rand());
            let rec_proof = self
                .framework
                .generate_proof(
                    &self.recursive_circuit_one,
                    [rec_proof],
                    [self.recursive_circuit_two.get_verifier_data()],
                    recursive_circuits_input,
                )
                .unwrap();

            assert_eq!(
                &rec_proof.public_inputs[NUM_PUBLIC_INPUTS..],
                self.framework.get_circuit_set_digest().flatten().as_slice()
            );

            self.recursive_circuit_one
                .circuit_data()
                .verify(rec_proof)
                .unwrap();
        }
    }

    const INPUT_SIZE: usize = 8;

    #[fixture]
    #[once]
    fn test_circuits() -> TestRecursiveCircuits<F, C, D, INPUT_SIZE> {
        TestRecursiveCircuits::<F, C, D, INPUT_SIZE>::new()
    }

    #[rstest]
    #[serial]
    fn test_recursive_circuit_framework(
        test_circuits: &TestRecursiveCircuits<F, C, D, INPUT_SIZE>,
    ) {
        test_circuits.run_test()
    }

    #[rstest]
    #[serial]
    fn test_recursive_circuit_framework_serialization(
        test_circuits: &TestRecursiveCircuits<F, C, D, INPUT_SIZE>,
    ) {
        let serialized = bincode::serialize(test_circuits).unwrap();
        let test_circuits: TestRecursiveCircuits<F, C, D, INPUT_SIZE> =
            bincode::deserialize(&serialized).unwrap();
        test_circuits.run_test()
    }

    #[test]
    fn test_verifier_circuit_of_recursive_circuits_set() {
        // test for circuits employing the `RecursiveCircuitsVerifierGadget`
        const INPUT_SIZE: usize = 8;
        const CIRCUIT_SET_SIZE: usize = 2;
        let config = CircuitConfig::standard_recursion_config();

        const NUM_PUBLIC_INPUTS: usize =
            <LeafCircuitWires<F, INPUT_SIZE> as CircuitLogicWires<F, D, 0>>::NUM_PUBLIC_INPUTS;
        // build a set of recursive circuits employing the `RecursiveCircuits` framework
        let circuit_builder = CircuitWithUniversalVerifierBuilder::<F, D, NUM_PUBLIC_INPUTS>::new::<
            C,
        >(config.clone(), CIRCUIT_SET_SIZE);

        let leaf_circuit = circuit_builder
            .build_circuit::<C, 0, LeafCircuitWires<F, INPUT_SIZE>>((1usize << 12, false));

        let recursive_circuit =
            circuit_builder.build_circuit::<C, 1, RecursiveCircuitWires<INPUT_SIZE>>(());

        let circuits = vec![
            prepare_recursive_circuit_for_circuit_set(&leaf_circuit),
            prepare_recursive_circuit_for_circuit_set(&recursive_circuit),
        ];

        let recursive_framework = RecursiveCircuits::new(circuits);
        // generate proof for the `leaf_circuit`
        let base_proof = {
            let inputs = array::from_fn(|_| F::rand());
            recursive_framework
                .generate_proof(&leaf_circuit, [], [], (inputs, F::rand()))
                .unwrap()
        };

        let leaf_circuit_vd = leaf_circuit.get_verifier_data();
        let recursive_circuit_vd = recursive_circuit.get_verifier_data();
        // generate proof for the `recursive_circuit`
        let recursive_circuits_input = array::from_fn(|_| F::rand());
        let rec_proof = recursive_framework
            .generate_proof(
                &recursive_circuit,
                [base_proof.clone()],
                [leaf_circuit_vd],
                recursive_circuits_input,
            )
            .unwrap();

        // Build a set of circuits employing the `RecursiveCircuitsVerifierGadget` to verify proofs generated for circuits belonging to the set
        // instantiated with `recursive_framework`
        let circuit_builder = CircuitWithUniversalVerifierBuilder::<F, D, NUM_PUBLIC_INPUTS>::new::<
            C,
        >(config.clone(), CIRCUIT_SET_SIZE);

        let verifier_gadget =
            RecursiveCircuitsVerifierGagdet::new(config.clone(), &recursive_framework);
        let verifier_circuit = circuit_builder
            .build_circuit::<C, 0, VerifierCircuitWires<C, D, NUM_PUBLIC_INPUTS>>(verifier_gadget);

        let verifier_gadget =
            RecursiveCircuitsVerifierGagdet::new(config.clone(), &recursive_framework);
        let verifier_circuit_fixed = circuit_builder
            .build_circuit::<C, 0, VerifierCircuitFixedWires<C, D, NUM_PUBLIC_INPUTS>>((
                verifier_gadget,
                recursive_circuit_vd.clone(),
            ));

        let verifier_circuits = vec![
            prepare_recursive_circuit_for_circuit_set(&verifier_circuit),
            prepare_recursive_circuit_for_circuit_set(&verifier_circuit_fixed),
        ];

        let recursive_framework_verifier_circuits = RecursiveCircuits::new(verifier_circuits);
        // check that proofs generated for any circuit in `recursive_framework` set is verified by `verifier_circuit`
        for (proof, vd) in [
            (base_proof.clone(), leaf_circuit_vd),
            (rec_proof.clone(), recursive_circuit_vd),
        ] {
            let proof = recursive_framework_verifier_circuits
                .generate_proof(
                    &verifier_circuit,
                    [],
                    [],
                    (recursive_framework.clone(), proof, vd.clone()),
                )
                .unwrap();

            verifier_circuit.circuit_data().verify(proof).unwrap();
        }

        // instead, for `verifier_circuit_fixed` only the proof generated with `recursive_circuit` should be verified

        let proof = recursive_framework_verifier_circuits
            .generate_proof(&verifier_circuit_fixed, [], [], rec_proof)
            .unwrap();
        verifier_circuit_fixed.circuit_data().verify(proof).unwrap();

        // check that `verifier_circuit_fixed` cannot verify the proof generated with `leaf_circuit`
        check_panic!(
            || recursive_framework_verifier_circuits
                .generate_proof(&verifier_circuit_fixed, [], [], base_proof)
                .unwrap(),
            "`verifier_circuit_fixed` did not fail 
            while recursively verifying a proof generated with `leaf_circuit`"
        );
    }
}
