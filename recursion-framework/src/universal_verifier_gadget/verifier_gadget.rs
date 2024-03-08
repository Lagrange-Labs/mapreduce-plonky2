use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::witness::{PartialWitness, WitnessWrite},
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{
            CircuitConfig, CommonCircuitData, VerifierCircuitTarget, VerifierOnlyCircuitData,
        },
        config::{AlgebraicHasher, GenericConfig, Hasher},
        proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget},
    },
};
use serde::{Deserialize, Serialize};

use crate::serialization::{
    circuit_data_serialization::SerializableRichField, deserialize, serialize,
};

use super::{
    build_data_for_universal_verifier,
    circuit_set::{
        check_circuit_digest_target, CircuitSet, CircuitSetMembershipTargets, CircuitSetTarget,
    },
    RECURSION_THRESHOLD,
};

use anyhow::Result;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
/// `UniversalVerifierTarget` comprises all the targets that are employed by the universal verifier
/// to recusively verify a proof and to check the membership of the digest of the verifier data employed
/// to verify the proof in the set of circuits bound to the universal verifier instance at hand
pub(crate) struct UniversalVerifierTarget<const D: usize> {
    circuit_set_membership: CircuitSetMembershipTargets,
    #[serde(serialize_with = "serialize", deserialize_with = "deserialize")]
    verified_proof: ProofWithPublicInputsTarget<D>,
    #[serde(serialize_with = "serialize", deserialize_with = "deserialize")]
    verifier_data: VerifierCircuitTarget,
}

impl<const D: usize> UniversalVerifierTarget<D> {
    pub(crate) fn get_proof_target(&self) -> &ProofWithPublicInputsTarget<D> {
        &self.verified_proof
    }

    //// Assigns the proofs and verifier data associated with the proof to the universal verifier targets. In particular,
    //// it generates the Merkle proof showing the circuit that generated this proof belongs to the set of circuits
    //// configured for this universal verifier.
    pub(crate) fn set_target<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>>(
        &self,
        pw: &mut PartialWitness<F>,
        circuit_set: &CircuitSet<F, C, D>,
        proof: &ProofWithPublicInputs<F, C, D>,
        verifier_data: &VerifierOnlyCircuitData<C, D>,
    ) -> Result<()>
    where
        C::Hasher: AlgebraicHasher<F>,
        [(); C::Hasher::HASH_SIZE]:,
    {
        pw.set_proof_with_pis_target(&self.verified_proof, proof);
        pw.set_verifier_data_target(&self.verifier_data, verifier_data);
        circuit_set.set_circuit_membership_target(
            pw,
            &self.circuit_set_membership,
            verifier_data.circuit_digest,
        )
    }
}
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(bound = "")]
/// `UniversalVerifierBuilder` is a data structure necessary to build instances of the universal verifier
/// in a circuit. It is mostly employed to cache the `CommonCircuitData` that are shared among all the
/// proofs being verified by the universal verifier, which are computed just once when initializing
/// `UniversalVerifierBuilder`
pub(crate) struct UniversalVerifierBuilder<
    F: RichField + Extendable<D>,
    const D: usize,
    const NUM_PUBLIC_INPUTS: usize,
> {
    #[serde(serialize_with = "serialize", deserialize_with = "deserialize")]
    rec_data: CommonCircuitData<F, D>,
    circuit_set_size: usize,
}

impl<F: SerializableRichField<D>, const D: usize, const NUM_PUBLIC_INPUTS: usize>
    UniversalVerifierBuilder<F, D, NUM_PUBLIC_INPUTS>
{
    pub(crate) fn new<C: GenericConfig<D, F = F> + 'static>(
        config: CircuitConfig,
        circuit_set_size: usize,
    ) -> Self
    where
        C::Hasher: AlgebraicHasher<F>,
        [(); C::Hasher::HASH_SIZE]:,
    {
        let rec_data = build_data_for_universal_verifier::<F, C, D>(config, NUM_PUBLIC_INPUTS);
        Self {
            rec_data,
            circuit_set_size,
        }
    }

    pub(crate) fn get_circuit_set_size(&self) -> usize {
        self.circuit_set_size
    }

    /// Creates a proof target and verifies it using the given verifier data and the common circuit data (shared by all
    /// proofs that are in the circuit set). It returns the proof targets.
    pub(crate) fn verify_proof_for_universal_verifier<C: GenericConfig<D, F = F>>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        verifier_data: &VerifierCircuitTarget,
    ) -> ProofWithPublicInputsTarget<D>
    where
        C::Hasher: AlgebraicHasher<F>,
        [(); C::Hasher::HASH_SIZE]:,
    {
        let proof = builder.add_virtual_proof_with_pis(&self.rec_data);
        builder.verify_proof::<C>(&proof, &verifier_data, &self.rec_data);
        proof
    }

    /// check that `circuit_set_target` is the same as the one exposed by the `proof`
    pub(crate) fn check_circuit_set_equality(
        builder: &mut CircuitBuilder<F, D>,
        circuit_set_target: &CircuitSetTarget,
        proof: &ProofWithPublicInputsTarget<D>,
    ) {
        let circuit_set_targets = circuit_set_target.to_targets();

        circuit_set_targets
            .iter()
            .zip(proof.public_inputs.iter().skip(NUM_PUBLIC_INPUTS))
            .for_each(|(&cs_t, &pi_t)| builder.connect(cs_t, pi_t));
    }
    /// Gadget to add an instance of the universal verifier, bound to the circuit set specified in `circuit_set_target`,
    /// to a circuit that is being built with `builder`
    pub(crate) fn universal_verifier_circuit<C: GenericConfig<D, F = F>>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        circuit_set_target: &CircuitSetTarget,
    ) -> UniversalVerifierTarget<D>
    where
        C::Hasher: AlgebraicHasher<F>,
        [(); C::Hasher::HASH_SIZE]:,
    {
        // allocate verifier data targets
        let verifier_data = VerifierCircuitTarget {
            constants_sigmas_cap: builder
                .add_virtual_cap(self.rec_data.config.fri_config.cap_height),
            circuit_digest: builder.add_virtual_hash(),
        };
        // verify proof
        let proof = self.verify_proof_for_universal_verifier::<C>(builder, &verifier_data);
        check_circuit_digest_target::<_, C, D>(builder, &verifier_data, RECURSION_THRESHOLD);
        let proof_membership_target = CircuitSetTarget::check_circuit_digest_membership::<F, C, D>(
            builder,
            circuit_set_target,
            &verifier_data.circuit_digest,
            self.circuit_set_size,
        );
        // check that the circuit set employed as public input in the recursively verified proof is the same as the one exposed by the recursive proof
        Self::check_circuit_set_equality(builder, circuit_set_target, &proof);

        UniversalVerifierTarget {
            circuit_set_membership: proof_membership_target,
            verified_proof: proof,
            verifier_data,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::array;

    use plonky2::plonk::{circuit_data::CircuitData, config::PoseidonGoldilocksConfig};

    use plonky2::field::types::Sample;

    use crate::circuit_builder::tests::LeafCircuitWires;
    use crate::framework::tests::check_panic;
    use crate::universal_verifier_gadget::wrap_circuit::test::mutable_final_proof_circuit_data;
    use crate::universal_verifier_gadget::CircuitSetDigest;
    use crate::{
        circuit_builder::{
            tests::{RecursiveCircuitWires, NUM_PUBLIC_INPUTS_TEST_CIRCUITS},
            CircuitLogicWires,
        },
        universal_verifier_gadget::wrap_circuit::WrapCircuit,
    };

    use super::*;
    use anyhow::Result;

    const NUM_PUBLIC_INPUTS: usize = NUM_PUBLIC_INPUTS_TEST_CIRCUITS;

    /// Test circuit whose wrapped proofs can be recursviely verified by the universal verifier circuit
    struct TestCircuitForUniversalVerifier<
        F: SerializableRichField<D>,
        C: GenericConfig<D, F = F> + 'static,
        const D: usize,
        const INPUT_SIZE: usize,
    >
    where
        C::Hasher: AlgebraicHasher<F>,
    {
        input_targets: LeafCircuitWires<F, INPUT_SIZE>,
        circuit_set_target: CircuitSetTarget,
        circuit_data: CircuitData<F, C, D>,
        wrap_circuit: WrapCircuit<F, C, D>,
    }

    impl<
            F: SerializableRichField<D>,
            C: GenericConfig<D, F = F>,
            const D: usize,
            const INPUT_SIZE: usize,
        > TestCircuitForUniversalVerifier<F, C, D, INPUT_SIZE>
    where
        C::Hasher: AlgebraicHasher<F>,
        [(); C::Hasher::HASH_SIZE]:,
    {
        fn build_circuit(
            config: CircuitConfig,
            build_parameters: <LeafCircuitWires::<F, INPUT_SIZE> as CircuitLogicWires<F,D,0>>::CircuitBuilderParams,
        ) -> Self {
            let mut builder = CircuitBuilder::<F, D>::new(config.clone());
            let input_targets =
                <LeafCircuitWires<F, INPUT_SIZE> as CircuitLogicWires<F, D, 0>>::circuit_logic(
                    &mut builder,
                    [],
                    build_parameters,
                );
            // we need to add a `CircuitSetTarget` to make the public inputs compatible with the format expected by the universal verifier
            let circuit_set_target = CircuitSetTarget::build_target(&mut builder);
            builder.register_public_inputs(circuit_set_target.to_targets().as_slice());

            let circuit_data = builder.build::<C>();

            let wrap_circuit = WrapCircuit::<F, C, D>::build_wrap_circuit(
                &circuit_data.verifier_only,
                &circuit_data.common,
                &config,
            );

            Self {
                input_targets,
                circuit_set_target,
                circuit_data,
                wrap_circuit,
            }
        }

        fn generate_base_proof(
            &self,
            circuit_set: &CircuitSet<F, C, D>,
            inputs: <LeafCircuitWires<F, INPUT_SIZE> as CircuitLogicWires<F, D, 0>>::Inputs,
        ) -> Result<ProofWithPublicInputs<F, C, D>> {
            let mut pw = PartialWitness::<F>::new();
            <LeafCircuitWires<F, INPUT_SIZE> as CircuitLogicWires<F, D, 0>>::assign_input(
                &self.input_targets,
                inputs,
                &mut pw,
            )?;
            self.circuit_set_target
                .set_target::<F, C, D>(&mut pw, &CircuitSetDigest::from(circuit_set));

            self.circuit_data.prove(pw)
        }

        fn wrap_base_proof(
            &self,
            base_proof: ProofWithPublicInputs<F, C, D>,
        ) -> Result<ProofWithPublicInputs<F, C, D>> {
            self.wrap_circuit.wrap_proof(base_proof)
        }

        fn generate_proof(
            &self,
            circuit_set: &CircuitSet<F, C, D>,
            inputs: <LeafCircuitWires<F, INPUT_SIZE> as CircuitLogicWires<F, D, 0>>::Inputs,
        ) -> Result<ProofWithPublicInputs<F, C, D>> {
            let proof = self.generate_base_proof(circuit_set, inputs)?;

            self.wrap_base_proof(proof)
        }

        fn get_circuit_data(&self) -> &CircuitData<F, C, D> {
            &self.wrap_circuit.final_proof_circuit_data()
        }
    }

    struct CircuitWithUniversalVerifier<
        F: SerializableRichField<D>,
        C: GenericConfig<D, F = F> + 'static,
        const D: usize,
        const INPUT_SIZE: usize,
    >
    where
        C::Hasher: AlgebraicHasher<F>,
    {
        verifier_targets: UniversalVerifierTarget<D>,
        input_targets: RecursiveCircuitWires<INPUT_SIZE>,
        circuit_set_target: CircuitSetTarget,
        circuit_data: CircuitData<F, C, D>,
        wrap_circuit: WrapCircuit<F, C, D>,
    }

    impl<
            F: SerializableRichField<D>,
            C: GenericConfig<D, F = F>,
            const D: usize,
            const INPUT_SIZE: usize,
        > CircuitWithUniversalVerifier<F, C, D, INPUT_SIZE>
    where
        C::Hasher: AlgebraicHasher<F>,
        [(); C::Hasher::HASH_SIZE]:,
    {
        fn build_circuit(config: CircuitConfig, circuit_set_size: usize) -> Self {
            let builder = UniversalVerifierBuilder::<F, D, NUM_PUBLIC_INPUTS>::new(
                config.clone(),
                circuit_set_size,
            );
            let mut circuit_builder = CircuitBuilder::<F, D>::new(config.clone());
            let circuit_set_target = CircuitSetTarget::build_target(&mut circuit_builder);
            let verifier_targets =
                builder.universal_verifier_circuit(&mut circuit_builder, &circuit_set_target);
            let proof_t = verifier_targets.get_proof_target();
            let input_targets =
                <RecursiveCircuitWires<INPUT_SIZE> as CircuitLogicWires<F, D, 1>>::circuit_logic(
                    &mut circuit_builder,
                    [proof_t],
                    (),
                );
            circuit_builder.register_public_inputs(circuit_set_target.to_targets().as_slice());

            let circuit_data = circuit_builder.build::<C>();

            let wrap_circuit = WrapCircuit::<F, C, D>::build_wrap_circuit(
                &circuit_data.verifier_only,
                &circuit_data.common,
                &config,
            );

            Self {
                verifier_targets,
                input_targets,
                circuit_set_target,
                circuit_data,
                wrap_circuit,
            }
        }

        fn generate_base_proof(
            &self,
            circuit_set: &CircuitSet<F, C, D>,
            proof: &ProofWithPublicInputs<F, C, D>,
            verifier_data: &VerifierOnlyCircuitData<C, D>,
            inputs: <RecursiveCircuitWires<INPUT_SIZE> as CircuitLogicWires<F, D, 1>>::Inputs,
        ) -> Result<ProofWithPublicInputs<F, C, D>> {
            let mut pw = PartialWitness::<F>::new();
            self.verifier_targets
                .set_target(&mut pw, circuit_set, proof, verifier_data)?;
            <RecursiveCircuitWires<INPUT_SIZE> as CircuitLogicWires<F, D, 1>>::assign_input(
                &self.input_targets,
                inputs,
                &mut pw,
            )?;
            self.circuit_set_target
                .set_target::<F, C, D>(&mut pw, &CircuitSetDigest::from(circuit_set));

            self.circuit_data.prove(pw)
        }

        fn generate_proof(
            &self,
            circuit_set: &CircuitSet<F, C, D>,
            proof: &ProofWithPublicInputs<F, C, D>,
            verifier_data: &VerifierOnlyCircuitData<C, D>,
            inputs: <RecursiveCircuitWires<INPUT_SIZE> as CircuitLogicWires<F, D, 1>>::Inputs,
        ) -> Result<ProofWithPublicInputs<F, C, D>> {
            let base_proof = self.generate_base_proof(circuit_set, proof, verifier_data, inputs)?;

            self.wrap_circuit.wrap_proof(base_proof)
        }

        fn get_circuit_data(&self) -> &CircuitData<F, C, D> {
            &self.wrap_circuit.final_proof_circuit_data()
        }
    }

    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    #[test]
    fn test_circuit_with_universal_verifier() {
        const INPUT_SIZE: usize = 8;
        const CIRCUIT_SET_SIZE: usize = 2;
        let config = CircuitConfig::standard_recursion_config();
        let base_circuit = TestCircuitForUniversalVerifier::<F, C, D, INPUT_SIZE>::build_circuit(
            config.clone(),
            (1usize << 12, false),
        );
        let universal_verifier_circuit =
            CircuitWithUniversalVerifier::<F, C, D, INPUT_SIZE>::build_circuit(
                config.clone(),
                CIRCUIT_SET_SIZE,
            );

        let circuit_set = CircuitSet::<F, C, D>::build_circuit_set(vec![
            base_circuit.get_circuit_data().verifier_only.circuit_digest,
            universal_verifier_circuit
                .get_circuit_data()
                .verifier_only
                .circuit_digest,
        ]);

        let circuit_set_digest = CircuitSetDigest::from(&circuit_set);

        let base_proof = base_circuit
            .generate_proof(&circuit_set, (array::from_fn(|_| F::rand()), F::rand()))
            .unwrap();

        base_circuit
            .get_circuit_data()
            .verify(base_proof.clone())
            .unwrap();

        let universal_verifier_proof = universal_verifier_circuit
            .generate_proof(
                &circuit_set,
                &base_proof,
                &base_circuit.get_circuit_data().verifier_only,
                array::from_fn(|_| F::rand()),
            )
            .unwrap();

        universal_verifier_circuit
            .get_circuit_data()
            .verify(universal_verifier_proof.clone())
            .unwrap();

        assert_eq!(
            &universal_verifier_proof.public_inputs[NUM_PUBLIC_INPUTS..],
            circuit_set_digest.flatten().as_slice()
        );

        // verify that universal verifier circuit can recursively verify its own proofs
        let universal_verifier_proof = universal_verifier_circuit
            .generate_proof(
                &circuit_set,
                &universal_verifier_proof,
                &universal_verifier_circuit.get_circuit_data().verifier_only,
                array::from_fn(|_| F::rand()),
            )
            .unwrap();

        universal_verifier_circuit
            .get_circuit_data()
            .verify(universal_verifier_proof.clone())
            .unwrap();

        assert_eq!(
            &universal_verifier_proof.public_inputs[NUM_PUBLIC_INPUTS..],
            circuit_set_digest.flatten().as_slice()
        );
    }

    #[test]
    fn negative_tests() {
        const INPUT_SIZE: usize = 8;
        const CIRCUIT_SET_SIZE: usize = 2;
        let config = CircuitConfig::standard_recursion_config();
        let base_circuit = TestCircuitForUniversalVerifier::<F, C, D, INPUT_SIZE>::build_circuit(
            config.clone(),
            (1usize << 12, false),
        );
        let universal_verifier_circuit =
            CircuitWithUniversalVerifier::<F, C, D, INPUT_SIZE>::build_circuit(
                config.clone(),
                CIRCUIT_SET_SIZE,
            );

        let circuit_set = CircuitSet::<F, C, D>::build_circuit_set(vec![
            base_circuit.get_circuit_data().verifier_only.circuit_digest,
            universal_verifier_circuit
                .get_circuit_data()
                .verifier_only
                .circuit_digest,
        ]);

        let mut base_circuit_variant =
            TestCircuitForUniversalVerifier::<F, C, D, INPUT_SIZE>::build_circuit(
                config.clone(),
                (1usize << 12, true),
            );

        let base_proof = base_circuit_variant
            .generate_base_proof(&circuit_set, (array::from_fn(|_| F::rand()), F::rand()))
            .unwrap();

        check_panic!(
            || base_circuit.wrap_base_proof(base_proof.clone()),
            "wrapping base proof generated with wrong base circuit didn't fail"
        );

        // use the proper wrap circuit
        println!("wrapping wrong base proof");
        let wrapped_proof = base_circuit_variant
            .wrap_base_proof(base_proof.clone())
            .unwrap();
        println!("wrong base proof wrapped");
        // universal verifier should detect that the circuit does not belong to circuit set
        let err = universal_verifier_circuit
            .generate_proof(
                &circuit_set,
                &wrapped_proof,
                &base_circuit_variant.get_circuit_data().verifier_only,
                array::from_fn(|_| F::rand()),
            )
            .unwrap_err();
        assert_eq!(
            format!("{}", err),
            "circuit digest not found",
            "universal verifier didn't fail when verifying a proof not belonging to circuit set"
        );

        // try to provide a verifier data of a circuit belonging to the set of circuits
        check_panic!(|| universal_verifier_circuit.generate_proof(
            &circuit_set,
            &wrapped_proof,
            &base_circuit.get_circuit_data().verifier_only,
            array::from_fn(|_| F::rand())
        ), "universal verifier didn't fail when verifying a proof for a circuit not belonging to circuit set 
                with a verifier data of a circuit belonging to circuit set");

        // employ a different circuit set including `base_circuit_variant` instead of `base_circuit
        let wrong_circuit_set = CircuitSet::<F, C, D>::build_circuit_set(vec![
            base_circuit_variant
                .get_circuit_data()
                .verifier_only
                .circuit_digest,
            universal_verifier_circuit
                .get_circuit_data()
                .verifier_only
                .circuit_digest,
        ]);

        check_panic!(|| universal_verifier_circuit.generate_proof(
            &wrong_circuit_set,
            &wrapped_proof,
            &base_circuit_variant.get_circuit_data().verifier_only,
            array::from_fn(|_| F::rand())
        ), "universal verifier didn't fail when employing a wrong circuit set to check membership of verifier data");

        // employ a valid proof of membership for a digest belongint to `circuit_set``, but verifying a proof of a circuit
        // not belonging to `circuit_set`
        {
            let mut pw = PartialWitness::<F>::new();
            pw.set_proof_with_pis_target(
                &universal_verifier_circuit.verifier_targets.verified_proof,
                &wrapped_proof,
            );
            pw.set_verifier_data_target(
                &universal_verifier_circuit.verifier_targets.verifier_data,
                &base_circuit_variant.get_circuit_data().verifier_only,
            );
            circuit_set
                .set_circuit_membership_target(
                    &mut pw,
                    &universal_verifier_circuit
                        .verifier_targets
                        .circuit_set_membership,
                    base_circuit.get_circuit_data().verifier_only.circuit_digest,
                )
                .unwrap();
            <RecursiveCircuitWires<INPUT_SIZE> as CircuitLogicWires<F, D, 1>>::assign_input(
                &universal_verifier_circuit.input_targets,
                array::from_fn(|_| F::rand()),
                &mut pw,
            )
            .unwrap();
            universal_verifier_circuit
                .circuit_set_target
                .set_target(&mut pw, &CircuitSetDigest::from(&circuit_set));

            check_panic!(
                || universal_verifier_circuit.circuit_data.prove(pw),
                "universal verifier didn't fail when providing a valid proof of memberhsip for a verifier data 
                different from the one being employed to recursively verify the proof"
            );
        }

        // change only the circuit digest of the wrap circuit of `base_circuit_variant` replacing it with the circuit
        // of a circuit in the set
        let circuit_data = mutable_final_proof_circuit_data(&mut base_circuit_variant.wrap_circuit);
        // change the circuit digest both for prover and verifier data to ensure that the wrapped
        // proof is generated employing a circuit digest belonging to the correct set of circuits
        circuit_data.verifier_only.circuit_digest =
            base_circuit.get_circuit_data().verifier_only.circuit_digest;
        circuit_data.prover_only.circuit_digest =
            base_circuit.get_circuit_data().prover_only.circuit_digest;
        println!("wrapping proof with wrong circuit digest");
        let wrapped_proof = base_circuit_variant.wrap_base_proof(base_proof).unwrap();
        check_panic!(|| universal_verifier_circuit.generate_proof(
            &circuit_set,
            &wrapped_proof,
            &base_circuit_variant.get_circuit_data().verifier_only,
            array::from_fn(|_| F::rand())
        ), "universal verifier didn't fail when verifying a proof for a circuit with the wrong circuit digest");
    }

    #[test]
    fn test_universal_verifier_target_serialization() {
        const INPUT_SIZE: usize = 8;
        const CIRCUIT_SET_SIZE: usize = 2;
        let config = CircuitConfig::standard_recursion_config();
        let universal_verifier_circuit =
            CircuitWithUniversalVerifier::<F, C, D, INPUT_SIZE>::build_circuit(
                config.clone(),
                CIRCUIT_SET_SIZE,
            );

        // test `UniversalVerifierTarget` serialization
        let encoded = bincode::serialize(&universal_verifier_circuit.verifier_targets).unwrap();
        let verifier_targets: UniversalVerifierTarget<D> = bincode::deserialize(&encoded).unwrap();

        assert_eq!(
            verifier_targets,
            universal_verifier_circuit.verifier_targets
        );
    }
}
