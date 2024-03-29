use plonky2::{
    hash::hash_types::MerkleCapTarget,
    iop::witness::{PartialWitness, WitnessWrite},
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{
            CircuitConfig, CircuitData, CommonCircuitData, VerifierCircuitTarget,
            VerifierOnlyCircuitData,
        },
        config::{AlgebraicHasher, GenericConfig, Hasher},
        proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget},
    },
};
use serde::{Deserialize, Serialize};

use crate::{
    serialization::{
        circuit_data_serialization::SerializableRichField, deserialize_vec, serialize_vec,
    },
    universal_verifier_gadget::{circuit_set::check_circuit_digest_target, RECURSION_THRESHOLD},
};

use anyhow::Result;

/// Data structure with all input/output targets and the `CircuitData` for each circuit employed
/// to recursively wrap a proof up to the recursion threshold. The data structure contains a set
/// of targets and a `CircuitData` for each wrap step.
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(bound = "")]
pub(crate) struct WrapCircuit<
    F: SerializableRichField<D>,
    C: GenericConfig<D, F = F> + 'static,
    const D: usize,
> where
    C::Hasher: AlgebraicHasher<F>,
{
    #[serde(serialize_with = "serialize_vec", deserialize_with = "deserialize_vec")]
    proof_targets: Vec<ProofWithPublicInputsTarget<D>>,
    #[serde(serialize_with = "serialize_vec", deserialize_with = "deserialize_vec")]
    circuit_data: Vec<CircuitData<F, C, D>>,
    #[serde(serialize_with = "serialize_vec", deserialize_with = "deserialize_vec")]
    inner_data: Vec<VerifierCircuitTarget>,
}

impl<F: SerializableRichField<D>, C: GenericConfig<D, F = F>, const D: usize> WrapCircuit<F, C, D>
where
    C::Hasher: AlgebraicHasher<F>,
    [(); C::Hasher::HASH_SIZE]:,
{
    /// build the wrap circuit for a proof enforcing the circuit with verifier data `inner_vd`
    /// and `inner_cd`
    pub(crate) fn build_wrap_circuit(
        inner_vd: &VerifierOnlyCircuitData<C, D>,
        inner_cd: &CommonCircuitData<F, D>,
        config: &CircuitConfig,
    ) -> Self {
        let mut vd = inner_vd;
        let mut cd = inner_cd;
        let mut wrap_circuit = Self {
            proof_targets: Vec::new(),
            circuit_data: Vec::new(),
            inner_data: Vec::new(),
        };

        loop {
            let mut builder = CircuitBuilder::<F, D>::new(config.clone());
            let wrap_step = wrap_circuit.circuit_data.len();
            let pt = builder.add_virtual_proof_with_pis(cd);
            let inner_data = VerifierCircuitTarget {
                constants_sigmas_cap:
                    // we allocate `constants_sigmas_cap` as constants only in the first wrapping step,
                    // as otherwise it is not possible to obtain a wrapping circuit which is as
                    // small as the recursion threshold
                    if wrap_step != 0 {
                        builder.add_virtual_cap(cd.config.fri_config.cap_height)
                    } else {
                        MerkleCapTarget(
                            vd.constants_sigmas_cap.0.iter().map(|hash|
                            builder.constant_hash(*hash)
                            ).collect::<Vec<_>>()
                        )
                    },
                // instead, `circuit_digest` is a constant for all the wrapping circuits
                circuit_digest: builder.constant_hash(vd.circuit_digest),
            };
            builder.verify_proof::<C>(&pt, &inner_data, cd);

            if wrap_step != 0 {
                // in wrapping circuits where the `constants_sigmas_cap` are allocated as private
                // inputs, their correctness is enforced by re-computing the circuit digest and
                // comparing it with the constant one hardcoded in the wrapping circuit at hand
                check_circuit_digest_target::<_, C, D>(&mut builder, &inner_data, cd.degree_bits());
            }

            for pi_t in pt.public_inputs.iter() {
                builder.register_public_input(*pi_t)
            }

            let data = builder.build::<C>();

            wrap_circuit.proof_targets.push(pt);
            wrap_circuit.circuit_data.push(data);
            wrap_circuit.inner_data.push(inner_data);
            let circuit_data = wrap_circuit.circuit_data.last().unwrap();
            (cd, vd) = (&circuit_data.common, &circuit_data.verifier_only);

            log::debug!(
                "wrap step {} done. circuit size is {}",
                wrap_step + 1,
                cd.degree_bits()
            );
            if circuit_data.common.degree_bits() == RECURSION_THRESHOLD {
                break;
            }
        }

        wrap_circuit
    }

    /// Creates the intermediary wrapping proof over the given `inner_proof` and enforcing their correctness
    /// according to the wrap circuit defined in `build_wrap_circuit`.
    pub(crate) fn wrap_proof(
        &self,
        inner_proof: ProofWithPublicInputs<F, C, D>,
    ) -> Result<ProofWithPublicInputs<F, C, D>> {
        let mut proof = inner_proof;
        let mut circuit_data: Option<&VerifierOnlyCircuitData<C, D>> = None;

        for ((pt, cd), inner_data) in self
            .proof_targets
            .iter()
            .zip(self.circuit_data.iter())
            .zip(self.inner_data.iter())
        {
            let mut pw = PartialWitness::new();
            pw.set_proof_with_pis_target(pt, &proof);
            if let Some(vd) = circuit_data {
                // no need to set `constants_sigmas_cap` target in the first wrapping step, as they
                // are hardcoded as constant in the first wrapping circuit
                pw.set_cap_target(&inner_data.constants_sigmas_cap, &vd.constants_sigmas_cap);
            }

            proof = cd.prove(pw)?;
            circuit_data = Some(&cd.verifier_only);
        }

        Ok(proof)
    }

    // Helper function that returns a pointer to the circuit data of the circuit for the last
    // wrap step
    pub(crate) fn final_proof_circuit_data(&self) -> &CircuitData<F, C, D> {
        self.circuit_data.last().unwrap()
    }
}

#[cfg(test)]
pub(crate) mod test {
    use std::array;

    use plonky2::field::types::Sample;
    use plonky2::gates::noop::NoopGate;
    use plonky2::plonk::config::PoseidonGoldilocksConfig;

    use super::*;
    use crate::{
        circuit_builder::{tests::LeafCircuitWires, CircuitLogicWires},
        framework::tests::check_panic,
        serialization::circuit_data_serialization::SerializableRichField,
    };

    use serial_test::serial;

    pub(crate) fn mutable_final_proof_circuit_data<
        F: SerializableRichField<D>,
        C: GenericConfig<D, F = F>,
        const D: usize,
    >(
        circuit: &mut WrapCircuit<F, C, D>,
    ) -> &mut CircuitData<F, C, D>
    where
        C::Hasher: AlgebraicHasher<F>,
    {
        circuit.circuit_data.last_mut().unwrap()
    }

    struct TestCircuit<
        F: SerializableRichField<D>,
        C: GenericConfig<D, F = F> + 'static,
        const D: usize,
        const INPUT_SIZE: usize,
    >
    where
        C::Hasher: AlgebraicHasher<F>,
    {
        targets: LeafCircuitWires<F, INPUT_SIZE>,
        circuit_data: CircuitData<F, C, D>,
        wrap_circuit: WrapCircuit<F, C, D>,
    }

    impl<
            F: SerializableRichField<D>,
            C: GenericConfig<D, F = F>,
            const D: usize,
            const INPUT_SIZE: usize,
        > TestCircuit<F, C, D, INPUT_SIZE>
    where
        C::Hasher: AlgebraicHasher<F>,
        [(); C::Hasher::HASH_SIZE]:,
    {
        fn build_circuit(
            config: CircuitConfig,
            build_parameters: <LeafCircuitWires::<F, INPUT_SIZE> as CircuitLogicWires<F,D,0>>::CircuitBuilderParams,
        ) -> Self {
            let mut builder = CircuitBuilder::<F, D>::new(config.clone());
            let targets =
                <LeafCircuitWires<F, INPUT_SIZE> as CircuitLogicWires<F, D, 0>>::circuit_logic(
                    &mut builder,
                    [],
                    build_parameters,
                );

            let circuit_data = builder.build::<C>();

            let wrap_circuit = WrapCircuit::<F, C, D>::build_wrap_circuit(
                &circuit_data.verifier_only,
                &circuit_data.common,
                &config,
            );

            Self {
                targets,
                circuit_data,
                wrap_circuit,
            }
        }

        fn generate_base_proof(
            &self,
            inputs: <LeafCircuitWires<F, INPUT_SIZE> as CircuitLogicWires<F, D, 0>>::Inputs,
        ) -> Result<ProofWithPublicInputs<F, C, D>> {
            let mut pw = PartialWitness::<F>::new();
            <LeafCircuitWires<F, INPUT_SIZE> as CircuitLogicWires<F, D, 0>>::assign_input(
                &self.targets,
                inputs,
                &mut pw,
            )?;

            self.circuit_data.prove(pw)
        }

        fn generate_proof(
            &self,
            inputs: <LeafCircuitWires<F, INPUT_SIZE> as CircuitLogicWires<F, D, 0>>::Inputs,
        ) -> Result<ProofWithPublicInputs<F, C, D>> {
            let proof = self.generate_base_proof(inputs)?;

            self.wrap_circuit.wrap_proof(proof)
        }

        fn get_circuit_data(&self) -> &CircuitData<F, C, D> {
            &self.wrap_circuit.final_proof_circuit_data()
        }
    }

    #[test]
    #[serial]
    fn test_wrap_circuit_keys() {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        const INPUT_SIZE: usize = 8;

        let config = CircuitConfig::standard_recursion_config();
        const NUM_HASHES_IN_TEST_CIRCUIT: usize = 1usize << 12;
        let test_circuit = TestCircuit::<F, C, D, INPUT_SIZE>::build_circuit(
            config.clone(),
            (NUM_HASHES_IN_TEST_CIRCUIT, false),
        );

        let wrap_proof = test_circuit
            .generate_proof((array::from_fn(|_| F::rand()), F::rand()))
            .unwrap();

        let test_circuit_variant = TestCircuit::<F, C, D, INPUT_SIZE>::build_circuit(
            config.clone(),
            (NUM_HASHES_IN_TEST_CIRCUIT, true),
        );

        let wrap_proof_swap = test_circuit_variant
            .generate_proof((array::from_fn(|_| F::rand()), F::rand()))
            .unwrap();

        assert_eq!(
            test_circuit.circuit_data.common.degree_bits(),
            test_circuit_variant.circuit_data.common.degree_bits(),
        );

        test_circuit.get_circuit_data().verify(wrap_proof).unwrap();

        test_circuit_variant
            .get_circuit_data()
            .verify(wrap_proof_swap)
            .unwrap();

        assert_ne!(
            test_circuit.circuit_data.verifier_only,
            test_circuit_variant.circuit_data.verifier_only
        );

        assert_ne!(
            test_circuit.get_circuit_data().verifier_only,
            test_circuit_variant.get_circuit_data().verifier_only
        );

        // check that wrapping a proof with the wrong wrapping circuit does not work
        let base_proof_variant_circuit = test_circuit_variant
            .generate_base_proof((array::from_fn(|_| F::rand()), F::rand()))
            .unwrap();
        check_panic!(
            || test_circuit
                .wrap_circuit
                .wrap_proof(base_proof_variant_circuit)
                .unwrap(),
            "wrapping proof with wrong circuit did not panic"
        );
    }

    #[test]
    fn test_wrapping_base_circuit_with_domain_separator() {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let config = CircuitConfig::standard_recursion_config();

        let mut builder = CircuitBuilder::<F, D>::new(config.clone());
        for _ in 0..=(1 << 12) {
            builder.add_gate(NoopGate, vec![]);
        }
        builder.set_domain_separator(vec![F::rand()]);
        let pi_t = builder.add_virtual_public_input();

        let data = builder.build::<C>();

        assert_eq!(data.common.degree_bits(), 13);

        let wrap_circuit =
            WrapCircuit::build_wrap_circuit(&data.verifier_only, &data.common, &config);

        let mut pw = PartialWitness::new();
        let public_input = F::rand();
        pw.set_target(pi_t, public_input);

        let proof = data.prove(pw).unwrap();

        let wrapped_proof = wrap_circuit.wrap_proof(proof).unwrap();

        assert_eq!(wrapped_proof.public_inputs[0], public_input);

        wrap_circuit
            .final_proof_circuit_data()
            .verify(wrapped_proof)
            .unwrap()
    }
}
