use plonky2::{field::extension::Extendable, hash::hash_types::{MerkleCapTarget, RichField}, iop::witness::{PartialWitness, WitnessWrite}, plonk::{circuit_builder::CircuitBuilder, circuit_data::{CircuitConfig, CircuitData, CommonCircuitData, VerifierCircuitTarget, VerifierOnlyCircuitData}, 
    config::{AlgebraicHasher, GenericConfig, Hasher}, proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget}}
};

use crate::universal_verifier_gadget::{circuit_set::check_circuit_digest_target, RECURSION_THRESHOLD};

use anyhow::Result;

// Data structure with all input/output targets and the `CircuitData` for each circuit employed
// to recursively wrap a proof up to the recursion threshold. The data structure contains a set
// of targets and a `CircuitData` for each wrap step.
pub(crate) struct WrapCircuit<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize> {
    proof_targets: Vec<ProofWithPublicInputsTarget<D>>,
    circuit_data: Vec<CircuitData<F, C, D>>,
    inner_data: Vec<VerifierCircuitTarget>,
}

impl<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>
    WrapCircuit<F, C, D>
where
    C::Hasher: AlgebraicHasher<F>,
    [(); C::Hasher::HASH_SIZE]:,
{
    // build the wrap circuit for a proof enforcing the circuit with verifier data `inner_vd`
    // and `inner_cd`
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
                builder.register_public_input(pi_t.clone())
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

    // wrap a proof `inner_proof` enforcing the circuit with data `inner_cd` employing the wrap
    // circuit
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
