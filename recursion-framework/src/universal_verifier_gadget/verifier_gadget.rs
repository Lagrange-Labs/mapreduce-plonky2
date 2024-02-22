use plonky2::{field::extension::Extendable, hash::hash_types::RichField, iop::witness::{PartialWitness, WitnessWrite}, plonk::{circuit_builder::CircuitBuilder, 
    circuit_data::{CircuitConfig, CommonCircuitData, VerifierCircuitTarget, VerifierOnlyCircuitData}, config::{AlgebraicHasher, GenericConfig, Hasher}, proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget}}};

use super::{build_data_for_recursive_aggregation, circuit_set::{check_circuit_digest_target, CircuitSet, CircuitSetMembershipTargets, CircuitSetTarget}, RECURSION_THRESHOLD};

use anyhow::Result;


#[derive(Debug)]
pub(crate) struct UniversalVerifierTargets<const D: usize> {
    circuit_set_membership: CircuitSetMembershipTargets,
    verified_proof: ProofWithPublicInputsTarget<D>,
    verifier_data: VerifierCircuitTarget,
}

impl<const D: usize> UniversalVerifierTargets<D> {
    pub(crate) fn get_proof_target(&self) -> &ProofWithPublicInputsTarget<D> {
        &self.verified_proof
    }

    pub(crate) fn set_universal_verifier_targets<
        F: RichField + Extendable<D>, 
        C: GenericConfig<D, F = F>,
    >(
        &self, 
        pw: &mut PartialWitness<F>, 
        circuit_set: &CircuitSet<F,C,D>,
        proof: &ProofWithPublicInputs<F,C,D>,
        verifier_data: &VerifierOnlyCircuitData<C,D>
    ) -> Result<()> 
    where C::Hasher: AlgebraicHasher<F>,
    [(); C::Hasher::HASH_SIZE]:,
    {
        pw.set_proof_with_pis_target(&self.verified_proof, proof);
        pw.set_verifier_data_target(&self.verifier_data, verifier_data);
        circuit_set.set_circuit_membership_target(pw, &self.circuit_set_membership, verifier_data.circuit_digest)
    }
}

pub(crate) struct UniversalVerifierBuilder<
    F: RichField + Extendable<D>, 
    const D: usize,
    const NUM_PUBLIC_INPUTS: usize,
> {
    rec_data: CommonCircuitData<F,D>,
    circuit_set_size: usize,
}

impl<
    F: RichField + Extendable<D>, 
    const D: usize,
    const NUM_PUBLIC_INPUTS: usize,
> UniversalVerifierBuilder<F,D, NUM_PUBLIC_INPUTS> {
    pub(crate) fn new<C: GenericConfig<D, F = F>>(
        config: CircuitConfig, 
        circuit_set_size: usize
    ) -> Self 
    where 
        C::Hasher: AlgebraicHasher<F>,
        [(); C::Hasher::HASH_SIZE]:,
    {
        let rec_data =
        build_data_for_recursive_aggregation::<F, C, D>(config, NUM_PUBLIC_INPUTS);
        Self {
            rec_data,
            circuit_set_size,
        }
    }

    pub(crate) fn get_circuit_set_size(&self) -> usize {
        self.circuit_set_size
    }

    pub(crate) fn verify_proof_for_universal_verifier<
        C: GenericConfig<D, F = F>,
    >(
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

    // check that `circuit_set_target` is the same as the one exposed by the `proof`
    pub(crate) fn check_circuit_set_equality(
        builder: &mut CircuitBuilder<F, D>,
        circuit_set_target: &CircuitSetTarget,
        proof: &ProofWithPublicInputsTarget<D>,
    ) {
        let circuit_set_targets = circuit_set_target.to_targets();
        
        circuit_set_targets.iter().zip(proof.public_inputs.iter().skip(NUM_PUBLIC_INPUTS))
        .for_each(|(&cs_t, &pi_t)| builder.connect(cs_t, pi_t));
    }

    pub(crate) fn universal_verifier_circuit<
        C: GenericConfig<D, F = F>,
    >(
        &self,
        builder: &mut CircuitBuilder<F,D>,
        circuit_set_target: &CircuitSetTarget,
    ) -> UniversalVerifierTargets<D>
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

        UniversalVerifierTargets {
            circuit_set_membership: proof_membership_target,
            verified_proof: proof,
            verifier_data,
        }
    }
}