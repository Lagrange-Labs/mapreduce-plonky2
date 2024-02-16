use plonky2::{field::extension::Extendable, hash::hash_types::RichField, plonk::{circuit_data::VerifierOnlyCircuitData, 
config::{AlgebraicHasher, GenericConfig, Hasher}, proof::ProofWithPublicInputs}};

use crate::{circuit_builder::{CircuitLogic, CircuitWithUniversalVerifier}, universal_verifier_gadget::{CircuitSet, CircuitSetDigest}};

use anyhow::Result;
/// This trait is employed to fetch the `VerifierOnlyCircuitData` of a circuit, which is needed to verify
/// a proof with the universal verifier
pub trait RecursiveCircuitInfo<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize
> {
    /// Returns a reference to the `VerifierOnlyCircuitData` of the circuit implementing this trait
    fn get_verifier_data(&self) -> &VerifierOnlyCircuitData<C,D>;

}

/// `RecursivecircuitInfo` trait is automatically implemented for any `CircuitWithUniversalVerifier` 
/// and for `&CircuitWithUniversalVerifier` 
impl<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
    const NUM_VERIFIERS: usize,
    CL: CircuitLogic<F,D, NUM_VERIFIERS>,
> RecursiveCircuitInfo<F,C,D> for CircuitWithUniversalVerifier<F,C,D,NUM_VERIFIERS, CL> 
where 
    C::Hasher: AlgebraicHasher<F>,
    [(); C::Hasher::HASH_SIZE]:,
{
    fn get_verifier_data(&self) -> & VerifierOnlyCircuitData<C,D> {
        &self.circuit_data().verifier_only
    }
}

impl<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
    T: RecursiveCircuitInfo<F,C,D>,
> RecursiveCircuitInfo<F,C,D> for &T {
    fn get_verifier_data(&self) -> &VerifierOnlyCircuitData<C,D> {
        (*self).get_verifier_data()
    }
}

/// `RecursiveCircuits` is a data structure employed to generate proofs for a given set of circuits, 
/// which are basically instances of `CircuitWithUniversalVerifier`
pub struct RecursiveCircuits<
F: RichField + Extendable<D>,
C: GenericConfig<D, F = F>,
const D: usize
> {
    circuit_set: CircuitSet<F,C,D>,
}

impl<
F: RichField + Extendable<D>,
C: GenericConfig<D, F = F> + 'static,
const D: usize
> RecursiveCircuits<F,C,D> 
where
    C::Hasher: AlgebraicHasher<F>,
    [(); C::Hasher::HASH_SIZE]:,
{
    /// Instantiate a `RecursiveCircuits` data structure employing the list of circuits provided as input
    pub fn new(circuits: Vec<Box<dyn RecursiveCircuitInfo<F,C,D> + '_>>) -> Self {
        let circuit_digests = circuits.into_iter().map(|circuit| {
            circuit.as_ref().get_verifier_data().circuit_digest
        }).collect::<Vec<_>>();
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
        CL: CircuitLogic<F,D,NUM_VERIFIERS>, 
    >(
        &self,
        circuit: &CircuitWithUniversalVerifier<F,C,D,NUM_VERIFIERS,CL>,
        input_proofs: [ProofWithPublicInputs<F,C,D>; NUM_VERIFIERS],
        input_verifier_data: [&VerifierOnlyCircuitData<C,D>; NUM_VERIFIERS],
        custom_inputs: CL::Inputs,
    ) -> Result<ProofWithPublicInputs<F,C,D>> {
        circuit.generate_proof(input_proofs, input_verifier_data, &self.circuit_set, custom_inputs)
    }

    /// Get the digest of the circuit set as a list of field elements, which should be equal to 
    /// the list of public inputs corresponding to the circuit set digest in the generated proofs 
    pub fn get_circuit_set_digest(&self) -> Vec<F> {
        CircuitSetDigest::from(&self.circuit_set).flatten()
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

#[cfg(test)]
mod tests {
    use std::array;

    use plonky2::plonk::{circuit_data::CircuitConfig, config::PoseidonGoldilocksConfig};
    use plonky2::field::types::Sample;
    use serial_test::serial;

    use crate::circuit_builder::{tests::{LeafCircuit, RecursiveCircuit}, CircuitWithUniversalVerifierBuilder};

    use super::*;
    
    #[test]
    #[serial]
    fn test_recursive_circuit_framework()
    {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        const INPUT_SIZE: usize = 8;
        const CIRCUIT_SET_SIZE: usize = 5;
        let config = CircuitConfig::standard_recursion_config();

        let num_public_inputs = <LeafCircuit::<INPUT_SIZE> as CircuitLogic<F,D,0>>::NUM_PUBLIC_INPUTS;
        let circuit_builder = CircuitWithUniversalVerifierBuilder::<F,D>::new::<C>(config, CIRCUIT_SET_SIZE, num_public_inputs);
        
        let leaf_circuit = circuit_builder.build_circuit::<C, 0, LeafCircuit<INPUT_SIZE>>(1usize << 12);

        let recursive_circuit_one = circuit_builder.build_circuit::<C, 1, RecursiveCircuit<INPUT_SIZE>>(());

        let recursive_circuit_two = circuit_builder.build_circuit::<C, 2, RecursiveCircuit<INPUT_SIZE>>(());

        let recursive_circuit_three = circuit_builder.build_circuit::<C, 3, RecursiveCircuit<INPUT_SIZE>>(());

        let recursive_circuit_four = circuit_builder.build_circuit::<C, 4, RecursiveCircuit<INPUT_SIZE>>(());

        let circuits = vec![
            prepare_recursive_circuit_for_circuit_set(&leaf_circuit), 
            prepare_recursive_circuit_for_circuit_set(&recursive_circuit_one),
            prepare_recursive_circuit_for_circuit_set(&recursive_circuit_two),
            prepare_recursive_circuit_for_circuit_set(&recursive_circuit_three),
            prepare_recursive_circuit_for_circuit_set(&recursive_circuit_four),
        ];

        let recursive_framework = RecursiveCircuits::new(circuits);

        let base_proofs = (0..7).map(|_| {
            let inputs = array::from_fn(|_| F::rand());
            recursive_framework.generate_proof(&leaf_circuit, [], [], (inputs, F::rand()))
        }).collect::<Result<Vec<_>>>().unwrap();
        
        let leaf_circuit_vd = leaf_circuit.get_verifier_data();

        let recursive_circuits_input = array::from_fn(|_| F::rand());
        let rec_proof_1 = recursive_framework.generate_proof(
            &recursive_circuit_four,
           base_proofs[..4].to_vec().try_into().unwrap() , 
           [leaf_circuit_vd; 4], 
           recursive_circuits_input,
        ).unwrap();

        assert_eq!(&rec_proof_1.public_inputs[num_public_inputs..], recursive_framework.get_circuit_set_digest().as_slice());

        let recursive_circuits_input = array::from_fn(|_| F::rand());
        let rec_proof_2 = recursive_framework.generate_proof(
            &recursive_circuit_three,
           base_proofs[4..].to_vec().try_into().unwrap() , 
           [leaf_circuit_vd; 3], 
           recursive_circuits_input,
        ).unwrap();
        

        assert_eq!(&rec_proof_2.public_inputs[num_public_inputs..], recursive_framework.get_circuit_set_digest().as_slice());
    
        let recursive_circuits_input = array::from_fn(|_| F::rand());
        let rec_proof = recursive_framework.generate_proof(
            &recursive_circuit_two,
           [rec_proof_1, rec_proof_2], 
           [recursive_circuit_four.get_verifier_data(), recursive_circuit_three.get_verifier_data()],
           recursive_circuits_input,
        ).unwrap();

        assert_eq!(&rec_proof.public_inputs[num_public_inputs..], recursive_framework.get_circuit_set_digest().as_slice());
    
        let recursive_circuits_input = array::from_fn(|_| F::rand());
        let rec_proof = recursive_framework.generate_proof(
            &recursive_circuit_one, 
            [rec_proof], 
            [recursive_circuit_two.get_verifier_data()], 
            recursive_circuits_input
        ).unwrap();
        
        assert_eq!(&rec_proof.public_inputs[num_public_inputs..], recursive_framework.get_circuit_set_digest().as_slice());
        
        recursive_circuit_one.circuit_data().verify(rec_proof).unwrap();
    }
}