use crate::{C, D, F};
use mp2_common::{
    default_config, proof::ProofWithVK, public_inputs::PublicInputCommon, utils::ToTargets,
};
use plonky2::{
    field::types::Field,
    iop::{target::Target, witness::PartialWitness},
    plonk::circuit_builder::CircuitBuilder,
};
use plonky2_ecgfp5::gadgets::curve::CircuitBuilderEcGFp5;
use recursion_framework::{
    circuit_builder::CircuitLogicWires,
    framework::{
        RecursiveCircuits, RecursiveCircuitsVerifierGagdet, RecursiveCircuitsVerifierTarget,
    },
};
use serde::{Deserialize, Serialize};

use crate::{length_extraction, values_extraction};

use super::{
    api::{FinalExtractionBuilderParams, NUM_IO},
    base_circuit,
    base_circuit::{BaseCircuitProofInputs, BaseCircuitProofWires},
    PublicInputs,
};

/// This circuit contains the logic to prove the final extraction of a mapping
/// variable associated with a length slot.
#[derive(Clone, Debug)]
pub struct LengthedCircuit {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct LengthedWires {}

impl LengthedCircuit {
    fn build(
        b: &mut CircuitBuilder<F, D>,
        block_pi: &[Target],
        contract_pi: &[Target],
        value_pi: &[Target],
        length_pi: &[Target],
    ) -> LengthedWires {
        // Right now for length circuit we don't support MERGE, we only give a single table. Need
        // to create other circuit to handle different table with length.
        let base_wires = base_circuit::BaseCircuit::build(b, block_pi, contract_pi, vec![value_pi]);
        let value_pi = values_extraction::PublicInputs::<Target>::new(value_pi);
        let dv = value_pi.values_digest_target().to_targets();

        let len_pi = length_extraction::PublicInputs::<Target>::from_slice(length_pi);
        // pseudo code:
        // assert length_proof.T == -1
        // assert length_proof.N == value_proof.N
        // assert length_proof.H == value_proof.H
        // dm += length_proof.DM
        let mpt_key = len_pi.mpt_key_wire();
        let minus_one = b.constant(F::NEG_ONE);
        b.connect(mpt_key.pointer, minus_one);
        let length_n = len_pi.length();
        let value_n = &value_pi.n();
        b.connect(*length_n, *value_n);
        len_pi
            .root_hash()
            .enforce_equal(b, &value_pi.root_hash_target());
        // 0 because there is only one value proof to verify
        let final_dm = b.curve_add(base_wires.dm, len_pi.metadata_digest());
        PublicInputs::new(
            &base_wires.bh,
            &base_wires.prev_bh,
            // here the value digest is the same since for length proof, it is assumed the table
            // digest is in Compound format (i.e. multiple rows inside digest already).
            &dv,
            &final_dm.to_targets(),
            &base_wires.bn.to_targets(),
            &[b._false().target],
        )
        .register_args(b);
        LengthedWires {}
    }

    fn assign(&self, _pw: &mut PartialWitness<F>, _wires: &LengthedWires) {}
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct LengthedRecursiveWires {
    base: BaseCircuitProofWires,
    length_proof_wires: RecursiveCircuitsVerifierTarget<D>,
    wires: LengthedWires,
}

pub(crate) struct LengthedCircuitInput {
    base: BaseCircuitProofInputs,
    length_proof: ProofWithVK,
    length_circuit_set: RecursiveCircuits<F, C, D>,
    lengthed: LengthedCircuit,
}

impl LengthedCircuitInput {
    pub(crate) fn new(
        base_proofs: BaseCircuitProofInputs,
        length_proof: ProofWithVK,
        length_circuit_set: RecursiveCircuits<F, C, D>,
    ) -> Self {
        Self {
            base: base_proofs,
            length_proof,
            length_circuit_set,
            lengthed: LengthedCircuit {},
        }
    }
}

pub(crate) const LENGTH_SET_NUM_IO: usize = length_extraction::PublicInputs::<Target>::TOTAL_LEN;

impl CircuitLogicWires<F, D, 0> for LengthedRecursiveWires {
    type CircuitBuilderParams = FinalExtractionBuilderParams;
    type Inputs = LengthedCircuitInput;

    const NUM_PUBLIC_INPUTS: usize = NUM_IO;

    fn circuit_logic(
        builder: &mut CircuitBuilder<F, D>,
        _verified_proofs: [&plonky2::plonk::proof::ProofWithPublicInputsTarget<D>; 0],
        builder_parameters: Self::CircuitBuilderParams,
    ) -> Self {
        // there is only one value proof to verify for length circuit, see "merge" circuit for more
        // info if one wants to final extract on multiple tables.
        let base = BaseCircuitProofInputs::build(builder, &builder_parameters, 1);
        let verifier_gadget = RecursiveCircuitsVerifierGagdet::<_, _, D, LENGTH_SET_NUM_IO>::new(
            default_config(),
            &builder_parameters.length_circuit_set,
        );
        let length_proof_wires = verifier_gadget.verify_proof_in_circuit_set(builder);
        let length_pi = length_proof_wires.get_public_input_targets::<F, LENGTH_SET_NUM_IO>();
        let wires = LengthedCircuit::build(
            builder,
            base.get_block_public_inputs(),
            base.get_contract_public_inputs(),
            base.get_value_public_inputs(),
            length_pi,
        );
        Self {
            base,
            length_proof_wires,
            wires,
        }
    }

    fn assign_input(&self, inputs: Self::Inputs, pw: &mut PartialWitness<F>) -> anyhow::Result<()> {
        inputs.base.assign_proof_targets(pw, &self.base)?;
        let (proof, vd) = (&inputs.length_proof).into();
        self.length_proof_wires
            .set_target(pw, &inputs.length_circuit_set, proof, vd)?;
        inputs.lengthed.assign(pw, &self.wires);
        Ok(())
    }
}

#[cfg(test)]
mod test {

    use super::*;
    use base_circuit::test::{ProofsPi, ProofsPiTarget};
    use mp2_test::circuit::{run_circuit, UserCircuit};
    use plonky2::iop::witness::WitnessWrite;

    #[derive(Clone, Debug)]
    struct TestLengthedCircuit {
        circuit: LengthedCircuit,
        pis: ProofsPi,
        len_pi: Vec<F>,
    }

    struct TestLengthedWires {
        circuit: LengthedWires,
        pis: ProofsPiTarget,
        len_pi: Vec<Target>,
    }

    impl UserCircuit<F, D> for TestLengthedCircuit {
        type Wires = TestLengthedWires;
        fn build(c: &mut plonky2::plonk::circuit_builder::CircuitBuilder<F, D>) -> Self::Wires {
            let pis = ProofsPiTarget::new(c);
            let len_pi =
                c.add_virtual_targets(length_extraction::PublicInputs::<Target>::TOTAL_LEN);
            let wires = LengthedCircuit::build(
                c,
                &pis.blocks_pi,
                &pis.contract_pi,
                &pis.values_pi,
                &len_pi,
            );
            TestLengthedWires {
                circuit: wires,
                pis,
                len_pi,
            }
        }
        fn prove(&self, pw: &mut plonky2::iop::witness::PartialWitness<F>, wires: &Self::Wires) {
            wires.pis.assign(pw, &self.pis);
            self.circuit.assign(pw, &wires.circuit);
            pw.set_target_arr(&wires.len_pi, &self.len_pi);
        }
    }

    #[test]
    fn test_final_lengthed_circuit() {
        let pis = ProofsPi::random();
        let len_pi = pis.length_inputs();
        let test_circuit = TestLengthedCircuit {
            pis: pis.clone(),
            circuit: LengthedCircuit {},
            len_pi,
        };
        let len_pi = length_extraction::PublicInputs::<F>::from_slice(&test_circuit.len_pi);
        let len_dm = len_pi.metadata_point();
        let proof = run_circuit::<F, D, C, _>(test_circuit);
        pis.check_proof_public_inputs(&proof, Some(len_dm));
    }
}
