use crate::{D, F};
use derive_more::From;
use mp2_common::{public_inputs::PublicInputCommon, utils::ToTargets};
use plonky2::{
    iop::{target::Target, witness::PartialWitness},
    plonk::circuit_builder::CircuitBuilder,
};
use recursion_framework::circuit_builder::CircuitLogicWires;
use serde::{Deserialize, Serialize};

use crate::values_extraction;

use super::{
    api::{FinalExtractionBuilderParams, NUM_IO},
    base_circuit::{self, BaseCircuitProofInputs, BaseCircuitProofWires},
    PublicInputs,
};

/// This circuit contains the logic to prove the final extraction of a simple
/// variable (like uint256) or a mapping without an associated length slot.
#[derive(Clone, Debug, From)]
pub struct SimpleCircuit;

impl SimpleCircuit {
    fn build(
        b: &mut CircuitBuilder<F, D>,
        block_pi: &[Target],
        contract_pi: &[Target],
        value_pi: &[Target],
    ) {
        // only one value proof to verify for this circuit
        let base_wires = base_circuit::BaseCircuit::build(b, block_pi, contract_pi, vec![value_pi]);

        let value_pi = values_extraction::PublicInputs::<Target>::new(value_pi);
        let final_dv = value_pi.values_digest_target();
        PublicInputs::new(
            &base_wires.bh,
            &base_wires.prev_bh,
            &final_dv.to_targets(),
            &base_wires.dm.to_targets(),
            &base_wires.bn.to_targets(),
            &[b._false().target],
        )
        .register_args(b);
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub(crate) struct SimpleCircuitRecursiveWires {
    /// NOTE: assumed to be containing a single value inside, in the vec.
    base: BaseCircuitProofWires,
}

pub struct SimpleCircuitInput {
    base: BaseCircuitProofInputs,
}

impl SimpleCircuitInput {
    pub(crate) fn new(base: BaseCircuitProofInputs) -> Self {
        Self { base }
    }
}

impl CircuitLogicWires<F, D, 0> for SimpleCircuitRecursiveWires {
    type CircuitBuilderParams = FinalExtractionBuilderParams;

    type Inputs = SimpleCircuitInput;

    const NUM_PUBLIC_INPUTS: usize = NUM_IO;

    fn circuit_logic(
        builder: &mut CircuitBuilder<F, D>,
        _verified_proofs: [&plonky2::plonk::proof::ProofWithPublicInputsTarget<D>; 0],
        builder_parameters: Self::CircuitBuilderParams,
    ) -> Self {
        // only one proof to verify for this simple circuit
        let base = BaseCircuitProofInputs::build(builder, &builder_parameters, 1);
        SimpleCircuit::build(
            builder,
            base.get_block_public_inputs(),
            base.get_contract_public_inputs(),
            base.get_value_public_inputs(),
        );
        Self { base }
    }

    fn assign_input(&self, inputs: Self::Inputs, pw: &mut PartialWitness<F>) -> anyhow::Result<()> {
        inputs.base.assign_proof_targets(pw, &self.base)?;
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use base_circuit::test::{ProofsPi, ProofsPiTarget};
    use crate::C;
    use mp2_test::circuit::{run_circuit, UserCircuit};

    #[derive(Clone, Debug)]
    struct TestSimpleCircuit {
        pis: ProofsPi,
    }

    struct TestSimpleWires {
        pis: ProofsPiTarget,
    }

    impl UserCircuit<F, D> for TestSimpleCircuit {
        type Wires = TestSimpleWires;
        fn build(c: &mut plonky2::plonk::circuit_builder::CircuitBuilder<F, D>) -> Self::Wires {
            let pis = ProofsPiTarget::new(c);
            SimpleCircuit::build(c, &pis.blocks_pi, &pis.contract_pi, &pis.values_pi);
            TestSimpleWires { pis }
        }
        fn prove(&self, pw: &mut plonky2::iop::witness::PartialWitness<F>, wires: &Self::Wires) {
            wires.pis.assign(pw, &self.pis);
        }
    }

    #[test]
    fn test_final_simple_circuit() {
        let pis = ProofsPi::random();
        let test_circuit = TestSimpleCircuit { pis: pis.clone() };
        let proof = run_circuit::<F, D, C, _>(test_circuit);
        pis.check_proof_public_inputs(&proof, None);

        let test_circuit = TestSimpleCircuit { pis: pis.clone() };
        let proof = run_circuit::<F, D, C, _>(test_circuit);
        pis.check_proof_public_inputs(&proof, None);
    }
}
