use derive_more::{From, Into};
use mp2_common::{
    digest::{TableDimension, TableDimensionWire},
    public_inputs::PublicInputCommon,
    utils::ToTargets,
    D, F,
};
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
#[derive(Clone, Debug, From, Into)]
pub struct SimpleCircuit(TableDimension);

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct SimpleWires(TableDimensionWire);

impl SimpleCircuit {
    fn build(
        b: &mut CircuitBuilder<F, D>,
        block_pi: &[Target],
        contract_pi: &[Target],
        value_pi: &[Target],
    ) -> SimpleWires {
        // only one value proof to verify for this circuit
        let base_wires = base_circuit::BaseCircuit::build(b, block_pi, contract_pi, vec![value_pi]);

        let value_pi = values_extraction::PublicInputs::<Target>::new(value_pi);
        let dv = value_pi.values_digest_target();
        // Compute the final value digest depending on the table dimension
        let dimension: TableDimensionWire = b.add_virtual_bool_target_safe().into();
        let final_dv = dimension.conditional_row_digest(b, dv);
        PublicInputs::new(
            &base_wires.bh,
            &base_wires.prev_bh,
            &final_dv.to_targets(),
            &base_wires.dm.to_targets(),
            &base_wires.bn.to_targets(),
        )
        .register_args(b);
        SimpleWires(dimension)
    }

    fn assign(&self, pw: &mut PartialWitness<F>, wires: &SimpleWires) {
        self.0.assign_wire(pw, &wires.0);
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub(crate) struct SimpleCircuitRecursiveWires {
    /// NOTE: assumed to be containing a single value inside, in the vec.
    base: BaseCircuitProofWires,
    simple_wires: SimpleWires,
}

pub struct SimpleCircuitInput {
    base: BaseCircuitProofInputs,
    simple: SimpleCircuit,
}

impl SimpleCircuitInput {
    pub(crate) fn new(base: BaseCircuitProofInputs, dimension: TableDimension) -> Self {
        Self {
            base,
            simple: dimension.into(),
        }
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
        let wires = SimpleCircuit::build(
            builder,
            base.get_block_public_inputs(),
            base.get_contract_public_inputs(),
            base.get_value_public_inputs(),
        );
        Self {
            base,
            simple_wires: wires,
        }
    }

    fn assign_input(&self, inputs: Self::Inputs, pw: &mut PartialWitness<F>) -> anyhow::Result<()> {
        inputs.base.assign_proof_targets(pw, &self.base)?;
        inputs.simple.assign(pw, &self.simple_wires);
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use base_circuit::test::{ProofsPi, ProofsPiTarget};
    use mp2_common::C;
    use mp2_test::circuit::{run_circuit, UserCircuit};

    #[derive(Clone, Debug)]
    struct TestSimpleCircuit {
        circuit: SimpleCircuit,
        pis: ProofsPi,
    }

    struct TestSimpleWires {
        circuit: SimpleWires,
        pis: ProofsPiTarget,
    }

    impl UserCircuit<F, D> for TestSimpleCircuit {
        type Wires = TestSimpleWires;
        fn build(c: &mut plonky2::plonk::circuit_builder::CircuitBuilder<F, D>) -> Self::Wires {
            let pis = ProofsPiTarget::new(c);
            let wires = SimpleCircuit::build(c, &pis.blocks_pi, &pis.contract_pi, &pis.values_pi);
            TestSimpleWires {
                circuit: wires,
                pis,
            }
        }
        fn prove(&self, pw: &mut plonky2::iop::witness::PartialWitness<F>, wires: &Self::Wires) {
            wires.pis.assign(pw, &self.pis);
            self.circuit.assign(pw, &wires.circuit)
        }
    }

    #[test]
    fn test_final_simple_circuit() {
        let pis = ProofsPi::random();
        let test_circuit = TestSimpleCircuit {
            pis: pis.clone(),
            circuit: TableDimension::Compound.into(),
        };
        let proof = run_circuit::<F, D, C, _>(test_circuit);
        pis.check_proof_public_inputs(&proof, TableDimension::Compound, None);

        let test_circuit = TestSimpleCircuit {
            pis: pis.clone(),
            circuit: TableDimension::Single.into(),
        };
        let proof = run_circuit::<F, D, C, _>(test_circuit);
        pis.check_proof_public_inputs(&proof, TableDimension::Single, None);
    }
}
