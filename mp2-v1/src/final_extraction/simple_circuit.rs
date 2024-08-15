use mp2_common::{
    group_hashing::CircuitBuilderGroupHashing,
    public_inputs::PublicInputCommon,
    serialization::{deserialize, serialize},
    utils::ToTargets,
    D, F,
};
use plonky2::{
    iop::{
        target::{BoolTarget, Target},
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::circuit_builder::CircuitBuilder,
};
use plonky2_ecgfp5::gadgets::curve::CircuitBuilderEcGFp5;
use recursion_framework::circuit_builder::CircuitLogicWires;
use serde::{Deserialize, Serialize};

use crate::values_extraction;

use super::{
    api::{FinalExtractionBuilderParams, NUM_IO},
    base_circuit,
    base_circuit::{BaseCircuitProofInputs, BaseCircuitProofWires},
    PublicInputs,
};

/// This circuit contains the logic to prove the final extraction of a simple
/// variable (like uint256) or a mapping without an associated length slot.
#[derive(Clone, Debug)]
pub struct SimpleCircuit {
    /// Set to true for types that
    /// * have multiple entries (like an mapping, unlike a single uin256 for example)
    /// * don't need or have an associated length slot to combine with
    /// It happens contracts don't have a length slot associated with the mapping
    /// like ERC20 and thus there is no proof circuits have looked at _all_ the entries
    /// due to limitations on EVM (there is no mapping.len()).
    compound_type: bool,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct SimpleWires {
    #[serde(serialize_with = "serialize", deserialize_with = "deserialize")]
    compound: BoolTarget,
}

impl SimpleCircuit {
    fn build(
        b: &mut CircuitBuilder<F, D>,
        block_pi: &[Target],
        contract_pi: &[Target],
        value_pi: &[Target],
    ) -> SimpleWires {
        let base_wires = base_circuit::BaseCircuit::build(b, block_pi, contract_pi, value_pi);

        let value_pi = values_extraction::PublicInputs::<Target>::new(value_pi);
        let dv = value_pi.values_digest_target().to_targets();
        let single_variable = b.map_to_curve_point(&dv);
        let compound = b.add_virtual_bool_target_safe();
        let final_dv = b.curve_select(compound, value_pi.values_digest_target(), single_variable);
        PublicInputs::new(
            &base_wires.bh,
            &base_wires.prev_bh,
            &final_dv.to_targets(),
            &base_wires.dm.to_targets(),
            &base_wires.bn.to_targets(),
        )
        .register_args(b);
        SimpleWires { compound }
    }

    fn assign(&self, pw: &mut PartialWitness<F>, wires: &SimpleWires) {
        pw.set_bool_target(wires.compound, self.compound_type);
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub(crate) struct SimpleCircuitRecursiveWires {
    base: BaseCircuitProofWires,
    simple_wires: SimpleWires,
}

pub struct SimpleCircuitInput {
    base: BaseCircuitProofInputs,
    simple: SimpleCircuit,
}

impl SimpleCircuitInput {
    pub(crate) fn new(base: BaseCircuitProofInputs, compound: bool) -> Self {
        let simple = SimpleCircuit {
            compound_type: compound,
        };
        Self { base, simple }
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
        let base = BaseCircuitProofInputs::build(builder, &builder_parameters);
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
    use plonky2::plonk::config::GenericConfig;

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
            circuit: SimpleCircuit {
                compound_type: true,
            },
        };
        let proof = run_circuit::<F, D, C, _>(test_circuit);
        pis.check_proof_public_inputs(&proof, true, None);

        let test_circuit = TestSimpleCircuit {
            pis: pis.clone(),
            circuit: SimpleCircuit {
                compound_type: false,
            },
        };
        let proof = run_circuit::<F, D, C, _>(test_circuit);
        pis.check_proof_public_inputs(&proof, false, None);
    }
}
