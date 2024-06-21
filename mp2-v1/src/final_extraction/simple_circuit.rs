use mp2_common::public_inputs::PublicInputCommon;
use mp2_common::{group_hashing::CircuitBuilderGroupHashing, types::GFp, utils::ToTargets};
use plonky2::iop::target::BoolTarget;
use plonky2::iop::witness::WitnessWrite;
use plonky2::{
    iop::{target::Target, witness::PartialWitness},
    plonk::circuit_builder::CircuitBuilder,
};
use plonky2_ecgfp5::gadgets::curve::CircuitBuilderEcGFp5;

use crate::values_extraction;

use super::{base_circuit, PublicInputs};

#[derive(Clone, Debug)]
struct SimpleCircuit {
    /// Set to true for types that
    /// * have multiple entries (like an mapping, unlike a single uin256 for example)
    /// * don't need or have an associated length slot to combine with
    /// It happens contracts don't have a length slot associated with the mapping
    /// like ERC20 and thus there is no proof circuits have looked at _all_ the entries
    /// due to limitations on EVM (there is no mapping.len()).
    compound_type: bool,
}

#[derive(Debug, Clone)]
struct SimpleWires {
    compound: BoolTarget,
}

impl SimpleCircuit {
    fn build(
        b: &mut CircuitBuilder<GFp, 2>,
        block_pi: &[Target],
        contract_pi: &[Target],
        value_pi: &[Target],
    ) -> SimpleWires {
        let base_wires = base_circuit::BaseCircuit::build(b, block_pi, contract_pi, value_pi);

        let value_pi = values_extraction::PublicInputs::<Target>::new(value_pi);
        let dv = value_pi.values_digest().to_targets();
        let single_variable = b.map_to_curve_point(&dv);
        let compound = b.add_virtual_bool_target_safe();
        let final_dv = b.curve_select(compound, value_pi.values_digest(), single_variable);
        PublicInputs::new(
            &base_wires.bh,
            &base_wires.prev_bh,
            &final_dv.to_targets(),
            &base_wires.dm.to_targets(),
            &base_wires.bn,
        )
        .register_args(b);
        SimpleWires { compound }
    }

    fn assign(&self, pw: &mut PartialWitness<GFp>, wires: &SimpleWires) {
        pw.set_bool_target(wires.compound, self.compound_type);
    }
}

#[cfg(test)]
mod test {
    use crate::contract_extraction;

    use super::*;
    use base_circuit::test::{ProofsPi, ProofsPiTarget};
    use mp2_common::{group_hashing::map_to_curve_point, utils::ToFields};
    use mp2_test::circuit::{run_circuit, UserCircuit};
    use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
    pub const D: usize = 2;
    pub type C = PoseidonGoldilocksConfig;
    pub type F = <C as GenericConfig<D>>::F;

    #[derive(Clone, Debug)]
    struct TestSimpleCircuit {
        circuit: SimpleCircuit,
        pis: ProofsPi,
    }

    struct TestSimpleWires {
        circuit: SimpleWires,
        pis: ProofsPiTarget,
    }

    impl UserCircuit<GFp, 2> for TestSimpleCircuit {
        type Wires = TestSimpleWires;
        fn build(c: &mut plonky2::plonk::circuit_builder::CircuitBuilder<GFp, 2>) -> Self::Wires {
            let pis = ProofsPiTarget::new(c);
            let wires = SimpleCircuit::build(c, &pis.blocks_pi, &pis.contract_pi, &pis.values_pi);
            TestSimpleWires {
                circuit: wires,
                pis,
            }
        }
        fn prove(&self, pw: &mut plonky2::iop::witness::PartialWitness<GFp>, wires: &Self::Wires) {
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
        let proof_pis = PublicInputs::from_slice(&proof.public_inputs);
        // TODO once block extraction done
        //assert_eq!(proof_pis.bn, pis.blocks_pi.bn);
        //assert_eq!(proof_pis.bh, pis.blocks_pi.bh);
        //assert_eq!(proof_pis.prev_bh, pis.blocks_pi.ph);

        // check digests
        let value_pi = values_extraction::PublicInputs::new(&pis.values_pi);
        assert_eq!(proof_pis.value_point(), value_pi.values_digest());
        // metadata is addition of contract and value
        let expected_dm = pis.contract_dm + pis.value_dm;
        assert_eq!(proof_pis.metadata_point(), expected_dm.to_weierstrass());

        let test_circuit = TestSimpleCircuit {
            pis: pis.clone(),
            circuit: SimpleCircuit {
                compound_type: false,
            },
        };
        let proof = run_circuit::<F, D, C, _>(test_circuit);
        let proof_pis = PublicInputs::from_slice(&proof.public_inputs);
        // in this case, dv is D(value_dv)
        let exp_dv = map_to_curve_point(&pis.value_dv.to_weierstrass().to_fields());
        assert_eq!(proof_pis.value_point(), exp_dv.to_weierstrass());
    }
}
