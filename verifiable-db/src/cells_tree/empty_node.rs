//! Module handling the empty node inside a cells tree

use super::public_inputs::PublicInputs;
use crate::{CBuilder, D, F};
use anyhow::Result;
use mp2_common::{
    poseidon::empty_poseidon_hash, public_inputs::PublicInputCommon, utils::ToTargets,
};
use plonky2::{iop::witness::PartialWitness, plonk::proof::ProofWithPublicInputsTarget};
use plonky2_ecgfp5::gadgets::curve::CircuitBuilderEcGFp5;
use recursion_framework::circuit_builder::CircuitLogicWires;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EmptyNodeWires;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EmptyNodeCircuit;

impl EmptyNodeCircuit {
    pub fn build(b: &mut CBuilder) -> EmptyNodeWires {
        // h = Poseidon("")
        let empty_hash = empty_poseidon_hash();
        let h = b.constant_hash(*empty_hash).elements;

        // ZERO
        let zero = b.zero();

        // CURVE_ZERO
        let curve_zero = b.curve_zero().to_targets();

        // Register the public inputs.
        PublicInputs::new(&h, &curve_zero, &curve_zero, &zero, &zero).register(b);

        EmptyNodeWires
    }
}

/// Num of children = 0
impl CircuitLogicWires<F, D, 0> for EmptyNodeWires {
    type CircuitBuilderParams = ();

    type Inputs = EmptyNodeCircuit;

    const NUM_PUBLIC_INPUTS: usize = PublicInputs::<F>::total_len();

    fn circuit_logic(
        builder: &mut CBuilder,
        _verified_proofs: [&ProofWithPublicInputsTarget<D>; 0],
        _: Self::CircuitBuilderParams,
    ) -> Self {
        EmptyNodeCircuit::build(builder)
    }

    fn assign_input(&self, _inputs: Self::Inputs, _pw: &mut PartialWitness<F>) -> Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::C;
    use mp2_test::circuit::{run_circuit, UserCircuit};
    use plonky2::field::types::Field;
    use plonky2_ecgfp5::curve::curve::WeierstrassPoint;

    impl UserCircuit<F, D> for EmptyNodeCircuit {
        type Wires = EmptyNodeWires;

        fn build(b: &mut CBuilder) -> Self::Wires {
            EmptyNodeCircuit::build(b)
        }

        fn prove(&self, _pw: &mut PartialWitness<F>, _wires: &Self::Wires) {}
    }

    #[test]
    fn test_cells_tree_empty_node_circuit() {
        let test_circuit = EmptyNodeCircuit;
        let proof = run_circuit::<F, D, C, _>(test_circuit);
        let pi = PublicInputs::from_slice(&proof.public_inputs);
        // Check the node Poseidon hash
        {
            let empty_hash = empty_poseidon_hash();
            assert_eq!(pi.h, empty_hash.elements);
        }
        // Check individual values digest
        assert_eq!(
            pi.individual_values_digest_point(),
            WeierstrassPoint::NEUTRAL
        );
        // Check multiplier values digest
        assert_eq!(
            pi.multiplier_values_digest_point(),
            WeierstrassPoint::NEUTRAL
        );
        // Check individual counter
        assert_eq!(pi.individual_counter(), F::ZERO);
        // Check multiplier counter
        assert_eq!(pi.multiplier_counter(), F::ZERO);
    }
}
