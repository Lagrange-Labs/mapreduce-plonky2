use super::{
    public_inputs::PublicInputs,
    row::{Row, RowWire},
};
use crate::cells_tree;
use derive_more::{From, Into};
use mp2_common::{
    default_config,
    poseidon::{empty_poseidon_hash, H},
    proof::ProofWithVK,
    public_inputs::PublicInputCommon,
    utils::ToTargets,
    C, D, F,
};
use plonky2::{
    iop::{target::Target, witness::PartialWitness},
    plonk::{circuit_builder::CircuitBuilder, proof::ProofWithPublicInputsTarget},
};
use recursion_framework::{
    circuit_builder::CircuitLogicWires,
    framework::{
        RecursiveCircuits, RecursiveCircuitsVerifierGagdet, RecursiveCircuitsVerifierTarget,
    },
};
use serde::{Deserialize, Serialize};
use std::iter::once;

// new type to implement the circuit logic on each differently
// deref to access directly the same members - read only so it's ok
#[derive(Clone, Debug, From, Into)]
pub struct LeafCircuit(Row);

#[derive(Clone, Serialize, Deserialize, From, Into)]
pub(crate) struct LeafWires(RowWire);

impl LeafCircuit {
    pub(crate) fn build(b: &mut CircuitBuilder<F, D>, cells_pis: &[Target]) -> LeafWires {
        let cells_pis = cells_tree::PublicInputs::from_slice(cells_pis);
        let row = RowWire::new(b);
        let id = row.identifier();
        let value = row.value().to_targets();
        let digest = row.digest(b, &cells_pis);

        // H(left_child_hash,right_child_hash,min,max,index_identifier,index_value,cells_tree_hash)
        // in our case, min == max == index_value
        // left_child_hash == right_child_hash == empty_hash since there is not children
        let empty_hash = b.constant_hash(*empty_poseidon_hash()).to_targets();
        let inputs = empty_hash
            .clone()
            .into_iter()
            .chain(empty_hash)
            .chain(value.clone())
            .chain(value.clone())
            .chain(once(id))
            .chain(value.clone())
            .chain(cells_pis.node_hash_target())
            .collect::<Vec<_>>();
        let row_hash = b.hash_n_to_hash_no_pad::<H>(inputs);
        PublicInputs::new(
            &row_hash.elements,
            &digest.individual_vd.to_targets(),
            &digest.multiplier_vd.to_targets(),
            &digest.row_id_multiplier.to_targets(),
            &value,
            &value,
            &[digest.is_merge.target],
        )
        .register(b);

        LeafWires(row)
    }

    fn assign(&self, pw: &mut PartialWitness<F>, wires: &LeafWires) {
        self.0.assign_wires(pw, &wires.0);
    }
}

#[derive(Serialize, Deserialize)]
pub(crate) struct RecursiveLeafWires {
    cells_verifier: RecursiveCircuitsVerifierTarget<D>,
    leaf_wires: LeafWires,
}

///  Circuit input that contains the  local witness value
///  as well as the cells proof to verify
#[derive(Clone, Debug)]
pub(crate) struct RecursiveLeafInput {
    pub(crate) witness: LeafCircuit,
    pub(crate) cells_proof: ProofWithVK,
    // given here as well so it's not saved in the parameters
    pub(crate) cells_set: RecursiveCircuits<F, C, D>,
}

impl CircuitLogicWires<F, D, 0> for RecursiveLeafWires {
    // cells set
    type CircuitBuilderParams = RecursiveCircuits<F, C, D>;

    type Inputs = RecursiveLeafInput;

    const NUM_PUBLIC_INPUTS: usize = PublicInputs::<Target>::total_len();

    fn circuit_logic(
        builder: &mut CircuitBuilder<F, D>,
        _verified_proofs: [&ProofWithPublicInputsTarget<D>; 0],
        builder_parameters: Self::CircuitBuilderParams,
    ) -> Self {
        const CELLS_IO: usize = cells_tree::PublicInputs::<Target>::total_len();
        let verifier_gadget = RecursiveCircuitsVerifierGagdet::<F, C, D, CELLS_IO>::new(
            default_config(),
            &builder_parameters,
        );
        let cells_verifier_gadget = verifier_gadget.verify_proof_in_circuit_set(builder);
        let cells_pi = cells_verifier_gadget.get_public_input_targets::<F, CELLS_IO>();
        RecursiveLeafWires {
            // run the row leaf circuit just with the public inputs of the cells proof
            leaf_wires: LeafCircuit::build(builder, cells_pi),
            cells_verifier: cells_verifier_gadget,
        }
    }

    fn assign_input(&self, inputs: Self::Inputs, pw: &mut PartialWitness<F>) -> anyhow::Result<()> {
        inputs.witness.assign(pw, &self.leaf_wires);
        let (proof, vd) = inputs.cells_proof.into();
        self.cells_verifier
            .set_target(pw, &inputs.cells_set, &proof, &vd)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        cells_tree::PublicInputs as CellsPublicInputs, row_tree::public_inputs::PublicInputs,
    };
    use itertools::Itertools;
    use mp2_common::{poseidon::empty_poseidon_hash, utils::ToFields, C, D, F};
    use mp2_test::circuit::{run_circuit, UserCircuit};
    use plonky2::{
        iop::{target::Target, witness::WitnessWrite},
        plonk::{circuit_builder::CircuitBuilder, config::Hasher},
    };
    use std::iter::once;

    #[derive(Debug, Clone)]
    struct TestLeafCircuit {
        circuit: LeafCircuit,
        cells_pi: Vec<F>,
    }

    impl UserCircuit<F, D> for TestLeafCircuit {
        type Wires = (LeafWires, Vec<Target>);

        fn build(c: &mut CircuitBuilder<F, D>) -> Self::Wires {
            let cells_pi = c.add_virtual_targets(cells_tree::PublicInputs::<Target>::total_len());
            (LeafCircuit::build(c, &cells_pi), cells_pi)
        }

        fn prove(&self, pw: &mut plonky2::iop::witness::PartialWitness<F>, wires: &Self::Wires) {
            pw.set_target_arr(&wires.1, &self.cells_pi);
            self.circuit.assign(pw, &wires.0);
        }
    }

    fn test_row_tree_leaf_circuit(is_multiplier: bool, cells_multiplier: bool) {
        let cells_pi = CellsPublicInputs::sample(cells_multiplier);

        let row = Row::sample(is_multiplier);
        let id = row.cell.identifier;
        let value = row.cell.value;
        let row_digest = row.digest(&CellsPublicInputs::from_slice(&cells_pi));

        let circuit = LeafCircuit::from(row);
        let test_circuit = TestLeafCircuit {
            circuit,
            cells_pi: cells_pi.clone(),
        };
        let cells_pi = CellsPublicInputs::from_slice(&cells_pi);

        let proof = run_circuit::<F, D, C, _>(test_circuit);
        let pi = PublicInputs::from_slice(&proof.public_inputs);

        // Check root hash
        {
            let value = value.to_fields();
            let empty_hash = empty_poseidon_hash().to_fields();
            let inputs = empty_hash
                .iter()
                .chain(empty_hash.iter())
                .chain(value.iter())
                .chain(value.iter())
                .chain(once(&id))
                .chain(value.iter())
                .chain(cells_pi.to_node_hash_raw())
                .cloned()
                .collect_vec();
            let exp_root_hash = H::hash_no_pad(&inputs);
            assert_eq!(pi.root_hash(), exp_root_hash);
        }
        // Check individual digest
        assert_eq!(
            pi.individual_digest_point(),
            row_digest.individual_vd.to_weierstrass()
        );
        // Check multiplier digest
        assert_eq!(
            pi.multiplier_digest_point(),
            row_digest.multiplier_vd.to_weierstrass()
        );
        // Check row ID multiplier
        assert_eq!(pi.row_id_multiplier(), row_digest.row_id_multiplier);
        // Check minimum value
        assert_eq!(pi.min_value(), value);
        // Check maximum value
        assert_eq!(pi.max_value(), value);
        // Check merge flag
        assert_eq!(pi.merge_flag(), row_digest.is_merge);
    }

    #[test]
    fn row_tree_leaf() {
        test_row_tree_leaf_circuit(false, false);
    }

    #[test]
    fn row_tree_leaf_node_multiplier() {
        test_row_tree_leaf_circuit(true, false);
    }

    #[test]
    fn row_tree_leaf_cells_multiplier() {
        test_row_tree_leaf_circuit(false, true);
    }

    #[test]
    fn row_tree_leaf_all_multipliers() {
        test_row_tree_leaf_circuit(true, true);
    }
}
