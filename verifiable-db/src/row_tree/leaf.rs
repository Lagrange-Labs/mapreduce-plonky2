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
    iop::{
        target::Target,
        witness::PartialWitness,
    },
    plonk::{circuit_builder::CircuitBuilder, proof::ProofWithPublicInputsTarget},
};
use recursion_framework::{
    circuit_builder::CircuitLogicWires,
    framework::{
        RecursiveCircuits, RecursiveCircuitsVerifierGagdet, RecursiveCircuitsVerifierTarget,
    },
};
use serde::{Deserialize, Serialize};

use crate::cells_tree::{self, Cell, CellWire};

use super::public_inputs::PublicInputs;

// new type to implement the circuit logic on each differently
// deref to access directly the same members - read only so it's ok
#[derive(Clone, Debug, From, Into)]
pub struct LeafCircuit(Cell);

#[derive(Clone, Serialize, Deserialize, From, Into)]
pub(crate) struct LeafWires(CellWire);

impl LeafCircuit {
    pub(crate) fn build(b: &mut CircuitBuilder<F, D>, cells_pis: &[Target]) -> LeafWires {
        let cells_pis = cells_tree::PublicInputs::from_slice(cells_pis);
        // D(index_id||pack_u32(index_value)
        let tuple = CellWire::new(b);
        // set the right digest depending on the multiplier and accumulate the ones from the public
        // inputs of the cell root proof
        let split_digest = tuple.split_and_accumulate_digest(b, cells_pis.split_digest_target());
        // final_digest = HashToInt(D(mul_digest)) * D(ind_digest)
        // NOTE This additional digest is necessary since the individual digest is supposed to be a
        // full row, that is how it is extracted from MPT
        let (final_digest, is_merge) = split_digest.cond_combine_to_row_digest(b);

        // H(left_child_hash,right_child_hash,min,max,index_identifier,index_value,cells_tree_hash)
        // in our case, min == max == index_value
        // left_child_hash == right_child_hash == empty_hash since there is not children
        let empty_hash = b.constant_hash(*empty_poseidon_hash());
        let inputs = empty_hash
            .to_targets()
            .iter()
            .chain(empty_hash.to_targets().iter())
            .chain(tuple.value.to_targets().iter())
            .chain(tuple.value.to_targets().iter())
            .chain(tuple.to_targets().iter())
            .chain(cells_pis.node_hash().to_targets().iter())
            .cloned()
            .collect::<Vec<_>>();
        let row_hash = b.hash_n_to_hash_no_pad::<H>(inputs);
        let value_fields = tuple.value.to_targets();
        PublicInputs::new(
            &row_hash.elements,
            &final_digest.to_targets(),
            &value_fields,
            &value_fields,
            &[is_merge.target],
        )
        .register(b);
        LeafWires(tuple)
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

    const NUM_PUBLIC_INPUTS: usize = PublicInputs::<Target>::TOTAL_LEN;

    fn circuit_logic(
        builder: &mut CircuitBuilder<F, D>,
        _verified_proofs: [&ProofWithPublicInputsTarget<D>; 0],
        builder_parameters: Self::CircuitBuilderParams,
    ) -> Self {
        const CELLS_IO: usize = cells_tree::PublicInputs::<Target>::TOTAL_LEN;
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

    use alloy::primitives::U256;
    use mp2_common::{
        group_hashing::{cond_field_hashed_scalar_mul, map_to_curve_point},
        poseidon::empty_poseidon_hash,
        utils::ToFields,
        CHasher, C, D, F,
    };
    use mp2_test::circuit::{run_circuit, UserCircuit};
    use plonky2::{
        field::types::Sample,
        hash::{hash_types::HashOut, hashing::hash_n_to_hash_no_pad},
        iop::{target::Target, witness::WitnessWrite},
        plonk::{circuit_builder::CircuitBuilder, config::Hasher},
    };
    use plonky2_ecgfp5::curve::curve::Point;
    use rand::{thread_rng, Rng};

    use crate::{
        cells_tree::{self, Cell},
        row_tree::public_inputs::PublicInputs,
    };

    use super::{LeafCircuit, LeafWires};

    #[derive(Debug, Clone)]
    struct TestLeafCircuit {
        circuit: LeafCircuit,
        cells_pi: Vec<F>,
    }

    impl UserCircuit<F, D> for TestLeafCircuit {
        type Wires = (LeafWires, Vec<Target>);

        fn build(c: &mut CircuitBuilder<F, D>) -> Self::Wires {
            let cells_pi = c.add_virtual_targets(cells_tree::PublicInputs::<Target>::TOTAL_LEN);
            (LeafCircuit::build(c, &cells_pi), cells_pi)
        }

        fn prove(&self, pw: &mut plonky2::iop::witness::PartialWitness<F>, wires: &Self::Wires) {
            pw.set_target_arr(&wires.1, &self.cells_pi);
            self.circuit.assign(pw, &wires.0);
        }
    }

    fn test_row_tree_leaf_circuit(is_multiplier: bool, cells_multiplier: bool) {
        let mut rng = thread_rng();
        let value = U256::from_limbs(rng.gen::<[u64; 4]>());
        let identifier = F::rand();
        let row_cell = Cell::new(identifier, value, is_multiplier);
        let circuit = LeafCircuit::from(row_cell.clone());
        let tuple = row_cell.clone();

        let ind_cells_digest = Point::rand().to_fields();
        // TODO: test with other than neutral
        let mul_cells_digest = if cells_multiplier {
            Point::rand().to_fields()
        } else {
            Point::NEUTRAL.to_fields()
        };
        let cells_hash = HashOut::rand().to_fields();
        let cells_pi_struct =
            cells_tree::PublicInputs::new(&cells_hash, &ind_cells_digest, &mul_cells_digest);
        let cells_pi = cells_pi_struct.to_vec();
        let test_circuit = TestLeafCircuit { circuit, cells_pi };
        let proof = run_circuit::<F, D, C, _>(test_circuit);
        let pi = PublicInputs::from_slice(&proof.public_inputs);
        assert_eq!(value, pi.max_value_u256());
        assert_eq!(value, pi.min_value_u256());
        let empty_hash = empty_poseidon_hash();
        let inputs = empty_hash
            .to_fields()
            .iter()
            .chain(empty_hash.to_fields().iter())
            .chain(tuple.value.to_fields().iter())
            .chain(tuple.value.to_fields().iter())
            .chain(tuple.to_fields().iter())
            .chain(cells_hash.iter())
            .cloned()
            .collect::<Vec<_>>();
        let row_hash = hash_n_to_hash_no_pad::<F, <CHasher as Hasher<F>>::Permutation>(&inputs);
        assert_eq!(row_hash, pi.root_hash_hashout());
        // final_digest = HashToInt(mul_digest) * D(ind_digest)
        let split_digest =
            row_cell.split_and_accumulate_digest(cells_pi_struct.split_digest_point());
        let result = split_digest.cond_combine_to_row_digest();
        assert_eq!(result.to_weierstrass(), pi.rows_digest_field());
        assert_eq!(split_digest.is_merge_case(), pi.is_merge_flag());
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
