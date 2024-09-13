use derive_more::{From, Into};
use mp2_common::{
    default_config,
    group_hashing::{circuit_hashed_scalar_mul, CircuitBuilderGroupHashing},
    poseidon::H,
    proof::ProofWithVK,
    public_inputs::PublicInputCommon,
    u256::CircuitBuilderU256,
    utils::ToTargets,
    C, D, F,
};
use plonky2::{
    iop::{target::Target, witness::PartialWitness},
    plonk::{circuit_builder::CircuitBuilder, proof::ProofWithPublicInputsTarget},
};
use plonky2_ecgfp5::gadgets::curve::CircuitBuilderEcGFp5;
use recursion_framework::{
    circuit_builder::CircuitLogicWires,
    framework::{
        RecursiveCircuits, RecursiveCircuitsVerifierGagdet, RecursiveCircuitsVerifierTarget,
    },
};
use serde::{Deserialize, Serialize};
use std::array::from_fn as create_array;

use crate::cells_tree::{self, Cell, CellWire};

use super::public_inputs::PublicInputs;
// Arity not strictly needed now but may be an easy way to increase performance
// easily down the line with less recursion. Best to provide code which is easily
// amenable to a different arity rather than hardcoding binary tree only
#[derive(Clone, Debug, From, Into)]
pub struct FullNodeCircuit(Cell);

#[derive(Clone, Serialize, Deserialize, From, Into)]
pub(crate) struct FullNodeWires(CellWire);

impl FullNodeCircuit {
    pub(crate) fn build(
        b: &mut CircuitBuilder<F, D>,
        left_pi: &[Target],
        right_pi: &[Target],
        cells_pi: &[Target],
    ) -> FullNodeWires {
        let cells_pi = cells_tree::PublicInputs::from_slice(cells_pi);
        let min_child = PublicInputs::from_slice(left_pi);
        let max_child = PublicInputs::from_slice(right_pi);
        let tuple = CellWire::new(b);
        let node_min = min_child.min_value();
        let node_max = max_child.max_value();
        // enforcing BST property
        let _true = b._true();
        let left_comparison = b.is_less_or_equal_than_u256(&min_child.max_value(), &tuple.value);
        let right_comparison = b.is_less_or_equal_than_u256(&tuple.value, &max_child.min_value());
        b.connect(left_comparison.target, _true.target);
        b.connect(right_comparison.target, _true.target);

        // Poseidon(p1.H || p2.H || node_min || node_max || index_id || index_value ||p.H)) as H
        let inputs = min_child
            .root_hash()
            .to_targets()
            .iter()
            .chain(max_child.root_hash().to_targets().iter())
            .chain(node_min.to_targets().iter())
            .chain(node_max.to_targets().iter())
            .chain(tuple.to_targets().iter())
            .chain(cells_pi.node_hash().to_targets().iter())
            .cloned()
            .collect::<Vec<_>>();
        let hash = b.hash_n_to_hash_no_pad::<H>(inputs);

        // final_digest = HashToInt(mul_digest) * D(ind_digest) + left.digest() + right.digest()
        let (digest_ind, digest_mul) = tuple.split_and_accumulate_digest(b, &cells_pi);
        let digest_ind = b.map_to_curve_point(&digest_ind.to_targets());
        let row_digest = circuit_hashed_scalar_mul(b, digest_mul.to_targets(), digest_ind);

        // add this row digest with the rest
        let final_digest = b.curve_add(min_child.rows_digest(), max_child.rows_digest());
        let final_digest = b.curve_add(final_digest, row_digest);
        PublicInputs::new(
            &hash.to_targets(),
            &final_digest.to_targets(),
            &node_min.to_targets(),
            &node_max.to_targets(),
        )
        .register(b);
        FullNodeWires(tuple)
    }
    fn assign(&self, pw: &mut PartialWitness<F>, wires: &FullNodeWires) {
        self.0.assign_wires(pw, &wires.0);
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct RecursiveFullWires {
    cells_verifier: RecursiveCircuitsVerifierTarget<D>,
    full_wires: FullNodeWires,
}

#[derive(Clone, Debug)]
pub(crate) struct RecursiveFullInput {
    pub(crate) witness: FullNodeCircuit,
    pub(crate) cells_proof: ProofWithVK,
    pub(crate) cells_set: RecursiveCircuits<F, C, D>,
}

pub(crate) const NUM_CHILDREN: usize = 2;
impl CircuitLogicWires<F, D, NUM_CHILDREN> for RecursiveFullWires {
    type CircuitBuilderParams = RecursiveCircuits<F, C, D>;

    type Inputs = RecursiveFullInput;

    const NUM_PUBLIC_INPUTS: usize = PublicInputs::<Target>::TOTAL_LEN;

    fn circuit_logic(
        builder: &mut CircuitBuilder<F, D>,
        verified_proofs: [&ProofWithPublicInputsTarget<D>; NUM_CHILDREN],
        builder_parameters: Self::CircuitBuilderParams,
    ) -> Self {
        const CELLS_IO: usize = cells_tree::PublicInputs::<Target>::TOTAL_LEN;
        let verifier_gadget = RecursiveCircuitsVerifierGagdet::<F, C, D, CELLS_IO>::new(
            default_config(),
            &builder_parameters,
        );
        let cells_verifier_gadget = verifier_gadget.verify_proof_in_circuit_set(builder);
        let cells_pi = cells_verifier_gadget.get_public_input_targets::<F, CELLS_IO>();
        let children_pi: [&[Target]; 2] =
            create_array(|i| Self::public_input_targets(verified_proofs[i]));
        RecursiveFullWires {
            // run the row leaf circuit just with the public inputs of the cells proof
            full_wires: FullNodeCircuit::build(builder, children_pi[0], children_pi[1], cells_pi),
            cells_verifier: cells_verifier_gadget,
        }
    }

    fn assign_input(&self, inputs: Self::Inputs, pw: &mut PartialWitness<F>) -> anyhow::Result<()> {
        inputs.witness.assign(pw, &self.full_wires);
        let (proof, vd) = inputs.cells_proof.into();
        self.cells_verifier
            .set_target(pw, &inputs.cells_set, &proof, &vd)
    }
}

#[cfg(test)]
pub(crate) mod test {

    use alloy::primitives::U256;
    use mp2_common::{
        group_hashing::{field_hashed_scalar_mul, map_to_curve_point},
        poseidon::H,
        utils::ToFields,
        C, D, F,
    };
    use mp2_test::{
        circuit::{run_circuit, UserCircuit},
        utils::weierstrass_to_point,
    };
    use plonky2::{
        field::types::Sample,
        hash::hash_types::HashOut,
        iop::{
            target::Target,
            witness::{PartialWitness, WitnessWrite},
        },
        plonk::{circuit_builder::CircuitBuilder, config::Hasher},
    };
    use plonky2_ecgfp5::curve::curve::Point;

    use crate::{cells_tree, row_tree::public_inputs::PublicInputs};

    use super::{FullNodeCircuit, FullNodeWires, *};

    #[derive(Clone, Debug)]
    struct TestFullNodeCircuit {
        circuit: FullNodeCircuit,
        left_pi: Vec<F>,
        right_pi: Vec<F>,
        cells_pi: Vec<F>,
    }

    impl UserCircuit<F, D> for TestFullNodeCircuit {
        type Wires = (FullNodeWires, Vec<Target>, Vec<Target>, Vec<Target>);

        fn build(c: &mut CircuitBuilder<F, D>) -> Self::Wires {
            let cells_pi = c.add_virtual_targets(cells_tree::PublicInputs::<Target>::TOTAL_LEN);
            let left_pi = c.add_virtual_targets(PublicInputs::<Target>::TOTAL_LEN);
            let right_pi = c.add_virtual_targets(PublicInputs::<Target>::TOTAL_LEN);
            (
                FullNodeCircuit::build(c, &left_pi, &right_pi, &cells_pi),
                left_pi,
                right_pi,
                cells_pi,
            )
        }

        fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
            self.circuit.assign(pw, &wires.0);
            pw.set_target_arr(&wires.1, &self.left_pi);
            pw.set_target_arr(&wires.2, &self.right_pi);
            pw.set_target_arr(&wires.3, &self.cells_pi);
        }
    }

    pub(crate) fn generate_random_pi(min: usize, max: usize) -> Vec<F> {
        let hash = HashOut::rand();
        let digest = Point::rand();
        let min = U256::from(min);
        let max = U256::from(max);
        PublicInputs::new(
            &hash.to_fields(),
            &digest.to_weierstrass().to_fields(),
            &min.to_fields(),
            &max.to_fields(),
        )
        .to_vec()
    }

    #[test]
    fn row_tree_full_circuit() {
        let cells_point = Point::rand();
        let ind_cell_digest = cells_point.to_weierstrass().to_fields();
        let mul_cell_digest = Point::NEUTRAL.to_fields();
        let cells_hash = HashOut::rand().to_fields();
        let cells_pi_struct =
            cells_tree::PublicInputs::new(&cells_hash, &ind_cell_digest, &mul_cell_digest);
        let cells_pi = cells_pi_struct.to_vec();

        let (left_min, left_max) = (10, 15);
        // this should work since we allow multipleicities of indexes in the row tree
        let (right_min, right_max) = (18, 30);
        let value = U256::from(18); // 15 < 18 < 23
        let identifier = F::rand();
        let tuple = Cell::new(identifier, value, false);
        let node_circuit = FullNodeCircuit::from(tuple.clone());
        let left_pi = generate_random_pi(left_min, left_max);
        let right_pi = generate_random_pi(right_min, right_max);
        let test_circuit = TestFullNodeCircuit {
            circuit: node_circuit,
            left_pi: left_pi.clone(),
            right_pi: right_pi.clone(),
            cells_pi,
        };
        let proof = run_circuit::<F, D, C, _>(test_circuit);
        let pi = PublicInputs::from_slice(&proof.public_inputs);
        let left_pis = PublicInputs::from_slice(&left_pi);
        let right_pis = PublicInputs::from_slice(&right_pi);

        assert_eq!(U256::from(left_min), pi.min_value_u256());
        assert_eq!(U256::from(right_max), pi.max_value_u256());
        // Poseidon(p1.H || p2.H || node_min || node_max || index_id || index_value ||p.H)) as H
        let left_hash = PublicInputs::from_slice(&left_pi).root_hash_hashout();
        let right_hash = PublicInputs::from_slice(&right_pi).root_hash_hashout();
        let inputs = left_hash
            .to_fields()
            .iter()
            .chain(right_hash.to_fields().iter())
            .chain(left_pis.min_value_u256().to_fields().iter())
            .chain(right_pis.max_value_u256().to_fields().iter())
            .chain(Cell::new(identifier, value, false).to_fields().iter())
            .chain(cells_hash.iter())
            .cloned()
            .collect::<Vec<_>>();
        let hash = H::hash_no_pad(&inputs);
        assert_eq!(hash, pi.root_hash_hashout());

        // final_digest = HashToInt(mul_digest) * D(ind_digest) + p1.digest() + p2.digest()
        let (row_ind, row_mul) = tuple.split_and_accumulate_digest(&cells_pi_struct);
        let ind_final = map_to_curve_point(&row_ind.to_fields());
        let row_digest = field_hashed_scalar_mul(row_mul.to_fields(), ind_final);

        let p1dr = weierstrass_to_point(&PublicInputs::from_slice(&left_pi).rows_digest_field());
        let p2dr = weierstrass_to_point(&PublicInputs::from_slice(&right_pi).rows_digest_field());
        let result_digest = p1dr + p2dr + row_digest;
        assert_eq!(result_digest.to_weierstrass(), pi.rows_digest_field());
    }
}
