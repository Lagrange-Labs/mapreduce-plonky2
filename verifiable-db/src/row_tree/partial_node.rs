use plonky2::plonk::proof::ProofWithPublicInputsTarget;

use mp2_common::{
    default_config,
    group_hashing::{circuit_hashed_scalar_mul, CircuitBuilderGroupHashing},
    hash::hash_maybe_first,
    poseidon::empty_poseidon_hash,
    proof::ProofWithVK,
    public_inputs::PublicInputCommon,
    serialization::{deserialize, serialize},
    u256::CircuitBuilderU256,
    utils::ToTargets,
    C, D, F,
};
use plonky2::{
    self,
    iop::{
        target::{BoolTarget, Target},
        witness::{PartialWitness, WitnessWrite},
    },
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

use crate::cells_tree::{
    self, circuit_accumulate_proof_digest, circuit_decide_digest_section, Cell, CellWire,
};

use super::public_inputs::PublicInputs;

#[derive(Clone, Debug)]
pub struct PartialNodeCircuit {
    pub(crate) tuple: Cell,
    pub(crate) is_child_at_left: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct PartialNodeWires {
    tuple: CellWire,
    #[serde(serialize_with = "serialize", deserialize_with = "deserialize")]
    is_child_at_left: BoolTarget,
}

impl PartialNodeCircuit {
    pub(crate) fn new(tuple: Cell, is_child_at_left: bool) -> Self {
        Self {
            tuple,
            is_child_at_left,
        }
    }
    fn build(
        b: &mut CircuitBuilder<F, D>,
        child_pi: &[Target],
        cells_pi: &[Target],
    ) -> PartialNodeWires {
        let cells_pi = cells_tree::PublicInputs::from_slice(cells_pi);
        let tuple = CellWire::new(b);
        // bool target range checked in poseidon gate
        let is_child_at_left = b.add_virtual_bool_target_unsafe();
        let child_pi = PublicInputs::from_slice(child_pi);
        // max_left = left ? child_proof.max : index_value
        // min_right = left ? index_value : child_proof.min
        let max_left = b.select_u256(is_child_at_left, &child_pi.max_value(), &tuple.value);
        let min_right = b.select_u256(is_child_at_left, &tuple.value, &child_pi.min_value());
        let bst_enforced = b.is_less_or_equal_than_u256(&max_left, &min_right);
        let _true = b._true();
        b.connect(bst_enforced.target, _true.target);
        // node_min = left ? child_proof.min : index_value
        // node_max = left ? index_value : child_proof.max
        let node_min = b.select_u256(is_child_at_left, &child_pi.min_value(), &tuple.value);
        let node_max = b.select_u256(is_child_at_left, &tuple.value, &child_pi.max_value());

        let empty_hash = b.constant_hash(*empty_poseidon_hash());
        // left_hash = left ? child_proof.H : H("")
        // right_hash = left ? H("") : child_proof.H
        // Note this is equal to swap_if_condition_true(is_left, H(""),child_proof.H)
        // hence we can do the first with a single poseidon call
        // h = Poseidon(left_hash || right_hash || node_min || node_max || index_id || index_value || cells_proof.H)
        let rest = node_min
            .to_targets()
            .iter()
            .chain(node_max.to_targets().iter())
            .chain(tuple.to_targets().iter())
            .chain(cells_pi.node_hash().to_targets().iter())
            .cloned()
            .collect::<Vec<_>>();
        //  if child at left, then hash should be child_proof.H || H("") || rest
        //  if child at right, then hash should be H("") || child_proof.H || rest
        let node_hash = hash_maybe_first(
            b,
            is_child_at_left,
            empty_hash.elements,
            child_pi.root_hash().elements,
            &rest,
        );

        // final_digest = HashToInt(mul_digest) * D(ind_digest)
        let (digest_ind, digest_mult) = tuple.split_and_accumulate_digest(b, &cells_pi);
        let digest_ind = b.map_to_curve_point(&digest_ind.to_targets());
        let row_digest = circuit_hashed_scalar_mul(b, digest_mult.to_targets(), digest_ind);

        let final_digest = b.curve_add(child_pi.rows_digest(), row_digest);
        PublicInputs::new(
            &node_hash,
            &final_digest.to_targets(),
            &node_min.to_targets(),
            &node_max.to_targets(),
        )
        .register(b);
        PartialNodeWires {
            tuple,
            is_child_at_left,
        }
    }

    fn assign(&self, pw: &mut PartialWitness<F>, wires: &PartialNodeWires) {
        self.tuple.assign_wires(pw, &wires.tuple);
        pw.set_bool_target(wires.is_child_at_left, self.is_child_at_left);
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct RecursivePartialWires {
    cells_verifier: RecursiveCircuitsVerifierTarget<D>,
    partial_wires: PartialNodeWires,
}

pub(crate) struct RecursivePartialInput {
    pub(crate) witness: PartialNodeCircuit,
    pub(crate) cells_proof: ProofWithVK,
    pub(crate) cells_set: RecursiveCircuits<F, C, D>,
}

pub(crate) const NUM_CHILDREN: usize = 1;
impl CircuitLogicWires<F, D, NUM_CHILDREN> for RecursivePartialWires {
    type CircuitBuilderParams = RecursiveCircuits<F, C, D>;

    type Inputs = RecursivePartialInput;

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
        let child_pi = Self::public_input_targets(verified_proofs[0]);
        RecursivePartialWires {
            // run the row leaf circuit just with the public inputs of the cells proof
            partial_wires: PartialNodeCircuit::build(builder, child_pi, cells_pi),
            cells_verifier: cells_verifier_gadget,
        }
    }

    fn assign_input(&self, inputs: Self::Inputs, pw: &mut PartialWitness<F>) -> anyhow::Result<()> {
        inputs.witness.assign(pw, &self.partial_wires);
        let (proof, vd) = inputs.cells_proof.into();
        self.cells_verifier
            .set_target(pw, &inputs.cells_set, &proof, &vd)
    }
}

#[cfg(test)]
pub mod test {
    use mp2_common::{
        group_hashing::{field_hashed_scalar_mul, map_to_curve_point},
        poseidon::empty_poseidon_hash,
        utils::ToFields,
        CHasher,
    };
    use plonky2::{hash::hash_types::HashOut, plonk::config::Hasher};
    use plonky2_ecgfp5::curve::curve::Point;

    use alloy::primitives::U256;
    use mp2_common::{C, D, F};
    use mp2_test::{
        circuit::{run_circuit, UserCircuit},
        utils::weierstrass_to_point,
    };
    use plonky2::{
        field::types::Sample,
        hash::hashing::hash_n_to_hash_no_pad,
        iop::{target::Target, witness::WitnessWrite},
        plonk::circuit_builder::CircuitBuilder,
    };

    use crate::{
        cells_tree::{self, Cell},
        row_tree::{
            full_node::test::generate_random_pi, partial_node::PartialNodeCircuit,
            public_inputs::PublicInputs,
        },
    };

    use super::PartialNodeWires;

    #[derive(Clone, Debug)]
    struct TestPartialNodeCircuit {
        child_pi: Vec<F>,
        cells_pi: Vec<F>,
        circuit: PartialNodeCircuit,
    }

    impl UserCircuit<F, D> for TestPartialNodeCircuit {
        type Wires = (PartialNodeWires, Vec<Target>, Vec<Target>);

        fn build(c: &mut CircuitBuilder<F, D>) -> Self::Wires {
            let child_pi = c.add_virtual_targets(PublicInputs::<Target>::TOTAL_LEN);
            let cells_pi = c.add_virtual_targets(cells_tree::PublicInputs::<Target>::TOTAL_LEN);
            let wires = PartialNodeCircuit::build(c, &child_pi, &cells_pi);
            (wires, child_pi, cells_pi)
        }

        fn prove(&self, pw: &mut plonky2::iop::witness::PartialWitness<F>, wires: &Self::Wires) {
            pw.set_target_arr(&wires.1, &self.child_pi);
            pw.set_target_arr(&wires.2, &self.cells_pi);
            self.circuit.assign(pw, &wires.0);
        }
    }

    #[test]
    fn partial_node_child_left() {
        partial_node_circuit(true)
    }
    #[test]
    fn partial_node_child_right() {
        partial_node_circuit(false)
    }

    pub fn partial_safety_check<T: Into<U256>>(
        child_min: T,
        child_max: T,
        node_value: U256,
        child_at_left: bool,
    ) {
        // max_left = left ? child_proof.max : index_value
        // min_right = left ? index_value : child_proof.min
        let (max_left, min_right) = match child_at_left {
            true => (child_max.into(), node_value),
            false => (node_value, child_min.into()),
        };
        assert!(max_left <= min_right);
    }

    fn partial_node_circuit(child_at_left: bool) {
        let is_multiplier = false;
        let tuple = Cell::new(F::rand(), U256::from(18), is_multiplier);
        let (child_min, child_max) = match child_at_left {
            true => (U256::from(10), U256::from(15)),
            false => (U256::from(20), U256::from(25)),
        };
        partial_safety_check(child_min, child_max, tuple.value, child_at_left);
        let node_circuit = PartialNodeCircuit::new(tuple.clone(), child_at_left);
        let child_pi = generate_random_pi(child_min.to(), child_max.to());
        let cells_point = Point::rand();
        let ind_cell_digest = cells_point.to_weierstrass().to_fields();
        let cells_hash = HashOut::rand().to_fields();
        let mul_cell_digest = Point::NEUTRAL.to_fields();
        let cells_pi_struct =
            cells_tree::PublicInputs::new(&cells_hash, &ind_cell_digest, &mul_cell_digest);
        let cells_pi = cells_pi_struct.to_vec();
        let test_circuit = TestPartialNodeCircuit {
            circuit: node_circuit,
            cells_pi: cells_pi.clone(),
            child_pi: child_pi.clone(),
        };
        let proof = run_circuit::<F, D, C, _>(test_circuit);
        let pi = PublicInputs::from_slice(&proof.public_inputs);
        // node_min = left ? child_proof.min : index_value
        // node_max = left ? index_value : child_proof.max
        let (node_min, node_max) = match child_at_left {
            true => (pi.min_value_u256(), tuple.value),
            false => (tuple.value, pi.max_value_u256()),
        };
        // Poseidon(p1.H || p2.H || node_min || node_max || index_id || index_value ||p.H)) as H
        let child_hash = PublicInputs::from_slice(&child_pi).root_hash_hashout();
        let empty_hash = empty_poseidon_hash();
        let input_hash = match child_at_left {
            true => [child_hash.to_fields(), empty_hash.to_fields()].concat(),
            false => [empty_hash.to_fields(), child_hash.to_fields()].concat(),
        };
        let inputs = input_hash
            .iter()
            .chain(node_min.to_fields().iter())
            .chain(node_max.to_fields().iter())
            .chain(tuple.to_fields().iter())
            .chain(cells_hash.iter())
            .cloned()
            .collect::<Vec<_>>();
        let hash = hash_n_to_hash_no_pad::<F, <CHasher as Hasher<F>>::Permutation>(&inputs);
        assert_eq!(hash, pi.root_hash_hashout());
        // final_digest = HashToInt(mul_digest) * D(ind_digest) + row_proof.digest()
        let (row_ind, row_mul) = tuple.split_and_accumulate_digest(&cells_pi_struct);
        let ind_final = map_to_curve_point(&row_ind.to_fields());
        let res = field_hashed_scalar_mul(row_mul.to_fields(), ind_final);
        // then adding with the rest of the rows digest, the other nodes
        let res =
            res + weierstrass_to_point(&PublicInputs::from_slice(&child_pi).rows_digest_field());
        assert_eq!(res.to_weierstrass(), pi.rows_digest_field());
    }
}
