use plonky2::{
    hash::poseidon::PoseidonHash,
    plonk::{config::AlgebraicHasher, proof::ProofWithPublicInputsTarget},
};

use mp2_common::{
    default_config,
    group_hashing::CircuitBuilderGroupHashing,
    poseidon::{empty_poseidon_hash, H, P},
    proof::ProofWithVK,
    public_inputs::PublicInputCommon,
    serialization::{deserialize, serialize},
    u256::CircuitBuilderU256,
    utils::ToTargets,
    C, D, F,
};
use plonky2::{
    hash::{
        hash_types::{HashOutTarget, NUM_HASH_OUT_ELTS},
        hashing::PlonkyPermutation,
    },
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

use crate::cells_tree;

use super::{public_inputs::PublicInputs, IndexTuple, IndexTupleWire};

#[derive(Clone, Debug)]
pub struct PartialNodeCircuit {
    tuple: IndexTuple,
    is_child_at_left: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct PartialNodeWires {
    tuple: IndexTupleWire,
    #[serde(serialize_with = "serialize", deserialize_with = "deserialize")]
    is_child_at_left: BoolTarget,
}

impl PartialNodeCircuit {
    pub(crate) fn new(tuple: IndexTuple, is_child_at_left: bool) -> Self {
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
        let cells_pi = cells_tree::PublicInputs::from_slice(&cells_pi);
        let tuple = IndexTupleWire::new(b);
        let is_child_at_left = b.add_virtual_bool_target_safe();
        let child_pi = PublicInputs::from_slice(child_pi);
        // max_left = left ? child_proof.max : index_value
        // min_right = left ? index_value : child_proof.min
        let max_left = b.select_u256(is_child_at_left, &child_pi.max_value(), &tuple.index_value);
        let min_right = b.select_u256(is_child_at_left, &tuple.index_value, &child_pi.min_value());
        let bst_enforced = b.is_less_than_u256(&max_left, &min_right);
        let _true = b._true();
        b.connect(bst_enforced.target, _true.target);
        // node_min = left ? child_proof.min : index_value
        // node_max = left ? index_value : child_proof.max
        let node_min = b.select_u256(is_child_at_left, &child_pi.min_value(), &tuple.index_value);
        let node_max = b.select_u256(is_child_at_left, &tuple.index_value, &child_pi.max_value());

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
        let node_hash = hash_maybe_first(
            b,
            is_child_at_left,
            empty_hash.elements,
            child_pi.root_hash().elements,
            &rest,
        );
        // child_proof.DR + D(cells_proof.DC + D(index_id || index_value))
        let inner = tuple.digest(b);
        let inner2 = b.curve_add(inner, cells_pi.digest_target());
        let outer = b.map_to_curve_point(&inner2.to_targets());
        let result = b.curve_add(child_pi.rows_digest(), outer);
        PublicInputs::new(
            &node_hash,
            &result.to_targets(),
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
        const ROWS_IO: usize = super::public_inputs::PublicInputs::<Target>::TOTAL_LEN;
        let verifier_gadget = RecursiveCircuitsVerifierGagdet::<F, C, D, CELLS_IO>::new(
            default_config(),
            &builder_parameters,
        );
        let cells_verifier_gadget = verifier_gadget.verify_proof_in_circuit_set(builder);
        let cells_pi = cells_verifier_gadget.get_public_input_targets::<F, CELLS_IO>();
        let child_pi = verified_proofs[0].public_inputs.as_slice();
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

// maybe swap the first two elements and hashes the rest after with it
fn hash_maybe_first(
    c: &mut CircuitBuilder<F, D>,
    should_swap: BoolTarget,
    elem1: [Target; NUM_HASH_OUT_ELTS],
    elem2: [Target; NUM_HASH_OUT_ELTS],
    rest: &[Target],
) -> Vec<Target> {
    let zero = c.zero();
    let mut state = P::new(core::iter::repeat(zero));
    // absorb the first two inputs and do the swap
    state.set_from_slice(&[elem1, elem2].concat(), 0);
    state = H::permute_swapped(state, should_swap, c);
    // Absorb all the rest of the input chunks.
    let t = c._false();
    for input_chunk in rest.chunks(P::RATE) {
        state.set_from_slice(input_chunk, 0);
        state = H::permute_swapped(state, t, c);
    }

    // Squeeze until we have the desired number of outputs.
    let mut outputs = Vec::new();
    loop {
        for &item in state.squeeze() {
            outputs.push(item);
            if outputs.len() == NUM_HASH_OUT_ELTS {
                return outputs;
            }
        }
        state.permute();
    }
}

#[cfg(test)]
mod test {
    use mp2_common::{
        group_hashing::map_to_curve_point, poseidon::empty_poseidon_hash, utils::ToFields,
    };
    use plonky2::{field::types::Field, hash::hash_types::HashOut};
    use plonky2_ecgfp5::curve::curve::Point;
    use std::{array::from_fn as create_array, cell};

    use ethers::types::U256;
    use mp2_common::{C, D, F};
    use mp2_test::circuit::{run_circuit, UserCircuit};
    use plonky2::{
        field::types::Sample,
        hash::{
            hash_types::NUM_HASH_OUT_ELTS, hashing::hash_n_to_hash_no_pad,
            poseidon::PoseidonPermutation,
        },
        iop::{
            target::{BoolTarget, Target},
            witness::WitnessWrite,
        },
        plonk::circuit_builder::CircuitBuilder,
    };

    use crate::{
        cells_tree,
        row_tree::{
            full_node::test::generate_random_pi, partial_node::PartialNodeCircuit,
            public_inputs::PublicInputs, IndexTuple,
        },
    };

    use super::{hash_maybe_first, PartialNodeWires};

    const REST: usize = 7;
    #[derive(Debug, Clone)]
    struct TestPartialSwap {
        elem1: Vec<F>,
        elem2: Vec<F>,
        should_swap: bool,
        rest: Vec<F>,
    }

    impl UserCircuit<F, D> for TestPartialSwap {
        type Wires = (Vec<Target>, Vec<Target>, BoolTarget, Vec<Target>);

        fn build(c: &mut CircuitBuilder<F, D>) -> Self::Wires {
            let elem1 = c.add_virtual_targets(NUM_HASH_OUT_ELTS);
            let elem2 = c.add_virtual_targets(NUM_HASH_OUT_ELTS);
            let cond = c.add_virtual_bool_target_safe();
            let rest = c.add_virtual_targets(REST);
            let hash = hash_maybe_first(
                c,
                cond,
                elem1.clone().try_into().unwrap(),
                elem2.clone().try_into().unwrap(),
                &rest,
            );
            c.register_public_inputs(&hash);
            (elem1, elem2, cond, rest)
        }

        fn prove(&self, pw: &mut plonky2::iop::witness::PartialWitness<F>, wires: &Self::Wires) {
            pw.set_target_arr(&wires.0, &self.elem1);
            pw.set_target_arr(&wires.1, &self.elem2);
            pw.set_bool_target(wires.2, self.should_swap);
            pw.set_target_arr(&wires.3, &self.rest);
        }
    }

    #[test]
    fn test_partial_swap() {
        let elem1 = (0..NUM_HASH_OUT_ELTS)
            .map(|_| F::rand())
            .collect::<Vec<_>>();
        let elem2 = (0..NUM_HASH_OUT_ELTS)
            .map(|_| F::rand())
            .collect::<Vec<_>>();
        let rest = (0..REST).map(|_| F::rand()).collect::<Vec<_>>();
        for should_swap in [true, false] {
            let circuit = TestPartialSwap {
                elem1: elem1.clone(),
                elem2: elem2.clone(),
                should_swap,
                rest: rest.clone(),
            };
            let proof = run_circuit::<F, D, C, _>(circuit);
            let pi = proof.public_inputs;
            // do it outside circuit
            let tuple = match should_swap {
                false => [elem1.clone(), elem2.clone()].concat(),
                true => [elem2.clone(), elem1.clone()].concat(),
            };
            let inputs = tuple.iter().chain(rest.iter()).cloned().collect::<Vec<_>>();
            let hash = hash_n_to_hash_no_pad::<F, PoseidonPermutation<F>>(&inputs);
            assert_eq!(&hash.elements.as_slice(), &pi.as_slice());
        }
    }

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
    fn test_partial_node_circuit() {
        let (child_min, child_max) = (10, 15);
        let value = U256::from(18); // 15 < 18 < 23
        let identifier = F::rand();
        let child_at_left = true; // because node value is less than max of left child
        let tuple = IndexTuple::new(identifier, value);
        let node_circuit = PartialNodeCircuit::new(tuple.clone(), child_at_left);
        let child_pi = generate_random_pi(child_min, child_max);
        let cells_point = Point::rand();
        let cells_digest = cells_point.to_weierstrass().to_fields();
        let cells_hash = HashOut::rand().to_fields();
        let cells_pi = cells_tree::PublicInputs::new(&cells_hash, &cells_digest).to_vec();
        let test_circuit = TestPartialNodeCircuit {
            circuit: node_circuit,
            cells_pi: cells_pi.clone(),
            child_pi: child_pi.clone(),
        };
        let proof = run_circuit::<F, D, C, _>(test_circuit);
        let pi = PublicInputs::from_slice(&proof.public_inputs);
        let (min, max) = match child_at_left {
            true => {
                assert_eq!(U256::from(child_min), pi.min_value_u256());
                assert_eq!(value, pi.max_value_u256());
                (pi.min_value_u256(), value)
            }
            false => {
                assert_eq!(value, pi.min_value_u256());
                assert_eq!(U256::from(child_min), pi.max_value_u256());
                (value, pi.min_value_u256())
            }
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
            .chain(min.to_fields().iter())
            .chain(max.to_fields().iter())
            .chain(tuple.to_fields().iter())
            .chain(cells_hash.iter())
            .cloned()
            .collect::<Vec<_>>();
        let hash = hash_n_to_hash_no_pad::<F, PoseidonPermutation<F>>(&inputs);
        assert_eq!(hash, pi.root_hash_hashout());
        // child_proof.DR + D(cells_proof.DC + D(index_id || index_value)) as DR
        let inner = map_to_curve_point(&tuple.to_fields());
        let inner2 = inner + cells_point;
        let outer = map_to_curve_point(&inner2.to_weierstrass().to_fields());
        let res = Point::decode(
            PublicInputs::from_slice(&child_pi)
                .rows_digest_field()
                .encode(),
        )
        .unwrap()
            + outer;
        assert_eq!(res.to_weierstrass(), pi.rows_digest_field());
    }
}
