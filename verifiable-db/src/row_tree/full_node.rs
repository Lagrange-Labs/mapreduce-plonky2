use derive_more::{Deref, From};
use mp2_common::{
    group_hashing::CircuitBuilderGroupHashing, public_inputs::PublicInputCommon,
    u256::CircuitBuilderU256, utils::ToTargets, D, F, H,
};
use plonky2::{
    iop::{target::Target, witness::PartialWitness},
    plonk::{circuit_builder::CircuitBuilder, config::GenericConfig},
};
use plonky2_ecgfp5::gadgets::curve::CircuitBuilderEcGFp5;
use serde::{Deserialize, Serialize};

use super::{public_inputs::PublicInputs, IndexTuple, IndexTupleWire};
// Arity not strictly needed now but may be an easy way to increase performance
// easily down the line with less recursion. Best to provide code which is easily
// amenable to a different arity rather than hardcoding binary tree only
#[derive(Clone, Debug, From, Deref)]
pub struct FullNodeCircuit(IndexTuple);

#[derive(Clone, Serialize, Deserialize, From, Deref)]
struct FullNodeWires(IndexTupleWire);

impl FullNodeCircuit {
    pub(crate) fn build(
        b: &mut CircuitBuilder<F, D>,
        left_pi: &[Target],
        right_pi: &[Target],
        _cells_pi: &[Target],
    ) -> FullNodeWires {
        let min_child = PublicInputs::from_slice(left_pi);
        let max_child = PublicInputs::from_slice(right_pi);
        let tuple = IndexTupleWire::new(b);
        let node_min = min_child.min_value();
        let node_max = max_child.max_value();
        // enforcing BST property
        let _true = b._true();
        let left_comparison = b.is_less_than_u256(&min_child.max_value(), &tuple.index_value);
        let right_comparison = b.is_less_than_u256(&tuple.index_value, &max_child.min_value());
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
            .cloned()
            // TODO: hash of cell proof when merged
            //.chain(vec![])
            .collect::<Vec<_>>();
        let hash = b.hash_n_to_hash_no_pad::<H>(inputs);
        // expose p1.DR + p2.DR + D(p.DC + D(index_id || index_value)) as DR
        let inner = tuple.digest(b);
        // TODO once cell proof merged
        //let inner = inner + cells_pis.digest();
        let row_digest = b.map_to_curve_point(&inner.to_targets());
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
        self.assign_wires(pw, wires);
    }
}

#[cfg(test)]
pub(crate) mod test {
    use std::hash::Hash;

    use ethers::abi::ethereum_types::Public;
    use ethers::types::U256;
    use mp2_common::group_hashing::map_to_curve_point;
    use mp2_common::H;
    use mp2_common::{utils::ToFields, C, D, F};
    use mp2_test::circuit::{run_circuit, UserCircuit};
    use plonky2::hash::hash_types::HashOut;
    use plonky2::hash::hashing::hash_n_to_hash_no_pad;
    use plonky2::hash::poseidon::{self, PoseidonHash, PoseidonPermutation};
    use plonky2::iop::witness::{PartialWitness, WitnessWrite};
    use plonky2::plonk::circuit_builder::CircuitBuilder;
    use plonky2::{field::types::Sample, iop::target::Target};
    use plonky2_ecgfp5::curve::curve::{Point, WeierstrassPoint};
    use rand::Rng;

    use crate::row_tree::public_inputs::PublicInputs;
    use crate::row_tree::IndexTuple;

    use super::{FullNodeCircuit, FullNodeWires};

    #[derive(Clone, Debug)]
    struct TestFullNodeCircuit {
        circuit: FullNodeCircuit,
        left_pi: Vec<F>,
        right_pi: Vec<F>,
    }

    impl UserCircuit<F, D> for TestFullNodeCircuit {
        type Wires = (FullNodeWires, Vec<Target>, Vec<Target>);

        fn build(c: &mut CircuitBuilder<F, D>) -> Self::Wires {
            // TODO: change that once cells tree merged
            let cells_pi = [c.add_virtual_target()];
            let left_pi = c.add_virtual_targets(PublicInputs::<Target>::TOTAL_LEN);
            let right_pi = c.add_virtual_targets(PublicInputs::<Target>::TOTAL_LEN);
            (
                FullNodeCircuit::build(c, &left_pi, &right_pi, &cells_pi),
                left_pi,
                right_pi,
            )
        }

        fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
            self.circuit.assign(pw, &wires.0);
            pw.set_target_arr(&wires.1, &self.left_pi);
            pw.set_target_arr(&wires.2, &self.right_pi);
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

    fn weierstrass_to_point(w: &WeierstrassPoint) -> Point {
        Point::decode(w.encode()).unwrap()
    }

    #[test]
    fn test_row_tree_leaf_circuit() {
        let (left_min, left_max) = (10, 15);
        let (right_min, right_max) = (23, 30);
        let value = U256::from(18); // 15 < 18 < 23
        let identifier = F::rand();
        let tuple = IndexTuple::new(identifier, value);
        let node_circuit = FullNodeCircuit::from(tuple.clone());
        let left_pi = generate_random_pi(left_min, left_max);
        let right_pi = generate_random_pi(right_min, right_max);
        let test_circuit = TestFullNodeCircuit {
            circuit: node_circuit,
            left_pi: left_pi.clone(),
            right_pi: right_pi.clone(),
        };
        let proof = run_circuit::<F, D, C, _>(test_circuit);
        let pi = PublicInputs::from_slice(&proof.public_inputs);
        assert_eq!(U256::from(left_min), pi.min_value_u256());
        assert_eq!(U256::from(right_max), pi.max_value_u256());
        // TODO replace by singler Hasher implementation for cells
        // Poseidon(p1.H || p2.H || node_min || node_max || index_id || index_value ||p.H)) as H
        let left_hash = PublicInputs::from_slice(&left_pi).root_hash_hashout();
        let right_hash = PublicInputs::from_slice(&right_pi).root_hash_hashout();
        let inputs = left_hash
            .to_fields()
            .iter()
            .chain(right_hash.to_fields().iter())
            .chain(pi.min_value_u256().to_fields().iter())
            .chain(pi.max_value_u256().to_fields().iter())
            .chain(IndexTuple::new(identifier, value).to_fields().iter())
            .cloned()
            .collect::<Vec<_>>();
        // TODO add cells tree hash once ready
        // TODO: replace by common H
        let hash = hash_n_to_hash_no_pad::<F, PoseidonPermutation<F>>(&inputs);
        assert_eq!(hash, pi.root_hash_hashout());

        // expose p1.DR + p2.DR + D(p.DC + D(index_id || index_value)) as DR
        let inner = map_to_curve_point(&tuple.to_fields());
        let outer = map_to_curve_point(&inner.to_weierstrass().to_fields());
        let p1dr = weierstrass_to_point(&PublicInputs::from_slice(&left_pi).rows_digest_field());
        let p2dr = weierstrass_to_point(&PublicInputs::from_slice(&right_pi).rows_digest_field());
        let result_digest = p1dr + p2dr + outer;
        assert_eq!(result_digest.to_weierstrass(), pi.rows_digest_field());
    }
}
