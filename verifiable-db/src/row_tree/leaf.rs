use ethers::types::U256;
use mp2_common::public_inputs::PublicInputCommon;
use mp2_common::u256::{UInt256Target, WitnessWriteU256};
use mp2_common::{
    group_hashing::CircuitBuilderGroupHashing, u256::CircuitBuilderU256, utils::ToTargets, D, F,
};
use mp2_common::{C, H};
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::iop::target::Target;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::config::GenericConfig;
use plonky2::{hash::hash_types::HashOutTarget, plonk::circuit_builder::CircuitBuilder};
use plonky2_ecgfp5::gadgets::curve::CircuitBuilderEcGFp5;
use serde::{Deserialize, Serialize};
use std::array::from_fn as create_array;

use super::public_inputs::PublicInputs;
use super::{IndexTuple, IndexTupleWire};
use derive_more::{Constructor, Deref, From};

// new type to implement the circuit logic on each differently
// deref to access directly the same members - read only so it's ok
#[derive(Clone, Debug, Deref, From, Constructor)]
pub struct LeafCircuit(IndexTuple);

#[derive(Clone, Serialize, Deserialize, Deref, From)]
struct LeafWires(IndexTupleWire);

impl LeafCircuit {
    pub(crate) fn build(b: &mut CircuitBuilder<F, D>, _cells_pis: &[Target]) -> LeafWires {
        // D(index_id||pack_u32(index_value)
        let tuple = IndexTupleWire::new(b);
        let d1 = tuple.digest(b);
        // D(proof.DC + D(index_id||pack_u32(index_value)))
        // TODO: replace once cells tree public inputs is merged
        let cells_digest = b.curve_zero();
        let input_digest = b.curve_add(cells_digest, d1);
        let row_digest = b
            .map_to_curve_point(&input_digest.to_targets())
            .to_targets();
        // TODO: replace with const from cells tree that hash empty string
        let zero = b.zero();
        let empty_hash = HashOutTarget {
            elements: create_array(|_| zero),
        };
        // H(left_child_hash,right_child_hash,min,max,index_identifier,index_value,cells_tree_hash)
        // in our case, min == max == index_value
        let inputs = empty_hash
            .to_targets()
            .iter()
            .chain(empty_hash.to_targets().iter())
            .chain(tuple.index_value.to_targets().iter())
            .chain(tuple.index_value.to_targets().iter())
            .chain(tuple.to_targets().iter())
            // TODO: replace via hash once cells tree is merged
            .chain(empty_hash.to_targets().iter())
            .cloned()
            .collect::<Vec<_>>();
        let row_hash = b.hash_n_to_hash_no_pad::<H>(inputs);
        let value_fields = tuple.index_value.to_targets();
        PublicInputs::new(
            &row_hash.elements,
            &row_digest,
            &value_fields,
            &value_fields,
        )
        .register(b);
        LeafWires(tuple)
    }

    fn assign(&self, pw: &mut PartialWitness<F>, wires: &LeafWires) {
        self.0.assign_wires(pw, wires);
    }
}

#[cfg(test)]
mod test {
    use std::array::from_fn as create_array;

    use ethers::types::U256;
    use mp2_common::group_hashing::map_to_curve_point;
    use mp2_common::utils::ToFields;
    use mp2_common::{C, D, F};
    use mp2_test::circuit::{run_circuit, UserCircuit};
    use plonky2::field::types::Field;
    use plonky2::hash::hashing::hash_n_to_hash_no_pad;
    use plonky2::hash::poseidon::PoseidonPermutation;
    use plonky2::plonk::circuit_builder::CircuitBuilder;
    use plonky2::{field::types::Sample, hash::hash_types::HashOut};
    use plonky2_ecgfp5::curve::curve::Point;
    use rand::{thread_rng, Rng};

    use crate::row_tree::{public_inputs::PublicInputs, IndexTuple};

    use super::{LeafCircuit, LeafWires};

    impl UserCircuit<F, D> for LeafCircuit {
        type Wires = LeafWires;

        fn build(c: &mut CircuitBuilder<F, D>) -> Self::Wires {
            // TODO: change that once cells tree merged
            let cells_pi = [c.add_virtual_target()];
            LeafCircuit::build(c, &cells_pi)
        }

        fn prove(&self, pw: &mut plonky2::iop::witness::PartialWitness<F>, wires: &Self::Wires) {
            self.assign(pw, wires);
        }
    }

    #[test]
    fn test_row_tree_leaf_circuit() {
        let mut rng = thread_rng();
        let value = U256::from(rng.gen::<[u8; 32]>());
        let identifier = F::rand();
        let tuple = IndexTuple::new(identifier, value);
        let circuit = LeafCircuit::from(tuple.clone());
        let proof = run_circuit::<F, D, C, _>(circuit);
        let pi = PublicInputs::from_slice(&proof.public_inputs);
        assert_eq!(value, pi.max_value_u256());
        assert_eq!(value, pi.min_value_u256());
        let empty_hash = HashOut {
            elements: create_array(|_| F::ZERO),
        };
        let inputs = empty_hash
            .to_fields()
            .iter()
            .chain(empty_hash.to_fields().iter())
            .chain(tuple.index_value.to_fields().iter())
            .chain(tuple.index_value.to_fields().iter())
            .chain(tuple.to_fields().iter())
            .chain(empty_hash.to_fields().iter())
            .cloned()
            .collect::<Vec<_>>();
        let row_hash = hash_n_to_hash_no_pad::<F, PoseidonPermutation<F>>(&inputs);
        assert_eq!(row_hash, pi.root_hash_hashout());
        // D(proof.DC + D(index_id||pack_u32(index_value)))
        let cells_digest = Point::NEUTRAL;
        let inner = map_to_curve_point(&tuple.to_fields());
        let result_inner = inner + cells_digest;
        let result = map_to_curve_point(&result_inner.to_weierstrass().to_fields());
        assert_eq!(result.to_weierstrass(), pi.rows_digest_field())
    }
}
