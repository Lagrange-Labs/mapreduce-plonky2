use ethers::types::U256;
use mp2_common::public_inputs::PublicInputCommon;
use mp2_common::u256::{UInt256Target, WitnessWriteU256};
use mp2_common::{
    group_hashing::CircuitBuilderGroupHashing, u256::CircuitBuilderU256, utils::ToTargets, D, F,
};
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::iop::target::Target;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::{hash::hash_types::HashOutTarget, plonk::circuit_builder::CircuitBuilder};
use plonky2_ecgfp5::gadgets::curve::CircuitBuilderEcGFp5;
use serde::{Deserialize, Serialize};
use std::array::from_fn as create_array;

use super::public_inputs::PublicInputs;

#[derive(Clone, Debug)]
struct LeafCircuit {
    /// secondary index value
    index_value: U256,
    /// identifier of the column for the secondary index
    index_identifier: F,
}

#[derive(Clone, Serialize, Deserialize)]
struct LeafWires {
    index_value: UInt256Target,
    index_identifier: Target,
}

impl LeafCircuit {
    pub(crate) fn new(index_identifier: F, index_value: U256) -> Self {
        Self {
            index_identifier,
            index_value,
        }
    }

    pub(crate) fn build(b: &mut CircuitBuilder<F, D>, _cells_pis: &[Target]) -> LeafWires {
        // D(index_id||pack_u32(index_value)
        let index_value = b.add_virtual_u256();
        let index_identifier = b.add_virtual_target();
        let inputs = std::iter::once(index_identifier)
            .chain(index_value.to_targets())
            .collect::<Vec<_>>();
        let d1 = b.map_to_curve_point(&inputs);
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
            .elements
            .to_vec()
            .iter()
            .chain(empty_hash.elements.to_vec().iter())
            .chain(index_value.to_targets().iter())
            .chain(index_value.to_targets().iter())
            .chain([index_identifier].iter())
            .chain(index_value.to_targets().iter())
            // TODO: replace via hash once cells tree is merged
            .chain(empty_hash.elements.to_vec().iter())
            .cloned()
            .collect::<Vec<_>>();
        let row_hash = b.hash_n_to_hash_no_pad::<PoseidonHash>(inputs);
        let value_fields = index_value.to_targets();
        PublicInputs::new(
            &row_hash.elements,
            &row_digest,
            &value_fields,
            &value_fields,
        )
        .register(b);
        LeafWires {
            index_value,
            index_identifier,
        }
    }

    fn assign(&self, pw: &mut PartialWitness<F>, wires: &LeafWires) {
        pw.set_u256_target(&wires.index_value, self.index_value);
        pw.set_target(wires.index_identifier, self.index_identifier);
    }
}

#[cfg(test)]
mod test {
    use ethers::types::U256;
    use mp2_common::{utils::ToFields, C, D, F};
    use mp2_test::circuit::{run_circuit, UserCircuit};
    use plonky2::field::types::Sample;
    use plonky2::plonk::circuit_builder::CircuitBuilder;
    use rand::{thread_rng, Rng};

    use crate::row_tree::public_inputs::PublicInputs;

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
        let circuit = LeafCircuit::new(identifier, value);
        let proof = run_circuit::<F, D, C, _>(circuit);
        let pi = PublicInputs::from_slice(&proof.public_inputs);
        assert_eq!(value, pi.max_value_field());
        assert_eq!(value, pi.min_value_field());
    }
}
