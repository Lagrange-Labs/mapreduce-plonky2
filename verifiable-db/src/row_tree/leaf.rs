use mp2_common::{
    default_config,
    group_hashing::CircuitBuilderGroupHashing,
    poseidon::{H, P},
    proof::ProofWithVK,
    public_inputs::PublicInputCommon,
    serialization::{deserialize, serialize},
    u256::{CircuitBuilderU256, UInt256Target, WitnessWriteU256},
    utils::ToTargets,
    C, D, F,
};
use plonky2::{
    hash::{hash_types::HashOutTarget, poseidon::PoseidonHash},
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::VerifierCircuitData,
        config::GenericConfig,
        proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget},
    },
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

use crate::{cells_tree, row_tree};

use super::{
    public_inputs::{PublicInputs, TOTAL_LEN},
    IndexTuple, IndexTupleWire,
};
use derive_more::{Constructor, Deref, From};

// new type to implement the circuit logic on each differently
// deref to access directly the same members - read only so it's ok
#[derive(Clone, Debug, Deref, From, Constructor)]
pub(crate) struct LeafCircuit(IndexTuple);

#[derive(Clone, Serialize, Deserialize, Deref, From)]
pub(crate) struct LeafWires(IndexTupleWire);

impl LeafCircuit {
    pub(crate) fn build(b: &mut CircuitBuilder<F, D>, cells_pis: &[Target]) -> LeafWires {
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

#[derive(Serialize, Deserialize)]
pub(crate) struct RecursiveLeafWires {
    cells_verifier: RecursiveCircuitsVerifierTarget<D>,
    leaf_wires: LeafWires,
}

///  Circuit input that contains the  local witness value
///  as well as the cells proof to verify
#[derive(Clone, Debug)]
pub struct RecursiveLeafInput {
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
        const ROWS_IO: usize = super::public_inputs::PublicInputs::<Target>::TOTAL_LEN;
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
    use std::array::from_fn as create_array;

    use ethers::types::U256;
    use mp2_common::{group_hashing::map_to_curve_point, utils::ToFields, C, D, F};
    use mp2_test::circuit::{run_circuit, UserCircuit};
    use plonky2::{
        field::types::{Field, Sample},
        hash::{
            hash_types::HashOut, hashing::hash_n_to_hash_no_pad, poseidon::PoseidonPermutation,
        },
        plonk::circuit_builder::CircuitBuilder,
    };
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
