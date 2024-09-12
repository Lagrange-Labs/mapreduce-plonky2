use mp2_common::{
    default_config,
    group_hashing::{scalar_mul, CircuitBuilderGroupHashing},
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
use plonky2_ecgfp5::gadgets::curve::CircuitBuilderEcGFp5;
use recursion_framework::{
    circuit_builder::CircuitLogicWires,
    framework::{
        RecursiveCircuits, RecursiveCircuitsVerifierGagdet, RecursiveCircuitsVerifierTarget,
    },
};
use serde::{Deserialize, Serialize};

use crate::cells_tree::{self, accumulate_proof_digest, decide_digest_section};

use super::{public_inputs::PublicInputs, IndexTuple, IndexTupleWire};
use derive_more::{Constructor, Deref, From};

// new type to implement the circuit logic on each differently
// deref to access directly the same members - read only so it's ok
#[derive(Clone, Debug, Deref, From, Constructor)]
pub struct LeafCircuit(IndexTuple);

#[derive(Clone, Serialize, Deserialize, Deref, From)]
pub(crate) struct LeafWires(IndexTupleWire);

impl LeafCircuit {
    pub(crate) fn build(b: &mut CircuitBuilder<F, D>, cells_pis: &[Target]) -> LeafWires {
        let cells_pis = cells_tree::PublicInputs::from_slice(cells_pis);
        // D(index_id||pack_u32(index_value)
        let tuple = IndexTupleWire::new(b);
        let d1 = tuple.digest(b);
        let (digest_ind, digest_mult) = decide_digest_section(b, d1, tuple.is_multiplier);
        // final_digest = HashToInt(mul_digest) * D(ind_digest)
        let (digest_ind, digest_mult) =
            accumulate_proof_digest(b, digest_ind, digest_mult, cells_pis);
        let digest_ind = b.map_to_curve_point(&digest_ind.to_targets()).to_targets();
        let final_digest = scalar_mul(b, digest_mult, digest_ind);
        // H(left_child_hash,right_child_hash,min,max,index_identifier,index_value,cells_tree_hash)
        // in our case, min == max == index_value
        // left_child_hash == right_child_hash == empty_hash since there is not children
        let empty_hash = b.constant_hash(*empty_poseidon_hash());
        let inputs = empty_hash
            .to_targets()
            .iter()
            .chain(empty_hash.to_targets().iter())
            .chain(tuple.index_value.to_targets().iter())
            .chain(tuple.index_value.to_targets().iter())
            .chain(tuple.to_targets().iter())
            .chain(cells_pis.node_hash().to_targets().iter())
            .cloned()
            .collect::<Vec<_>>();
        let row_hash = b.hash_n_to_hash_no_pad::<H>(inputs);
        let value_fields = tuple.index_value.to_targets();
        PublicInputs::new(
            &row_hash.elements,
            &final_digest,
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
        group_hashing::map_to_curve_point, poseidon::empty_poseidon_hash, utils::ToFields, CHasher,
        C, D, F,
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
        cells_tree,
        row_tree::{public_inputs::PublicInputs, IndexTuple},
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

    #[test]
    fn test_row_tree_leaf_circuit() {
        let mut rng = thread_rng();
        let value = U256::from_limbs(rng.gen::<[u64; 4]>());
        let identifier = F::rand();
        let tuple = IndexTuple::new(identifier, value);
        let circuit = LeafCircuit::from(tuple.clone());
        let cells_point = Point::rand();
        let cells_digest = cells_point.to_weierstrass().to_fields();
        let cells_hash = HashOut::rand().to_fields();
        let cells_pi = cells_tree::PublicInputs::new(&cells_hash, &cells_digest).to_vec();
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
            .chain(tuple.index_value.to_fields().iter())
            .chain(tuple.index_value.to_fields().iter())
            .chain(tuple.to_fields().iter())
            .chain(cells_hash.iter())
            .cloned()
            .collect::<Vec<_>>();
        let row_hash = hash_n_to_hash_no_pad::<F, <CHasher as Hasher<F>>::Permutation>(&inputs);
        assert_eq!(row_hash, pi.root_hash_hashout());
        // D(proof.DC + D(index_id||pack_u32(index_value)))
        let inner = map_to_curve_point(&tuple.to_fields());
        let result_inner = inner + cells_point;
        let result = map_to_curve_point(&result_inner.to_weierstrass().to_fields());
        assert_eq!(result.to_weierstrass(), pi.rows_digest_field())
    }
}
