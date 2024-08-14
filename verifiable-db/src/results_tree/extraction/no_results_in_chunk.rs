use crate::results_tree::extraction::PublicInputs;
use alloy::primitives::U256;
use mp2_common::{
    public_inputs::PublicInputCommon,
    serialization::{deserialize, serialize},
    types::CBuilder,
    u256::CircuitBuilderU256,
    utils::{greater_than, ToTargets},
    D, F,
};
use plonky2::{
    hash::hash_types::{HashOut, HashOutTarget},
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::proof::ProofWithPublicInputsTarget,
};
use plonky2_ecgfp5::gadgets::curve::CircuitBuilderEcGFp5;
use recursion_framework::circuit_builder::CircuitLogicWires;
use serde::{Deserialize, Serialize};
use std::iter;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NoResultsInChunkWires {
    num_records: Target,
    #[serde(serialize_with = "serialize", deserialize_with = "deserialize")]
    results_tree_hash: HashOutTarget,
    offset_range_min: Target,
    offset_range_max: Target,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NoResultsInChunkCircuit {
    /// Number of records in the results tree
    pub(crate) num_records: F,
    /// Hash of the results tree
    pub(crate) results_tree_hash: HashOut<F>,
    /// Minimum offset range bound
    pub(crate) offset_range_min: F,
    /// Maximum offset range bound
    pub(crate) offset_range_max: F,
}

impl NoResultsInChunkCircuit {
    pub fn build(b: &mut CBuilder) -> NoResultsInChunkWires {
        let zero_u256 = b.zero_u256();
        let curve_zero = b.curve_zero();
        let one = b.one();
        let ttrue = b._true();

        let num_records = b.add_virtual_target();
        let results_tree_hash = b.add_virtual_hash();
        let [offset_range_min, offset_range_max] = b.add_virtual_target_arr();

        // Ensure that the query is asking to retrieve results with an offset
        // being greater than the overall number of results
        let is_greater = greater_than(b, offset_range_min, num_records, 32);
        b.connect(is_greater.target, ttrue.target);

        // Register the public inputs.
        PublicInputs::new(
            &results_tree_hash.to_targets(),
            &zero_u256.to_targets(),
            &zero_u256.to_targets(),
            &zero_u256.to_targets(),
            &[one; 2],
            &[one],
            &[num_records],
            &[offset_range_min],
            &[offset_range_max],
            &curve_zero.to_targets(),
        )
        .register(b);

        NoResultsInChunkWires {
            num_records,
            results_tree_hash,
            offset_range_min,
            offset_range_max,
        }
    }

    fn assign(&self, pw: &mut PartialWitness<F>, wires: &NoResultsInChunkWires) {
        pw.set_target(wires.num_records, self.num_records);
        pw.set_hash_target(wires.results_tree_hash, self.results_tree_hash);
        pw.set_target(wires.offset_range_min, self.offset_range_min);
        pw.set_target(wires.offset_range_max, self.offset_range_max);
    }
}

/// Verified proof number = 0
pub(crate) const NUM_VERIFIED_PROOFS: usize = 0;

impl CircuitLogicWires<F, D, NUM_VERIFIED_PROOFS> for NoResultsInChunkWires {
    type CircuitBuilderParams = ();
    type Inputs = NoResultsInChunkCircuit;

    const NUM_PUBLIC_INPUTS: usize = PublicInputs::<F>::total_len();

    fn circuit_logic(
        builder: &mut CBuilder,
        _verified_proofs: [&ProofWithPublicInputsTarget<D>; NUM_VERIFIED_PROOFS],
        _builder_parameters: Self::CircuitBuilderParams,
    ) -> Self {
        Self::Inputs::build(builder)
    }

    fn assign_input(&self, inputs: Self::Inputs, pw: &mut PartialWitness<F>) -> anyhow::Result<()> {
        inputs.assign(pw, self);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mp2_common::C;
    use mp2_test::{
        circuit::{run_circuit, UserCircuit},
        utils::gen_random_field_hash,
    };
    use plonky2::field::types::Field;
    use plonky2_ecgfp5::curve::curve::WeierstrassPoint;
    use rand::{thread_rng, Rng};

    impl UserCircuit<F, D> for NoResultsInChunkCircuit {
        type Wires = NoResultsInChunkWires;

        fn build(b: &mut CBuilder) -> Self::Wires {
            NoResultsInChunkCircuit::build(b)
        }

        fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
            self.assign(pw, wires);
        }
    }

    #[test]
    fn test_no_results_in_chunk_circuit() {
        // Construct the witness.
        let mut rng = thread_rng();
        let num_records = F::from_canonical_u32(rng.gen());
        let results_tree_hash = gen_random_field_hash();
        let offset_range_min = num_records + F::ONE;
        let offset_range_max = offset_range_min + F::from_canonical_u32(rng.gen());

        // Construct the circuit.
        let test_circuit = NoResultsInChunkCircuit {
            num_records,
            results_tree_hash,
            offset_range_min,
            offset_range_max,
        };

        // Proof for the test circuit.
        let proof = run_circuit::<F, D, C, _>(test_circuit);
        let pi = PublicInputs::from_slice(&proof.public_inputs);

        // Check the public inputs.
        // Tree hash
        assert_eq!(pi.tree_hash(), results_tree_hash);

        // Min value
        assert_eq!(pi.min_value(), U256::ZERO);

        // Max value
        assert_eq!(pi.max_value(), U256::ZERO);

        // Primary index value
        assert_eq!(pi.primary_index_value(), U256::ZERO);

        // Index ids
        assert_eq!(pi.index_ids(), [F::ONE; 2]);

        // Min counter
        assert_eq!(pi.min_counter(), F::ONE);

        // Max counter
        assert_eq!(pi.max_counter(), num_records);

        // Offset range min
        assert_eq!(pi.offset_range_min(), offset_range_min);

        // Offset range max
        assert_eq!(pi.offset_range_max(), offset_range_max);

        // Accumulator
        assert_eq!(pi.accumulator(), WeierstrassPoint::NEUTRAL);
    }
}
