//! The dummy circuit used for generating the proof of no provable indexing data

use super::{
    api::{FinalExtractionBuilderParams, NUM_IO},
    PublicInputs, DUMMY_METADATA_DIGEST_PREFIX,
};
use alloy::primitives::U256;
use anyhow::Result;
use derive_more::derive::Constructor;
use itertools::Itertools;
use mp2_common::{
    digest::Digest,
    group_hashing::CircuitBuilderGroupHashing,
    keccak::PACKED_HASH_LEN,
    public_inputs::PublicInputCommon,
    serialization::{deserialize, serialize},
    types::CBuilder,
    u256::{CircuitBuilderU256, UInt256Target, WitnessWriteU256},
    utils::{ToFields, ToTargets},
    D, F,
};
use plonky2::{
    iop::{
        target::{BoolTarget, Target},
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::proof::ProofWithPublicInputsTarget,
};
use plonky2_ecgfp5::gadgets::curve::{CircuitBuilderEcGFp5, CurveTarget, PartialWitnessCurve};
use recursion_framework::circuit_builder::CircuitLogicWires;
use serde::{Deserialize, Serialize};
use std::array;

#[derive(Clone, Debug, Constructor)]
pub struct DummyCircuit {
    /// Merge flag
    is_merge: bool,
    /// Block number
    block_number: U256,
    /// Packed block hash
    block_hash: [F; PACKED_HASH_LEN],
    /// Packed block hash of the previous block
    prev_block_hash: [F; PACKED_HASH_LEN],
    /// Metadata digest for the rows extracted
    /// This value can be computed outside of the circuit depending on the data source,
    /// the circuits don’t care how it is computed given that we are not proving the
    /// provenance of the data.
    metadata_digest: Digest,
    /// Row values digest of all the rows extracted
    /// This must corresponds to the value digest that will be re-computed when
    /// constructing the rows tree for the current block.
    row_digest: Digest,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DummyWires {
    #[serde(serialize_with = "serialize", deserialize_with = "deserialize")]
    is_merge: BoolTarget,
    block_number: UInt256Target,
    block_hash: [Target; PACKED_HASH_LEN],
    prev_block_hash: [Target; PACKED_HASH_LEN],
    #[serde(serialize_with = "serialize", deserialize_with = "deserialize")]
    metadata_digest: CurveTarget,
    #[serde(serialize_with = "serialize", deserialize_with = "deserialize")]
    row_digest: CurveTarget,
}

impl DummyCircuit {
    fn build(b: &mut CBuilder) -> DummyWires {
        let is_merge = b.add_virtual_bool_target_unsafe();
        let block_number = b.add_virtual_u256_unsafe();
        let [block_hash, prev_block_hash] = array::from_fn(|_| b.add_virtual_target_arr());
        let [metadata_digest, row_digest] = array::from_fn(|_| b.add_virtual_curve_target());

        // Add the prefix to the metadata digest to ensure the metadata digest
        // will keep track of whether we use this dummy circuit or not.
        let prefix = b.constants(&DUMMY_METADATA_DIGEST_PREFIX.to_fields());
        let inputs = prefix
            .into_iter()
            .chain(metadata_digest.to_targets())
            .collect_vec();
        let encoded_metadata_digest = b.map_to_curve_point(&inputs);

        PublicInputs::new(
            &block_hash,
            &prev_block_hash,
            &row_digest.to_targets(),
            &encoded_metadata_digest.to_targets(),
            &block_number.to_targets(),
            &[is_merge.target],
        )
        .register_args(b);

        DummyWires {
            is_merge,
            block_number,
            block_hash,
            prev_block_hash,
            metadata_digest,
            row_digest,
        }
    }

    fn assign(&self, pw: &mut PartialWitness<F>, wires: &DummyWires) {
        pw.set_bool_target(wires.is_merge, self.is_merge);
        pw.set_u256_target(&wires.block_number, self.block_number);
        [
            (wires.block_hash, self.block_hash),
            (wires.prev_block_hash, self.prev_block_hash),
        ]
        .iter()
        .for_each(|(t, v)| {
            pw.set_target_arr(t, v);
        });
        [
            (wires.metadata_digest, self.metadata_digest),
            (wires.row_digest, self.row_digest),
        ]
        .iter()
        .for_each(|(t, v)| {
            pw.set_curve_target(*t, v.to_weierstrass());
        });
    }
}

impl CircuitLogicWires<F, D, 0> for DummyWires {
    type CircuitBuilderParams = FinalExtractionBuilderParams;
    type Inputs = DummyCircuit;

    const NUM_PUBLIC_INPUTS: usize = NUM_IO;

    fn circuit_logic(
        builder: &mut CBuilder,
        _verified_proofs: [&ProofWithPublicInputsTarget<D>; 0],
        _builder_parameters: Self::CircuitBuilderParams,
    ) -> Self {
        DummyCircuit::build(builder)
    }

    fn assign_input(&self, inputs: Self::Inputs, pw: &mut PartialWitness<F>) -> Result<()> {
        inputs.assign(pw, self);
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use mp2_common::C;
    use mp2_test::circuit::{run_circuit, UserCircuit};

    impl UserCircuit<F, D> for DummyCircuit {
        type Wires = DummyWires;

        fn build(cb: &mut CBuilder) -> Self::Wires {
            DummyCircuit::build(cb)
        }

        fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
            self.assign(pw, wires);
        }
    }

    #[test]
    fn test_final_extraction_dummy_circuit() {
        /*
                let mut rng = thread_rng();

                let identifier = rng.gen::<u32>().to_field();
                let value = U256::from_limbs(rng.gen::<[u64; 4]>());
                let value_fields = value.to_fields();

                let test_circuit: LeafCircuit = Cell {
                    identifier,
                    value,
                    is_multiplier,
                }
                .into();

                let proof = run_circuit::<F, D, C, _>(test_circuit);
                let pi = PublicInputs::from_slice(&proof.public_inputs);
                // Check the node Poseidon hash
                {
                    let empty_hash = empty_poseidon_hash();
                    let inputs: Vec<_> = empty_hash
                        .elements
                        .iter()
                        .cloned()
                        .chain(empty_hash.elements)
                        .chain(iter::once(identifier))
                        .chain(value_fields.clone())
                        .collect();
                    let exp_hash = H::hash_no_pad(&inputs);

                    assert_eq!(pi.h, exp_hash.elements);
                }
                // Check the cells digest
                {
                    let inputs: Vec<_> = iter::once(identifier).chain(value_fields).collect();
                    let exp_digest = map_to_curve_point(&inputs).to_weierstrass();
                    match is_multiplier {
                        true => assert_eq!(pi.multiplier_digest_point(), exp_digest),
                        false => assert_eq!(pi.individual_digest_point(), exp_digest),
                    }
                }
        */
    }
}
