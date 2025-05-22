//! The dummy circuit used for generating the proof of no provable indexing data

use super::{
    api::{FinalExtractionBuilderParams, NUM_IO},
    PublicInputs, DUMMY_METADATA_DIGEST_PREFIX,
};
use crate::{CBuilder, D, F};
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
    u256::{CircuitBuilderU256, UInt256Target, WitnessWriteU256},
    utils::{ToFields, ToTargets},
};
use plonky2::{
    field::{extension::quintic::QuinticExtension, goldilocks_field::GoldilocksField},
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::proof::ProofWithPublicInputsTarget,
};
use plonky2_ecgfp5::gadgets::curve::{CircuitBuilderEcGFp5, CurveTarget, PartialWitnessCurve};
use recursion_framework::circuit_builder::CircuitLogicWires;
use serde::{de::Error, Deserialize, Deserializer, Serialize, Serializer};
use std::array;

fn to_quintic<S>(digest: &Digest, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    digest.encode().serialize(serializer)
}

fn from_quintic<'de, D>(deserializer: D) -> Result<Digest, D::Error>
where
    D: Deserializer<'de>,
{
    let quintic = QuinticExtension::<GoldilocksField>::deserialize(deserializer)?;
    Digest::decode(quintic).ok_or(D::Error::custom("Invalid quintic"))
}

#[derive(Clone, Debug, Constructor, Serialize, Deserialize)]
pub struct DummyCircuit {
    /// Block number
    primary_index: U256,
    /// Packed block hash
    root_of_trust: [F; PACKED_HASH_LEN],
    /// Packed block hash of the previous block
    prev_root_of_trust: [F; PACKED_HASH_LEN],
    /// Metadata digest for the rows extracted
    /// This value can be computed outside of the circuit depending on the data source,
    /// the circuits don’t care how it is computed given that we are not proving the
    /// provenance of the data.
    #[serde(serialize_with = "to_quintic", deserialize_with = "from_quintic")]
    metadata_digest: Digest,
    /// Row values digest of all the rows extracted
    /// This must corresponds to the value digest that will be re-computed when
    /// constructing the rows tree for the current block.
    #[serde(serialize_with = "to_quintic", deserialize_with = "from_quintic")]
    row_digest: Digest,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DummyWires {
    primary_index: UInt256Target,
    root_of_trust: [Target; PACKED_HASH_LEN],
    prev_root_of_trust: [Target; PACKED_HASH_LEN],
    #[serde(serialize_with = "serialize", deserialize_with = "deserialize")]
    metadata_digest: CurveTarget,
    #[serde(serialize_with = "serialize", deserialize_with = "deserialize")]
    row_digest: CurveTarget,
}

impl DummyCircuit {
    fn build(b: &mut CBuilder) -> DummyWires {
        let primary_index = b.add_virtual_u256_unsafe();
        let [root_of_trust, prev_root_of_trust] = array::from_fn(|_| b.add_virtual_target_arr());
        let [metadata_digest, row_digest] = array::from_fn(|_| b.add_virtual_curve_target());

        // Add the prefix to the metadata digest to ensure the metadata digest
        // will keep track of whether we use this dummy circuit or not.
        let prefix = b.constants(&DUMMY_METADATA_DIGEST_PREFIX.to_fields());
        let inputs = prefix
            .into_iter()
            .chain(metadata_digest.to_targets())
            .collect_vec();
        let encoded_metadata_digest = b.map_to_curve_point(&inputs);

        let _false = b._false();

        PublicInputs::new(
            &root_of_trust,
            &prev_root_of_trust,
            &row_digest.to_targets(),
            &encoded_metadata_digest.to_targets(),
            &primary_index.to_targets(),
            &[_false.target],
        )
        .register_args(b);

        DummyWires {
            primary_index,
            root_of_trust,
            prev_root_of_trust,
            metadata_digest,
            row_digest,
        }
    }

    fn assign(&self, pw: &mut PartialWitness<F>, wires: &DummyWires) {
        pw.set_u256_target(&wires.primary_index, self.primary_index);
        [
            (wires.root_of_trust, self.root_of_trust),
            (wires.prev_root_of_trust, self.prev_root_of_trust),
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
    use crate::C;
    use mp2_common::group_hashing::map_to_curve_point;
    use mp2_test::circuit::{run_circuit, UserCircuit};
    use plonky2::field::types::Sample;
    use rand::{thread_rng, Rng};

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
        let rng = &mut thread_rng();

        let primary_index = U256::from(rng.gen::<u64>());
        let [root_of_trust, prev_root_of_trust] = array::from_fn(|_| F::rand_array());
        let [metadata_digest, row_digest] = array::from_fn(|_| Digest::sample(rng));

        let test_circuit = DummyCircuit::new(
            primary_index,
            root_of_trust,
            prev_root_of_trust,
            metadata_digest,
            row_digest,
        );

        let proof = run_circuit::<F, D, C, _>(test_circuit);
        let pi = PublicInputs::from_slice(&proof.public_inputs);

        // Check the public inputs.
        assert_eq!(U256::from(pi.block_number()), primary_index);
        assert_eq!(pi.block_hash_raw(), root_of_trust);
        assert_eq!(pi.prev_block_hash_raw(), prev_root_of_trust);
        assert_eq!(pi.value_point(), row_digest.to_weierstrass());
        {
            let prefix = DUMMY_METADATA_DIGEST_PREFIX.to_fields();
            let inputs = prefix
                .into_iter()
                .chain(metadata_digest.to_fields())
                .collect_vec();
            let expected_metadata_digest = map_to_curve_point(&inputs);
            assert_eq!(
                pi.metadata_point(),
                expected_metadata_digest.to_weierstrass()
            );
        }
    }
}
