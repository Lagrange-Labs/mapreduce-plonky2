//! Module containing circuit code for a dummy value extraction circuit when an MPT contains no relevant data
//! for the object we are indexing.

use super::public_inputs::{PublicInputs, PublicInputsArgs};
use alloy::primitives::B256;
use anyhow::Result;
use itertools::Itertools;
use mp2_common::{
    array::Array,
    group_hashing::{map_to_curve_point, CircuitBuilderGroupHashing},
    keccak::{OutputHash, PACKED_HASH_LEN},
    mpt_sequential::MPTKeyWire,
    public_inputs::PublicInputCommon,
    rlp::MAX_KEY_NIBBLE_LEN,
    serialization::{deserialize, serialize},
    types::{CBuilder, GFp},
    utils::{Endianness, Packer, ToFields, ToTargets},
    D, F,
};
use plonky2::{
    field::types::Field,
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::proof::ProofWithPublicInputsTarget,
};
use plonky2_ecgfp5::{
    curve::curve::Point,
    gadgets::curve::{CircuitBuilderEcGFp5, CurveTarget},
};
use recursion_framework::circuit_builder::CircuitLogicWires;
use serde::{Deserialize, Serialize};

pub(crate) const EMPTY_TABLE: &str = "EMPTY_EXTRACTION";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmptyExtractionWires {
    root: Array<Target, PACKED_HASH_LEN>,
    metadata_digest: Vec<Target>,
}

impl EmptyExtractionWires {
    /// Add constant `EMPTY_TABLE` to the digest provided as input
    pub(crate) fn add_empty_identifier_to_digest(
        b: &mut CBuilder,
        digest: &CurveTarget,
    ) -> CurveTarget {
        let inputs = EMPTY_TABLE
            .as_bytes()
            .pack(Endianness::Big)
            .into_iter()
            .map(|empty_id| b.constant(F::from_canonical_u32(empty_id)))
            .chain(digest.to_targets())
            .collect_vec();
        b.map_to_curve_point(&inputs)
    }
}

/// Circuit to proving the processing of an extension node
#[derive(Clone, Debug, Copy, Serialize, Deserialize)]
pub struct EmptyExtractionCircuit {
    pub(crate) root_hash: B256,
    #[serde(serialize_with = "serialize", deserialize_with = "deserialize")]
    pub(crate) metadata_digest: Point,
}

impl EmptyExtractionCircuit {
    pub fn build(b: &mut CBuilder) -> EmptyExtractionWires {
        // Build the key wire which will have all zeroes for nibbles and the pointer set to F::NEG_ONE
        let neg_one = b.constant(GFp::NEG_ONE);
        let zero = b.zero();
        let nibble_arr: [Target; MAX_KEY_NIBBLE_LEN] = std::array::from_fn(|_| zero);
        let key_nibbles = Array::<Target, MAX_KEY_NIBBLE_LEN>::from_array(nibble_arr);
        let key = MPTKeyWire {
            key: key_nibbles,
            pointer: neg_one,
        };

        // Build the output hash array
        let root = OutputHash::new(b);

        // Build the metadata target
        let dm = b.add_virtual_curve_target();

        // Add empty circuit identifier to the metadata digest, to ensure that this circuit
        // is employed only for tables where there could be no values to be extracted
        let final_dm = EmptyExtractionWires::add_empty_identifier_to_digest(b, &dm);

        // Expose the public inputs.
        PublicInputsArgs {
            h: &root,
            k: &key,
            dv: b.curve_zero(),
            dm: final_dm,
            n: b.zero(),
        }
        .register(b);

        EmptyExtractionWires {
            root: root.downcast_to_targets(),
            metadata_digest: dm.to_targets(),
        }
    }

    pub fn assign(&self, pw: &mut PartialWitness<GFp>, wires: &EmptyExtractionWires) {
        // Set the root
        let packed_root = self
            .root_hash
            .0
            .pack(Endianness::Little)
            .into_iter()
            .map(GFp::from_canonical_u32)
            .collect::<Vec<GFp>>();
        pw.set_target_arr(&wires.root.arr, &packed_root);

        pw.set_target_arr(
            &wires.metadata_digest,
            &self.metadata_digest.to_weierstrass().to_fields(),
        );
    }

    /// Method to add the constant identifier `EMPTY_TABLE` to the input digest
    pub(crate) fn add_empty_identifier_to_digest(digest: Point) -> Point {
        map_to_curve_point(
            &EMPTY_TABLE
                .as_bytes()
                .pack(Endianness::Big)
                .into_iter()
                .map(F::from_canonical_u32)
                .chain(digest.to_fields())
                .collect_vec(),
        )
    }
}

/// Num of children = 1
impl CircuitLogicWires<GFp, D, 0> for EmptyExtractionWires {
    type CircuitBuilderParams = ();

    type Inputs = EmptyExtractionCircuit;

    const NUM_PUBLIC_INPUTS: usize = PublicInputs::<GFp>::TOTAL_LEN;

    fn circuit_logic(
        builder: &mut CBuilder,
        _verified_proofs: [&ProofWithPublicInputsTarget<D>; 0],
        _builder_parameters: Self::CircuitBuilderParams,
    ) -> Self {
        EmptyExtractionCircuit::build(builder)
    }

    fn assign_input(&self, inputs: Self::Inputs, pw: &mut PartialWitness<GFp>) -> Result<()> {
        inputs.assign(pw, self);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{super::public_inputs::tests::new_extraction_public_inputs, *};

    use mp2_common::{
        rlp::MAX_KEY_NIBBLE_LEN,
        utils::{Endianness, Packer},
        C, D, F,
    };
    use mp2_test::circuit::{run_circuit, UserCircuit};
    use plonky2::{
        field::types::{Field, PrimeField64, Sample},
        iop::{target::Target, witness::WitnessWrite},
        plonk::circuit_builder::CircuitBuilder,
    };

    #[derive(Clone, Debug)]
    struct TestEmptyExtractionCircuit<'a> {
        c: EmptyExtractionCircuit,
        exp_pi: PublicInputs<'a, F>,
    }

    impl UserCircuit<F, D> for TestEmptyExtractionCircuit<'_> {
        // Extension node wires + child public inputs
        type Wires = (EmptyExtractionWires, Vec<Target>);

        fn build(b: &mut CircuitBuilder<F, D>) -> Self::Wires {
            let exp_pi = b.add_virtual_targets(PublicInputs::<Target>::TOTAL_LEN);
            let ext_wires = EmptyExtractionCircuit::build(b);

            (ext_wires, exp_pi)
        }

        fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
            self.c.assign(pw, &wires.0);

            assert_eq!(wires.1.len(), PublicInputs::<Target>::TOTAL_LEN);
            assert_eq!(
                self.exp_pi.proof_inputs.len(),
                PublicInputs::<Target>::TOTAL_LEN
            );
            pw.set_target_arr(&wires.1, self.exp_pi.proof_inputs)
        }
    }

    #[test]
    fn test_values_extraction_empty_circuit() {
        // Prepare the public inputs
        let random_hash = B256::random();
        let md = Point::rand();
        // compute the metadata digest expected to be computed by the circuit
        let expected_md =
            EmptyExtractionCircuit::add_empty_identifier_to_digest(md).to_weierstrass();
        let key = vec![0u8; MAX_KEY_NIBBLE_LEN];
        let ptr = GFp::NEG_ONE.to_canonical_u64() as usize;
        let values_digest = Point::NEUTRAL.to_weierstrass();

        let exp_pi = new_extraction_public_inputs(
            &random_hash.0.pack(Endianness::Little),
            &key,
            ptr,
            &values_digest,
            &expected_md,
            0,
        );

        let exp_pi = PublicInputs::new(&exp_pi);

        // Quick test to see if we can convert back to public inputs.
        assert_eq!(random_hash.0.pack(Endianness::Little), exp_pi.root_hash());
        let (exp_key, exp_ptr) = exp_pi.mpt_key_info();
        assert_eq!(
            key.iter()
                .cloned()
                .map(F::from_canonical_u8)
                .collect::<Vec<_>>(),
            exp_key,
        );
        assert_eq!(exp_ptr, GFp::NEG_ONE);
        assert_eq!(Point::NEUTRAL.to_weierstrass(), exp_pi.values_digest());
        assert_eq!(expected_md, exp_pi.metadata_digest());
        assert_eq!(GFp::ZERO, exp_pi.n());

        let circuit = TestEmptyExtractionCircuit {
            c: EmptyExtractionCircuit {
                root_hash: random_hash,
                metadata_digest: md,
            },
            exp_pi: exp_pi.clone(),
        };
        let proof = run_circuit::<F, D, C, _>(circuit);
        let pi = PublicInputs::new(&proof.public_inputs);

        {
            let exp_hash = random_hash.0.pack(Endianness::Little);
            assert_eq!(pi.root_hash(), exp_hash);
        }
        {
            let (key, ptr) = pi.mpt_key_info();
            assert_eq!(key, exp_key);

            assert_eq!(ptr, exp_ptr);
        }
        assert_eq!(pi.values_digest(), exp_pi.values_digest());
        assert_eq!(pi.metadata_digest(), exp_pi.metadata_digest());
        assert_eq!(pi.n(), exp_pi.n());
    }
}
