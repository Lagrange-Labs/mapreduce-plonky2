//! Module containing circuit code for a dummy value extraction circuit when an MPT contains no relevant data
//! for the object we are indexing.

use super::public_inputs::{PublicInputs, PublicInputsArgs};
use alloy::primitives::B256;
use anyhow::Result;
use mp2_common::{
    array::Array,
    keccak::{OutputHash, PACKED_HASH_LEN},
    mpt_sequential::MPTKeyWire,
    public_inputs::PublicInputCommon,
    rlp::MAX_KEY_NIBBLE_LEN,
    serialization::{deserialize, serialize},
    types::{CBuilder, GFp},
    utils::{Endianness, Packer, ToFields, ToTargets},
    D,
};
use plonky2::{
    field::types::{Field, PrimeField64},
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::proof::ProofWithPublicInputsTarget,
};
use plonky2_ecgfp5::{curve::curve::Point, gadgets::curve::CircuitBuilderEcGFp5};
use recursion_framework::circuit_builder::CircuitLogicWires;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DummyNodeWires {
    root: Array<Target, PACKED_HASH_LEN>,
    metadata_digest: Vec<Target>,
    key: MPTKeyWire,
}

/// Circuit to proving the processing of an extension node
#[derive(Clone, Debug, Copy, Serialize, Deserialize)]
pub struct DummyNodeCircuit {
    pub(crate) root_hash: B256,
    #[serde(serialize_with = "serialize", deserialize_with = "deserialize")]
    pub(crate) metadata_digest: Point,
}

impl DummyNodeCircuit {
    pub fn build(b: &mut CBuilder) -> DummyNodeWires {
        // Build the key wire which will have all zeroes for nibbles and the pointer set to F::NEG_ONE
        let key = MPTKeyWire::new(b);

        // Build the output hash array
        let root = OutputHash::new(b);

        // Build the metadata target
        let dm = b.add_virtual_curve_target();

        // Expose the public inputs.
        PublicInputsArgs {
            h: &root,
            k: &key,
            dv: b.curve_zero(),
            dm,
            n: b.zero(),
        }
        .register(b);

        DummyNodeWires {
            root: root.downcast_to_targets(),
            metadata_digest: dm.to_targets(),
            key,
        }
    }

    pub fn assign(&self, pw: &mut PartialWitness<GFp>, wires: &DummyNodeWires) {
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

        // First get field negative one in usize form
        let ptr = GFp::NEG_ONE.to_canonical_u64() as usize;
        wires.key.assign(pw, &[0; MAX_KEY_NIBBLE_LEN], ptr);
    }
}

/// Num of children = 1
impl CircuitLogicWires<GFp, D, 0> for DummyNodeWires {
    type CircuitBuilderParams = ();

    type Inputs = DummyNodeCircuit;

    const NUM_PUBLIC_INPUTS: usize = PublicInputs::<GFp>::TOTAL_LEN;

    fn circuit_logic(
        builder: &mut CBuilder,
        _verified_proofs: [&ProofWithPublicInputsTarget<D>; 0],
        _builder_parameters: Self::CircuitBuilderParams,
    ) -> Self {
        DummyNodeCircuit::build(builder)
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
        field::types::{Field, Sample},
        iop::{target::Target, witness::WitnessWrite},
        plonk::circuit_builder::CircuitBuilder,
    };

    #[derive(Clone, Debug)]
    struct TestDummyNodeCircuit<'a> {
        c: DummyNodeCircuit,
        exp_pi: PublicInputs<'a, F>,
    }

    impl UserCircuit<F, D> for TestDummyNodeCircuit<'_> {
        // Extension node wires + child public inputs
        type Wires = (DummyNodeWires, Vec<Target>);

        fn build(b: &mut CircuitBuilder<F, D>) -> Self::Wires {
            let exp_pi = b.add_virtual_targets(PublicInputs::<Target>::TOTAL_LEN);
            let ext_wires = DummyNodeCircuit::build(b);

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
    fn test_values_extraction_dummy_node_circuit() {
        // Prepare the public inputs
        let random_hash = B256::random();
        let md = Point::rand();
        let random_md = md.to_weierstrass();
        let key = vec![0u8; MAX_KEY_NIBBLE_LEN];
        let ptr = GFp::NEG_ONE.to_canonical_u64() as usize;
        let values_digest = Point::NEUTRAL.to_weierstrass();

        let exp_pi = new_extraction_public_inputs(
            &random_hash.0.pack(Endianness::Little),
            &key,
            ptr,
            &values_digest,
            &random_md,
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
        assert_eq!(random_md, exp_pi.metadata_digest());
        assert_eq!(GFp::ZERO, exp_pi.n());

        let circuit = TestDummyNodeCircuit {
            c: DummyNodeCircuit {
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
