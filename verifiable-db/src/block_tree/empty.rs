//! Module with the circuit used when we don't update the Block tree. For instance in the case of Receipts
//! if there are no relevent event logs in a block we still have to advance the IVC proof

use super::public_inputs::PublicInputs;
use crate::extraction::{ExtractionPI, ExtractionPIWrap};

use alloy::primitives::U256;
use anyhow::Result;
use mp2_common::{
    default_config,
    poseidon::H,
    proof::ProofWithVK,
    public_inputs::PublicInputCommon,
    serialization::{deserialize, serialize},
    types::CBuilder,
    u256::{CircuitBuilderU256, UInt256Target, WitnessWriteU256},
    utils::ToTargets,
    CHasher, C, D, F,
};
use plonky2::{
    hash::hash_types::{HashOut, HashOutTarget},
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{circuit_builder::CircuitBuilder, config::Hasher, proof::ProofWithPublicInputsTarget},
};

use plonky2_ecgfp5::gadgets::curve::CircuitBuilderEcGFp5;
use recursion_framework::{
    circuit_builder::CircuitLogicWires,
    framework::{
        RecursiveCircuits, RecursiveCircuitsVerifierGagdet, RecursiveCircuitsVerifierTarget,
    },
};
use serde::{Deserialize, Serialize};
use std::{iter, marker::PhantomData};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EmptyWires {
    /// Identifier of the block number column
    pub(crate) index_identifier: Target,
    /// The old root of the tree,
    #[serde(serialize_with = "serialize", deserialize_with = "deserialize")]
    pub(crate) h_old: HashOutTarget,
    /// The old minimum value
    pub(crate) min_val: UInt256Target,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EmptyCircuit {
    /// Identifier of the block number column
    pub(crate) index_identifier: F,
    /// The old root of the tree,
    pub(crate) h_old: HashOut<F>,
    /// The old minimum value
    pub(crate) min_val: U256,
}

impl EmptyCircuit {
    fn build<E: ExtractionPIWrap>(b: &mut CBuilder, extraction_pi: &[Target]) -> EmptyWires {
        let zero_256 = b.zero_u256();
        let curve_zero = b.curve_zero();
        let index_identifier = b.add_virtual_target();

        let min_val = b.add_virtual_u256();

        let extraction_pi = E::PI::from_slice(extraction_pi);

        let block_number = extraction_pi.primary_index_value();

        // Compute the hash of table metadata, to be exposed as public input to prove to
        // the verifier that we extracted the correct storage slots and we place the data
        // in the expected columns of the constructed tree; we add also the identifier
        // of the block number column to the table metadata.
        // metadata_hash = H(extraction_proof.DM || block_id)
        let inputs = extraction_pi
            .metadata_set_digest()
            .to_targets()
            .iter()
            .cloned()
            .chain(iter::once(index_identifier))
            .collect();
        let metadata_hash = b.hash_n_to_hash_no_pad::<CHasher>(inputs).elements;

        let h_old = b.add_virtual_hash();

        // Register the public inputs.
        PublicInputs::new(
            &h_old.to_targets(),
            &h_old.to_targets(),
            &min_val.to_targets(),
            &zero_256.to_targets(),
            &block_number,
            &extraction_pi.commitment(),
            &extraction_pi.prev_commitment(),
            &metadata_hash,
            &curve_zero.to_targets(),
        )
        .register(b);

        EmptyWires {
            index_identifier,
            h_old,
            min_val,
        }
    }

    /// Assign the wires.
    fn assign(&self, pw: &mut PartialWitness<F>, wires: &EmptyWires) {
        pw.set_target(wires.index_identifier, self.index_identifier);
        pw.set_u256_target(&wires.min_val, self.min_val);
        pw.set_hash_target(wires.h_old, self.h_old);
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct RecursiveEmptyWires<E: ExtractionPIWrap> {
    empty_wires: EmptyWires,
    extraction_verifier: RecursiveCircuitsVerifierTarget<D>,
    _e: PhantomData<E>,
}

#[derive(Clone, Debug)]
pub(crate) struct RecursiveEmptyInput {
    pub(crate) witness: EmptyCircuit,
    pub(crate) extraction_proof: ProofWithVK,
    pub(crate) extraction_set: RecursiveCircuits<F, C, D>,
}

impl<E: ExtractionPIWrap> CircuitLogicWires<F, D, 0> for RecursiveEmptyWires<E>
where
    [(); E::PI::TOTAL_LEN]:,
    [(); <H as Hasher<F>>::HASH_SIZE]:,
{
    // Final extraction circuit set + rows tree circuit set
    type CircuitBuilderParams = RecursiveCircuits<F, C, D>;

    type Inputs = RecursiveEmptyInput;

    const NUM_PUBLIC_INPUTS: usize = PublicInputs::<Target>::TOTAL_LEN;

    fn circuit_logic(
        builder: &mut CircuitBuilder<F, D>,
        _verified_proofs: [&ProofWithPublicInputsTarget<D>; 0],
        builder_parameters: Self::CircuitBuilderParams,
    ) -> Self {
        let extraction_verifier =
            RecursiveCircuitsVerifierGagdet::<F, C, D, { E::PI::TOTAL_LEN }>::new(
                default_config(),
                &builder_parameters,
            );
        let extraction_verifier = extraction_verifier.verify_proof_in_circuit_set(builder);
        let extraction_pi =
            extraction_verifier.get_public_input_targets::<F, { E::PI::TOTAL_LEN }>();

        let empty_wires = EmptyCircuit::build::<E>(builder, extraction_pi);

        RecursiveEmptyWires {
            empty_wires,
            extraction_verifier,
            _e: PhantomData,
        }
    }

    fn assign_input(&self, inputs: Self::Inputs, pw: &mut PartialWitness<F>) -> Result<()> {
        inputs.witness.assign(pw, &self.empty_wires);

        let (proof, vd) = inputs.extraction_proof.into();
        self.extraction_verifier
            .set_target(pw, &inputs.extraction_set, &proof, &vd)
    }
}

#[cfg(test)]
mod tests {
    use crate::block_tree::{
        leaf::tests::compute_expected_hash,
        tests::{TestPIField, TestPITargets},
    };

    use super::{super::tests::random_extraction_pi, *};
    use alloy::primitives::U256;
    use mp2_common::{
        digest::Digest,
        utils::{Fieldable, ToFields},
    };
    use mp2_test::{
        circuit::{run_circuit, UserCircuit},
        utils::random_vector,
    };
    use plonky2::{field::types::Field, hash::hash_types::NUM_HASH_OUT_ELTS};
    use rand::{thread_rng, Rng};

    #[derive(Clone, Debug)]
    struct TestEmptyCircuit<'a> {
        c: EmptyCircuit,
        extraction_pi: &'a [F],
    }

    impl UserCircuit<F, D> for TestEmptyCircuit<'_> {
        // Parent node wires + extraction public inputs
        type Wires = (EmptyWires, Vec<Target>);

        fn build(b: &mut CBuilder) -> Self::Wires {
            let extraction_pi = b.add_virtual_targets(TestPITargets::TOTAL_LEN);

            let empty_wires = EmptyCircuit::build::<TestPITargets>(b, &extraction_pi);

            (empty_wires, extraction_pi)
        }

        fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
            self.c.assign(pw, &wires.0);

            assert_eq!(wires.1.len(), TestPITargets::TOTAL_LEN);
            pw.set_target_arr(&wires.1, self.extraction_pi);
        }
    }

    #[test]
    fn test_block_index_empty_circuit() {
        test_empty_circuit();
    }

    fn test_empty_circuit() {
        let mut rng = thread_rng();

        let index_identifier = rng.gen::<u32>().to_field();

        let h_old = HashOut::from_vec(random_vector::<u32>(NUM_HASH_OUT_ELTS).to_fields());

        let min_val = U256::from_limbs(std::array::from_fn(|_| rng.gen()));
        let extraction_pi =
            &random_extraction_pi(&mut rng, U256::from(1), &Digest::NEUTRAL.to_fields(), false);

        let test_circuit = TestEmptyCircuit {
            c: EmptyCircuit {
                index_identifier,
                h_old,
                min_val,
            },
            extraction_pi,
        };

        let proof = run_circuit::<F, D, C, _>(test_circuit);
        let pi = PublicInputs::from_slice(&proof.public_inputs);
        let extraction_pi = TestPIField::from_slice(extraction_pi);

        let block_number = extraction_pi.block_number_raw();

        // Check old hash
        {
            assert_eq!(pi.h_old, h_old.to_fields());
        }
        // Check new hash
        {
            assert_eq!(pi.h_new, h_old.to_fields());
        }
        // Check minimum block number
        {
            let exp_val: [F; 8] = min_val.to_fields().try_into().unwrap();
            assert_eq!(pi.min, exp_val);
        }
        // Check maximum block number
        {
            assert_eq!(pi.max, [F::ZERO; 8]);
        }
        // Check block number
        {
            assert_eq!(pi.block_number, block_number);
        }
        // Check block hash
        {
            assert_eq!(pi.block_hash, extraction_pi.block_hash_raw());
        }
        // Check previous block hash
        {
            assert_eq!(pi.prev_block_hash, extraction_pi.prev_block_hash_raw());
        }
        // Check metadata hash
        {
            let exp_hash = compute_expected_hash(&extraction_pi, index_identifier);

            assert_eq!(pi.metadata_hash, exp_hash.elements);
        }
        // Check new node digest
        {
            assert_eq!(
                pi.new_value_set_digest_point(),
                Digest::NEUTRAL.to_weierstrass()
            );
        }
    }
}
