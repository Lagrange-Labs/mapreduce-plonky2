use mp2_common::{
    default_config,
    keccak::OutputHash,
    proof::{deserialize_proof, verify_proof_fixed_circuit, ProofWithVK},
    public_inputs::PublicInputCommon,
    serialization::{deserialize, serialize},
    utils::{FromTargets, ToTargets},
    C, D, F,
};
use plonky2::{
    field::{goldilocks_field::GoldilocksField, types::Field},
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget},
    },
};

use recursion_framework::{
    circuit_builder::CircuitLogicWires,
    framework::{
        RecursiveCircuits, RecursiveCircuitsVerifierGagdet, RecursiveCircuitsVerifierTarget,
    },
};
use serde::{Deserialize, Serialize};

use crate::{block_extraction, values_extraction};

use super::{
    api::{FinalExtractionBuilderParams, NUM_IO},
    PublicInputs,
};

use anyhow::Result;

/// This circuit is more like a gadget. This contains the logic of the common part
/// between all the final extraction circuits. It should not be used on its own.
#[derive(Debug, Clone, Copy)]
pub struct ReceiptExtractionCircuit;

impl ReceiptExtractionCircuit {
    pub(crate) fn build(
        b: &mut CircuitBuilder<GoldilocksField, 2>,
        block_pi: &[Target],
        value_pi: &[Target],
    ) {
        // TODO: homogeinize the public inputs structs
        let block_pi =
            block_extraction::public_inputs::PublicInputs::<Target>::from_slice(block_pi);
        let value_pi = values_extraction::PublicInputs::<Target>::new(value_pi);

        let minus_one = b.constant(GoldilocksField::NEG_ONE);

        // enforce the MPT key extraction reached the root
        b.connect(value_pi.mpt_key().pointer, minus_one);

        // enforce block_pi.state_root == contract_pi.state_root
        block_pi
            .receipt_root()
            .enforce_equal(b, &OutputHash::from_targets(value_pi.root_hash_info()));

        PublicInputs::new(
            block_pi.bh,
            block_pi.prev_bh,
            // here the value digest is the same since for length proof, it is assumed the table
            // digest is in Compound format (i.e. multiple rows inside digest already).
            &value_pi.values_digest_target().to_targets(),
            &value_pi.metadata_digest_target().to_targets(),
            &block_pi.bn.to_targets(),
            &[b._false().target],
        )
        .register_args(b);
    }
}

/// The wires that are needed for the recursive framework, that concerns verifying  the input
/// proofs
#[derive(Serialize, Deserialize, Clone, Debug)]
pub(crate) struct ReceiptRecursiveWires {
    /// Wires containing the block and value proof
    verification: ReceiptCircuitProofWires,
}

impl CircuitLogicWires<F, D, 0> for ReceiptRecursiveWires {
    type CircuitBuilderParams = FinalExtractionBuilderParams;

    type Inputs = ReceiptCircuitProofInputs;

    const NUM_PUBLIC_INPUTS: usize = NUM_IO;

    fn circuit_logic(
        builder: &mut CircuitBuilder<F, D>,
        _verified_proofs: [&plonky2::plonk::proof::ProofWithPublicInputsTarget<D>; 0],
        builder_parameters: Self::CircuitBuilderParams,
    ) -> Self {
        let verification = ReceiptCircuitProofInputs::build(builder, &builder_parameters);
        ReceiptExtractionCircuit::build(
            builder,
            verification.get_block_public_inputs(),
            verification.get_value_public_inputs(),
        );
        Self { verification }
    }

    fn assign_input(&self, inputs: Self::Inputs, pw: &mut PartialWitness<F>) -> anyhow::Result<()> {
        inputs.assign_proof_targets(pw, &self.verification)?;
        Ok(())
    }
}

/// This parameter struct is not intended to be built on its own
/// but rather as a sub-component of the two final extraction parameters set.
/// This parameter contains the common logic of verifying a block and
/// value proof automatically from the right verification keys / circuit set.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub(crate) struct ReceiptCircuitProofWires {
    /// single circuit proof extracting block hash, block number, previous hash
    /// and receipt root
    #[serde(serialize_with = "serialize", deserialize_with = "deserialize")]
    block_proof: ProofWithPublicInputsTarget<D>,
    /// circuit set extracting the values from receipt trie of the block
    value_proof: RecursiveCircuitsVerifierTarget<D>,
}

pub(crate) const VALUE_SET_NUM_IO: usize = values_extraction::PublicInputs::<F>::TOTAL_LEN;

#[derive(Clone, Debug)]
pub struct ReceiptCircuitInput {
    block_proof: ProofWithPublicInputs<F, C, D>,
    value_proof: ProofWithVK,
}

impl ReceiptCircuitInput {
    pub(super) fn new(block_proof: Vec<u8>, value_proof: Vec<u8>) -> Result<Self> {
        Ok(Self {
            block_proof: deserialize_proof(&block_proof)?,
            value_proof: ProofWithVK::deserialize(&value_proof)?,
        })
    }
}
#[derive(Clone, Debug)]
pub(crate) struct ReceiptCircuitProofInputs {
    proofs: ReceiptCircuitInput,
    value_circuit_set: RecursiveCircuits<F, C, D>,
}

impl ReceiptCircuitProofInputs {
    pub(crate) fn new_from_proofs(
        proofs: ReceiptCircuitInput,
        value_circuit_set: RecursiveCircuits<F, C, D>,
    ) -> Self {
        Self {
            proofs,
            value_circuit_set,
        }
    }

    pub(crate) fn build(
        cb: &mut CircuitBuilder<F, D>,
        params: &FinalExtractionBuilderParams,
    ) -> ReceiptCircuitProofWires {
        let config = default_config();
        let value_proof_wires = RecursiveCircuitsVerifierGagdet::<F, C, D, VALUE_SET_NUM_IO>::new(
            config.clone(),
            &params.value_circuit_set,
        )
        .verify_proof_in_circuit_set(cb);

        let block_proof_wires = verify_proof_fixed_circuit(cb, &params.block_vk);
        ReceiptCircuitProofWires {
            block_proof: block_proof_wires,
            value_proof: value_proof_wires,
        }
    }

    pub(crate) fn assign_proof_targets(
        &self,
        pw: &mut PartialWitness<F>,
        wires: &ReceiptCircuitProofWires,
    ) -> anyhow::Result<()> {
        pw.set_proof_with_pis_target(&wires.block_proof, &self.proofs.block_proof);

        let (proof, vd) = (&self.proofs.value_proof).into();
        wires
            .value_proof
            .set_target(pw, &self.value_circuit_set, proof, vd)?;

        Ok(())
    }
}

impl ReceiptCircuitProofWires {
    pub(crate) fn get_block_public_inputs(&self) -> &[Target] {
        self.block_proof.public_inputs.as_slice()
    }

    pub(crate) fn get_value_public_inputs(&self) -> &[Target] {
        self.value_proof
            .get_public_input_targets::<F, VALUE_SET_NUM_IO>()
    }
}

#[cfg(test)]
pub(crate) mod test {

    use crate::final_extraction::{base_circuit::test::ProofsPi, PublicInputs};

    use super::*;
    use alloy::primitives::U256;
    use anyhow::Result;

    use mp2_common::{
        keccak::PACKED_HASH_LEN,
        rlp::MAX_KEY_NIBBLE_LEN,
        utils::{Endianness, Packer, ToFields},
    };
    use mp2_test::{
        circuit::{run_circuit, UserCircuit},
        utils::random_vector,
    };
    use plonky2::{
        field::types::{PrimeField64, Sample},
        hash::hash_types::HashOut,
        iop::witness::WitnessWrite,
        plonk::config::GenericHashOut,
    };
    use plonky2_ecgfp5::curve::curve::Point;
    use values_extraction::public_inputs::tests::new_extraction_public_inputs;

    #[derive(Clone, Debug)]
    struct TestReceiptCircuit {
        pis: ReceiptsProofsPi,
    }

    struct TestReceiptWires {
        pis: ReceiptsProofsPiTarget,
    }

    impl UserCircuit<F, D> for TestReceiptCircuit {
        type Wires = TestReceiptWires;
        fn build(c: &mut CircuitBuilder<F, D>) -> Self::Wires {
            let proofs_pi = ReceiptsProofsPiTarget::new(c);
            ReceiptExtractionCircuit::build(c, &proofs_pi.blocks_pi, &proofs_pi.values_pi);
            TestReceiptWires { pis: proofs_pi }
        }
        fn prove(&self, pw: &mut PartialWitness<GoldilocksField>, wires: &Self::Wires) {
            wires.pis.assign(pw, &self.pis);
        }
    }

    #[derive(Clone, Debug)]
    pub(crate) struct ReceiptsProofsPiTarget {
        pub(crate) blocks_pi: Vec<Target>,
        pub(crate) values_pi: Vec<Target>,
    }

    impl ReceiptsProofsPiTarget {
        pub(crate) fn new(b: &mut CircuitBuilder<F, D>) -> Self {
            Self {
                blocks_pi: b.add_virtual_targets(
                    block_extraction::public_inputs::PublicInputs::<Target>::TOTAL_LEN,
                ),
                values_pi: b
                    .add_virtual_targets(values_extraction::PublicInputs::<Target>::TOTAL_LEN),
            }
        }
        pub(crate) fn assign(&self, pw: &mut PartialWitness<F>, pis: &ReceiptsProofsPi) {
            pw.set_target_arr(&self.values_pi, pis.values_pi.as_ref());
            pw.set_target_arr(&self.blocks_pi, pis.blocks_pi.as_ref());
        }
    }

    /// TODO: refactor this struct to mimick exactly the base circuit wires in that it can contain
    /// multiple values
    #[derive(Clone, Debug)]
    pub(crate) struct ReceiptsProofsPi {
        pub(crate) blocks_pi: Vec<F>,
        pub(crate) values_pi: Vec<F>,
    }

    impl ReceiptsProofsPi {
        /// Function takes in a [`ProofsPi`] instance and generates a set of values public inputs
        /// that agree with the provided receipts root from the `blocks_pi`.
        pub(crate) fn generate_from_proof_pi_value(base_info: &ProofsPi) -> ReceiptsProofsPi {
            let original = base_info.value_inputs();
            let block_pi = base_info.block_inputs();
            let (k, t) = original.mpt_key_info();
            let new_value_digest = Point::rand();
            let new_metadata_digest = Point::rand();
            let new_values_pi = new_extraction_public_inputs(
                &block_pi
                    .receipt_root_raw()
                    .iter()
                    .map(|byte| byte.to_canonical_u64() as u32)
                    .collect::<Vec<u32>>(),
                &k.iter()
                    .map(|byte| byte.to_canonical_u64() as u8)
                    .collect::<Vec<u8>>(),
                t.to_canonical_u64() as usize,
                &new_value_digest.to_weierstrass(),
                &new_metadata_digest.to_weierstrass(),
                original.n().to_canonical_u64() as usize,
            );

            Self {
                blocks_pi: base_info.blocks_pi.clone(),
                values_pi: new_values_pi,
            }
        }

        pub(crate) fn block_inputs(&self) -> block_extraction::PublicInputs<F> {
            block_extraction::PublicInputs::from_slice(&self.blocks_pi)
        }

        pub(crate) fn value_inputs(&self) -> values_extraction::PublicInputs<F> {
            values_extraction::PublicInputs::new(&self.values_pi)
        }

        pub(crate) fn check_proof_public_inputs(&self, proof: &ProofWithPublicInputs<F, C, D>) {
            let proof_pis = PublicInputs::from_slice(&proof.public_inputs);
            let block_pi = self.block_inputs();

            assert_eq!(proof_pis.bn, block_pi.bn);
            assert_eq!(proof_pis.h, block_pi.bh);
            assert_eq!(proof_pis.ph, block_pi.prev_bh);

            // check digests
            let value_pi = self.value_inputs();

            assert_eq!(proof_pis.value_point(), value_pi.values_digest());

            assert_eq!(proof_pis.metadata_point(), value_pi.metadata_digest());
        }

        pub(crate) fn random() -> Self {
            let value_h = HashOut::<F>::rand().to_bytes().pack(Endianness::Little);
            let key = random_vector(MAX_KEY_NIBBLE_LEN);
            let ptr = usize::MAX;
            let value_dv = Point::rand();
            let value_dm = Point::rand();
            let n = 10;
            let values_pi = new_extraction_public_inputs(
                &value_h,
                &key,
                ptr,
                &value_dv.to_weierstrass(),
                &value_dm.to_weierstrass(),
                n,
            );

            let th = &random_vector::<u32>(PACKED_HASH_LEN).to_fields();
            let sh = &random_vector::<u32>(PACKED_HASH_LEN).to_fields();

            // The receipts root and value root need to agree
            let rh = &value_h.to_fields();

            let block_number = U256::from(F::rand().to_canonical_u64()).to_fields();
            let block_hash = HashOut::<F>::rand()
                .to_bytes()
                .pack(Endianness::Little)
                .to_fields();
            let parent_block_hash = HashOut::<F>::rand()
                .to_bytes()
                .pack(Endianness::Little)
                .to_fields();
            let blocks_pi = block_extraction::public_inputs::PublicInputs {
                bh: &block_hash,
                prev_bh: &parent_block_hash,
                bn: &block_number,
                sh,
                th,
                rh,
            }
            .to_vec();
            ReceiptsProofsPi {
                blocks_pi,
                values_pi,
            }
        }
    }

    #[test]
    fn final_simple_value() -> Result<()> {
        let pis = ReceiptsProofsPi::random();
        let test_circuit = TestReceiptCircuit { pis: pis.clone() };
        let proof = run_circuit::<F, D, C, _>(test_circuit);
        pis.check_proof_public_inputs(&proof);
        Ok(())
    }
}
