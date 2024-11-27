use mp2_common::{
    default_config,
    keccak::{OutputHash, PACKED_HASH_LEN},
    proof::{deserialize_proof, verify_proof_fixed_circuit, ProofWithVK},
    serialization::{deserialize, serialize},
    u256::UInt256Target,
    utils::FromTargets,
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
use plonky2_ecgfp5::gadgets::curve::CurveTarget;
use recursion_framework::{
    circuit_builder::CircuitLogicWires,
    framework::{
        RecursiveCircuits, RecursiveCircuitsVerifierGagdet, RecursiveCircuitsVerifierTarget,
    },
};
use serde::{Deserialize, Serialize};

use crate::{block_extraction, values_extraction};

use super::api::{FinalExtractionBuilderParams, NUM_IO};

use anyhow::Result;

/// This circuit is more like a gadget. This contains the logic of the common part
/// between all the final extraction circuits. It should not be used on its own.
#[derive(Debug, Clone, Copy)]
pub struct ReceiptExtractionCircuit;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiptExtractionWires {
    #[serde(serialize_with = "serialize", deserialize_with = "deserialize")]
    pub(crate) dm: CurveTarget,
    #[serde(serialize_with = "serialize", deserialize_with = "deserialize")]
    pub(crate) dv: CurveTarget,
    pub(crate) bh: [Target; PACKED_HASH_LEN],
    pub(crate) prev_bh: [Target; PACKED_HASH_LEN],
    pub(crate) bn: UInt256Target,
}

impl ReceiptExtractionCircuit {
    pub(crate) fn build(
        b: &mut CircuitBuilder<GoldilocksField, 2>,
        block_pi: &[Target],
        value_pi: &[Target],
    ) -> ReceiptExtractionWires {
        // TODO: homogeinize the public inputs structs
        let block_pi =
            block_extraction::public_inputs::PublicInputs::<Target>::from_slice(block_pi);
        let value_pi = values_extraction::PublicInputs::<Target>::new(value_pi);

        let minus_one = b.constant(GoldilocksField::NEG_ONE);

        // enforce the MPT key extraction reached the root
        b.connect(value_pi.mpt_key().pointer, minus_one);

        // enforce block_pi.state_root == contract_pi.state_root
        block_pi
            .state_root()
            .enforce_equal(b, &OutputHash::from_targets(value_pi.root_hash_info()));
        ReceiptExtractionWires {
            dm: value_pi.metadata_digest_target(),
            dv: value_pi.values_digest_target(),
            bh: block_pi.block_hash_raw().try_into().unwrap(), // safe to unwrap as we give as input the slice of the expected length
            prev_bh: block_pi.prev_block_hash_raw().try_into().unwrap(), // safe to unwrap as we give as input the slice of the expected length
            bn: block_pi.block_number(),
        }
    }
}

/// The wires that are needed for the recursive framework, that concerns verifying  the input
/// proofs
#[derive(Serialize, Deserialize, Clone, Debug)]
pub(crate) struct ReceiptRecursiveWires {
    /// Wires containing the block and value proof
    verification: ReceiptCircuitProofWires,
    /// Wires information to check that the value corresponds to the block
    consistency: ReceiptExtractionWires,
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
        // value proof for table a and value proof for table b = 2
        let verification = ReceiptCircuitProofInputs::build(builder, &builder_parameters);
        let consistency = ReceiptExtractionCircuit::build(
            builder,
            verification.get_block_public_inputs(),
            verification.get_value_public_inputs(),
        );
        Self {
            verification,
            consistency,
        }
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
