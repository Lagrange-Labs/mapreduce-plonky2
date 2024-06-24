use mp2_common::{
    group_hashing::CircuitBuilderGroupHashing, keccak::PACKED_HASH_LEN, serialization::{deserialize, serialize}, u256::{self, UInt256Target}, C, D, F
};
use plonky2::{
    field::{goldilocks_field::GoldilocksField, types::Field},
    iop::{target::Target, witness::{PartialWitness, WitnessWrite}},
    plonk::{circuit_builder::CircuitBuilder, circuit_data::VerifierCircuitData, proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget}},
};
use plonky2_ecgfp5::gadgets::curve::CurveTarget;
use recursion_framework::framework::{RecursiveCircuits, RecursiveCircuitsVerifierGagdet, RecursiveCircuitsVerifierTarget};
use serde::{Deserialize, Serialize};

use crate::{api::{default_config, deserialize_proof, ProofWithVK}, block_extraction, contract_extraction, values_extraction};

use super::api::FinalExtractionBuilderParams;

use anyhow::Result;

/// This circuit is more like a gadget. This contains the logic of the common part
/// between all the final extraction circuits. It should not be used on its own.
#[derive(Debug, Clone)]
pub struct BaseCircuit {}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaseWires {
    #[serde(serialize_with="serialize", deserialize_with="deserialize")]
    pub(crate) dm: CurveTarget,
    pub(crate) bh: [Target; PACKED_HASH_LEN],
    pub(crate) prev_bh: [Target; PACKED_HASH_LEN],
    pub(crate) bn: UInt256Target,
}

impl BaseCircuit {
    pub(crate) fn build(
        b: &mut CircuitBuilder<GoldilocksField, 2>,
        block_pi: &[Target],
        contract_pi: &[Target],
        value_pi: &[Target],
    ) -> BaseWires {
        // TODO: homogeinize the public inputs structs
        let block_pi = block_extraction::public_inputs::PublicInputs::<Target>::from_slice(block_pi);
        let value_pi = values_extraction::PublicInputs::<Target>::new(value_pi);
        let contract_pi = contract_extraction::PublicInputs::<Target>::from_slice(contract_pi);

        let minus_one = b.constant(GoldilocksField::NEG_ONE);
        b.connect(value_pi.mpt_key().pointer, minus_one);
        b.connect(contract_pi.mpt_key().pointer, minus_one);

        let metadata =
            b.add_curve_point(&[value_pi.metadata_digest(), contract_pi.metadata_digest()]);

        // enforce contract_pi.storage_root == value_pi.storage_root
        contract_pi.storage_root().enforce_equal(b, &value_pi.root_hash());
        // enforce block_pi.state_root == contract_pi.state_root
        block_pi.state_root().enforce_equal(b, &contract_pi.root_hash());
        BaseWires {
            dm: metadata,
            bh: block_pi.block_hash_raw().try_into().unwrap(), // safe to unwrap as we give as input the slice of the expected length
            prev_bh: block_pi.prev_block_hash_raw().try_into().unwrap(), // safe to unwrap as we give as input the slice of the expected length
            bn: block_pi.block_number(),
        }
    }

    pub(crate) fn assign(&self, pw: &mut PartialWitness<GoldilocksField>, wires: &BaseWires) {}
}

/// This parameter struct is not intended to be built on its own
/// but rather as a sub-component of the two final extraction parameters set.
/// This parameter contains the common logic of verifying a block, contract and
/// value proof automatically from the right verification keys / circuit set.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub(crate) struct BaseCircuitProofWires {
    /// single circuit proof extracting block hash, block number, previous hash
    /// and state root
    #[serde(serialize_with = "serialize", deserialize_with = "deserialize")]
    block_proof: ProofWithPublicInputsTarget<D>,
    /// circuit set extracting contract leaf from state trie
    contract_proof: RecursiveCircuitsVerifierTarget<D>,
    /// circuit set extracting the values from storage trie of the contract
    value_proof: RecursiveCircuitsVerifierTarget<D>,
}

const CONTRACT_SET_NUM_IO: usize = contract_extraction::PublicInputs::<F>::TOTAL_LEN;
const VALUE_SET_NUM_IO: usize = values_extraction::PublicInputs::<F>::TOTAL_LEN;

#[derive(Clone, Debug)]
pub(super) struct BaseCircuitInput {
    block_proof: ProofWithPublicInputs<F, C, D>,
    contract_proof: ProofWithVK,
    value_proof: ProofWithVK,
}

impl BaseCircuitInput {
    pub(super) fn new(
        block_proof: Vec<u8>,
        contract_proof: Vec<u8>,
        value_proof: Vec<u8>,
    ) -> Result<Self> {
       Ok(
        Self {
            block_proof: deserialize_proof(&block_proof)?,
            contract_proof: ProofWithVK::deserialize(&contract_proof)?,
            value_proof: ProofWithVK::deserialize(&value_proof)?,
        }
       ) 
    }
}
#[derive(Clone, Debug)]
pub(crate) struct BaseCircuitProofInputs {
    proofs: BaseCircuitInput,
    contract_circuit_set: RecursiveCircuits<F, C, D>,
    value_circuit_set: RecursiveCircuits<F, C, D>,
}

impl BaseCircuitProofInputs {
    pub(crate) fn new_from_proofs(
        proofs: BaseCircuitInput,
        contract_circuit_set: RecursiveCircuits<F, C, D>,
        value_circuit_set: RecursiveCircuits<F, C, D>,
    ) -> Self {
        Self {
            proofs,
            contract_circuit_set,
            value_circuit_set,
        }
    }

    pub(crate) fn build(
        cb: &mut CircuitBuilder<F, D>,
        params: &FinalExtractionBuilderParams,
    ) -> BaseCircuitProofWires {
        let config = default_config();
        let contract_verifier =
            RecursiveCircuitsVerifierGagdet::<F, C, D, CONTRACT_SET_NUM_IO>::new(
                config.clone(),
                &params.contract_circuit_set,
            );
        let value_verifier = RecursiveCircuitsVerifierGagdet::<F, C, D, VALUE_SET_NUM_IO>::new(
            config.clone(),
            &params.value_circuit_set,
        );
        let contract_proof_wires = contract_verifier.verify_proof_in_circuit_set(cb);
        let value_proof_wires = value_verifier.verify_proof_in_circuit_set(cb);
        let block_proof_wires = crate::api::verify_proof_fixed_circuit(cb, &params.block_vk);
        BaseCircuitProofWires {
            block_proof: block_proof_wires,
            contract_proof: contract_proof_wires,
            value_proof: value_proof_wires,
        }
    }

    pub(crate) fn assign_proof_targets(&self,
        pw: &mut PartialWitness<F>, 
        wires: &BaseCircuitProofWires
    ) -> anyhow::Result<()> {
        pw.set_proof_with_pis_target(&wires.block_proof, &self.proofs.block_proof);
        let (proof, vd) = (&self.proofs.contract_proof).into();
        wires.contract_proof.set_target(
            pw, 
            &self.contract_circuit_set, 
            proof, 
            vd,
        )?;
        let (proof, vd) = (&self.proofs.value_proof).into();
        wires.value_proof.set_target(
            pw, 
            &self.value_circuit_set, 
            proof, 
            vd
        )
    }
}

impl BaseCircuitProofWires {
    pub(crate) fn get_block_public_inputs(&self) -> &[Target] {
        self.block_proof.public_inputs.as_slice()
    }

    pub(crate) fn get_contract_public_inputs(&self) -> &[Target] {
        self.contract_proof.get_public_input_targets::<F, CONTRACT_SET_NUM_IO>()
    }

    pub(crate) fn get_value_public_inputs(&self) -> &[Target] {
        self.value_proof.get_public_input_targets::<F, VALUE_SET_NUM_IO>()
    }
}



#[cfg(test)]
pub(crate) mod test {
    use super::*;
    use anyhow::Result;
    use contract_extraction::build_circuits_params;
    use ethers::types::U256;
    use mp2_common::{
        keccak::PACKED_HASH_LEN,
        mpt_sequential::MPTKeyWire,
        rlp::MAX_KEY_NIBBLE_LEN,
        types::GFp,
        utils::{Endianness, IntTargetWriter, Packer, ToFields},
    };
    use mp2_test::{
        circuit::{run_circuit, setup_circuit, UserCircuit},
        utils::random_vector,
    };
    use plonky2::{
        field::types::{PrimeField64, Sample},
        hash::hash_types::HashOut,
        iop::witness::WitnessWrite,
        plonk::config::{GenericConfig, GenericHashOut, PoseidonGoldilocksConfig},
    };
    use plonky2_ecgfp5::curve::curve::{Point, WeierstrassPoint};
    use std::array::from_fn as create_array;
    use values_extraction::public_inputs::tests::new_extraction_public_inputs;

    pub const D: usize = 2;
    pub type C = PoseidonGoldilocksConfig;
    pub type F = <C as GenericConfig<D>>::F;

    #[derive(Clone, Debug)]
    struct TestBaseCircuit {
        pis: ProofsPi,
        circuit: BaseCircuit,
    }

    struct TestBaseWires {
        pis: ProofsPiTarget,
        base: BaseWires,
    }

    impl UserCircuit<GoldilocksField, 2> for TestBaseCircuit {
        type Wires = TestBaseWires;
        fn build(c: &mut CircuitBuilder<GoldilocksField, 2>) -> Self::Wires {
            let proofs_pi = ProofsPiTarget::new(c);
            let base_wires = BaseCircuit::build(
                c,
                &proofs_pi.blocks_pi,
                &proofs_pi.contract_pi,
                &proofs_pi.values_pi,
            );
            TestBaseWires {
                base: base_wires,
                pis: proofs_pi,
            }
        }
        fn prove(&self, pw: &mut PartialWitness<GoldilocksField>, wires: &Self::Wires) {
            self.circuit.assign(pw, &wires.base);
            wires.pis.assign(pw, &self.pis);
        }
    }

    #[derive(Clone, Debug)]
    pub(crate) struct ProofsPiTarget {
        pub(crate) blocks_pi: Vec<Target>,
        pub(crate) contract_pi: Vec<Target>,
        pub(crate) values_pi: Vec<Target>,
    }

    impl ProofsPiTarget {
        pub(crate) fn new(b: &mut CircuitBuilder<GFp, 2>) -> Self {
            Self {
                blocks_pi: b.add_virtual_targets(
                    block_extraction::public_inputs::PublicInputs::<Target>::TOTAL_LEN),
                contract_pi: b
                    .add_virtual_targets(contract_extraction::PublicInputs::<Target>::TOTAL_LEN),
                values_pi: b
                    .add_virtual_targets(values_extraction::PublicInputs::<Target>::TOTAL_LEN),
            }
        }
        pub(crate) fn assign(&self, pw: &mut PartialWitness<GFp>, pis: &ProofsPi) {
            pw.set_target_arr(&self.values_pi, &pis.values_pi.as_ref());
            pw.set_target_arr(&self.contract_pi, &pis.contract_pi.as_ref());
            pw.set_target_arr(&self.blocks_pi, &pis.blocks_pi.as_ref());
        }
    }

    #[derive(Clone, Debug)]
    pub(crate) struct ProofsPi {
        pub(crate) value_dm: Point,
        pub(crate) value_dv: Point,
        pub(crate) contract_dm: Point,
        pub(crate) blocks_pi: Vec<GFp>,
        pub(crate) contract_pi: Vec<GFp>,
        pub(crate) values_pi: Vec<GFp>,
    }

    impl ProofsPi {
        pub(crate) fn contract_inputs(&self) -> contract_extraction::PublicInputs<GFp> {
            contract_extraction::PublicInputs::from_slice(&self.contract_pi)
        }

        pub(crate) fn value_inputs(&self) -> values_extraction::PublicInputs<GFp> {
            values_extraction::PublicInputs::new(&self.values_pi)
        }

        pub(crate) fn random() -> Self {
            let value_h = HashOut::<GFp>::rand().to_bytes().pack(Endianness::Little);
            let key = random_vector(64);
            let ptr = usize::max_value();
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

            let h = &random_vector::<u32>(PACKED_HASH_LEN).to_fields();
            let contract_dm = Point::rand();
            let key = &random_vector::<u8>(MAX_KEY_NIBBLE_LEN).to_fields();
            let ptr = &GFp::NEG_ONE; // simulating end of MPT recursion
            let s = &value_h.to_fields();
            let contract_pi = contract_extraction::PublicInputs {
                h,
                dm: &contract_dm.to_weierstrass().to_fields(),
                k: key,
                t: ptr,
                s,
            }
            .to_vec();
            let block_number = U256::from(F::rand().to_canonical_u64()).to_fields();
            let block_hash = HashOut::<GFp>::rand().to_bytes().pack(Endianness::Little).to_fields();
            let parent_block_hash = HashOut::<GFp>::rand().to_bytes().pack(Endianness::Little).to_fields();
            let blocks_pi = block_extraction::public_inputs::PublicInputs {
                bh: &block_hash,
                prev_bh: &parent_block_hash,
                bn: &block_number,
                sh: h,
            }.to_vec();
            ProofsPi {
                contract_dm,
                value_dm,
                value_dv,
                blocks_pi,
                values_pi,
                contract_pi,
            }
        }
    }

    #[test]
    fn final_simple_value() -> Result<()> {
        let pis = ProofsPi::random();
        let test_circuit = TestBaseCircuit {
            pis,
            circuit: BaseCircuit {},
        };
        run_circuit::<F, D, C, _>(test_circuit);
        Ok(())
    }
}
