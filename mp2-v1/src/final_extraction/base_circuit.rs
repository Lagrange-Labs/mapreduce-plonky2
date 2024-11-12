use itertools::Itertools;
use mp2_common::{
    default_config,
    group_hashing::CircuitBuilderGroupHashing,
    keccak::PACKED_HASH_LEN,
    proof::{deserialize_proof, verify_proof_fixed_circuit, ProofWithVK},
    serialization::{deserialize, serialize},
    u256::UInt256Target,
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
use recursion_framework::framework::{
    RecursiveCircuits, RecursiveCircuitsVerifierGagdet, RecursiveCircuitsVerifierTarget,
};
use serde::{Deserialize, Serialize};

use crate::{block_extraction, contract_extraction, values_extraction};

use super::api::FinalExtractionBuilderParams;

use anyhow::Result;

/// This circuit is more like a gadget. This contains the logic of the common part
/// between all the final extraction circuits. It should not be used on its own.
#[derive(Debug, Clone)]
pub struct BaseCircuit {}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaseWires {
    #[serde(serialize_with = "serialize", deserialize_with = "deserialize")]
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
        value_pis: Vec<&[Target]>,
    ) -> BaseWires {
        // TODO: homogeinize the public inputs structs
        let block_pi =
            block_extraction::public_inputs::PublicInputs::<Target>::from_slice(block_pi);
        let value_pis = value_pis
            .iter()
            .map(|i| values_extraction::PublicInputs::<Target>::new(i))
            .collect_vec();

        let contract_pi = contract_extraction::PublicInputs::<Target>::from_slice(contract_pi);

        let minus_one = b.constant(GoldilocksField::NEG_ONE);
        for value_pi in value_pis.iter() {
            // enforce the MPT key extraction reached the root
            b.connect(value_pi.mpt_key().pointer, minus_one);

            // enforce contract_pi.storage_root == value_pi.storage_root
            contract_pi
                .storage_root()
                .enforce_equal(b, &value_pi.root_hash_target());
        }
        b.connect(contract_pi.mpt_key().pointer, minus_one);

        let mut base_dm = value_pis[0].metadata_digest_target();
        for vp in value_pis.iter().skip(1) {
            base_dm = b.add_curve_point(&[base_dm, vp.metadata_digest_target()]);
        }
        let final_dm = b.add_curve_point(&[base_dm, contract_pi.metadata_digest()]);

        // enforce block_pi.state_root == contract_pi.state_root
        block_pi
            .state_root()
            .enforce_equal(b, &contract_pi.root_hash());
        BaseWires {
            dm: final_dm,
            bh: block_pi.block_hash_raw().try_into().unwrap(), // safe to unwrap as we give as input the slice of the expected length
            prev_bh: block_pi.prev_block_hash_raw().try_into().unwrap(), // safe to unwrap as we give as input the slice of the expected length
            bn: block_pi.block_number(),
        }
    }
    #[cfg(test)]
    pub(crate) fn assign(&self, _pw: &mut PartialWitness<GoldilocksField>, _wires: &BaseWires) {}
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
    value_proof: Vec<RecursiveCircuitsVerifierTarget<D>>,
}

pub(crate) const CONTRACT_SET_NUM_IO: usize = contract_extraction::PublicInputs::<F>::TOTAL_LEN;
pub(crate) const VALUE_SET_NUM_IO: usize = values_extraction::PublicInputs::<F>::TOTAL_LEN;
// CHORE: Remove this when relevant PR is merged
#[allow(dead_code)]
pub(crate) const BLOCK_SET_NUM_IO: usize =
    block_extraction::public_inputs::PublicInputs::<F>::TOTAL_LEN;

#[derive(Clone, Debug)]
pub struct BaseCircuitInput {
    block_proof: ProofWithPublicInputs<F, C, D>,
    contract_proof: ProofWithVK,
    value_proofs: Vec<ProofWithVK>,
}

impl BaseCircuitInput {
    pub(super) fn new(
        block_proof: Vec<u8>,
        contract_proof: Vec<u8>,
        value_proofs: Vec<Vec<u8>>,
    ) -> Result<Self> {
        Ok(Self {
            block_proof: deserialize_proof(&block_proof)?,
            contract_proof: ProofWithVK::deserialize(&contract_proof)?,
            value_proofs: value_proofs
                .iter()
                .map(|p| ProofWithVK::deserialize(p))
                .collect::<Result<Vec<_>>>()?,
        })
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
        nb_values_proofs: usize,
    ) -> BaseCircuitProofWires {
        let config = default_config();
        let contract_verifier =
            RecursiveCircuitsVerifierGagdet::<F, C, D, CONTRACT_SET_NUM_IO>::new(
                config.clone(),
                &params.contract_circuit_set,
            );
        let value_wires = (0..nb_values_proofs)
            .map(|_| {
                let verifier = RecursiveCircuitsVerifierGagdet::<F, C, D, VALUE_SET_NUM_IO>::new(
                    config.clone(),
                    &params.value_circuit_set,
                );
                verifier.verify_proof_in_circuit_set(cb)
            })
            .collect();
        let contract_proof_wires = contract_verifier.verify_proof_in_circuit_set(cb);
        let block_proof_wires = verify_proof_fixed_circuit(cb, &params.block_vk);
        BaseCircuitProofWires {
            block_proof: block_proof_wires,
            contract_proof: contract_proof_wires,
            value_proof: value_wires,
        }
    }

    pub(crate) fn assign_proof_targets(
        &self,
        pw: &mut PartialWitness<F>,
        wires: &BaseCircuitProofWires,
    ) -> anyhow::Result<()> {
        pw.set_proof_with_pis_target(&wires.block_proof, &self.proofs.block_proof);
        let (proof, vd) = (&self.proofs.contract_proof).into();
        wires
            .contract_proof
            .set_target(pw, &self.contract_circuit_set, proof, vd)?;
        for (w, proof) in wires
            .value_proof
            .iter()
            .zip(self.proofs.value_proofs.iter())
        {
            let (p, vd) = proof.into();
            w.set_target(pw, &self.value_circuit_set, p, vd)?;
        }
        Ok(())
    }
}

impl BaseCircuitProofWires {
    pub(crate) fn get_block_public_inputs(&self) -> &[Target] {
        self.block_proof.public_inputs.as_slice()
    }

    pub(crate) fn get_contract_public_inputs(&self) -> &[Target] {
        self.contract_proof
            .get_public_input_targets::<F, CONTRACT_SET_NUM_IO>()
    }

    /// Assume there is at least one entry and returns the first one
    pub(crate) fn get_value_public_inputs(&self) -> &[Target] {
        self.value_proof[0].get_public_input_targets::<F, VALUE_SET_NUM_IO>()
    }
    pub(crate) fn get_value_public_inputs_at(&self, idx: usize) -> &[Target] {
        self.value_proof[idx].get_public_input_targets::<F, VALUE_SET_NUM_IO>()
    }
}

#[cfg(test)]
pub(crate) mod test {
    use std::iter::once;

    use crate::{final_extraction::PublicInputs, length_extraction};

    use super::*;
    use alloy::primitives::U256;
    use anyhow::Result;
    use itertools::Itertools;
    use mp2_common::{
        digest::TableDimension,
        group_hashing::map_to_curve_point,
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
    use plonky2_ecgfp5::curve::curve::{Point, WeierstrassPoint};
    use values_extraction::public_inputs::tests::new_extraction_public_inputs;

    #[derive(Clone, Debug)]
    struct TestBaseCircuit {
        pis: ProofsPi,
        circuit: BaseCircuit,
    }

    struct TestBaseWires {
        pis: ProofsPiTarget,
        base: BaseWires,
    }

    impl UserCircuit<F, D> for TestBaseCircuit {
        type Wires = TestBaseWires;
        fn build(c: &mut CircuitBuilder<F, D>) -> Self::Wires {
            let proofs_pi = ProofsPiTarget::new(c);
            let base_wires = BaseCircuit::build(
                c,
                &proofs_pi.blocks_pi,
                &proofs_pi.contract_pi,
                vec![&proofs_pi.values_pi],
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
        pub(crate) fn new(b: &mut CircuitBuilder<F, D>) -> Self {
            Self {
                blocks_pi: b.add_virtual_targets(
                    block_extraction::public_inputs::PublicInputs::<Target>::TOTAL_LEN,
                ),
                contract_pi: b
                    .add_virtual_targets(contract_extraction::PublicInputs::<Target>::TOTAL_LEN),
                values_pi: b
                    .add_virtual_targets(values_extraction::PublicInputs::<Target>::TOTAL_LEN),
            }
        }
        pub(crate) fn assign(&self, pw: &mut PartialWitness<F>, pis: &ProofsPi) {
            pw.set_target_arr(&self.values_pi, pis.values_pi.as_ref());
            pw.set_target_arr(&self.contract_pi, pis.contract_pi.as_ref());
            pw.set_target_arr(&self.blocks_pi, pis.blocks_pi.as_ref());
        }
    }

    /// TODO: refactor this struct to mimick exactly the base circuit wires in that it can contain
    /// multiple values
    #[derive(Clone, Debug)]
    pub(crate) struct ProofsPi {
        pub(crate) blocks_pi: Vec<F>,
        pub(crate) contract_pi: Vec<F>,
        pub(crate) values_pi: Vec<F>,
    }

    impl ProofsPi {
        /// Returns the same blocks and contract pi but with a new values pi that share the same
        /// contract and block information, i.e. the base circuit checks pass with both values for
        /// the same contract and block pis
        /// Essentially, the value pi returned contains a different value and metadata digest, the
        /// rest is the same
        pub(crate) fn generate_new_random_value(&self) -> ProofsPi {
            let original = values_extraction::PublicInputs::new(&self.values_pi);
            let (k, t) = original.mpt_key_info();
            let new_value_digest = Point::rand();
            let new_metadata_digest = Point::rand();
            let new_values_pi = original
                .root_hash_info()
                .iter()
                .chain(k.iter())
                .chain(once(&t))
                .chain(new_value_digest.to_weierstrass().to_fields().iter())
                .chain(new_metadata_digest.to_weierstrass().to_fields().iter())
                .chain(once(&original.n()))
                .cloned()
                .collect_vec();
            Self {
                blocks_pi: self.blocks_pi.clone(),
                contract_pi: self.contract_pi.clone(),
                values_pi: new_values_pi,
            }
        }
        pub(crate) fn contract_inputs(&self) -> contract_extraction::PublicInputs<F> {
            contract_extraction::PublicInputs::from_slice(&self.contract_pi)
        }

        pub(crate) fn block_inputs(&self) -> block_extraction::PublicInputs<F> {
            block_extraction::PublicInputs::from_slice(&self.blocks_pi)
        }

        pub(crate) fn value_inputs(&self) -> values_extraction::PublicInputs<F> {
            values_extraction::PublicInputs::new(&self.values_pi)
        }

        pub(crate) fn length_inputs(&self) -> Vec<F> {
            let value_pi = self.value_inputs();
            // construction of length extract public inputs
            let h = value_pi.root_hash_info(); // same hash as value root
            let len_dm = Point::rand();
            let key = random_vector(64)
                .into_iter()
                .map(F::from_canonical_u8)
                .collect_vec();
            let ptr = F::NEG_ONE;
            let n = value_pi.n(); // give same length
            let len_dm_fields = len_dm.to_weierstrass().to_fields();
            length_extraction::PublicInputs::<F>::from_parts(h, &len_dm_fields, &key, &ptr, &n)
                .to_vec()
        }
        /// check public inputs of the proof match with the ones in `self`.
        /// `compound_type` is a flag to specify whether `proof` is generated for a simple or compound type
        /// `length_dm` is the metadata digest of a length proof, which is provided only for proofs related
        /// to a compound type with a length slot
        pub(crate) fn check_proof_public_inputs(
            &self,
            proof: &ProofWithPublicInputs<F, C, D>,
            dimension: TableDimension,
            length_dm: Option<WeierstrassPoint>,
        ) {
            let proof_pis = PublicInputs::from_slice(&proof.public_inputs);
            let block_pi =
                block_extraction::public_inputs::PublicInputs::from_slice(&self.blocks_pi);
            assert_eq!(proof_pis.bn, block_pi.bn);
            assert_eq!(proof_pis.h, block_pi.bh);
            assert_eq!(proof_pis.ph, block_pi.prev_bh);

            // check digests
            let value_pi = values_extraction::PublicInputs::new(&self.values_pi);
            if let TableDimension::Compound = dimension {
                assert_eq!(proof_pis.value_point(), value_pi.values_digest());
            } else {
                // in this case, dv is D(value_dv)
                let exp_dv = map_to_curve_point(&value_pi.values_digest().to_fields());
                assert_eq!(proof_pis.value_point(), exp_dv.to_weierstrass());
            }
            // metadata is addition of contract and value
            // ToDo: make it a trait once we understand it's sound
            let weierstrass_to_point = |wp: WeierstrassPoint| {
                Point::decode(wp.encode()).inspect(|p| {
                    // safety-check
                    assert_eq!(p.to_weierstrass(), wp);
                })
            };
            let contract_pi = contract_extraction::PublicInputs::from_slice(&self.contract_pi);
            let contract_dm = weierstrass_to_point(contract_pi.metadata_point()).unwrap();
            let value_dm = weierstrass_to_point(value_pi.metadata_digest()).unwrap();
            let expected_dm = if let Some(len_dm) = length_dm {
                let len_dm = weierstrass_to_point(len_dm).unwrap();
                contract_dm + value_dm + len_dm
            } else {
                contract_dm + value_dm
            };
            assert_eq!(proof_pis.metadata_point(), expected_dm.to_weierstrass());
        }

        pub(crate) fn random() -> Self {
            let value_h = HashOut::<F>::rand().to_bytes().pack(Endianness::Little);
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
            let ptr = &F::NEG_ONE; // simulating end of MPT recursion
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
                sh: h,
            }
            .to_vec();
            ProofsPi {
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
