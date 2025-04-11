use alloy::primitives::U256;
use itertools::Itertools;
use mp2_common::{
    default_config,
    keccak::PACKED_HASH_LEN,
    poseidon::{empty_poseidon_hash, flatten_poseidon_hash_target, HashPermutation},
    proof::ProofWithVK,
    public_inputs::PublicInputCommon,
    serialization::{deserialize, serialize},
    types::HashOutput,
    u256::{CircuitBuilderU256, UInt256Target, WitnessWriteU256},
    utils::{HashBuilder, TargetsConnector, ToFields, ToTargets},
    CHasher, C, D, F,
};
use plonky2::{
    field::types::Field,
    hash::{
        hash_types::{HashOut, HashOutTarget},
        hashing::hash_n_to_hash_no_pad,
    },
    iop::{
        target::{BoolTarget, Target},
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::circuit_builder::CircuitBuilder,
};
use plonky2_ecgfp5::gadgets::curve::CircuitBuilderEcGFp5;
use recursion_framework::{
    circuit_builder::CircuitLogicWires,
    framework::{
        RecursiveCircuits, RecursiveCircuitsVerifierGagdet, RecursiveCircuitsVerifierTarget,
    },
};
use serde::{Deserialize, Serialize};

const PROVABLE_DATA_COMMITMENT_PREFIX: &[u8] = b"DATA_COMMIT";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct IVCCircuit {
    pub(crate) provable_data_commitment: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct IVCCircuitWires {
    #[serde(serialize_with = "serialize", deserialize_with = "deserialize")]
    pub(crate) commit_to_data: BoolTarget,
}
/// Add data commitment constant prefix to the metadata hash
pub fn add_provable_data_commitment_prefix(metadata_hash: HashOutput) -> HashOutput {
    let hash = IVCCircuit::add_provable_data_commitment_prefix(HashOut::from(metadata_hash));
    HashOutput::from(hash)
}

impl IVCCircuit {
    fn build(
        c: &mut CircuitBuilder<F, D>,
        block_pi: &[Target],
        prev_proof: &[Target],
    ) -> IVCCircuitWires {
        assert_eq!(prev_proof.len(), super::NUM_IO);
        let _true = c._true();
        let block_pi = crate::block_tree::PublicInputs::from_slice(block_pi);
        let prev_pi = super::PublicInputs::from_slice(prev_proof);

        // accumulate the order-agnostic digest of all the previously
        // inserted nodes with the one of the new node
        // expose prev_proof.DT + new_block_proof.new_node_digest as DT
        let new_value_set_digest =
            c.curve_add(prev_pi.value_set_digest(), block_pi.new_value_set_digest());
        // compute block hash as the hash of multiset digest of the table in case `commit_to_data` is true
        let data_hash = c.hash_n_to_hash_no_pad::<CHasher>(new_value_set_digest.to_targets());
        let flattened_hash = flatten_poseidon_hash_target(c, data_hash);
        let block_hash = block_pi.current_block_hash();
        // select between flattener hash and block hash depending on `commit_to_data` flag
        let commit_to_data = c.add_virtual_bool_target_safe();
        let commitment = flattened_hash
            .into_iter()
            .zip_eq(block_hash)
            .map(|(dh, bh)| c.select(commit_to_data, dh, bh))
            .collect_vec();

        // This is the original blockchain hash
        // assert prev_proof.BH == new_block_proof.prev_block_hash
        c.connect_targets(prev_pi.block_hash(), block_pi.prev_block_hash());

        // assert prev_proof.H_i == new_block_proof.H_old
        c.connect_targets(prev_pi.merkle_hash(), block_pi.old_merkle_hash());
        // assert prev_proof.z_0 == new_block_proof.min
        c.enforce_equal_u256(&prev_pi.z0(), &block_pi.min_value());
        // compute metadata hash for new block: we add the constant DATA_COMMITMENT_ID depending on
        // whether the exposed commitment is the commitment to the table data or not
        let hash_payload = block_pi
            .metadata_hash()
            .to_targets()
            .into_iter()
            .chain(
                PROVABLE_DATA_COMMITMENT_PREFIX
                    .iter()
                    .map(|b| c.constant(F::from_canonical_u8(*b))),
            )
            .collect_vec();
        let data_commit_metadata_hash = c.hash_n_to_hash_no_pad::<CHasher>(hash_payload);
        let metadata_hash = c.select_hash(
            commit_to_data,
            &data_commit_metadata_hash,
            &HashOutTarget::from_vec(block_pi.metadata_hash().to_vec()),
        );

        //assert prev_proof.M == new_block_proof.M
        c.connect_targets(prev_pi.metadata_hash(), &metadata_hash.to_targets());

        // if is_dummy(prev_proof):
        //	    assert new_block_proof.H_old == H("")
        //	    assert prev_proof.DT == CURVE_ZERO
        //
        // Indicator is if the previous proof exposes the empty hash as the merkle hash.
        let empty_hash = c.constant_hash(*empty_poseidon_hash());
        let is_this_first_proof = c.is_equal_targets(empty_hash, prev_pi.merkle_hash());
        let empty_set_digest = c.curve_zero();
        let cond1 = c.is_equal_targets(block_pi.old_merkle_hash(), empty_hash);
        let cond2 = c.is_equal_targets(prev_pi.value_set_digest(), empty_set_digest);
        let andded = c.and(cond1, cond2);
        let final_cond = c.select(is_this_first_proof, andded.target, _true.target);
        c.connect(final_cond, _true.target);

        super::PublicInputs::new(
            &block_pi.new_merkle_hash_target().to_targets(),
            prev_pi.metadata_hash(),
            &new_value_set_digest.to_targets(),
            &prev_pi.z0().to_targets(),
            block_pi.block_number,
            &commitment,
        )
        .register(c);

        IVCCircuitWires { commit_to_data }
    }

    fn assign(&self, pw: &mut PartialWitness<F>, wires: &IVCCircuitWires) {
        pw.set_bool_target(wires.commit_to_data, self.provable_data_commitment);
    }

    pub(crate) fn add_provable_data_commitment_prefix(mh: HashOut<F>) -> HashOut<F> {
        let inputs = mh
            .to_fields()
            .into_iter()
            .chain(
                PROVABLE_DATA_COMMITMENT_PREFIX
                    .iter()
                    .map(|b| F::from_canonical_u8(*b)),
            )
            .collect_vec();
        hash_n_to_hash_no_pad::<F, HashPermutation>(&inputs)
    }
}

pub(crate) const BLOCK_IO: usize = crate::block_tree::PublicInputs::<Target>::TOTAL_LEN;
#[derive(Serialize, Deserialize)]
pub struct RecursiveIVCWires {
    ivc: IVCCircuitWires,
    block_verifier: RecursiveCircuitsVerifierTarget<D>,
}

#[derive(Clone, Debug)]
pub struct RecursiveIVCInput {
    pub(crate) ivc: IVCCircuit,
    pub(crate) block_proof: ProofWithVK,
    pub(crate) block_set: RecursiveCircuits<F, C, D>,
}

impl CircuitLogicWires<F, D, 1> for RecursiveIVCWires {
    // to verify the block proof
    type CircuitBuilderParams = RecursiveCircuits<F, C, D>;

    type Inputs = RecursiveIVCInput;

    const NUM_PUBLIC_INPUTS: usize = super::NUM_IO;

    fn circuit_logic(
        builder: &mut CircuitBuilder<F, D>,
        verified_proofs: [&plonky2::plonk::proof::ProofWithPublicInputsTarget<D>; 1],
        builder_parameters: Self::CircuitBuilderParams,
    ) -> Self {
        let block_verifier = RecursiveCircuitsVerifierGagdet::<F, C, D, BLOCK_IO>::new(
            default_config(),
            &builder_parameters,
        );
        let block_verifier = block_verifier.verify_proof_in_circuit_set(builder);
        let block_pi = block_verifier.get_public_input_targets::<F, BLOCK_IO>();

        let prev_pi = Self::public_input_targets(verified_proofs[0]);
        let ivc = IVCCircuit::build(builder, block_pi, prev_pi);
        RecursiveIVCWires {
            ivc,
            block_verifier,
        }
    }

    fn assign_input(&self, inputs: Self::Inputs, pw: &mut PartialWitness<F>) -> anyhow::Result<()> {
        inputs.ivc.assign(pw, &self.ivc);
        let (proof, vd) = inputs.block_proof.into();
        self.block_verifier
            .set_target(pw, &inputs.block_set, &proof, &vd)?;
        Ok(())
    }
}

/// Dummy circuit holding the values that are given to the first block proof created.
/// The circuit takes care of exporting the right values such that when the proof is verified
/// inside the regular IVC circuits, the checks matches.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DummyCircuit {
    pub(crate) metadata_hash: HashOut<F>,
    pub(crate) z0: U256,
    pub(crate) block_hash: [F; PACKED_HASH_LEN],
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DummyWires {
    #[serde(serialize_with = "serialize", deserialize_with = "deserialize")]
    md_set_digest: HashOutTarget,
    z0: UInt256Target,
    block_hash: [Target; PACKED_HASH_LEN],
}

impl DummyCircuit {
    pub fn build(c: &mut CircuitBuilder<F, D>) -> DummyWires {
        let md = c.add_virtual_hash();
        let z0 = c.add_virtual_u256();
        // for first proof, zi = z0- 1
        // such that block_proof.zi = z0 so in circuit the check
        // block_proof.zi = block_proof.z0 = prev_pi.zi + 1 = (prev_pi.z0-1) + 1
        // passes
        let big_one = c.one_u256();
        // we enforce it's not  overflowing  in the main circuit
        let (zi, _) = c.sub_u256(&z0, &big_one);
        let empty_hash_f = empty_poseidon_hash();
        let empty_hash = c.constant_hash(*empty_hash_f);
        let block_hash = c.add_virtual_target_arr();
        let value_set_digest = c.curve_zero();
        super::PublicInputs::new(
            &empty_hash.to_targets(),
            &md.to_targets(),
            &value_set_digest.to_targets(),
            &z0.to_targets(),
            &zi.to_targets(),
            &block_hash,
        )
        .register(c);
        DummyWires {
            md_set_digest: md,
            z0,
            block_hash,
        }
    }
    pub fn assign(&self, pw: &mut PartialWitness<F>, wires: &DummyWires) {
        // safety check, since we need to do -1 on it. It is anyway checked in the  main circuit
        // but easier to debug it already now.
        assert!(self.z0 != U256::ZERO);
        pw.set_hash_target(wires.md_set_digest, self.metadata_hash);
        pw.set_u256_target(&wires.z0, self.z0);
        pw.set_target_arr(&wires.block_hash, &self.block_hash);
    }
}

impl CircuitLogicWires<F, D, 0> for DummyWires {
    type CircuitBuilderParams = ();

    type Inputs = DummyCircuit;

    const NUM_PUBLIC_INPUTS: usize = super::NUM_IO;

    fn circuit_logic(
        builder: &mut CircuitBuilder<F, D>,
        _verified_proofs: [&plonky2::plonk::proof::ProofWithPublicInputsTarget<D>; 0],
        _builder_parameters: Self::CircuitBuilderParams,
    ) -> Self {
        DummyCircuit::build(builder)
    }

    fn assign_input(&self, inputs: Self::Inputs, pw: &mut PartialWitness<F>) -> anyhow::Result<()> {
        inputs.assign(pw, self);
        Ok(())
    }
}

#[cfg(test)]
pub(super) mod test {

    use anyhow::Result;

    use alloy::primitives::U256;
    use mp2_common::{
        group_hashing::weierstrass_to_point,
        poseidon::{empty_poseidon_hash, flatten_poseidon_hash_value, HashPermutation},
        utils::ToFields,
        C, D, F,
    };
    use mp2_test::circuit::{run_circuit, UserCircuit};
    use plonky2::{
        hash::{hash_types::HashOut, hashing::hash_n_to_hash_no_pad},
        iop::{target::Target, witness::WitnessWrite},
    };

    use plonky2_ecgfp5::curve::curve::Point;
    use rand::{thread_rng, Rng};

    use crate::{block_tree::tests::random_block_index_pi, ivc::circuit::DummyCircuit};

    use super::{super::PublicInputs as IVCPI, DummyWires, IVCCircuit, IVCCircuitWires};

    impl UserCircuit<F, D> for DummyCircuit {
        type Wires = DummyWires;

        fn build(c: &mut plonky2::plonk::circuit_builder::CircuitBuilder<F, D>) -> Self::Wires {
            DummyCircuit::build(c)
        }

        fn prove(&self, pw: &mut plonky2::iop::witness::PartialWitness<F>, wires: &Self::Wires) {
            self.assign(pw, wires)
        }
    }

    #[derive(Debug, Clone)]
    struct TestCircuit {
        c: IVCCircuit,
        prev_pi: Vec<F>,
        block_pi: Vec<F>,
    }

    impl UserCircuit<F, D> for TestCircuit {
        type Wires = (Vec<Target>, Vec<Target>, IVCCircuitWires);

        fn build(c: &mut plonky2::plonk::circuit_builder::CircuitBuilder<F, D>) -> Self::Wires {
            let prev_pi = c.add_virtual_targets(super::super::NUM_IO);
            let block_pi =
                c.add_virtual_targets(crate::block_tree::PublicInputs::<Target>::TOTAL_LEN);
            let ivc = IVCCircuit::build(c, &block_pi, &prev_pi);
            (prev_pi, block_pi, ivc)
        }

        fn prove(&self, pw: &mut plonky2::iop::witness::PartialWitness<F>, wires: &Self::Wires) {
            pw.set_target_arr(&wires.0, &self.prev_pi);
            pw.set_target_arr(&wires.1, &self.block_pi);
            self.c.assign(pw, &wires.2);
        }
    }

    pub(crate) fn compute_data_commitment(value_digest: &Point) -> HashOut<F> {
        let inputs = value_digest.to_fields();
        hash_n_to_hash_no_pad::<F, HashPermutation>(&inputs)
    }

    #[test]
    fn ivc_circuit() -> Result<()> {
        let rng = &mut thread_rng();
        // block_pi
        let [min, max, block_number] = [0; 3].map(|_| U256::from_limbs(rng.gen::<[u64; 4]>()));
        let minf: Vec<F> = min.to_fields();
        let block_pi = random_block_index_pi(rng, min, max, block_number);
        let block_pi = crate::block_tree::PublicInputs::from_slice(&block_pi);
        // previous ivc_pi
        let z0 = min;
        // previous block number
        let zi = block_number - U256::from(1);
        let (z0f, zif) = (z0.to_fields(), zi.to_fields());
        // First case where we  construct a ivc pi which is not designated as the dummy first one
        let commit_to_data = rng.gen();
        let expected_metadata_hash = if commit_to_data {
            IVCCircuit::add_provable_data_commitment_prefix(HashOut::from_partial(
                block_pi.metadata_hash(),
            ))
            .to_fields()
        } else {
            block_pi.metadata_hash().to_vec()
        };
        let prev_pi = IVCPI::new(
            // since this is the previous proof, we put the previous merkle root
            block_pi.h_old,
            &expected_metadata_hash,
            block_pi.new_node_digest,
            &z0f,
            &zif,
            // since this is the previous proof, we put the previous blockchain hash
            block_pi.prev_block_hash,
        );
        let prev_pi_field = prev_pi.to_vec();
        assert_eq!(prev_pi_field.len(), crate::ivc::NUM_IO);
        let tc = TestCircuit {
            c: IVCCircuit {
                provable_data_commitment: commit_to_data,
            },
            prev_pi: prev_pi_field.to_vec(),
            block_pi: block_pi.to_vec(),
        };
        assert_eq!(
            tc.block_pi.len(),
            crate::block_tree::PublicInputs::<F>::TOTAL_LEN
        );
        assert!(tc.prev_pi.len() == crate::ivc::NUM_IO);
        let proof = run_circuit::<F, D, C, _>(tc);
        let pi = super::super::PublicInputs::from_slice(&proof.public_inputs);
        {
            assert_eq!(
                pi.merkle_root_hash_fields(),
                block_pi.new_merkle_hash_field()
            );
            assert_eq!(pi.metadata_hash(), &expected_metadata_hash,);
            // adding the previous value digest with the new block proof value digest
            let exp_set_digest = weierstrass_to_point(&prev_pi.value_set_digest_point())
                + weierstrass_to_point(&block_pi.new_value_set_digest_point());
            assert_eq!(
                pi.value_set_digest_point().to_fields(),
                exp_set_digest.to_fields()
            );
            assert_eq!(pi.z0_u256(), z0);
            assert_eq!(pi.zi_u256(), block_number);
            assert_eq!(
                pi.block_hash_fields(),
                if commit_to_data {
                    flatten_poseidon_hash_value(compute_data_commitment(&exp_set_digest))
                } else {
                    block_pi.block_hash()
                }
            );
        }

        //
        //
        // --------------------------------------------------------
        // Second case where we construct a ivc pi which is the dummy proof
        // we set min = max = block_number, and hash = empty, and zi = z0-1
        let commit_to_data = rng.gen();
        let expected_metadata_hash = if commit_to_data {
            IVCCircuit::add_provable_data_commitment_prefix(HashOut::from_partial(
                block_pi.metadata_hash(),
            ))
            .to_fields()
        } else {
            block_pi.metadata_hash().to_vec()
        };
        let dummy_circuit = DummyCircuit {
            // we expose the previous block hash, that is not "proved" in our system
            block_hash: block_pi.prev_block_hash_fields(),
            metadata_hash: HashOut::try_from(expected_metadata_hash.as_slice())?,
            z0,
        };
        let proof = run_circuit::<F, D, C, _>(dummy_circuit);
        let prev_pi = proof.public_inputs;
        assert_eq!(prev_pi.len(), crate::ivc::NUM_IO);

        let empty_hash = empty_poseidon_hash().to_fields();
        let block_pi = crate::block_tree::PublicInputs::new(
            block_pi.h_new,
            &empty_hash,
            &minf,
            &minf,
            &minf,
            block_pi.block_hash,
            block_pi.prev_block_hash,
            block_pi.metadata_hash(),
            block_pi.new_node_digest,
        );
        let tc = TestCircuit {
            c: IVCCircuit {
                provable_data_commitment: commit_to_data,
            },
            prev_pi: prev_pi.to_vec(),
            block_pi: block_pi.to_vec(),
        };
        assert_eq!(
            tc.block_pi.len(),
            crate::block_tree::PublicInputs::<F>::TOTAL_LEN
        );
        assert_eq!(tc.prev_pi.len(), crate::ivc::NUM_IO);
        let proof = run_circuit::<F, D, C, _>(tc);
        let pi = super::super::PublicInputs::from_slice(&proof.public_inputs);
        {
            assert_eq!(
                pi.merkle_root_hash_fields(),
                block_pi.new_merkle_hash_field()
            );
            assert_eq!(pi.metadata_hash(), &expected_metadata_hash);
            assert_eq!(
                pi.value_set_digest_point(),
                block_pi.new_value_set_digest_point()
            );
            assert_eq!(pi.z0_u256(), z0);
            assert_eq!(pi.zi_u256(), min);
            assert_eq!(
                pi.block_hash_fields(),
                if commit_to_data {
                    flatten_poseidon_hash_value(compute_data_commitment(&weierstrass_to_point(
                        &block_pi.new_value_set_digest_point(),
                    )))
                } else {
                    block_pi.block_hash()
                }
            );
        }
        Ok(())
    }
}
