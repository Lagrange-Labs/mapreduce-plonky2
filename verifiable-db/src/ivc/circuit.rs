use ethers::types::U256;
use mp2_common::{
    group_hashing::CircuitBuilderGroupHashing,
    keccak::PACKED_HASH_LEN,
    poseidon::empty_poseidon_hash,
    public_inputs::PublicInputCommon,
    types::{HashOutput, CURVE_TARGET_LEN, VALUE_LEN},
    u256::{CircuitBuilderU256, UInt256Target, WitnessWriteU256},
    utils::{FromTargets, TargetsConnector, ToFields, ToTargets},
    D, F,
};
use plonky2::{
    hash::hash_types::{HashOut, HashOutTarget},
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::circuit_builder::CircuitBuilder,
};
use plonky2_crypto::u32::arithmetic_u32::CircuitBuilderU32;
use plonky2_ecgfp5::{
    curve::curve::Point,
    gadgets::curve::{CircuitBuilderEcGFp5, CurveTarget, PartialWitnessCurve},
};

struct IVCCircuit;

impl IVCCircuit {
    pub(crate) fn build(c: &mut CircuitBuilder<F, D>, block_pi: &[Target], prev_proof: &[Target]) {
        assert_eq!(
            prev_proof.len(),
            super::PublicInputs::<Target>::TOTAL_LEN + 1
        );
        let _true = c._true();
        let block_pi = crate::block_tree::PublicInputs::from_slice(block_pi);
        let prev_pi = super::PublicInputs::from_slice(prev_proof);

        // assert prev_proof.BH == new_block_proof.prev_block_hash
        //c.connect_targets(prev_pi.block_hash(), block_pi.prev_block_hash());

        // This is the original blockchain hash
        // assert prev_proof.H_i == new_block_proof.H_old
        c.connect_targets(prev_pi.merkle_hash(), block_pi.old_merkle_hash());
        // assert prev_proof.z_i + 1 == new_block_proof.block_number
        let big_one = c.one_u256();
        let (expected_zi, carry) = c.add_u256(&prev_pi.zi(), &big_one);
        // make sure there is no carry
        let small_zero = c.zero_u32();
        c.connect_u32(small_zero, carry);
        c.enforce_equal_u256(&expected_zi, &block_pi.index_value());
        // assert prev_proof.z_0 == new_block_proof.min
        c.enforce_equal_u256(&prev_pi.z0(), &block_pi.min_value());
        //assert prev_proof.M == new_block_proof.M
        c.connect_curve_points(
            prev_pi.metadata_set_digest(),
            block_pi.metadata_set_digest(),
        );

        // last public input is an indicator if this proof is the first one on the IVC module_path!()
        // or not. 1 for the former case and 0 for the latter cases. Only the dummy circuit used
        // for the initial proof outputs 1.
        let zero = c.zero();
        // if is_dummy(prev_proof):
        //	    assert new_block_proof.H_old == H("")
        //	    assert prev_proof.DT == CURVE_ZERO
        //	the following should panic if public input is not of the right length
        let dummy_indicator = prev_proof[super::PublicInputs::<Target>::TOTAL_LEN];
        let is_this_first_proof = c.is_equal(dummy_indicator, zero);
        let empty_hash = c.constant_hash(*empty_poseidon_hash());
        let empty_set_digest = c.curve_zero();
        let cond1 = c.is_equal_targets(block_pi.old_merkle_hash(), empty_hash);
        let cond2 = c.is_equal_targets(prev_pi.value_set_digest(), empty_set_digest);
        let andded = c.and(cond1, cond2);
        let final_cond = c.select(is_this_first_proof, andded.target, _true.target);
        c.connect(final_cond, _true.target);

        // accumulate the order-agnostic digest of all the previously
        // inserted nodes with the one of the new node
        // expose prev_proof.DT + new_block_proof.new_node_digest as DT
        let new_value_set_digest =
            c.curve_add(prev_pi.value_set_digest(), block_pi.new_value_set_digest());
        super::PublicInputs::new(
            block_pi.new_merkle_hash_target().to_targets(),
            prev_pi.metadata_set_digest().to_targets(),
            new_value_set_digest.to_targets(),
            prev_pi.z0().to_targets(),
            block_pi.block_number.to_vec(),
            block_pi.current_block_hash(),
        )
        .register(c);
        // need to register the extra public input as 1 to indicate this is not the dummy proof
        // anymore
        let one = c.one();
        c.register_public_input(one);
    }
}

/// Dummy circuit holding the values that are given to the first block proof created.
/// The circuit takes care of exporting the right values such that when the proof is verified
/// inside the regular IVC circuits, the checks matches.
#[derive(Clone, Debug)]
struct DummyCircuit {
    metadata_set_digest: Point,
    z0: U256,
    block_hash: [F; PACKED_HASH_LEN],
}

struct DummyWires {
    md_set_digest: CurveTarget,
    z0: UInt256Target,
    block_hash: [Target; PACKED_HASH_LEN],
}

impl DummyCircuit {
    pub fn build(c: &mut CircuitBuilder<F, D>) -> DummyWires {
        let md = c.add_virtual_curve_target();
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
            empty_hash.to_targets(),
            md.to_targets(),
            value_set_digest.to_targets(),
            z0.to_targets(),
            zi.to_targets(),
            block_hash.to_vec(),
        )
        .register(c);
        // we also need to register the extra public input indicating this is the "first dummy
        // proof"
        let zero = c.zero();
        c.register_public_input(zero);
        DummyWires {
            md_set_digest: md,
            z0,
            block_hash,
        }
    }
    pub fn assign(&self, pw: &mut PartialWitness<F>, wires: &DummyWires) {
        // safety check, since we need to do -1 on it. It is anyway checked in the  main circuit
        // but easier to debug it already now.
        assert!(self.z0 != U256::zero());
        pw.set_curve_target(
            wires.md_set_digest,
            self.metadata_set_digest.to_weierstrass(),
        );
        pw.set_u256_target(&wires.z0, self.z0);
        pw.set_target_arr(&wires.block_hash, &self.block_hash);
    }
}

#[cfg(test)]
mod test {
    use std::ops::Sub;

    use ethers::types::U256;
    use mp2_common::{
        keccak::PACKED_HASH_LEN,
        poseidon::empty_poseidon_hash,
        utils::{FromFields, ToFields},
        C, D, F,
    };
    use mp2_test::{
        circuit::{run_circuit, UserCircuit},
        utils::random_vector,
    };
    use plonky2::{
        field::types::{Field, Sample},
        hash::hash_types::HashOut,
        iop::{target::Target, witness::WitnessWrite},
    };
    use plonky2_ecgfp5::curve::curve::Point;

    use rand::{thread_rng, Rng};

    use crate::{block_tree, ivc::circuit::DummyCircuit};

    use super::{super::PublicInputs as IVCPI, DummyWires, IVCCircuit};

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
        prev_pi: Vec<F>,
        block_pi: Vec<F>,
    }

    impl UserCircuit<F, D> for TestCircuit {
        type Wires = (Vec<Target>, Vec<Target>);

        fn build(c: &mut plonky2::plonk::circuit_builder::CircuitBuilder<F, D>) -> Self::Wires {
            let prev_pi =
                c.add_virtual_targets(super::super::PublicInputs::<Target>::TOTAL_LEN + 1);
            let block_pi =
                c.add_virtual_targets(crate::block_tree::PublicInputs::<Target>::TOTAL_LEN);
            IVCCircuit::build(c, &block_pi, &prev_pi);
            (prev_pi, block_pi)
        }

        fn prove(&self, pw: &mut plonky2::iop::witness::PartialWitness<F>, wires: &Self::Wires) {
            pw.set_target_arr(&wires.0, &self.prev_pi);
            pw.set_target_arr(&wires.1, &self.block_pi);
        }
    }

    #[test]
    fn ivc_circuit() {
        // block_pi
        let previous_merkle_root = HashOut::rand().to_fields();
        let new_merkle_root = HashOut::rand().to_fields();
        let [min, max, block_number] = [0; 3].map(|_| U256(thread_rng().gen::<[u64; 4]>()));
        let (minf, maxf, bnf) = (min.to_fields(), max.to_fields(), block_number.to_fields());
        let block_hash = [0; PACKED_HASH_LEN].map(|_| F::rand());
        let prev_block_hash = [0; PACKED_HASH_LEN].map(|_| F::rand());
        let msd = Point::rand();
        let metadata_set_digest = msd.to_fields();
        let value_set_digest = Point::rand().to_fields();
        let block_pi = block_tree::PublicInputs::new(
            &new_merkle_root,
            &previous_merkle_root,
            &minf,
            &maxf,
            &bnf,
            &block_hash,
            &prev_block_hash,
            &metadata_set_digest,
            &value_set_digest,
        );

        // previous ivc_pi
        let z0 = min;
        // previous block number
        let zi = block_number.sub(U256::one());
        let previous_value_set_digest = Point::rand().to_fields();
        // First case where we  construct a ivc pi which is not designated as the dummy first one
        let prev_pi = IVCPI::new(
            previous_merkle_root.clone(),
            metadata_set_digest.clone(),
            previous_value_set_digest.clone(),
            z0.to_fields(),
            zi.to_fields(),
            prev_block_hash.to_vec(),
        );
        let mut prev_pi_field = prev_pi.to_vec();
        // add an extra public input to designate this is not the initial proof
        prev_pi_field.push(F::ONE);
        assert_eq!(
            prev_pi_field.len(),
            super::super::PublicInputs::<Target>::TOTAL_LEN + 1
        );
        let tc = TestCircuit {
            prev_pi: prev_pi_field.to_vec(),
            block_pi: block_pi.to_vec(),
        };
        assert_eq!(
            tc.block_pi.len(),
            crate::block_tree::PublicInputs::<F>::TOTAL_LEN
        );
        assert!(tc.prev_pi.len() == super::super::PublicInputs::<F>::TOTAL_LEN + 1);
        let proof = run_circuit::<F, D, C, _>(tc);
        let pi = super::super::PublicInputs::from_slice(&proof.public_inputs);
        {
            assert_eq!(pi.merkle_root_hash_fields().to_fields(), new_merkle_root);
            assert_eq!(
                pi.metadata_set_digest_point().to_fields(),
                metadata_set_digest
            );
            let exp_set_digest = Point::from_fields(&previous_value_set_digest)
                + Point::from_fields(&value_set_digest);
            assert_eq!(
                pi.value_set_digest_point().to_fields(),
                exp_set_digest.to_fields()
            );
            assert_eq!(pi.z0_u256(), z0);
            assert_eq!(pi.zi_u256(), block_number);
            assert_eq!(pi.original_hash(), block_hash);
        }

        //
        //
        // --------------------------------------------------------
        // Second case where we construct a ivc pi which is the dummy proof
        // we set min = max = block_number, and hash = empty, and zi = z0-1
        let dummy_circuit = DummyCircuit {
            // we expose the previous block hash, that is not "proved" in our system
            block_hash: prev_block_hash,
            metadata_set_digest: msd,
            z0,
        };
        let proof = run_circuit::<F, D, C, _>(dummy_circuit);
        let prev_pi = proof.public_inputs;
        assert_eq!(
            prev_pi.len(),
            super::super::PublicInputs::<F>::TOTAL_LEN + 1
        );

        let empty_hash = empty_poseidon_hash().to_fields();
        let block_pi = block_tree::PublicInputs::new(
            &new_merkle_root,
            &empty_hash,
            &minf,
            &minf,
            &minf,
            &block_hash,
            &prev_block_hash,
            &metadata_set_digest,
            &value_set_digest,
        );

        let tc = TestCircuit {
            prev_pi: prev_pi.to_vec(),
            block_pi: block_pi.to_vec(),
        };
        assert_eq!(
            tc.block_pi.len(),
            crate::block_tree::PublicInputs::<F>::TOTAL_LEN
        );
        assert_eq!(
            tc.prev_pi.len(),
            super::super::PublicInputs::<F>::TOTAL_LEN + 1
        );
        let proof = run_circuit::<F, D, C, _>(tc);
        let pi = super::super::PublicInputs::from_slice(&proof.public_inputs);
        {
            assert_eq!(pi.merkle_root_hash_fields().to_fields(), new_merkle_root);
            assert_eq!(
                pi.metadata_set_digest_point().to_fields(),
                metadata_set_digest
            );
            let exp_set_digest = Point::from_fields(&value_set_digest);
            assert_eq!(
                pi.value_set_digest_point().to_fields(),
                exp_set_digest.to_fields()
            );
            assert_eq!(pi.z0_u256(), z0);
            assert_eq!(pi.zi_u256(), min);
            assert_eq!(pi.original_hash(), block_hash);
        }
    }
}
