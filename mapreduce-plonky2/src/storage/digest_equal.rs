use super::{
    length_match::PublicInputs as MPTPublicInputs, merkle::PublicInputs as MerklePublicInputs,
};
use crate::{
    group_hashing::CircuitBuilderGroupHashing,
    keccak::{OutputHash, PACKED_HASH_LEN},
    utils::{transform_to_curve_point, PackedAddressTarget, PACKED_ADDRESS_LEN},
};
use plonky2::{
    field::goldilocks_field::GoldilocksField,
    iop::target::{BoolTarget, Target},
    plonk::circuit_builder::CircuitBuilder,
};
use plonky2_ecgfp5::gadgets::{
    base_field::QuinticExtensionTarget,
    curve::{CircuitBuilderEcGFp5, CurveTarget},
};

/// This is a wrapper around an array of targets set as public inputs of any
/// proof generated in this module. They all share the same structure.
/// `D` Digest of all the values processed
/// `C1` MPT root of blockchain storage trie
/// `C2` Merkle root of LPN’s storage database (merkle tree)
/// `A` Address of smart contract
/// `M` Storage slot of the mapping
/// `S` Storage slot of the variable holding the length
#[derive(Clone, Debug)]
pub struct PublicInputs<'a, T: Clone> {
    pub(crate) proof_inputs: &'a [T],
}

impl<'a> PublicInputs<'a, Target> {
    pub fn register(
        cb: &mut CircuitBuilder<GoldilocksField, 2>,
        digest: &CurveTarget,
        mpt_root_hash: &OutputHash,
        merkle_root_hash: &OutputHash,
        contract_address: &PackedAddressTarget,
        mapping_slot: Target,
        length_slot: Target,
    ) {
        cb.register_curve_public_input(*digest);
        mpt_root_hash.register_as_input(cb);
        merkle_root_hash.register_as_input(cb);
        contract_address.register_as_input(cb);
        cb.register_public_input(mapping_slot);
        cb.register_public_input(length_slot);
    }

    /// Return the curve point target of digest defined over the public inputs.
    pub fn digest(&self) -> CurveTarget {
        let (x, y, is_inf) = self.digest_data();

        let x = QuinticExtensionTarget(x);
        let y = QuinticExtensionTarget(y);
        let flag = BoolTarget::new_unsafe(is_inf);

        CurveTarget(([x, y], flag))
    }
}

impl<'a, T: Copy> PublicInputs<'a, T> {
    /// `D` Digest of all the values processed
    /// `C1` MPT root of blockchain storage trie
    /// `C2` Merkle root of LPN’s storage database (merkle tree)
    /// `A` Address of smart contract
    /// `M` Storage slot of the mapping
    /// `S` Storage slot of the variable holding the length
    const D_IDX: usize = 0;
    const C1_IDX: usize = Self::D_IDX + 11; // 5*2+1 for curve target
    const C2_IDX: usize = Self::C1_IDX + PACKED_HASH_LEN;
    const A_IDX: usize = Self::C2_IDX + PACKED_HASH_LEN;
    const M_IDX: usize = Self::A_IDX + PACKED_ADDRESS_LEN;
    const S_IDX: usize = Self::M_IDX + 1;
    pub(crate) const TOTAL_LEN: usize = Self::S_IDX + 1;

    pub fn from(arr: &'a [T]) -> Self {
        Self { proof_inputs: arr }
    }

    /// Transform a list of elements to a curve point.
    pub fn digest_data(&self) -> ([T; 5], [T; 5], T) {
        transform_to_curve_point(&self.proof_inputs[Self::D_IDX..])
    }

    pub fn mpt_root_hash(&self) -> &[T] {
        &self.proof_inputs[Self::C1_IDX..Self::C2_IDX]
    }

    pub fn merkle_root_hash(&self) -> &[T] {
        &self.proof_inputs[Self::C2_IDX..Self::A_IDX]
    }

    pub fn contract_address(&self) -> &[T] {
        &self.proof_inputs[Self::A_IDX..Self::M_IDX]
    }

    pub fn mapping_slot(&self) -> T {
        self.proof_inputs[Self::M_IDX]
    }

    pub fn length_slot(&self) -> T {
        self.proof_inputs[Self::S_IDX]
    }
}

/// Digest equivalence circuit
#[derive(Clone, Debug)]
struct DigestEqualCircuit;

impl DigestEqualCircuit {
    /// Build for circuit.
    pub fn build(
        cb: &mut CircuitBuilder<GoldilocksField, 2>,
        mpt_pi: &[Target],
        merkle_pi: &[Target],
    ) {
        let mpt_pi = MPTPublicInputs::from(mpt_pi);
        let merkle_pi = MerklePublicInputs::from(merkle_pi);

        // Constrain both digests are equal.
        let mpt_digest = mpt_pi.digest();
        let merkle_digest = merkle_pi.digest();
        cb.connect_curve_points(mpt_digest, merkle_digest);

        // Register the public inputs.
        PublicInputs::register(
            cb,
            &mpt_digest,
            &mpt_pi.root_hash(),
            &merkle_pi.root_hash(),
            &mpt_pi.contract_address(),
            mpt_pi.mapping_slot(),
            mpt_pi.length_slot(),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        benches::init_logging,
        circuit::{test::run_circuit, UserCircuit},
        utils::{test::random_vector, CURVE_COORDINATE_LEN},
    };
    use plonky2::{
        field::types::{Field, Sample},
        iop::witness::{PartialWitness, WitnessWrite},
        plonk::{
            circuit_builder::CircuitBuilder,
            config::{GenericConfig, PoseidonGoldilocksConfig},
        },
    };
    use plonky2_ecgfp5::curve::curve::{Point, WeierstrassPoint};
    use rand::{thread_rng, Rng};
    use std::array;

    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    /// Test circuit
    #[derive(Clone, Debug)]
    struct TestCircuit {
        mpt_pi: Vec<F>,
        merkle_pi: Vec<F>,
    }

    impl UserCircuit<F, D> for TestCircuit {
        type Wires = (Vec<Target>, Vec<Target>);

        fn build(cb: &mut CircuitBuilder<F, D>) -> Self::Wires {
            let mpt_pi = cb.add_virtual_targets(MPTPublicInputs::<Target>::TOTAL_LEN);
            let merkle_pi = cb.add_virtual_targets(MerklePublicInputs::<Target>::TOTAL_LEN);

            DigestEqualCircuit::build(cb, &mpt_pi, &merkle_pi);

            (mpt_pi, merkle_pi)
        }

        fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
            pw.set_target_arr(&wires.0, &self.mpt_pi);
            pw.set_target_arr(&wires.1, &self.merkle_pi);
        }
    }

    /// Test the digest-equal circuit with simple random previous public inputs.
    #[test]
    fn test_digest_equal_circuit_simple() {
        init_logging();

        // Generate a random digest.
        let mut rng = thread_rng();
        let digest = Point::sample(&mut rng).to_weierstrass();

        let mpt_pi = generate_mpt_public_inputs(&digest);
        let merkle_pi = generate_merkle_public_inputs(&digest);

        let mpt_pi_wrapper = MPTPublicInputs::<F>::from(&mpt_pi);
        let merkle_pi_wrapper = MerklePublicInputs::<F>::from(&merkle_pi);

        // Get the expected public inputs.
        let exp_digest = (digest.x.0, digest.y.0, F::from_bool(digest.is_inf));
        let exp_mpt_root_hash = mpt_pi_wrapper.root_hash_data();
        let exp_merkle_root_hash = merkle_pi_wrapper.root_hash_data();
        let exp_contract_address = mpt_pi_wrapper.contract_address_data();
        let exp_mapping_slot = mpt_pi_wrapper.mapping_slot();
        let exp_length_slot = mpt_pi_wrapper.length_slot();

        let test_circuit = TestCircuit {
            mpt_pi: mpt_pi.clone(),
            merkle_pi: merkle_pi.clone(),
        };
        let proof = run_circuit::<F, D, C, _>(test_circuit);

        // Verify the public inputs.
        let pi = PublicInputs::<F>::from(&proof.public_inputs);
        assert_eq!(pi.digest_data(), exp_digest);
        assert_eq!(pi.mpt_root_hash(), exp_mpt_root_hash);
        assert_eq!(pi.merkle_root_hash(), exp_merkle_root_hash);
        assert_eq!(pi.contract_address(), exp_contract_address);
        assert_eq!(pi.mapping_slot(), exp_mapping_slot);
        assert_eq!(pi.length_slot(), exp_length_slot);
    }

    fn generate_mpt_public_inputs(digest: &WeierstrassPoint) -> Vec<F> {
        let mut pi: Vec<_> = random_vector::<u32>(MPTPublicInputs::<F>::TOTAL_LEN)
            .into_iter()
            .map(F::from_canonical_u32)
            .collect();

        // Set the digest.
        pi[MPTPublicInputs::<F>::D_IDX..MPTPublicInputs::<F>::D_IDX + CURVE_COORDINATE_LEN]
            .copy_from_slice(&digest.x.0);
        pi[MPTPublicInputs::<F>::D_IDX + CURVE_COORDINATE_LEN
            ..MPTPublicInputs::<F>::D_IDX + 2 * CURVE_COORDINATE_LEN]
            .copy_from_slice(&digest.y.0);
        pi[MPTPublicInputs::<F>::D_IDX + 2 * CURVE_COORDINATE_LEN] = F::from_bool(digest.is_inf);

        pi
    }

    fn generate_merkle_public_inputs(digest: &WeierstrassPoint) -> Vec<F> {
        let mut pi: Vec<_> = random_vector::<u32>(MerklePublicInputs::<F>::TOTAL_LEN)
            .into_iter()
            .map(F::from_canonical_u32)
            .collect();

        // Set the digest.
        pi[MerklePublicInputs::<F>::D_IDX..MerklePublicInputs::<F>::D_IDX + CURVE_COORDINATE_LEN]
            .copy_from_slice(&digest.x.0);
        pi[MerklePublicInputs::<F>::D_IDX + CURVE_COORDINATE_LEN
            ..MerklePublicInputs::<F>::D_IDX + 2 * CURVE_COORDINATE_LEN]
            .copy_from_slice(&digest.y.0);
        pi[MerklePublicInputs::<F>::D_IDX + 2 * CURVE_COORDINATE_LEN] = F::from_bool(digest.is_inf);

        pi
    }
}
