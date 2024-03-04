//! This circuit is used to verify the count of entries in the mapping
//! corresponds to the length value extracted from the storage trie.

use super::{
    length_extract::PublicInputs as LengthPublicInputs,
    mapping::PublicInputs as MappingPublicInputs,
};
use crate::{
    keccak::{OutputHash, PACKED_HASH_LEN},
    utils::{transform_to_curve_point, PackedAddressTarget, PACKED_ADDRESS_LEN},
};
use plonky2::{
    field::goldilocks_field::GoldilocksField, iop::target::BoolTarget, iop::target::Target,
    plonk::circuit_builder::CircuitBuilder,
};
use plonky2_crypto::u32::arithmetic_u32::U32Target;
use plonky2_ecgfp5::gadgets::{
    base_field::QuinticExtensionTarget,
    curve::{CircuitBuilderEcGFp5, CurveTarget},
};
use std::array;

/// This is a wrapper around an array of targets set as public inputs of any
/// proof generated in this module. They all share the same structure.
/// `D` Digest of the all mapping values
/// `A` contract address
/// `C` MPT root of the trie
/// `M` storage slot of the mapping
/// `S` storage slot of the variable holding the length
#[derive(Clone, Debug)]
pub struct PublicInputs<'a, T: Clone> {
    pub(crate) proof_inputs: &'a [T],
}

impl<'a> PublicInputs<'a, Target> {
    pub fn register(
        cb: &mut CircuitBuilder<GoldilocksField, 2>,
        digest: &CurveTarget,
        contract_address: &PackedAddressTarget,
        mpt_root_hash: &OutputHash,
        mapping_slot: Target,
        length_slot: Target,
    ) {
        cb.register_curve_public_input(*digest);
        contract_address.register_as_input(cb);
        mpt_root_hash.register_as_input(cb);
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

    pub fn contract_address(&self) -> PackedAddressTarget {
        let data = self.contract_address_data();
        array::from_fn(|i| U32Target(data[i])).into()
    }

    pub fn root_hash(&self) -> OutputHash {
        let data = self.root_hash_data();
        array::from_fn(|i| U32Target(data[i])).into()
    }
}

impl<'a, T: Copy> PublicInputs<'a, T> {
    pub(crate) const D_IDX: usize = 0;
    pub(crate) const A_IDX: usize = Self::D_IDX + 11; // 5*2+1 for curve target
    pub(crate) const C_IDX: usize = Self::A_IDX + PACKED_ADDRESS_LEN;
    pub(crate) const M_IDX: usize = Self::C_IDX + PACKED_HASH_LEN;
    pub(crate) const S_IDX: usize = Self::M_IDX + 1;
    pub(crate) const TOTAL_LEN: usize = Self::S_IDX + 1;

    pub fn from(arr: &'a [T]) -> Self {
        Self { proof_inputs: arr }
    }

    /// Transform a list of elements to a curve point.
    pub fn digest_data(&self) -> ([T; 5], [T; 5], T) {
        transform_to_curve_point(&self.proof_inputs[Self::D_IDX..])
    }

    pub fn contract_address_data(&self) -> &[T] {
        &self.proof_inputs[Self::A_IDX..Self::C_IDX]
    }

    pub fn root_hash_data(&self) -> &[T] {
        &self.proof_inputs[Self::C_IDX..Self::M_IDX]
    }

    pub fn mapping_slot(&self) -> T {
        self.proof_inputs[Self::M_IDX]
    }

    pub fn length_slot(&self) -> T {
        self.proof_inputs[Self::S_IDX]
    }
}

/// Length match circuit
#[derive(Clone, Debug)]
struct LengthMatchCircuit;

impl LengthMatchCircuit {
    /// Build for circuit.
    pub fn build(
        cb: &mut CircuitBuilder<GoldilocksField, 2>,
        length_pi: &[Target],
        mapping_pi: &[Target],
    ) {
        let length_pi = LengthPublicInputs::from(length_pi);
        let mapping_pi = MappingPublicInputs::from(mapping_pi);

        let mapping_slot = mapping_pi.mapping_slot();
        let length_slot = length_pi.storage_slot();
        let contract_address = length_pi.contract_address();
        let digest = mapping_pi.accumulator();

        // The MPT key pointer must be equal to -1 after traversing from leaf to
        // root.
        let (_, mpt_key_pointer) = mapping_pi.mpt_key_info();
        let neg_one = cb.neg_one();
        cb.connect(mpt_key_pointer, neg_one);

        // Constrain the entry lengths are equal.
        let length_value = length_pi.length_value();
        let n = mapping_pi.n();
        cb.connect(length_value, n);

        // Constrain the MPT root hashes are same.
        let length_root_hash = length_pi.root_hash();
        let mapping_root_hash = mapping_pi.root_hash();
        length_root_hash.enforce_equal(cb, &mapping_root_hash);

        // Register the public inputs.
        PublicInputs::register(
            cb,
            &digest,
            &contract_address,
            &length_root_hash,
            mapping_slot,
            length_slot,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        benches::init_logging,
        circuit::{test::run_circuit, UserCircuit},
        utils::test::random_vector,
    };
    use plonky2::{
        field::types::Field,
        iop::witness::{PartialWitness, WitnessWrite},
        plonk::{
            circuit_builder::CircuitBuilder,
            config::{GenericConfig, PoseidonGoldilocksConfig},
        },
    };
    use rand::{thread_rng, Rng};
    use std::array;

    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    /// Test circuit
    #[derive(Clone, Debug)]
    struct TestCircuit {
        length_pi: Vec<F>,
        mapping_pi: Vec<F>,
    }

    impl UserCircuit<F, D> for TestCircuit {
        type Wires = (Vec<Target>, Vec<Target>);

        fn build(cb: &mut CircuitBuilder<F, D>) -> Self::Wires {
            let length_pi = cb.add_virtual_targets(LengthPublicInputs::<Target>::TOTAL_LEN);
            let mapping_pi = cb.add_virtual_targets(MappingPublicInputs::<Target>::TOTAL_LEN);

            LengthMatchCircuit::build(cb, &length_pi, &mapping_pi);

            (length_pi, mapping_pi)
        }

        fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
            pw.set_target_arr(&wires.0, &self.length_pi);
            pw.set_target_arr(&wires.1, &self.mapping_pi);
        }
    }

    /// Test the length-match circuit with simple random previous public inputs.
    #[test]
    fn test_length_match_circuit_simple() {
        init_logging();

        let mut rng = thread_rng();
        let length_value = F::from_canonical_u64(rng.gen::<u64>());
        let mpt_root_hash: [F; PACKED_HASH_LEN] =
            array::from_fn(|_| F::from_canonical_u32(rng.gen::<u32>()));

        let length_pi = generate_length_public_inputs(length_value, &mpt_root_hash);
        let mapping_pi = generate_mapping_public_inputs(length_value, &mpt_root_hash);

        let test_circuit = TestCircuit {
            length_pi,
            mapping_pi,
        };
        run_circuit::<F, D, C, _>(test_circuit);
    }

    fn generate_length_public_inputs(length_value: F, mpt_root_hash: &[F]) -> Vec<F> {
        let mut pi: Vec<_> = random_vector::<u64>(LengthPublicInputs::<F>::TOTAL_LEN)
            .into_iter()
            .map(F::from_canonical_u64)
            .collect();

        pi[LengthPublicInputs::<F>::V_IDX] = length_value;
        pi[LengthPublicInputs::<F>::C_IDX..LengthPublicInputs::<F>::A_IDX]
            .copy_from_slice(mpt_root_hash);

        pi
    }

    fn generate_mapping_public_inputs(n: F, mpt_root_hash: &[F]) -> Vec<F> {
        let mut pi: Vec<_> = random_vector::<u64>(MappingPublicInputs::<F>::TOTAL_LEN)
            .into_iter()
            .map(F::from_canonical_u64)
            .collect();

        pi[MappingPublicInputs::<F>::T_IDX] = F::NEG_ONE;
        pi[MappingPublicInputs::<F>::N_IDX] = n;
        pi[MappingPublicInputs::<F>::C_IDX..].copy_from_slice(mpt_root_hash);

        pi
    }
}
