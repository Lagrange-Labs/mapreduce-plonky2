//! This circuit is used to verify the count of entries in the mapping
//! corresponds to the length value extracted from the storage trie.

use super::{
    length_extract::PublicInputs as LengthPublicInputs,
    mapping::PublicInputs as MappingPublicInputs,
};
use crate::{
    keccak::{OutputHash, PACKED_HASH_LEN},
    utils::{
        PackedAddressTarget, PackedStorageSlotTarget, PACKED_ADDRESS_LEN, PACKED_STORAGE_SLOT_LEN,
    },
};
use plonky2::{
    field::{extension::Extendable, goldilocks_field::GoldilocksField},
    hash::hash_types::RichField,
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::circuit_builder::CircuitBuilder,
};
use plonky2_ecgfp5::gadgets::curve::{CircuitBuilderEcGFp5, CurveTarget, PartialWitnessCurve};

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
        mapping_slot: &Target,
        length_slot: &PackedStorageSlotTarget,
    ) {
        cb.register_curve_public_input(*digest);
        contract_address.register_as_input(cb);
        mpt_root_hash.register_as_input(cb);
        cb.register_public_input(*mapping_slot);
        length_slot.register_as_input(cb);
    }
}

impl<'a, T: Copy> PublicInputs<'a, T> {
    const D_IDX: usize = 0;
    const A_IDX: usize = Self::D_IDX + 11; // 5*2+1 for curve target
    const C_IDX: usize = Self::A_IDX + PACKED_ADDRESS_LEN;
    const M_IDX: usize = Self::C_IDX + PACKED_HASH_LEN;
    const S_IDX: usize = Self::M_IDX + 1;
    pub(crate) const TOTAL_LEN: usize = Self::S_IDX + PACKED_STORAGE_SLOT_LEN;

    pub fn from(arr: &'a [T]) -> Self {
        Self { proof_inputs: arr }
    }

    pub fn digest(&self) -> &[T] {
        &self.proof_inputs[Self::D_IDX..Self::A_IDX]
    }

    pub fn contract_address(&self) -> &[T] {
        &self.proof_inputs[Self::A_IDX..Self::C_IDX]
    }

    pub fn mpt_root_hash(&self) -> &[T] {
        &self.proof_inputs[Self::C_IDX..Self::M_IDX]
    }

    pub fn mapping_storage_slot(&self) -> &[T] {
        &self.proof_inputs[Self::M_IDX..Self::S_IDX]
    }

    pub fn length_storage_slot(&self) -> &[T] {
        &self.proof_inputs[Self::S_IDX..]
    }
}

/// The elements to check equivalent for both length and mapping entries proofs
struct EqualElements {
    /// The length value (V) saved in length proof and the number of entries up
    /// to the given node (n) saved in mapping entries proof
    length: Target,
    /// MPT root hash (C) saved in both proofs
    mpt_root_hash: OutputHash,
}

impl EqualElements {
    fn new<F, const D: usize>(cb: &mut CircuitBuilder<F, D>) -> Self
    where
        F: RichField + Extendable<D>,
    {
        Self {
            length: cb.add_virtual_target(),
            mpt_root_hash: OutputHash::new(cb),
        }
    }

    fn assign<F>(&self, pw: &mut PartialWitness<F>, length: F, mpt_root_hash: &[F; PACKED_HASH_LEN])
    where
        F: RichField,
    {
        pw.set_target(self.length, length);
        self.mpt_root_hash.assign(pw, mpt_root_hash);
    }

    /// Constrain this is equal to the elements of another proof.
    fn assert_equal<F, const D: usize>(&self, cb: &mut CircuitBuilder<F, D>, other: &Self)
    where
        F: RichField + Extendable<D>,
    {
        let ttrue = cb._true().target;

        // Constrain the entry lengths are equal.
        let is_equal = cb.is_equal(self.length, other.length);
        cb.connect(is_equal.target, ttrue);

        // Constrain the MPT root hashes are same.
        let is_equal = self.mpt_root_hash.equals(cb, &other.mpt_root_hash);
        cb.connect(is_equal.target, ttrue);
    }
}

/// Length match wires
struct LengthMatchWires {
    /// The current MPT key pointer of entries proof, it should be equal to -1
    /// after traversing from leaf to root.
    mpt_key_pointer: Target,
    /// The storage slot of the mapping entries
    mapping_slot: Target,
    /// The storage slot of the variable holding the length
    length_slot: PackedStorageSlotTarget,
    /// Contract address
    contract_address: PackedAddressTarget,
    /// Digest of the all mapping entries
    digest: CurveTarget,
    /// The elements of length proof to check equivalent
    length_elements: EqualElements,
    /// The elements of mapping entries proof to check equivalent
    mapping_elements: EqualElements,
}

/// Length match circuit
#[derive(Clone, Debug)]
struct LengthMatchCircuit<F> {
    /// The public inputs of previous length extract proof
    length_proof: Vec<F>,
    /// The public inputs of previous mapping entries proof
    mapping_proof: Vec<F>,
}

impl<F> LengthMatchCircuit<F> {
    pub fn new(length_proof: Vec<F>, mapping_proof: Vec<F>) -> Self {
        Self {
            length_proof,
            mapping_proof,
        }
    }
}

impl LengthMatchCircuit<GoldilocksField> {
    /// Build for circuit.
    pub fn build(cb: &mut CircuitBuilder<GoldilocksField, 2>) -> LengthMatchWires {
        let mpt_key_pointer = cb.add_virtual_target();
        let mapping_slot = cb.add_virtual_target();
        let length_slot = PackedStorageSlotTarget::new(cb);
        let contract_address = PackedAddressTarget::new(cb);
        let digest = cb.add_virtual_curve_target();
        let length_elements = EqualElements::new(cb);
        let mapping_elements = EqualElements::new(cb);

        // The MPT key pointer must be equal to -1 after traversing from leaf to
        // root.
        let neg_one = cb.neg_one();
        cb.connect(mpt_key_pointer, neg_one);

        // Constrain the elements are equal for both length and entries proofs.
        length_elements.assert_equal(cb, &mapping_elements);

        // Register the public inputs.
        PublicInputs::register(
            cb,
            &digest,
            &contract_address,
            &length_elements.mpt_root_hash,
            &mapping_slot,
            &length_slot,
        );

        LengthMatchWires {
            mpt_key_pointer,
            mapping_slot,
            length_slot,
            contract_address,
            digest,
            length_elements,
            mapping_elements,
        }
    }

    /// Assign the wires.
    pub fn assign(&self, pw: &mut PartialWitness<GoldilocksField>, wires: &LengthMatchWires) {
        let length_pi = LengthPublicInputs::from(&self.length_proof);
        let mapping_pi = MappingPublicInputs::from(&self.mapping_proof);

        pw.set_target(wires.mpt_key_pointer, mapping_pi.mpt_key_info().1);
        pw.set_target(wires.mapping_slot, mapping_pi.mapping_slot());
        wires
            .length_slot
            .assign(pw, length_pi.storage_slot().try_into().unwrap());
        wires
            .contract_address
            .assign(pw, length_pi.contract_address().try_into().unwrap());
        pw.set_curve_target(wires.digest, mapping_pi.accumulator());
        wires.length_elements.assign(
            pw,
            length_pi.length_value(),
            length_pi.mpt_root_hash().try_into().unwrap(),
        );
        wires.mapping_elements.assign(
            pw,
            mapping_pi.n(),
            mapping_pi.root_hash_info().try_into().unwrap(),
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
        c: LengthMatchCircuit<F>,
    }

    impl UserCircuit<F, D> for TestCircuit {
        type Wires = LengthMatchWires;

        fn build(cb: &mut CircuitBuilder<F, D>) -> Self::Wires {
            LengthMatchCircuit::build(cb)
        }

        fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
            self.c.assign(pw, wires);
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
            c: LengthMatchCircuit::new(length_pi, mapping_pi),
        };
        run_circuit::<F, D, C, _>(test_circuit);
    }

    fn generate_length_public_inputs(length_value: F, mpt_root_hash: &[F]) -> Vec<F> {
        let mut pi: Vec<_> = random_vector::<u64>(LengthPublicInputs::<F>::TOTAL_LEN)
            .into_iter()
            .map(F::from_canonical_u64)
            .collect();

        pi[LengthPublicInputs::<F>::V_IDX] = length_value;
        pi[LengthPublicInputs::<F>::C_IDX..LengthPublicInputs::<F>::S_IDX]
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
