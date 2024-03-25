use plonky2::{
    field::{extension::Extendable, goldilocks_field::GoldilocksField},
    hash::hash_types::{HashOutTarget, RichField, NUM_HASH_OUT_ELTS},
    iop::target::Target,
    plonk::circuit_builder::CircuitBuilder,
};
use plonky2_ecgfp5::gadgets::curve::{CircuitBuilderEcGFp5, CurveTarget};

use crate::{
    group_hashing,
    keccak::PACKED_HASH_LEN,
    query2::{AddressTarget, ADDRESS_LEN},
    types::CURVE_TARGET_LEN,
    utils::convert_point_to_curve_target,
};

/// Public inputs of the provenance circuit
///
/// - `B` Block number
/// - `R` Aggregated range
/// - `C` Block leaf hash
/// - `B_MIN` Minimum block number
/// - `B_MAX` Maximum block number
/// - `A` Smart contract address
/// - `X` User/Owner address
/// - `M` Mapping slot
/// - `S` Length of the slot
/// - `Y` Aggregated storage digest
#[derive(Clone, Debug)]
pub struct PublicInputs<'a, T: Clone> {
    pub(crate) proof_inputs: &'a [T],
}

impl<'a, T: Clone> PublicInputs<'a, T> {
    pub(crate) const B_LEN: usize = 1;
    pub(crate) const R_LEN: usize = 1;
    pub(crate) const C_LEN: usize = NUM_HASH_OUT_ELTS;
    pub(crate) const B_MIN_LEN: usize = 1;
    pub(crate) const B_MAX_LEN: usize = 1;
    pub(crate) const A_LEN: usize = ADDRESS_LEN;
    pub(crate) const X_LEN: usize = ADDRESS_LEN;
    pub(crate) const M_LEN: usize = 1;
    pub(crate) const S_LEN: usize = 1;
    pub(crate) const D_LEN: usize = CURVE_TARGET_LEN;
    pub(crate) const TOTAL_LEN: usize = Self::B_LEN
        + Self::R_LEN
        + Self::C_LEN
        + Self::B_MIN_LEN
        + Self::B_MAX_LEN
        + Self::A_LEN
        + Self::X_LEN
        + Self::M_LEN
        + Self::S_LEN
        + Self::D_LEN;

    pub(crate) const B_IDX: usize = 0;
    pub(crate) const R_IDX: usize = Self::B_IDX + Self::B_LEN;
    pub(crate) const C_IDX: usize = Self::R_IDX + Self::R_LEN;
    pub(crate) const B_MIN_IDX: usize = Self::C_IDX + Self::C_LEN;
    pub(crate) const B_MAX_IDX: usize = Self::B_MIN_IDX + Self::B_MIN_LEN;
    pub(crate) const A_IDX: usize = Self::B_MAX_IDX + Self::B_MAX_LEN;
    pub(crate) const X_IDX: usize = Self::A_IDX + Self::A_LEN;
    pub(crate) const M_IDX: usize = Self::X_IDX + Self::X_LEN;
    pub(crate) const S_IDX: usize = Self::M_IDX + Self::M_LEN;
    pub(crate) const D_IDX: usize = Self::S_IDX + Self::S_LEN;
}

impl<'a, T: Copy> PublicInputs<'a, T> {
    /// Creates a representation of the public inputs from the provided slice.
    ///
    /// # Panics
    ///
    /// This function will panic if the length of the provided slice is smaller than
    /// [Self::TOTAL_LEN].
    pub fn from_slice(arr: &'a [T]) -> Self {
        assert!(
            Self::TOTAL_LEN <= arr.len(),
            "The public inputs slice length must be equal or greater than the expected length."
        );

        Self { proof_inputs: arr }
    }

    /// Block number
    pub fn block_number_data(&self) -> T {
        self.proof_inputs[Self::B_IDX]
    }

    /// Aggregated range
    pub fn range_data(&self) -> T {
        self.proof_inputs[Self::R_IDX]
    }

    /// Block leaf hash
    pub fn root_data(&self) -> &[T] {
        &self.proof_inputs[Self::C_IDX..Self::C_IDX + Self::C_LEN]
    }

    /// Minimum block number
    pub fn block_number_min_data(&self) -> T {
        self.proof_inputs[Self::B_MIN_IDX]
    }

    /// Maximum block number
    pub fn block_number_max_data(&self) -> T {
        self.proof_inputs[Self::B_MAX_IDX]
    }

    /// Smart contract address
    pub fn smart_contract_address_data(&self) -> &[T] {
        &self.proof_inputs[Self::A_IDX..Self::A_IDX + Self::A_LEN]
    }

    /// User/Owner address
    pub fn user_address_data(&self) -> &[T] {
        &self.proof_inputs[Self::X_IDX..Self::X_IDX + Self::X_LEN]
    }

    /// Mapping slot
    pub fn mapping_slot_data(&self) -> T {
        self.proof_inputs[Self::M_IDX]
    }

    /// Length of the slot
    pub fn length_slot_data(&self) -> T {
        self.proof_inputs[Self::S_IDX]
    }

    /// Aggregated storage digest
    pub fn digest_data(&self) -> &[T] {
        &self.proof_inputs[Self::D_IDX..Self::D_IDX + Self::D_LEN]
    }
}

impl<'a> PublicInputs<'a, Target> {
    pub fn register(
        b: &mut CircuitBuilder<GoldilocksField, 2>,
        block_number: Target,
        range: Target,
        root: &HashOutTarget,
        block_number_min: Target,
        block_number_max: Target,
        smart_contract_address: &AddressTarget,
        user_address: &AddressTarget,
        mapping_slot: Target,
        length_slot: Target,
        digest: CurveTarget,
    ) {
        b.register_public_input(block_number);
        b.register_public_input(range);
        b.register_public_inputs(&root.elements);
        b.register_public_input(block_number_min);
        b.register_public_input(block_number_max);
        smart_contract_address.register_as_public_input(b);
        user_address.register_as_public_input(b);
        b.register_public_input(mapping_slot);
        b.register_public_input(length_slot);
        b.register_curve_public_input(digest);
    }

    /// Block number
    pub fn block_number(&self) -> Target {
        self.proof_inputs[Self::B_IDX]
    }

    /// Aggregated range
    pub fn range(&self) -> Target {
        self.proof_inputs[Self::R_IDX]
    }

    /// Block leaf hash
    pub fn root(&self) -> HashOutTarget {
        HashOutTarget::try_from(self.root_data()).expect("len defined as constant")
    }

    /// Minimum block number
    pub fn block_number_min(&self) -> Target {
        self.proof_inputs[Self::B_MIN_IDX]
    }

    /// Maximum block number
    pub fn block_number_max(&self) -> Target {
        self.proof_inputs[Self::B_MAX_IDX]
    }

    /// Smart contract address
    pub fn smart_contract_address(&self) -> AddressTarget {
        AddressTarget::try_from(self.smart_contract_address_data())
            .expect("len defined as constant")
    }

    /// User/Owner address
    pub fn user_address(&self) -> AddressTarget {
        AddressTarget::try_from(self.user_address_data()).expect("len defined as constant")
    }

    /// Mapping slot
    pub fn mapping_slot(&self) -> Target {
        self.proof_inputs[Self::M_IDX]
    }

    /// Length of the slot
    pub fn length_slot(&self) -> Target {
        self.proof_inputs[Self::S_IDX]
    }

    /// Aggregated storage digest
    pub fn digest(&self) -> CurveTarget {
        let target = self.digest_data();
        let x = &target[0..group_hashing::N];
        let y = &target[group_hashing::N..2 * group_hashing::N];
        let f = target[2 * group_hashing::N];

        let x = x.try_into().expect("len defined as constant");
        let y = y.try_into().expect("len defined as constant");

        convert_point_to_curve_target((x, y, f))
    }
}

#[test]
fn digest_len_is_curve_target_len() {
    assert_eq!(PublicInputs::<()>::D_LEN, 2 * group_hashing::N + 1)
}
