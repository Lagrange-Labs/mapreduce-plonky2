use itertools::Itertools;
use plonky2::{
    field::{
        extension::{quintic::QuinticExtension, FieldExtension},
        goldilocks_field::GoldilocksField,
        types::Field,
    },
    hash::hash_types::{HashOut, HashOutTarget, NUM_HASH_OUT_ELTS},
    iop::target::Target,
    plonk::circuit_builder::CircuitBuilder,
};
use plonky2_crypto::u32::arithmetic_u32::U32Target;
use plonky2_ecgfp5::{
    curve::curve::WeierstrassPoint,
    gadgets::curve::{CircuitBuilderEcGFp5, CurveTarget},
};

use crate::{
    storage::CURVE_TARGET_SIZE,
    types::{PackedValueTarget, PACKED_VALUE_LEN},
    utils::{convert_point_to_curve_target, convert_slice_to_curve_point},
};

/// The public inputs required for the storage proof of query #2
///   - hash of this subtree (NUM_HASH_OUT_ELTS);
///   - digest of this subtree (CURVE_TARGET_GL_SIZE);
///   - value (owner) forwarded bottom-up (PACKED_VALUE_LEN)
#[derive(Debug)]
pub struct PublicInputs<'input, T: Clone> {
    pub inputs: &'input [T],
}
impl<'a, T: Clone + Copy> From<&'a [T]> for PublicInputs<'a, T> {
    fn from(inputs: &'a [T]) -> Self {
        assert_eq!(inputs.len(), Self::TOTAL_LEN);
        Self { inputs }
    }
}

impl<'a, T: Clone + Copy> PublicInputs<'a, T> {
    pub(crate) const ROOT_OFFSET: usize = 0;
    pub(crate) const ROOT_LEN: usize = NUM_HASH_OUT_ELTS;
    pub(crate) const DIGEST_OFFSET: usize = Self::ROOT_LEN;
    pub(crate) const DIGEST_LEN: usize = CURVE_TARGET_SIZE;
    pub(crate) const OWNER_OFFSET: usize = Self::ROOT_LEN + Self::DIGEST_LEN;
    pub(crate) const OWNER_LEN: usize = PACKED_VALUE_LEN;

    pub const TOTAL_LEN: usize = Self::ROOT_LEN + Self::DIGEST_LEN + Self::OWNER_LEN;

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

        Self { inputs: arr }
    }

    pub fn register(
        b: &mut CircuitBuilder<GoldilocksField, 2>,
        root: &HashOutTarget,
        digest: &CurveTarget,
        user: &PackedValueTarget,
    ) {
        b.register_public_inputs(&root.elements);
        b.register_curve_public_input(*digest);
        user.register_as_public_input(b);
    }

    /// Extracts the root hash components from the raw input
    pub(crate) fn root_raw(&self) -> &[T] {
        &self.inputs[Self::ROOT_OFFSET..Self::ROOT_OFFSET + Self::ROOT_LEN]
    }

    /// Extracts curve coordinates from the raw input
    pub fn digest_raw(
        &self,
    ) -> (
        [T; crate::group_hashing::EXTENSION_DEGREE],
        [T; crate::group_hashing::EXTENSION_DEGREE],
        T,
    ) {
        let raw = &self.inputs[Self::DIGEST_OFFSET..Self::DIGEST_OFFSET + Self::DIGEST_LEN];
        convert_slice_to_curve_point(raw)
    }

    /// Extracts the owner address
    fn owner_raw(&self) -> &[T] {
        &self.inputs[Self::OWNER_OFFSET..Self::OWNER_OFFSET + Self::OWNER_LEN]
    }
}

impl<'a> PublicInputs<'a, Target> {
    /// The digest of the current subtree
    pub fn digest(&self) -> CurveTarget {
        convert_point_to_curve_target(self.digest_raw())
    }

    /// The root hash of the current subtree
    pub fn root(&self) -> HashOutTarget {
        HashOutTarget::from(std::array::from_fn(|i| self.inputs[Self::ROOT_OFFSET + i]))
    }

    /// The owner address
    pub fn owner(&self) -> PackedValueTarget {
        PackedValueTarget::try_from(self.owner_raw().iter().map(|&t| U32Target(t)).collect_vec())
            .unwrap()
    }
}

impl<'a> PublicInputs<'a, GoldilocksField> {
    /// The digest point of the current subtree
    pub fn digest(&self) -> WeierstrassPoint {
        let (x, y, is_inf) = self.digest_raw();
        WeierstrassPoint {
            x: QuinticExtension::<GoldilocksField>::from_basefield_array(std::array::from_fn::<
                GoldilocksField,
                5,
                _,
            >(|i| x[i])),
            y: QuinticExtension::<GoldilocksField>::from_basefield_array(std::array::from_fn::<
                GoldilocksField,
                5,
                _,
            >(|i| y[i])),
            is_inf: is_inf.is_nonzero(),
        }
    }

    /// The GLs forming the hash of the current subtree
    pub fn root(&self) -> HashOut<GoldilocksField> {
        HashOut::from_vec(self.root_raw().to_owned())
    }

    /// The owner address as an array of GL
    pub fn owner(&self) -> &[GoldilocksField] {
        self.owner_raw()
    }
}
