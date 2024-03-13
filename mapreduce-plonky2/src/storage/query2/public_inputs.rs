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
use plonky2_ecgfp5::{
    curve::curve::WeierstrassPoint,
    gadgets::curve::{CircuitBuilderEcGFp5, CurveTarget},
};

use crate::{
    array::Array,
    storage::CURVE_TARGET_GL_SIZE,
    utils::{convert_point_to_curve_target, convert_slice_to_curve_point},
};

use super::AddressTarget;

/// The public inputs required for the storage proof of query #2
///   - hash of this subtree (NUM_HASH_OUT_ELTS);
///   - digest of this subtree (CURVE_TARGET_GL_SIZE);
///   - value (owner) forwarded bottom-up (AddressTarget::LEN)
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
    const ROOT_OFFSET: usize = 0;
    const ROOT_LEN: usize = NUM_HASH_OUT_ELTS;
    const DIGEST_OFFSET: usize = 4;

    pub const TOTAL_LEN: usize = Self::ROOT_LEN + CURVE_TARGET_GL_SIZE + AddressTarget::LEN;

    pub fn register(
        b: &mut CircuitBuilder<GoldilocksField, 2>,
        root: &HashOutTarget,
        digest: &CurveTarget,
        user: &AddressTarget,
    ) {
        b.register_public_inputs(&root.elements);
        b.register_curve_public_input(*digest);
        user.register_as_public_input(b);
    }

    /// Extracts the root hash components from the raw input
    fn root_raw(&self) -> &[T] {
        &self.inputs[Self::ROOT_OFFSET..Self::ROOT_OFFSET + Self::ROOT_LEN]
    }

    /// Extracts curve coordinates from the raw input
    pub fn digest_raw(
        &self,
    ) -> (
        [T; crate::group_hashing::N],
        [T; crate::group_hashing::N],
        T,
    ) {
        let raw = &self.inputs[Self::DIGEST_OFFSET..Self::DIGEST_OFFSET + CURVE_TARGET_GL_SIZE];
        convert_slice_to_curve_point(raw)
    }

    /// Extracts the owner address
    fn owner_raw(&self) -> &[T] {
        let start = Self::ROOT_LEN + CURVE_TARGET_GL_SIZE;
        &self.inputs[start..start + AddressTarget::LEN]
    }
}

impl<'a> PublicInputs<'a, Target> {
    /// The digest of the current subtree
    pub fn digest(&self) -> CurveTarget {
        convert_point_to_curve_target(self.digest_raw())
    }

    /// The root hash of the current subtree
    pub fn root(&self) -> HashOutTarget {
        HashOutTarget::try_from(std::array::from_fn(|i| self.inputs[Self::ROOT_OFFSET + i]))
            .unwrap()
    }

    /// The owner address
    pub fn owner(&self) -> AddressTarget {
        Array::try_from(self.owner_raw().to_vec()).unwrap()
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
