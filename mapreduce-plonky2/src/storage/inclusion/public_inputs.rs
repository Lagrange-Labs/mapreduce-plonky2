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

use crate::utils::{convert_point_to_curve_target, convert_slice_to_curve_point};

/// Stores the public input used to prove the inclusion of a value in a *binary* merkle tree.
///
///  * R - the hash born by the current node
///  * D – the digest of the values encoutered up until R
#[derive(Debug)]
pub struct PublicInputs<'input, FieldElt: Clone> {
    pub inputs: &'input [FieldElt],
}

impl<'a, T: Clone> From<&'a [T]> for PublicInputs<'a, T> {
    fn from(inputs: &'a [T]) -> Self {
        Self { inputs }
    }
}

impl<'a, T: Copy> PublicInputs<'a, T> {
    const ROOT_OFFSET: usize = 0;
    const ROOT_LEN: usize = NUM_HASH_OUT_ELTS;
    const DIGEST_OFFSET: usize = 4;
    const DIGEST_LEN: usize = 11;

    pub const TOTAL_LEN: usize = Self::ROOT_LEN + Self::DIGEST_LEN;

    pub fn register(
        b: &mut CircuitBuilder<GoldilocksField, 2>,
        root: &HashOutTarget,
        digest: &CurveTarget,
    ) {
        b.register_public_inputs(&root.elements);
        b.register_curve_public_input(*digest);
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
        let raw = &self.inputs[Self::DIGEST_OFFSET..Self::DIGEST_OFFSET + Self::DIGEST_LEN];
        convert_slice_to_curve_point(raw)
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
}
