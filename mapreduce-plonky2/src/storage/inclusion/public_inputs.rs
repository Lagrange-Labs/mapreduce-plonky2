use plonky2::{
    field::{
        extension::{quintic::QuinticExtension, FieldExtension},
        goldilocks_field::GoldilocksField,
        types::Field,
    },
    hash::hash_types::HashOutTarget,
    iop::target::{BoolTarget, Target},
    plonk::circuit_builder::CircuitBuilder,
};

use plonky2_ecgfp5::{
    curve::curve::WeierstrassPoint,
    gadgets::{
        base_field::QuinticExtensionTarget,
        curve::{CircuitBuilderEcGFp5, CurveTarget},
    },
};

/// Stores the public input used to prove the inclusion of a value in a *binary* merkle tree.
///
///  * R - the hash born by the current node
///  * D – the digest of the values encoutered up until R
pub struct PublicInputs<'input, FieldElt: Clone> {
    pub inputs: &'input [FieldElt],
}

impl<'a, T: Clone> From<&'a [T]> for PublicInputs<'a, T> {
    fn from(inputs: &'a [T]) -> Self {
        Self { inputs }
    }
}

impl<'a, T: Copy> PublicInputs<'a, T> {
    const EXTENSION: usize = 5;

    const ROOT_OFFSET: usize = 0;
    const ROOT_LEN: usize = 64; // 4×GL(8B) = 64B
    const DIGEST_OFFSET: usize = 4;
    const DIGEST_LEN: usize = 1;

    pub fn register(
        b: &mut CircuitBuilder<GoldilocksField, 2>,
        root: &HashOutTarget,
        digest: &CurveTarget,
    ) {
        b.register_curve_public_input(*digest);
        b.register_public_inputs(&root.elements);
    }

    /// Extracts curve coordinates from the raw input
    pub fn digest_raw(&self) -> ([T; 5], [T; 5], T) {
        let raw = &self.inputs[Self::DIGEST_OFFSET..Self::DIGEST_OFFSET + Self::DIGEST_LEN];
        assert!(raw.len() >= 5 * 2 + 1);
        let x = raw[0..Self::EXTENSION].try_into().unwrap();
        let y = raw[Self::EXTENSION..2 * Self::EXTENSION]
            .try_into()
            .unwrap();
        let flag = raw[2 * Self::EXTENSION];
        (x, y, flag)
    }

    /// Extracts the root hash components from the raw input
    fn root_raw(&self) -> &[T] {
        &self.inputs[Self::ROOT_OFFSET..Self::ROOT_OFFSET + Self::ROOT_LEN]
    }
}

impl<'a> PublicInputs<'a, Target> {
    /// The digest of the current subtree
    pub fn digest(&self) -> CurveTarget {
        let (x, y, is_inf) = self.digest_raw();
        let x = QuinticExtensionTarget(x);
        let y = QuinticExtensionTarget(y);
        let flag = BoolTarget::new_unsafe(is_inf);
        CurveTarget(([x, y], flag))
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
    pub fn root(&self) -> Vec<GoldilocksField> {
        self.root_raw().to_owned()
    }
}
