use plonky2::{
    field::{
        extension::{quintic::QuinticExtension, FieldExtension},
        goldilocks_field::GoldilocksField,
        types::Field,
    },
    hash::{hash_types::HashOutTarget, keccak::SPONGE_WIDTH},
    iop::target::{BoolTarget, Target},
    plonk::circuit_builder::CircuitBuilder,
};
use plonky2_crypto::u32::arithmetic_u32::U32Target;
use plonky2_ecgfp5::{
    curve::curve::WeierstrassPoint,
    gadgets::{
        base_field::QuinticExtensionTarget,
        curve::{CircuitBuilderEcGFp5, CurveTarget},
    },
};

use crate::{array::Array, keccak::OutputHash};

pub const POSEIDON_HASH_LEN: usize = SPONGE_WIDTH;

type EncodedPoseidonHash = Array<U32Target, { POSEIDON_HASH_LEN / 4 }>;

/// Stores the public input used to prove the inclusion of a value in a *binary* merkle tree.
///
///  * R - the hash born by the current node
///  * D – the digest of the values encoutered up until R
pub struct PublicInputs<'input, FieldElt: Clone> {
    pub inputs: &'input [FieldElt],
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

    fn root_raw(&self) -> &[T] {
        &self.inputs[Self::ROOT_OFFSET..Self::ROOT_OFFSET + Self::ROOT_LEN]
    }
}

impl<'a> PublicInputs<'a, Target> {
    pub fn digest(&self) -> CurveTarget {
        let (x, y, is_inf) = self.digest_raw();
        let x = QuinticExtensionTarget(x);
        let y = QuinticExtensionTarget(y);
        let flag = BoolTarget::new_unsafe(is_inf);
        CurveTarget(([x, y], flag))
    }

    pub fn root(&self) -> EncodedPoseidonHash {
        EncodedPoseidonHash::from_array(std::array::from_fn(|i| {
            U32Target(self.inputs[Self::ROOT_OFFSET + i])
        }))
    }
}

impl<'a> PublicInputs<'a, GoldilocksField> {
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

    pub fn root(&self) -> Vec<u32> {
        self.root_raw().iter().map(|x| x.0 as u32).collect()
    }
}
