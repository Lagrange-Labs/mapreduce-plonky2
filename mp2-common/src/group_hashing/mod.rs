//! Group hashing arithmetic and circuit functions

use plonky2::field::extension::FieldExtension;
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::field::types::Field;
use plonky2::iop::target::BoolTarget;
use plonky2::plonk::config::Hasher;
use plonky2::{
    field::extension::Extendable, iop::target::Target, plonk::circuit_builder::CircuitBuilder,
};
use plonky2_ecdsa::gadgets::nonnative::CircuitBuilderNonNative;

use plonky2_ecgfp5::curve::curve::Point;
use plonky2_ecgfp5::curve::scalar_field::Scalar;
use plonky2_ecgfp5::gadgets::base_field::QuinticExtensionTarget;
use plonky2_ecgfp5::{
    curve::curve::WeierstrassPoint,
    gadgets::{
        base_field::CircuitBuilderGFp5,
        curve::{CircuitBuilderEcGFp5, CurveTarget},
    },
};

mod curve_add;
pub mod field_to_curve;
mod sswu_gadget;
mod sswu_value;
mod utils;

/// Extension degree of EcGFp5 curve
pub const EXTENSION_DEGREE: usize = 5;

pub use curve_add::{add_curve_point, add_weierstrass_point};
/// Field-to-curve and curve point addition functions
pub use field_to_curve::map_to_curve_point;

use crate::poseidon::{hash_to_int_target, hash_to_int_value, HashableField, H};
use crate::types::CURVE_TARGET_LEN;
use crate::utils::ToTargets;
use crate::{
    types::{GFp, GFp5},
    utils::{FromFields, FromTargets, ToFields},
};
use crate::{CHasher, D, F};

/// Trait for adding field-to-curve and curve point addition functions to
/// circuit builder
pub trait CircuitBuilderGroupHashing {
    /// Calculate the curve target addition.
    fn add_curve_point(&mut self, targets: &[CurveTarget]) -> CurveTarget;

    /// Convert the field target to a curve target.
    fn map_one_to_curve_point(&mut self, target: Target) -> CurveTarget;

    /// Convert the field targets to a curve target.
    fn map_to_curve_point(&mut self, targets: &[Target]) -> CurveTarget;

    /// Require that two points must be strictly equal. It contrains the
    /// coodinates and infinity flag must be equal, and could also be used to
    /// check for the zero point which infinity flag is true as
    /// [NEUTRAL](https://github.com/Lagrange-Labs/plonky2-ecgfp5/blob/d5a6a0b7dfee4ab69d8c1c315f9f4407502f07eb/src/curve/curve.rs#L70).
    fn connect_curve_points(&mut self, a: CurveTarget, b: CurveTarget);
    /// Selects a curve target depending on the condition a.
    fn select_curve_point(
        &mut self,
        condition: BoolTarget,
        a: CurveTarget,
        b: CurveTarget,
    ) -> CurveTarget;
}

impl<F, const D: usize> CircuitBuilderGroupHashing for CircuitBuilder<F, D>
where
    F: HashableField + Extendable<D> + Extendable<EXTENSION_DEGREE>,
    Self: CircuitBuilderGFp5<F> + CircuitBuilderEcGFp5,
{
    fn add_curve_point(&mut self, targets: &[CurveTarget]) -> CurveTarget {
        curve_add::add_curve_target(self, targets)
    }

    fn map_one_to_curve_point(&mut self, target: Target) -> CurveTarget {
        self.map_to_curve_point(&[target])
    }

    fn map_to_curve_point(&mut self, targets: &[Target]) -> CurveTarget {
        field_to_curve::map_to_curve_target(self, targets)
    }

    fn connect_curve_points(&mut self, a: CurveTarget, b: CurveTarget) {
        let CurveTarget(([ax, ay], a_is_inf)) = a;
        let CurveTarget(([bx, by], b_is_inf)) = b;

        // Constrain two points are equal.
        self.connect_quintic_ext(ax, bx);
        self.connect_quintic_ext(ay, by);

        // Constrain the infinity flags are equal.
        self.connect(a_is_inf.target, b_is_inf.target);
    }
    fn select_curve_point(
        &mut self,
        condition: BoolTarget,
        a: CurveTarget,
        b: CurveTarget,
    ) -> CurveTarget {
        let ts = a
            .to_targets()
            .into_iter()
            .zip(b.to_targets())
            .map(|(a, b)| self.select(condition, a, b))
            .collect::<Vec<_>>();
        CurveTarget::from_targets(&ts)
    }
}

impl ToTargets for QuinticExtensionTarget {
    fn to_targets(&self) -> Vec<Target> {
        self.0.to_vec()
    }
}

impl FromTargets for CurveTarget {
    fn from_targets(t: &[Target]) -> Self {
        assert!(t.len() >= CURVE_TARGET_LEN);
        let x = QuinticExtensionTarget(t[0..EXTENSION_DEGREE].try_into().unwrap());
        let y = QuinticExtensionTarget(
            t[EXTENSION_DEGREE..EXTENSION_DEGREE * 2]
                .try_into()
                .unwrap(),
        );
        let is_inf = t[EXTENSION_DEGREE * 2];
        Self(([x, y], BoolTarget::new_unsafe(is_inf)))
    }
}

impl ToTargets for CurveTarget {
    fn to_targets(&self) -> Vec<Target> {
        let mut x = self.0 .0[0].to_targets();
        let mut y = self.0 .0[1].to_targets();
        let is_inf = self.0 .1.target;
        x.append(&mut y);
        x.push(is_inf);
        x
    }
}

impl FromFields<GoldilocksField> for WeierstrassPoint {
    fn from_fields(t: &[GFp]) -> Self {
        let x = std::array::from_fn::<_, EXTENSION_DEGREE, _>(|i| t[i]);
        let y = std::array::from_fn::<_, EXTENSION_DEGREE, _>(|i| t[i + EXTENSION_DEGREE]);
        let is_inf = t[EXTENSION_DEGREE * 2] == GFp::ONE;

        WeierstrassPoint {
            x: GFp5::from_basefield_array(x),
            y: GFp5::from_basefield_array(y),
            is_inf,
        }
    }
}

impl ToFields<GoldilocksField> for WeierstrassPoint {
    fn to_fields(&self) -> Vec<GoldilocksField> {
        let mut v = vec![];
        v.extend_from_slice(&self.x.0);
        v.extend_from_slice(&self.y.0);
        v.push(match self.is_inf {
            true => GoldilocksField::ONE,
            false => GoldilocksField::ZERO,
        });
        v
    }
}

impl ToFields<GoldilocksField> for Point {
    fn to_fields(&self) -> Vec<GoldilocksField> {
        self.to_weierstrass().to_fields()
    }
}

impl FromFields<GoldilocksField> for Point {
    fn from_fields(t: &[GoldilocksField]) -> Self {
        let w = &WeierstrassPoint::from_fields(t);
        weierstrass_to_point(w)
    }
}
/// This function CAN PANIC.
pub fn weierstrass_to_point(w: &WeierstrassPoint) -> Point {
    let p = Point::decode(w.encode()).expect("input weierstrass point invalid");
    assert_eq!(&p.to_weierstrass(), w);
    p
}

/// Common function to compute the digest of the block tree which uses a special format using
/// scalar multiplication
pub fn circuit_hashed_scalar_mul(
    b: &mut CircuitBuilder<F, D>,
    multiplier: CurveTarget,
    base: CurveTarget,
) -> CurveTarget {
    let hash = b.hash_n_to_hash_no_pad::<CHasher>(multiplier.to_targets());
    let int = hash_to_int_target(b, hash);
    let scalar = b.biguint_to_nonnative(&int);
    b.curve_scalar_mul(base, &scalar)
}

/// Common function to compute the digest of the block tree which uses a special format using
/// scalar multiplication. The output of that scalar mul is returned only if cond is true.
pub fn cond_circuit_hashed_scalar_mul(
    b: &mut CircuitBuilder<F, D>,
    cond: BoolTarget,
    multiplier: CurveTarget,
    base: CurveTarget,
) -> CurveTarget {
    let res_mul = circuit_hashed_scalar_mul(b, multiplier, base);
    b.curve_select(cond, res_mul, base)
}

pub fn field_hashed_scalar_mul(inputs: Vec<F>, base: Point) -> Point {
    let hash = H::hash_no_pad(&inputs);
    let int = hash_to_int_value(hash);
    let scalar = Scalar::from_noncanonical_biguint(int);
    scalar * base
}
/// Common function to compute a scalar multiplication in the format of HashToInt(inputs) * base
/// The output of scalar multiplication is returned if `cond` is true, `base` point is
/// returned otherwise
pub fn cond_field_hashed_scalar_mul(cond: bool, mul: Point, base: Point) -> Point {
    match cond {
        false => base,
        true => field_hashed_scalar_mul(mul.to_fields(), base),
    }
}

#[cfg(test)]
mod test {

    use plonky2::{field::types::Sample, iop::witness::PartialWitness};

    use plonky2_ecgfp5::{
        curve::curve::{Point, WeierstrassPoint},
        gadgets::curve::{CircuitBuilderEcGFp5, CurveTarget, PartialWitnessCurve},
    };

    use crate::{
        types::CBuilder,
        utils::{FromFields, ToFields},
        C, D, F,
    };
    use mp2_test::circuit::{run_circuit, UserCircuit};

    use super::{circuit_hashed_scalar_mul, field_hashed_scalar_mul, weierstrass_to_point};

    #[derive(Clone, Debug)]
    struct TestScalarMul {
        // point that we hash and move to biguint to scalar
        scalar: Point,
        base: Point,
    }

    struct TestScalarMulWires {
        scalar: CurveTarget,
        base: CurveTarget,
    }

    impl UserCircuit<F, D> for TestScalarMul {
        type Wires = TestScalarMulWires;

        fn build(b: &mut CBuilder) -> Self::Wires {
            let p = b.add_virtual_curve_target();
            let base = b.add_virtual_curve_target();
            let result = circuit_hashed_scalar_mul(b, p, base);
            b.register_curve_public_input(result);
            TestScalarMulWires { scalar: p, base }
        }

        fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
            pw.set_curve_target(wires.base, self.base.to_weierstrass());
            pw.set_curve_target(wires.scalar, self.scalar.to_weierstrass());
        }
    }

    #[test]
    fn test_scalar_mul() {
        let base = Point::rand();
        let scalar = Point::rand();
        let circuit = TestScalarMul { base, scalar };

        let proof = run_circuit::<F, D, C, _>(circuit);
        let exp = field_hashed_scalar_mul(scalar.to_fields(), base);
        let f = WeierstrassPoint::from_fields(&proof.public_inputs);
        let point = weierstrass_to_point(&f);
        assert_eq!(exp, point);
    }
}
