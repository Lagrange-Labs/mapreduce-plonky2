//! Group hashing arithmetic and circuit functions

use anyhow::Result;
use plonky2::field::extension::FieldExtension;
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::field::types::Field;
use plonky2::iop::target::BoolTarget;
use plonky2::{
    field::extension::Extendable, hash::hash_types::RichField, iop::target::Target,
    plonk::circuit_builder::CircuitBuilder,
};
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

pub use curve_add::add_curve_point;
/// Field-to-curve and curve point addition functions
pub use field_to_curve::map_to_curve_point;

use crate::utils::{FromBytes, ToTargets};
use crate::{
    types::{GFp, GFp5},
    utils::{FromFields, FromTargets, ToFields},
};

/// Trait for adding field-to-curve and curve point addition functions to
/// circuit builder
pub trait CircuitBuilderGroupHashing {
    /// Calculate the curve target addition.
    fn add_curve_point(&mut self, targets: &[CurveTarget]) -> CurveTarget;

    /// Convert the field target to a curve target.
    fn map_one_to_curve_point(&mut self, target: Target) -> CurveTarget;

    /// Convert the field targets to a curve target.
    fn map_to_curve_point(&mut self, targets: &[Target]) -> CurveTarget;

    /// Require that two points must be equal, and none is infinity.
    /// Unlike the [curve_eq](https://github.com/Lagrange-Labs/plonky2-ecgfp5/blob/d5a6a0b7dfee4ab69d8c1c315f9f4407502f07eb/src/gadgets/curve.rs#L83)
    /// function, this constrains none of the points is infinity.
    fn connect_curve_points(&mut self, a: CurveTarget, b: CurveTarget);
}

impl<F, const D: usize> CircuitBuilderGroupHashing for CircuitBuilder<F, D>
where
    F: RichField + Extendable<D> + Extendable<EXTENSION_DEGREE>,
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

        // Constrain none is infinity.
        let ffalse = self._false();
        self.connect(a_is_inf.target, ffalse.target);
        self.connect(b_is_inf.target, ffalse.target);
    }
}

impl ToTargets for QuinticExtensionTarget {
    fn to_targets(&self) -> Vec<Target> {
        self.0.to_vec()
    }
}

impl FromTargets for CurveTarget {
    fn from_targets(t: &[Target]) -> Self {
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
        let mut is_inf = self.0 .1.target;
        x.append(&mut y);
        x.push(is_inf);
        x
    }
}

impl FromFields<GFp> for WeierstrassPoint {
    fn from_fields(t: &[GFp]) -> Self {
        let q = GoldilocksField::from_canonical_u16(14);
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

impl FromBytes for WeierstrassPoint {
    fn from_bytes(value: Vec<u8>) -> Result<Self> {
        Ok(map_to_curve_point(
            &value
                .into_iter()
                .map(GFp::from_canonical_u8)
                .collect::<Vec<_>>(),
        )
        .to_weierstrass())
    }
}
