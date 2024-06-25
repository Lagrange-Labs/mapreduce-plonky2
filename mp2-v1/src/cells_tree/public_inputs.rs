//! Public inputs for Cells Tree Construction circuits

use mp2_common::{
    group_hashing::EXTENSION_DEGREE,
    public_inputs::{PublicInputCommon, PublicInputRange},
    types::{CBuilder, GFp, GFp5, CURVE_TARGET_LEN},
    utils::convert_point_to_curve_target,
};
use plonky2::{
    field::{extension::FieldExtension, types::Field},
    hash::hash_types::{HashOutTarget, NUM_HASH_OUT_ELTS},
    iop::target::Target,
};
use plonky2_ecgfp5::{curve::curve::WeierstrassPoint, gadgets::curve::CurveTarget};
use std::{array, iter};

// Cells Tree Construction public inputs:
// - `H : [4]F` : Poseidon hash of the subtree at this node
// - `DC : Digest[F]` : Cells digests accumulated up so far
const H_RANGE: PublicInputRange = 0..NUM_HASH_OUT_ELTS;
const DC_RANGE: PublicInputRange = H_RANGE.end..H_RANGE.end + CURVE_TARGET_LEN;

/// Public inputs for Cells Tree Construction
#[derive(Clone, Debug)]
pub struct PublicInputs<'a, T> {
    pub(crate) h: &'a [T],
    pub(crate) dc: (&'a [T], &'a [T], &'a T),
}

impl<'a> PublicInputCommon for PublicInputs<'a, Target> {
    const RANGES: &'static [PublicInputRange] = &[H_RANGE, DC_RANGE];

    fn register_args(&self, cb: &mut CBuilder) {
        cb.register_public_inputs(self.h);
        cb.register_public_inputs(self.dc.0);
        cb.register_public_inputs(self.dc.1);
        cb.register_public_input(*self.dc.2);
    }
}

impl<'a> PublicInputs<'a, GFp> {
    /// Get the cells digest point.
    pub fn cells_point(&self) -> WeierstrassPoint {
        let x = array::from_fn::<_, EXTENSION_DEGREE, _>(|i| self.dc.0[i]);
        let y = array::from_fn::<_, EXTENSION_DEGREE, _>(|i| self.dc.1[i]);
        let is_inf = self.dc.2 == &GFp::ONE;

        WeierstrassPoint {
            x: GFp5::from_basefield_array(x),
            y: GFp5::from_basefield_array(y),
            is_inf,
        }
    }
}

impl<'a> PublicInputs<'a, Target> {
    /// Create a new public inputs.
    pub fn new(h: &'a [Target], dc: &'a CurveTarget) -> Self {
        let dc_x = &dc.0 .0[0].0[..];
        let dc_y = &dc.0 .0[1].0[..];
        let dc_is_inf = &dc.0 .1.target;

        Self {
            h,
            dc: (dc_x, dc_y, dc_is_inf),
        }
    }

    /// Get the Poseidon hash of the subtree at this node.
    pub fn node_hash(&self) -> HashOutTarget {
        self.h.try_into().unwrap()
    }

    /// Get the cells digest target.
    pub fn cells_target(&self) -> CurveTarget {
        let x = array::from_fn::<_, EXTENSION_DEGREE, _>(|i| self.dc.0[i]);
        let y = array::from_fn::<_, EXTENSION_DEGREE, _>(|i| self.dc.1[i]);
        let is_inf = *self.dc.2;

        convert_point_to_curve_target((x, y, is_inf))
    }
}

impl<'a, T: Copy> PublicInputs<'a, T> {
    /// Total length of the public inputs
    pub(crate) const TOTAL_LEN: usize = DC_RANGE.end;

    /// Create from a slice.
    pub fn from_slice(pi: &'a [T]) -> Self {
        assert!(pi.len() >= Self::TOTAL_LEN);

        Self {
            h: &pi[H_RANGE],
            dc: (
                &pi[DC_RANGE.start..DC_RANGE.start + CURVE_TARGET_LEN / 2],
                &pi[DC_RANGE.start + CURVE_TARGET_LEN / 2..DC_RANGE.end - 1],
                &pi[DC_RANGE.end - 1],
            ),
        }
    }

    /// Combine to a vector.
    pub fn to_vec(&self) -> Vec<T> {
        self.h
            .iter()
            .chain(self.dc.0)
            .chain(self.dc.1)
            .chain(iter::once(self.dc.2))
            .cloned()
            .collect()
    }

    pub fn h_raw(&self) -> &'a [T] {
        self.h
    }

    pub fn dc_raw(&self) -> (&'a [T], &'a [T], &'a T) {
        self.dc
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mp2_common::{
        utils::{Fieldable, ToFields},
        C, D, F,
    };
    use mp2_test::{
        circuit::{run_circuit, UserCircuit},
        utils::random_vector,
    };
    use plonky2::{
        field::types::Sample,
        iop::{
            target::Target,
            witness::{PartialWitness, WitnessWrite},
        },
    };
    use plonky2_ecgfp5::curve::curve::Point;
    use rand::thread_rng;

    #[derive(Clone, Debug)]
    struct TestPICircuit<'a> {
        exp_pi: &'a [F],
    }

    impl<'a> UserCircuit<F, D> for TestPICircuit<'a> {
        type Wires = Vec<Target>;

        fn build(b: &mut CBuilder) -> Self::Wires {
            let pi = b.add_virtual_targets(PublicInputs::<Target>::TOTAL_LEN);
            PublicInputs::from_slice(&pi).register(b);

            pi
        }

        fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
            pw.set_target_arr(&wires, self.exp_pi);
        }
    }

    #[test]
    fn test_cells_tree_public_inputs() {
        let mut rng = thread_rng();

        // Prepare the public inputs.
        let h = &random_vector::<u32>(NUM_HASH_OUT_ELTS).to_fields();
        let dc = Point::sample(&mut rng).to_weierstrass();
        let dc_is_inf = if dc.is_inf { F::ONE } else { F::ZERO };
        let dc = (dc.x.0.as_slice(), dc.y.0.as_slice(), &dc_is_inf);
        let exp_pi = PublicInputs { h, dc };
        let exp_pi = &exp_pi.to_vec();

        let test_circuit = TestPICircuit { exp_pi };
        let proof = run_circuit::<F, D, C, _>(test_circuit);

        assert_eq!(&proof.public_inputs, exp_pi);
    }
}
