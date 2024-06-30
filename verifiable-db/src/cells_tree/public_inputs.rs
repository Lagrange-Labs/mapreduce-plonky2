//! Public inputs for Cells Tree Construction circuits

use mp2_common::{
    public_inputs::{PublicInputCommon, PublicInputRange},
    types::{CBuilder, GFp, CURVE_TARGET_LEN},
    utils::{FromFields, FromTargets},
};
use plonky2::{
    hash::hash_types::{HashOutTarget, NUM_HASH_OUT_ELTS},
    iop::target::Target,
};
use plonky2_ecgfp5::{curve::curve::WeierstrassPoint, gadgets::curve::CurveTarget};

// Cells Tree Construction public inputs:
// - `H : [4]F` : Poseidon hash of the subtree at this node
// - `DC : Digest[F]` : Cells digests accumulated up so far
const H_RANGE: PublicInputRange = 0..NUM_HASH_OUT_ELTS;
const DC_RANGE: PublicInputRange = H_RANGE.end..H_RANGE.end + CURVE_TARGET_LEN;

/// Public inputs for Cells Tree Construction
#[derive(Clone, Debug)]
pub struct PublicInputs<'a, T> {
    pub(crate) h: &'a [T],
    pub(crate) dc: &'a [T],
}

impl<'a> PublicInputCommon for PublicInputs<'a, Target> {
    const RANGES: &'static [PublicInputRange] = &[H_RANGE, DC_RANGE];

    fn register_args(&self, cb: &mut CBuilder) {
        cb.register_public_inputs(self.h);
        cb.register_public_inputs(self.dc);
    }
}

impl<'a> PublicInputs<'a, GFp> {
    /// Get the cells digest point.
    pub fn digest_point(&self) -> WeierstrassPoint {
        WeierstrassPoint::from_fields(self.dc)
    }
}

impl<'a> PublicInputs<'a, Target> {
    /// Get the Poseidon hash of the subtree at this node.
    pub fn node_hash(&self) -> HashOutTarget {
        self.h.try_into().unwrap()
    }

    /// Get the cells digest target.
    pub fn digest_target(&self) -> CurveTarget {
        CurveTarget::from_targets(self.dc)
    }
}

impl<'a, T: Copy> PublicInputs<'a, T> {
    /// Total length of the public inputs
    pub(crate) const TOTAL_LEN: usize = DC_RANGE.end;

    /// Create a new public inputs.
    pub fn new(h: &'a [T], dc: &'a [T]) -> Self {
        Self { h, dc }
    }
    /// Create from a slice.
    pub fn from_slice(pi: &'a [T]) -> Self {
        assert!(pi.len() >= Self::TOTAL_LEN);

        Self {
            h: &pi[H_RANGE],
            dc: &pi[DC_RANGE],
        }
    }

    /// Combine to a vector.
    pub fn to_vec(&self) -> Vec<T> {
        self.h.iter().chain(self.dc).cloned().collect()
    }

    pub fn h_raw(&self) -> &'a [T] {
        self.h
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
        field::types::{Field, Sample},
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
        let dc = &Point::sample(&mut rng).to_weierstrass().to_fields();
        let exp_pi = PublicInputs { h, dc };
        let exp_pi = &exp_pi.to_vec();

        let test_circuit = TestPICircuit { exp_pi };
        let proof = run_circuit::<F, D, C, _>(test_circuit);

        assert_eq!(&proof.public_inputs, exp_pi);
    }
}
