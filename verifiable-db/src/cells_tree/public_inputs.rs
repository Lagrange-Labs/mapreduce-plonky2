//! Public inputs for Cells Tree Construction circuits
use mp2_common::{
    digest::{SplitDigestPoint, SplitDigestTarget},
    group_hashing::weierstrass_to_point,
    public_inputs::{PublicInputCommon, PublicInputRange},
    types::{CBuilder, GFp, CURVE_TARGET_LEN},
    utils::{FromFields, FromTargets},
    F,
};
use plonky2::{
    hash::hash_types::{HashOut, HashOutTarget, NUM_HASH_OUT_ELTS},
    iop::target::Target,
};
use plonky2_ecgfp5::{curve::curve::WeierstrassPoint, gadgets::curve::CurveTarget};
use std::{array, fmt::Debug};

// Cells Tree Construction public inputs:
// - `H : [4]F` : Poseidon hash of the subtree at this node
// - `DI : Digest[F]` : Cells digests accumulated up so far for INDIVIDUAL digest
// - `DM: Digest[F]` : Cells digests accumulated up so far for MULTIPLIER digest
const H_RANGE: PublicInputRange = 0..NUM_HASH_OUT_ELTS;
const DI_RANGE: PublicInputRange = H_RANGE.end..H_RANGE.end + CURVE_TARGET_LEN;
const DM_RANGE: PublicInputRange = DI_RANGE.end..DI_RANGE.end + CURVE_TARGET_LEN;

/// Public inputs for Cells Tree Construction
#[derive(Clone, Debug)]
pub struct PublicInputs<'a, T> {
    pub(crate) h: &'a [T],
    pub(crate) ind: &'a [T],
    pub(crate) mul: &'a [T],
}

impl<'a> PublicInputCommon for PublicInputs<'a, Target> {
    const RANGES: &'static [PublicInputRange] = &[H_RANGE, DI_RANGE, DM_RANGE];

    fn register_args(&self, cb: &mut CBuilder) {
        cb.register_public_inputs(self.h);
        cb.register_public_inputs(self.ind);
        cb.register_public_inputs(self.mul);
    }
}

impl PublicInputs<'_, GFp> {
    /// Get the cells digest point.
    pub fn individual_digest_point(&self) -> WeierstrassPoint {
        WeierstrassPoint::from_fields(self.ind)
    }
    pub fn multiplier_digest_point(&self) -> WeierstrassPoint {
        WeierstrassPoint::from_fields(self.mul)
    }
    pub fn split_digest_point(&self) -> SplitDigestPoint {
        SplitDigestPoint {
            individual: weierstrass_to_point(&self.individual_digest_point()),
            multiplier: weierstrass_to_point(&self.multiplier_digest_point()),
        }
    }
}

impl PublicInputs<'_, Target> {
    /// Get the Poseidon hash of the subtree at this node.
    pub fn node_hash(&self) -> HashOutTarget {
        self.h.try_into().unwrap()
    }

    /// Get the individual digest target.
    pub fn individual_digest_target(&self) -> CurveTarget {
        CurveTarget::from_targets(self.ind)
    }

    /// Get the cells multiplier digest
    pub fn multiplier_digest_target(&self) -> CurveTarget {
        CurveTarget::from_targets(self.mul)
    }
    pub fn split_digest_target(&self) -> SplitDigestTarget {
        SplitDigestTarget {
            individual: self.individual_digest_target(),
            multiplier: self.multiplier_digest_target(),
        }
    }
}

impl<'a, T: Copy> PublicInputs<'a, T> {
    /// Total length of the public inputs
    pub(crate) const TOTAL_LEN: usize = DM_RANGE.end;

    /// Create a new public inputs.
    pub fn new(h: &'a [T], ind: &'a [T], mul: &'a [T]) -> Self {
        Self { h, ind, mul }
    }
    /// Create from a slice.
    pub fn from_slice(pi: &'a [T]) -> Self {
        assert!(pi.len() >= Self::TOTAL_LEN);

        Self {
            h: &pi[H_RANGE],
            ind: &pi[DI_RANGE],
            mul: &pi[DM_RANGE],
        }
    }

    /// Combine to a vector.
    pub fn to_vec(&self) -> Vec<T> {
        self.h
            .iter()
            .chain(self.ind)
            .chain(self.mul)
            .cloned()
            .collect()
    }

    pub fn h_raw(&self) -> &'a [T] {
        self.h
    }
}

impl PublicInputs<'_, F> {
    pub fn root_hash_hashout(&self) -> HashOut<F> {
        HashOut {
            elements: array::from_fn(|i| self.h[i]),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mp2_common::{utils::ToFields, C, D, F};
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

    impl UserCircuit<F, D> for TestPICircuit<'_> {
        type Wires = Vec<Target>;

        fn build(b: &mut CBuilder) -> Self::Wires {
            let pi = b.add_virtual_targets(PublicInputs::<Target>::TOTAL_LEN);
            PublicInputs::from_slice(&pi).register(b);

            pi
        }

        fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
            pw.set_target_arr(wires, self.exp_pi);
        }
    }

    #[test]
    fn test_cells_tree_public_inputs() {
        let mut rng = thread_rng();

        // Prepare the public inputs.
        let h = &random_vector::<u32>(NUM_HASH_OUT_ELTS).to_fields();
        let dc = &Point::sample(&mut rng).to_weierstrass().to_fields();
        let exp_pi = PublicInputs {
            h,
            ind: dc,
            mul: dc,
        };
        let exp_pi = &exp_pi.to_vec();

        let test_circuit = TestPICircuit { exp_pi };
        let proof = run_circuit::<F, D, C, _>(test_circuit);

        assert_eq!(&proof.public_inputs, exp_pi);
    }
}
