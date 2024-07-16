//! Public inputs for rows trees creation circuits
//!
use alloy::primitives::U256;
use mp2_common::{
    public_inputs::{PublicInputCommon, PublicInputRange},
    types::CURVE_TARGET_LEN,
    u256::{self, UInt256Target},
    utils::{FromFields, FromTargets},
    D, F,
};
use plonky2::{
    hash::hash_types::{HashOut, HashOutTarget, NUM_HASH_OUT_ELTS},
    iop::target::Target,
    plonk::circuit_builder::CircuitBuilder,
};
use plonky2_ecgfp5::{curve::curve::WeierstrassPoint, gadgets::curve::CurveTarget};
use std::array::from_fn as create_array;

// Contract extraction public Inputs:
// - `H : [4]F` : Poseidon hash of the leaf
// - `DR : Digest[F]` : accumulated digest of all the rows up to this node
// - `min : Uint256` : min value of the secondary index stored up to this node
// - `max : Uint256` : max value of the secondary index stored up to this node
const H_RANGE: PublicInputRange = 0..NUM_HASH_OUT_ELTS;
const DR_RANGE: PublicInputRange = H_RANGE.end..H_RANGE.end + CURVE_TARGET_LEN;
const MIN_RANGE: PublicInputRange = DR_RANGE.end..DR_RANGE.end + u256::NUM_LIMBS;
const MAX_RANGE: PublicInputRange = MIN_RANGE.end..MIN_RANGE.end + u256::NUM_LIMBS;

/// Public inputs for contract extraction
#[derive(Clone, Debug)]
pub struct PublicInputs<'a, T> {
    pub(crate) h: &'a [T],
    pub(crate) dr: &'a [T],
    pub(crate) min: &'a [T],
    pub(crate) max: &'a [T],
}

impl<'a> PublicInputCommon for PublicInputs<'a, Target> {
    const RANGES: &'static [PublicInputRange] = &[H_RANGE, DR_RANGE, MIN_RANGE, MAX_RANGE];

    fn register_args(&self, cb: &mut CircuitBuilder<F, D>) {
        cb.register_public_inputs(self.h);
        cb.register_public_inputs(self.dr);
        cb.register_public_inputs(self.min);
        cb.register_public_inputs(self.max);
    }
}

// mostly used for testing
impl<'a> PublicInputs<'a, F> {
    /// Get the metadata point.
    pub fn rows_digest_field(&self) -> WeierstrassPoint {
        WeierstrassPoint::from_fields(self.dr)
    }
    /// minimum index value
    pub fn min_value_u256(&self) -> U256 {
        U256::from_fields(self.min)
    }
    /// maximum index value
    pub fn max_value_u256(&self) -> U256 {
        U256::from_fields(self.max)
    }
    /// hash of the subtree at this node
    pub fn root_hash_hashout(&self) -> HashOut<F> {
        HashOut {
            elements: create_array(|i| self.h[i]),
        }
    }
}

impl<'a> PublicInputs<'a, Target> {
    /// Get the hash corresponding to the root of the subtree of this node
    pub fn root_hash(&self) -> HashOutTarget {
        HashOutTarget::from_targets(self.h)
    }

    pub fn rows_digest(&self) -> CurveTarget {
        let dv = self.dr;
        CurveTarget::from_targets(dv)
    }

    pub fn min_value(&self) -> UInt256Target {
        UInt256Target::from_targets(self.min)
    }
    pub fn max_value(&self) -> UInt256Target {
        UInt256Target::from_targets(self.max)
    }
}

pub const TOTAL_LEN: usize = PublicInputs::<Target>::TOTAL_LEN;

impl<'a, T: Copy> PublicInputs<'a, T> {
    /// Total length of the public inputs
    pub(crate) const TOTAL_LEN: usize = MAX_RANGE.end;

    /// Create from a slice.
    pub fn from_slice(pi: &'a [T]) -> Self {
        assert!(pi.len() >= Self::TOTAL_LEN);

        Self {
            h: &pi[H_RANGE],
            dr: &pi[DR_RANGE],
            min: &pi[MIN_RANGE],
            max: &pi[MAX_RANGE],
        }
    }

    /// Create a new public inputs.
    pub fn new(h: &'a [T], dr: &'a [T], min: &'a [T], max: &'a [T]) -> Self {
        assert_eq!(h.len(), NUM_HASH_OUT_ELTS);
        assert_eq!(dr.len(), CURVE_TARGET_LEN);
        assert_eq!(min.len(), u256::NUM_LIMBS);
        assert_eq!(max.len(), u256::NUM_LIMBS);
        Self { h, dr, min, max }
    }

    /// Combine to a vector.
    pub fn to_vec(&self) -> Vec<T> {
        self.h
            .iter()
            .chain(self.dr)
            .chain(self.min)
            .chain(self.max)
            .cloned()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::U256;
    use mp2_common::{public_inputs::PublicInputCommon, utils::ToFields, C, D, F};
    use mp2_test::circuit::{run_circuit, UserCircuit};
    use plonky2::{
        field::types::Sample,
        iop::{
            target::Target,
            witness::{PartialWitness, WitnessWrite},
        },
        plonk::config::GenericHashOut,
    };
    use plonky2_ecgfp5::curve::curve::Point;
    use rand::{thread_rng, Rng};

    #[derive(Clone, Debug)]
    struct TestPICircuit<'a> {
        exp_pi: &'a [F],
    }

    impl<'a> UserCircuit<F, D> for TestPICircuit<'a> {
        type Wires = Vec<Target>;

        fn build(b: &mut CircuitBuilder<F, D>) -> Self::Wires {
            let pi = b.add_virtual_targets(PublicInputs::<Target>::TOTAL_LEN);
            let pi = PublicInputs::from_slice(&pi);
            pi.register(b);
            pi.to_vec()
        }

        fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
            pw.set_target_arr(&wires, self.exp_pi);
        }
    }

    #[test]
    fn test_rows_tree_public_inputs() {
        let mut rng = thread_rng();

        // Prepare the public inputs.
        let h = HashOut::rand().to_vec();
        let dr = Point::sample(&mut rng);
        let drw = dr.to_weierstrass().to_fields();
        let min = U256::from_limbs(rng.gen::<[u64; 4]>()).to_fields();
        let max = U256::from_limbs(rng.gen::<[u64; 4]>()).to_fields();
        let exp_pi = PublicInputs::new(&h, &drw, &min, &max);
        let exp_pi = &exp_pi.to_vec();
        assert_eq!(exp_pi.len(), PublicInputs::<Target>::TOTAL_LEN);
        let test_circuit = TestPICircuit { exp_pi };
        let proof = run_circuit::<F, D, C, _>(test_circuit);

        assert_eq!(&proof.public_inputs, exp_pi);
    }
}
