//! Public inputs for rows trees creation circuits

use alloy::primitives::U256;
use mp2_common::{
    public_inputs::{PublicInputCommon, PublicInputRange},
    types::{CBuilder, CURVE_TARGET_LEN},
    u256::{self, UInt256Target},
    utils::{FromFields, FromTargets},
    F,
};
use plonky2::{
    hash::hash_types::{HashOut, NUM_HASH_OUT_ELTS},
    iop::target::Target,
};
use plonky2_ecgfp5::{curve::curve::WeierstrassPoint, gadgets::curve::CurveTarget};
use std::iter::once;

pub enum RowsTreePublicInputs {
    // `H : F[4]` - Poseidon hash of the leaf
    RootHash,
    // `individual_digest : Digest`  - Cumulative digest of the values of the cells which are accumulated in individual digest
    IndividualDigest,
    // `multiplier_digest : Digest`  - Cumulative digest of the values of the cells which are accumulated in multiplier digest
    MultiplierDigest,
    // `min : Uint256` - Minimum alue of the secondary index stored up to this node
    MinValue,
    // `max : Uint256` - Maximum value of the secondary index stored up to this node
    MaxValue,
    // `multiplier_counter : F` - Number of cells accumulated as multiplier
    MultiplierCounter,
}

/// Public inputs for Rows Tree Construction
#[derive(Clone, Debug)]
pub struct PublicInputs<'a, T> {
    pub(crate) h: &'a [T],
    pub(crate) individual_digest: &'a [T],
    pub(crate) multiplier_digest: &'a [T],
    pub(crate) min: &'a [T],
    pub(crate) max: &'a [T],
    pub(crate) multiplier_cnt: &'a T,
}

const NUM_PUBLIC_INPUTS: usize = RowsTreePublicInputs::MultiplierCounter as usize + 1;

impl<'a, T: Clone> PublicInputs<'a, T> {
    const PI_RANGES: [PublicInputRange; NUM_PUBLIC_INPUTS] = [
        Self::to_range(RowsTreePublicInputs::RootHash),
        Self::to_range(RowsTreePublicInputs::IndividualDigest),
        Self::to_range(RowsTreePublicInputs::MultiplierDigest),
        Self::to_range(RowsTreePublicInputs::MinValue),
        Self::to_range(RowsTreePublicInputs::MaxValue),
        Self::to_range(RowsTreePublicInputs::MultiplierCounter),
    ];

    const SIZES: [usize; NUM_PUBLIC_INPUTS] = [
        // Poseidon hash of the leaf
        NUM_HASH_OUT_ELTS,
        // Cumulative digest of the values of the cells which are accumulated in individual digest
        CURVE_TARGET_LEN,
        // Cumulative digest of the values of the cells which are accumulated in multiplier digest
        CURVE_TARGET_LEN,
        // Minimum value of the secondary index stored up to this node
        u256::NUM_LIMBS,
        // Maximum value of the secondary index stored up to this node
        u256::NUM_LIMBS,
        // Counter of the number of cells accumulated so far as multiplier
        1,
    ];

    pub(crate) const fn to_range(pi: RowsTreePublicInputs) -> PublicInputRange {
        let mut i = 0;
        let mut offset = 0;
        let pi_pos = pi as usize;
        while i < pi_pos {
            offset += Self::SIZES[i];
            i += 1;
        }
        offset..offset + Self::SIZES[pi_pos]
    }

    pub const fn total_len() -> usize {
        Self::to_range(RowsTreePublicInputs::MultiplierCounter).end
    }

    pub fn to_root_hash_raw(&self) -> &[T] {
        self.h
    }

    pub fn to_individual_digest_raw(&self) -> &[T] {
        self.individual_digest
    }

    pub fn to_multiplier_digest_raw(&self) -> &[T] {
        self.multiplier_digest
    }

    pub fn to_min_value_raw(&self) -> &[T] {
        self.min
    }

    pub fn to_max_value_raw(&self) -> &[T] {
        self.max
    }

    pub fn to_multiplier_counter_raw(&self) -> &T {
        self.multiplier_cnt
    }

    pub fn from_slice(input: &'a [T]) -> Self {
        assert!(
            input.len() >= Self::total_len(),
            "Input slice too short to build rows tree public inputs, must be at least {} elements",
            Self::total_len(),
        );

        Self {
            h: &input[Self::PI_RANGES[0].clone()],
            individual_digest: &input[Self::PI_RANGES[1].clone()],
            multiplier_digest: &input[Self::PI_RANGES[2].clone()],
            min: &input[Self::PI_RANGES[3].clone()],
            max: &input[Self::PI_RANGES[4].clone()],
            multiplier_cnt: &input[Self::PI_RANGES[5].clone()][0],
        }
    }

    pub fn new(
        h: &'a [T],
        individual_digest: &'a [T],
        multiplier_digest: &'a [T],
        min: &'a [T],
        max: &'a [T],
        multiplier_cnt: &'a T,
    ) -> Self {
        Self {
            h,
            individual_digest,
            multiplier_digest,
            min,
            max,
            multiplier_cnt,
        }
    }

    pub fn to_vec(&self) -> Vec<T> {
        self.h
            .iter()
            .chain(self.individual_digest)
            .chain(self.multiplier_digest)
            .chain(self.min)
            .chain(self.max)
            .chain(once(self.multiplier_cnt))
            .cloned()
            .collect()
    }
}

impl PublicInputCommon for PublicInputs<'_, Target> {
    const RANGES: &'static [PublicInputRange] = &Self::PI_RANGES;

    fn register_args(&self, cb: &mut CBuilder) {
        cb.register_public_inputs(self.h);
        cb.register_public_inputs(self.individual_digest);
        cb.register_public_inputs(self.multiplier_digest);
        cb.register_public_inputs(self.min);
        cb.register_public_inputs(self.max);
        cb.register_public_input(*self.multiplier_cnt);
    }
}

impl PublicInputs<'_, Target> {
    pub fn root_hash_target(&self) -> [Target; NUM_HASH_OUT_ELTS] {
        self.to_root_hash_raw().try_into().unwrap()
    }

    pub fn individual_digest_target(&self) -> CurveTarget {
        CurveTarget::from_targets(self.individual_digest)
    }

    pub fn multiplier_digest_target(&self) -> CurveTarget {
        CurveTarget::from_targets(self.multiplier_digest)
    }

    pub fn min_value_target(&self) -> UInt256Target {
        UInt256Target::from_targets(self.min)
    }

    pub fn max_value_target(&self) -> UInt256Target {
        UInt256Target::from_targets(self.max)
    }

    pub fn multiplier_counter_target(&self) -> Target {
        *self.to_multiplier_counter_raw()
    }
}

impl PublicInputs<'_, F> {
    pub fn root_hash(&self) -> HashOut<F> {
        HashOut::from_partial(self.h)
    }

    pub fn individual_digest_point(&self) -> WeierstrassPoint {
        WeierstrassPoint::from_fields(self.individual_digest)
    }

    pub fn multiplier_digest_point(&self) -> WeierstrassPoint {
        WeierstrassPoint::from_fields(self.multiplier_digest)
    }

    pub fn min_value(&self) -> U256 {
        U256::from_fields(self.min)
    }

    pub fn max_value(&self) -> U256 {
        U256::from_fields(self.max)
    }

    pub fn multiplier_counter(&self) -> F {
        *self.to_multiplier_counter_raw()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use mp2_common::{utils::ToFields, C, D, F};
    use mp2_test::circuit::{run_circuit, UserCircuit};
    use plonky2::{
        field::types::{Field, Sample},
        iop::{
            target::Target,
            witness::{PartialWitness, WitnessWrite},
        },
    };
    use plonky2_ecgfp5::curve::curve::Point;
    use rand::{thread_rng, Rng};
    use std::{array, slice};

    impl PublicInputs<'_, F> {
        pub(crate) fn sample(
            multiplier_digest: Point,
            min: usize,
            max: usize,
            multiplier_cnt: u64,
        ) -> Vec<F> {
            let h = HashOut::rand().to_fields();
            let individual_digest = Point::rand();
            let [individual_digest, multiplier_digest] =
                [individual_digest, multiplier_digest].map(|p| p.to_weierstrass().to_fields());
            let [min, max] = [min, max].map(|v| U256::from(v).to_fields());
            let multiplier_cnt = F::from_canonical_u64(multiplier_cnt);
            PublicInputs::new(
                &h,
                &individual_digest,
                &multiplier_digest,
                &min,
                &max,
                &multiplier_cnt,
            )
            .to_vec()
        }
    }

    #[derive(Clone, Debug)]
    struct TestPublicInputs<'a> {
        exp_pi: &'a [F],
    }

    impl UserCircuit<F, D> for TestPublicInputs<'_> {
        type Wires = Vec<Target>;

        fn build(b: &mut CBuilder) -> Self::Wires {
            let exp_pi = b.add_virtual_targets(PublicInputs::<Target>::total_len());
            PublicInputs::from_slice(&exp_pi).register(b);

            exp_pi
        }

        fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
            pw.set_target_arr(wires, self.exp_pi);
        }
    }

    #[test]
    fn test_rows_tree_public_inputs() {
        let rng = &mut thread_rng();

        // Prepare the public inputs.
        let multiplier_digest = Point::sample(rng);
        let [min, max] = array::from_fn(|_| rng.gen());
        let multiplier_cnt = rng.gen();
        let exp_pi = PublicInputs::sample(multiplier_digest, min, max, multiplier_cnt);
        let exp_pi = &exp_pi.to_vec();

        let test_circuit = TestPublicInputs { exp_pi };
        let proof = run_circuit::<F, D, C, _>(test_circuit);
        assert_eq!(&proof.public_inputs, exp_pi);

        // Check if the public inputs are constructed correctly.
        let pi = PublicInputs::from_slice(&proof.public_inputs);
        assert_eq!(
            &exp_pi[PublicInputs::<F>::to_range(RowsTreePublicInputs::RootHash)],
            pi.to_root_hash_raw(),
        );
        assert_eq!(
            &exp_pi[PublicInputs::<F>::to_range(RowsTreePublicInputs::IndividualDigest)],
            pi.to_individual_digest_raw(),
        );
        assert_eq!(
            &exp_pi[PublicInputs::<F>::to_range(RowsTreePublicInputs::MultiplierDigest)],
            pi.to_multiplier_digest_raw(),
        );
        assert_eq!(
            &exp_pi[PublicInputs::<F>::to_range(RowsTreePublicInputs::MinValue)],
            pi.to_min_value_raw(),
        );
        assert_eq!(
            &exp_pi[PublicInputs::<F>::to_range(RowsTreePublicInputs::MaxValue)],
            pi.to_max_value_raw(),
        );
        assert_eq!(
            &exp_pi[PublicInputs::<F>::to_range(RowsTreePublicInputs::MultiplierCounter)],
            slice::from_ref(pi.to_multiplier_counter_raw()),
        );
    }
}
