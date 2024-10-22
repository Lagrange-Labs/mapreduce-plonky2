//! Public inputs for Cells Tree Construction circuits

use mp2_common::{
    digest::{SplitDigestPoint, SplitDigestTarget},
    group_hashing::weierstrass_to_point,
    public_inputs::{PublicInputCommon, PublicInputRange},
    types::{CBuilder, CURVE_TARGET_LEN},
    utils::{FromFields, FromTargets},
    F,
};
use plonky2::{
    hash::hash_types::{HashOut, NUM_HASH_OUT_ELTS},
    iop::target::Target,
};
use plonky2_ecgfp5::{curve::curve::WeierstrassPoint, gadgets::curve::CurveTarget};

pub enum CellsTreePublicInputs {
    // `H : F[4]` - Poseidon hash of the subtree at this node
    NodeHash,
    // - `individual_vd : Digest` - Cumulative digest of values of cells accumulated as individual
    IndividualValuesDigest,
    // - `multiplier_vd : Digest` - Cumulative digest of values of cells accumulated as multiplier
    MultiplierValuesDigest,
    // - `individual_md : Digest` - Cumulative digest of metadata of cells accumulated as individual
    IndividualMetadataDigest,
    // - `multiplier_md : Digest` - Cumulative digest of metadata of cells accumulated as multiplier
    MultiplierMetadataDigest,
}

/// Public inputs for Cells Tree Construction
#[derive(Clone, Debug)]
pub struct PublicInputs<'a, T> {
    pub(crate) h: &'a [T],
    pub(crate) individual_vd: &'a [T],
    pub(crate) multiplier_vd: &'a [T],
    pub(crate) individual_md: &'a [T],
    pub(crate) multiplier_md: &'a [T],
}

const NUM_PUBLIC_INPUTS: usize = CellsTreePublicInputs::MultiplierMetadataDigest as usize + 1;

impl<'a, T: Clone> PublicInputs<'a, T> {
    const PI_RANGES: [PublicInputRange; NUM_PUBLIC_INPUTS] = [
        Self::to_range(CellsTreePublicInputs::NodeHash),
        Self::to_range(CellsTreePublicInputs::IndividualValuesDigest),
        Self::to_range(CellsTreePublicInputs::MultiplierValuesDigest),
        Self::to_range(CellsTreePublicInputs::IndividualMetadataDigest),
        Self::to_range(CellsTreePublicInputs::MultiplierMetadataDigest),
    ];

    const SIZES: [usize; NUM_PUBLIC_INPUTS] = [
        // Poseidon hash of the subtree at this node
        NUM_HASH_OUT_ELTS,
        // Cumulative digest of values of cells accumulated as individual
        CURVE_TARGET_LEN,
        // Cumulative digest of values of cells accumulated as multiplier
        CURVE_TARGET_LEN,
        // Cumulative digest of metadata of cells accumulated as individual
        CURVE_TARGET_LEN,
        // Cumulative digest of metadata of cells accumulated as multiplier
        CURVE_TARGET_LEN,
    ];

    pub(crate) const fn to_range(pi: CellsTreePublicInputs) -> PublicInputRange {
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
        Self::to_range(CellsTreePublicInputs::MultiplierMetadataDigest).end
    }

    pub fn to_node_hash_raw(&self) -> &[T] {
        self.h
    }

    pub fn to_individual_values_digest_raw(&self) -> &[T] {
        self.individual_vd
    }

    pub fn to_multiplier_values_digest_raw(&self) -> &[T] {
        self.multiplier_vd
    }

    pub fn to_individual_metadata_digest_raw(&self) -> &[T] {
        self.individual_md
    }

    pub fn to_multiplier_metadata_digest_raw(&self) -> &[T] {
        self.multiplier_md
    }

    pub fn from_slice(input: &'a [T]) -> Self {
        assert!(
            input.len() >= Self::total_len(),
            "Input slice too short to build cells tree public inputs, must be at least {} elements",
            Self::total_len(),
        );

        Self {
            h: &input[Self::PI_RANGES[0].clone()],
            individual_vd: &input[Self::PI_RANGES[1].clone()],
            multiplier_vd: &input[Self::PI_RANGES[2].clone()],
            individual_md: &input[Self::PI_RANGES[3].clone()],
            multiplier_md: &input[Self::PI_RANGES[4].clone()],
        }
    }

    pub fn new(
        h: &'a [T],
        individual_vd: &'a [T],
        multiplier_vd: &'a [T],
        individual_md: &'a [T],
        multiplier_md: &'a [T],
    ) -> Self {
        Self {
            h,
            individual_vd,
            multiplier_vd,
            individual_md,
            multiplier_md,
        }
    }

    pub fn to_vec(&self) -> Vec<T> {
        self.h
            .iter()
            .chain(self.individual_vd)
            .chain(self.multiplier_vd)
            .chain(self.individual_md)
            .chain(self.multiplier_md)
            .cloned()
            .collect()
    }
}

impl<'a> PublicInputCommon for PublicInputs<'a, Target> {
    const RANGES: &'static [PublicInputRange] = &Self::PI_RANGES;

    fn register_args(&self, cb: &mut CBuilder) {
        cb.register_public_inputs(self.h);
        cb.register_public_inputs(self.individual_vd);
        cb.register_public_inputs(self.multiplier_vd);
        cb.register_public_inputs(self.individual_md);
        cb.register_public_inputs(self.multiplier_md);
    }
}

impl<'a> PublicInputs<'a, Target> {
    pub fn node_hash_target(&self) -> [Target; NUM_HASH_OUT_ELTS] {
        self.to_node_hash_raw().try_into().unwrap()
    }

    pub fn individual_values_digest_target(&self) -> CurveTarget {
        CurveTarget::from_targets(self.individual_vd)
    }

    pub fn multiplier_values_digest_target(&self) -> CurveTarget {
        CurveTarget::from_targets(self.multiplier_vd)
    }

    pub fn individual_metadata_digest_target(&self) -> CurveTarget {
        CurveTarget::from_targets(self.individual_md)
    }

    pub fn multiplier_metadata_digest_target(&self) -> CurveTarget {
        CurveTarget::from_targets(self.multiplier_md)
    }

    pub fn split_values_digest_target(&self) -> SplitDigestTarget {
        SplitDigestTarget {
            individual: self.individual_values_digest_target(),
            multiplier: self.multiplier_values_digest_target(),
        }
    }

    pub fn split_metadata_digest_target(&self) -> SplitDigestTarget {
        SplitDigestTarget {
            individual: self.individual_metadata_digest_target(),
            multiplier: self.multiplier_metadata_digest_target(),
        }
    }
}

impl<'a> PublicInputs<'a, F> {
    pub fn node_hash(&self) -> HashOut<F> {
        HashOut::from_partial(self.to_node_hash_raw())
    }

    pub fn individual_values_digest_point(&self) -> WeierstrassPoint {
        WeierstrassPoint::from_fields(self.individual_vd)
    }

    pub fn multiplier_values_digest_point(&self) -> WeierstrassPoint {
        WeierstrassPoint::from_fields(self.multiplier_vd)
    }

    pub fn individual_metadata_digest_point(&self) -> WeierstrassPoint {
        WeierstrassPoint::from_fields(self.individual_md)
    }

    pub fn multiplier_metadata_digest_point(&self) -> WeierstrassPoint {
        WeierstrassPoint::from_fields(self.multiplier_md)
    }

    pub fn split_values_digest_point(&self) -> SplitDigestPoint {
        SplitDigestPoint {
            individual: weierstrass_to_point(&self.individual_values_digest_point()),
            multiplier: weierstrass_to_point(&self.multiplier_values_digest_point()),
        }
    }

    pub fn split_metadata_digest_point(&self) -> SplitDigestPoint {
        SplitDigestPoint {
            individual: weierstrass_to_point(&self.individual_metadata_digest_point()),
            multiplier: weierstrass_to_point(&self.multiplier_metadata_digest_point()),
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
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
    use rand::{thread_rng, Rng};
    use std::array;

    impl<'a> PublicInputs<'a, F> {
        pub(crate) fn sample(is_multiplier: bool) -> Vec<F> {
            let rng = &mut thread_rng();

            let h = random_vector::<u32>(NUM_HASH_OUT_ELTS).to_fields();

            let point_zero = WeierstrassPoint::NEUTRAL.to_fields();
            let [values_digest, metadata_digest] =
                array::from_fn(|_| Point::sample(rng).to_weierstrass().to_fields());
            let [individual_vd, multiplier_vd, individual_md, multiplier_md] = if is_multiplier {
                [
                    point_zero.clone(),
                    values_digest,
                    point_zero,
                    metadata_digest,
                ]
            } else {
                [
                    values_digest,
                    point_zero.clone(),
                    metadata_digest,
                    point_zero,
                ]
            };

            PublicInputs::new(
                &h,
                &individual_vd,
                &multiplier_vd,
                &individual_md,
                &multiplier_md,
            )
            .to_vec()
        }
    }

    #[derive(Clone, Debug)]
    struct TestPublicInputs<'a> {
        exp_pi: &'a [F],
    }

    impl<'a> UserCircuit<F, D> for TestPublicInputs<'a> {
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
    fn test_cells_tree_public_inputs() {
        let rng = &mut thread_rng();
        let is_multiplier = rng.gen();

        let exp_pi = &PublicInputs::sample(is_multiplier);
        let test_circuit = TestPublicInputs { exp_pi };
        let proof = run_circuit::<F, D, C, _>(test_circuit);
        assert_eq!(&proof.public_inputs, exp_pi);

        // Check if the public inputs are constructed correctly.
        let pi = PublicInputs::from_slice(&proof.public_inputs);
        assert_eq!(
            &exp_pi[PublicInputs::<F>::to_range(CellsTreePublicInputs::NodeHash)],
            pi.to_node_hash_raw(),
        );
        assert_eq!(
            &exp_pi[PublicInputs::<F>::to_range(CellsTreePublicInputs::IndividualValuesDigest)],
            pi.to_individual_values_digest_raw(),
        );
        assert_eq!(
            &exp_pi[PublicInputs::<F>::to_range(CellsTreePublicInputs::MultiplierValuesDigest)],
            pi.to_multiplier_values_digest_raw(),
        );
        assert_eq!(
            &exp_pi[PublicInputs::<F>::to_range(CellsTreePublicInputs::IndividualMetadataDigest)],
            pi.to_individual_metadata_digest_raw(),
        );
        assert_eq!(
            &exp_pi[PublicInputs::<F>::to_range(CellsTreePublicInputs::MultiplierMetadataDigest)],
            pi.to_multiplier_metadata_digest_raw(),
        );
    }
}
