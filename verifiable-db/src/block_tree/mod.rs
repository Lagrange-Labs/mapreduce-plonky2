mod api;
mod leaf;
mod membership;
mod parent;
mod public_inputs;

use std::iter::once;

use crate::{
    extraction::{ExtractionPI, ExtractionPIWrap},
    row_tree,
};
pub use api::{CircuitInput, PublicParameters};
use itertools::Itertools;
use mp2_common::{
    group_hashing::{
        circuit_hashed_scalar_mul, field_hashed_scalar_mul, weierstrass_to_point,
        CircuitBuilderGroupHashing,
    },
    poseidon::{empty_poseidon_hash, hash_to_int_target, hash_to_int_value, H},
    types::CBuilder,
    utils::{ToFields, ToTargets},
    CHasher, D, F,
};
use plonky2::{
    field::types::Field,
    iop::target::Target,
    plonk::{circuit_builder::CircuitBuilder, config::Hasher},
};
use plonky2_ecdsa::gadgets::nonnative::CircuitBuilderNonNative;

use plonky2_ecgfp5::{
    curve::{curve::Point, scalar_field::Scalar},
    gadgets::curve::{CircuitBuilderEcGFp5, CurveTarget},
};
pub use public_inputs::PublicInputs;

/// Common function to compute the digest of the block tree which uses a special format using
/// scalar1 multiplication
pub(crate) fn compute_index_digest(
    b: &mut CircuitBuilder<F, D>,
    inputs: Vec<Target>,
    base: CurveTarget,
) -> CurveTarget {
    let hash = b.hash_n_to_hash_no_pad::<CHasher>(inputs);
    let int = hash_to_int_target(b, hash);
    let scalar = b.biguint_to_nonnative(&int);
    b.curve_scalar_mul(base, &scalar)
}

/// Compute the final digest value.
pub fn compute_final_digest(
    is_merge_case: bool,
    rows_tree_pi: &row_tree::PublicInputs<F>,
) -> Point {
    let individual_digest = weierstrass_to_point(&rows_tree_pi.individual_digest_point());
    if !is_merge_case {
        return individual_digest;
    }
    // Compute the final row digest from rows_tree_proof for merge case:
    // row_id_multiplier = H2Int(H("") || rows_tree_proof.multiplier_counter)
    let empty_hash = empty_poseidon_hash();
    let inputs = empty_hash
        .to_fields()
        .into_iter()
        .chain(once(rows_tree_pi.multiplier_counter()))
        .collect_vec();
    let hash = H::hash_no_pad(&inputs);
    let row_id_multiplier = hash_to_int_value(hash);
    // multiplier_digest = rows_tree_proof.row_id_multiplier * rows_tree_proof.multiplier_vd
    let multiplier_vd = weierstrass_to_point(&rows_tree_pi.multiplier_digest_point());
    let row_id_multiplier = Scalar::from_noncanonical_biguint(row_id_multiplier);
    let multiplier_digest = multiplier_vd * row_id_multiplier;
    // rows_digest_merge = multiplier_digest * rows_tree_proof.DR
    let individual_digest = weierstrass_to_point(&rows_tree_pi.individual_digest_point());
    field_hashed_scalar_mul(multiplier_digest.to_fields(), individual_digest)
}

/// Compute the final digest target.
pub(crate) fn compute_final_digest_target<E>(
    b: &mut CBuilder,
    extraction_pi: &E::PI<'_>,
    rows_tree_pi: &row_tree::PublicInputs<Target>,
) -> CurveTarget
where
    E: ExtractionPIWrap,
{
    // Compute the final row digest from rows_tree_proof for merge case:
    // row_id_multiplier = H2Int(H("") || rows_tree_proof.multiplier_counter)
    let empty_hash = b.constant_hash(*empty_poseidon_hash());
    let inputs = empty_hash
        .to_targets()
        .into_iter()
        .chain(once(rows_tree_pi.multiplier_counter_target()))
        .collect();
    let hash = b.hash_n_to_hash_no_pad::<H>(inputs);
    let row_id_multiplier = hash_to_int_target(b, hash);
    // multiplier_digest = row_id_multiplier * rows_tree_proof.multiplier_vd
    let multiplier_vd = rows_tree_pi.multiplier_digest_target();
    let row_id_multiplier = b.biguint_to_nonnative(&row_id_multiplier);
    let multiplier_digest = b.curve_scalar_mul(multiplier_vd, &row_id_multiplier);
    // rows_digest_merge = multiplier_digest * rows_tree_proof.DR
    let individual_digest = rows_tree_pi.individual_digest_target();
    let rows_digest_merge = circuit_hashed_scalar_mul(b, multiplier_digest, individual_digest);

    // Choose the final row digest depending on whether we are in merge case or not:
    // final_digest = extraction_proof.is_merge ? rows_digest_merge : rows_tree_proof.DR
    let final_digest = b.curve_select(
        extraction_pi.is_merge_case(),
        rows_digest_merge,
        individual_digest,
    );

    // Enforce that the data extracted from the blockchain is the same as the data
    // employed to build the rows tree for this node:
    // assert final_digest == extraction_proof.DV
    b.connect_curve_points(final_digest, extraction_pi.value_set_digest());

    // Enforce that if we aren't in merge case, then no cells were accumulated in
    // multiplier digest:
    // assert extraction_proof.is_merge or rows_tree_proof.multiplier_vd == 0
    let curve_zero = b.curve_zero();
    let is_multiplier_vd_zero = b.curve_eq(rows_tree_pi.multiplier_digest_target(), curve_zero);
    let acc = b.or(extraction_pi.is_merge_case(), is_multiplier_vd_zero);
    b.assert_one(acc.target);

    final_digest
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::row_tree;
    use alloy::primitives::U256;
    use mp2_common::{
        keccak::PACKED_HASH_LEN,
        types::CBuilder,
        utils::{FromFields, ToFields},
        C, F,
    };
    use mp2_test::{
        circuit::{run_circuit, UserCircuit},
        utils::random_vector,
    };
    use plonky2::{
        field::types::{Field, Sample},
        hash::hash_types::NUM_HASH_OUT_ELTS,
        iop::{
            target::Target,
            witness::{PartialWitness, WitnessWrite},
        },
    };
    use plonky2_ecgfp5::curve::curve::Point;
    use rand::{rngs::ThreadRng, thread_rng, Rng};
    use std::array;

    pub(crate) type TestPITargets<'a> = crate::extraction::test::PublicInputs<'a, Target>;
    pub(crate) type TestPIField<'a> = crate::extraction::test::PublicInputs<'a, F>;

    /// Generate a random block index public inputs (of current module).
    pub(crate) fn random_block_index_pi(
        rng: &mut ThreadRng,
        min: U256,
        max: U256,
        block_number: U256,
    ) -> Vec<F> {
        let [h_new, h_old, metadata_hash] =
            [0; 3].map(|_| random_vector::<u32>(NUM_HASH_OUT_ELTS).to_fields());
        let [min, max, block_number] = [min, max, block_number].map(|u| u.to_fields());
        let [block_hash, prev_block_hash] =
            [0; 2].map(|_| random_vector::<u32>(PACKED_HASH_LEN).to_fields());
        let new_node_digest = Point::sample(rng).to_weierstrass().to_fields();
        super::PublicInputs::new(
            &h_new,
            &h_old,
            &min,
            &max,
            &block_number,
            &block_hash,
            &prev_block_hash,
            &metadata_hash,
            &new_node_digest,
        )
        .to_vec()
    }

    /// Generate a random rows tree public inputs.
    pub(crate) fn random_rows_tree_pi(rng: &mut ThreadRng, is_merge_case: bool) -> Vec<F> {
        let [min, max] = array::from_fn(|_| rng.gen());
        let multiplier_digest = if is_merge_case {
            Point::rand()
        } else {
            Point::NEUTRAL
        };
        let mulitplier_cnt = rng.gen_range(1..100);

        row_tree::PublicInputs::sample(multiplier_digest, min, max, mulitplier_cnt)
    }

    /// Generate a random extraction public inputs.
    pub(crate) fn random_extraction_pi(
        rng: &mut ThreadRng,
        block_number: U256,
        value_digest: &[F],
        is_merge_case: bool,
    ) -> Vec<F> {
        let [h, ph] = [0; 2].map(|_| random_vector::<u32>(PACKED_HASH_LEN).to_fields());
        let dm = Point::sample(rng).to_weierstrass().to_fields();
        let is_merge = [F::from_canonical_usize(is_merge_case as usize)];

        TestPIField::new(
            &h,
            &ph,
            value_digest,
            &dm,
            &block_number.to_fields(),
            &is_merge,
        )
        .to_vec()
    }

    #[derive(Clone, Debug)]
    struct TestFinalDigestCircuit<'a> {
        extraction_pi: &'a [F],
        rows_tree_pi: &'a [F],
    }

    impl UserCircuit<F, D> for TestFinalDigestCircuit<'_> {
        // Extraction PI + rows tree PI
        type Wires = (Vec<Target>, Vec<Target>);

        fn build(b: &mut CBuilder) -> Self::Wires {
            let extraction_pi = b.add_virtual_targets(TestPITargets::TOTAL_LEN);
            let rows_tree_pi = b.add_virtual_targets(row_tree::PublicInputs::<Target>::total_len());

            let final_digest = compute_final_digest_target::<TestPITargets>(
                b,
                &TestPITargets::from_slice(&extraction_pi),
                &row_tree::PublicInputs::from_slice(&rows_tree_pi),
            );

            b.register_curve_public_input(final_digest);

            (extraction_pi, rows_tree_pi)
        }

        fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
            pw.set_target_arr(&wires.0, self.extraction_pi);
            pw.set_target_arr(&wires.1, self.rows_tree_pi);
        }
    }

    #[test]
    fn test_block_tree_final_digest() {
        test_final_digest(true);
        test_final_digest(false);
    }

    fn test_final_digest(is_merge_case: bool) {
        let rng = &mut thread_rng();

        let rows_tree_pi = &random_rows_tree_pi(rng, is_merge_case);
        let exp_final_digest = compute_final_digest(
            is_merge_case,
            &row_tree::PublicInputs::from_slice(rows_tree_pi),
        );
        let block_number = U256::from_limbs(rng.gen());
        let extraction_pi = &random_extraction_pi(
            rng,
            block_number,
            &exp_final_digest.to_fields(),
            is_merge_case,
        );

        let test_circuit = TestFinalDigestCircuit {
            extraction_pi,
            rows_tree_pi,
        };

        let proof = run_circuit::<F, D, C, _>(test_circuit);
        let final_digest = Point::from_fields(&proof.public_inputs);

        assert_eq!(final_digest, exp_final_digest);
    }
}
