mod api;
mod leaf;
mod membership;
mod parent;
mod public_inputs;

use crate::{
    extraction::{ExtractionPI, ExtractionPIWrap},
    row_tree,
};
pub use api::{CircuitInput, PublicParameters};
use mp2_common::{
    group_hashing::{
        circuit_hashed_scalar_mul, field_hashed_scalar_mul, weierstrass_to_point,
        CircuitBuilderGroupHashing,
    },
    poseidon::hash_to_int_target,
    types::CBuilder,
    utils::ToFields,
    CHasher, D, F,
};
use plonky2::{field::types::Field, iop::target::Target, plonk::circuit_builder::CircuitBuilder};
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
pub(crate) fn compute_final_digest(
    is_merge_case: bool,
    rows_tree_pi: &row_tree::PublicInputs<F>,
) -> Point {
    let individual_digest = weierstrass_to_point(&rows_tree_pi.individual_digest_point());
    if !is_merge_case {
        return individual_digest;
    }

    // Compute the final row digest from rows_tree_proof for merge case:
    // multiplier_digest = rows_tree_proof.row_id_multiplier * rows_tree_proof.multiplier_vd
    let multiplier_vd = weierstrass_to_point(&rows_tree_pi.multiplier_digest_point());
    let row_id_multiplier = Scalar::from_noncanonical_biguint(rows_tree_pi.row_id_multiplier());
    let multiplier_digest = multiplier_vd * row_id_multiplier;
    // rows_digest_merge = multiplier_digest * rows_tree_proof.DR
    let individual_digest = weierstrass_to_point(&rows_tree_pi.individual_digest_point());
    field_hashed_scalar_mul(multiplier_digest.to_fields(), individual_digest)
}

/// Compute the final digest target.
pub(crate) fn compute_final_digest_target<'a, E>(
    b: &mut CBuilder,
    extraction_pi: &E::PI<'a>,
    rows_tree_pi: &row_tree::PublicInputs<Target>,
) -> CurveTarget
where
    E: ExtractionPIWrap,
{
    // Compute the final row digest from rows_tree_proof for merge case:
    // multiplier_digest = rows_tree_proof.row_id_multiplier * rows_tree_proof.multiplier_vd
    let multiplier_vd = rows_tree_pi.multiplier_digest_target();
    let row_id_multiplier = b.biguint_to_nonnative(&rows_tree_pi.row_id_multiplier_target());
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
    // assert extraction_proof.is_merge or rows_tree_proof.multiplier_vd != 0
    // => (1 - is_merge) * is_multiplier_vd_zero == false
    let ffalse = b._false();
    let curve_zero = b.curve_zero();
    let is_multiplier_vd_zero = b
        .curve_eq(rows_tree_pi.multiplier_digest_target(), curve_zero)
        .target;
    let should_be_false = b.arithmetic(
        F::NEG_ONE,
        F::ONE,
        extraction_pi.is_merge_case().target,
        is_multiplier_vd_zero,
        is_multiplier_vd_zero,
    );
    b.connect(should_be_false, ffalse.target);

    final_digest
}

#[cfg(test)]
pub(crate) mod tests {
    use alloy::primitives::U256;
    use mp2_common::{keccak::PACKED_HASH_LEN, poseidon::HASH_TO_INT_LEN, utils::ToFields, F};
    use mp2_test::utils::random_vector;
    use num::BigUint;
    use plonky2::{
        field::types::{Field, Sample},
        hash::hash_types::NUM_HASH_OUT_ELTS,
        iop::target::Target,
    };
    use plonky2_ecgfp5::curve::curve::Point;
    use rand::{rngs::ThreadRng, Rng};
    use std::array;

    use crate::row_tree;

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
        let multiplier_digest = Point::rand();
        let row_id_multiplier = BigUint::from_slice(&random_vector::<u32>(HASH_TO_INT_LEN));

        row_tree::PublicInputs::sample(
            multiplier_digest,
            row_id_multiplier,
            min,
            max,
            is_merge_case,
        )
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
}
