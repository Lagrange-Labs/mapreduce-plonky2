mod api;
mod empty_node;
mod full_node;
mod leaf;
mod partial_node;
mod public_inputs;

pub use api::{build_circuits_params, extract_hash_from_proof, CircuitInput, PublicParameters};
use mp2_common::{group_hashing::CircuitBuilderGroupHashing, types::CBuilder, utils::ToTargets};
use plonky2::iop::target::{BoolTarget, Target};
use plonky2_ecgfp5::gadgets::curve::CurveTarget;
pub use public_inputs::PublicInputs;

pub(crate) fn decide_digest_section(
    c: &mut CBuilder,
    digest: CurveTarget,
    is_multiplier: BoolTarget,
) -> (CurveTarget, CurveTarget) {
    let zero_curve = b.curve_zero();
    let digest_ind = b.curve_select(is_multiplier, zero_curve, digest);
    let digest_mult = b.curve_select(is_multiplier, digest, zero_curve);
    (digest_ind, digest_mult)
}
/// aggregate the digest of the child proof in the right digest
pub(crate) fn accumulate_proof_digest(
    c: &mut CBuilder,
    ind: CurveTarget,
    mul: CurveTarget,
    child_proof: PublicInputs<Target>,
) -> (CurveTarget, CurveTarget) {
    let child_digest_ind = child_proof.individual_digest_target();
    let digest_ind = c.add_curve_point(&[child_digest_ind, ind]).to_targets();
    let child_digest_mult = child_proof.multiplier_digest_target();
    let digest_mul = c.add_curve_point(&[child_digest_mult, mul]).to_targets();
    (digest_ind, digest_mul)
}
