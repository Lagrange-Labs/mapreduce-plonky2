pub mod digest_equal;
pub mod key;
pub mod length_extract;
pub mod length_match;
pub mod lpn;
pub mod mapping;

use plonky2::iop::target::Target;
use plonky2_ecgfp5::gadgets::curve::CurveTarget;

pub use digest_equal::PublicInputs;

pub(crate) const MAX_BRANCH_NODE_LEN: usize = 532;
pub(super) const MAX_LEAF_NODE_LEN: usize = MAX_EXTENSION_NODE_LEN;
/// rlp( rlp(max key 32b) + rlp(max value 32b) ) + 1 for compact encoding
/// see test_len()
pub(crate) const MAX_EXTENSION_NODE_LEN: usize = 69;

// Number of Goldilocks elements in CurveTarget
pub(crate) const CURVE_TARGET_SIZE: usize = 11;

fn iter_curve_target<'a>(t: &'a CurveTarget) -> impl Iterator<Item = &'a Target> {
    t.0 .0
        .iter()
        .flat_map(|x| x.0.iter())
        .chain(std::iter::once(&t.0 .1.target))
}
