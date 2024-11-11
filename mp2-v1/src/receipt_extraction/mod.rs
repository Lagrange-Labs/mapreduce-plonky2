pub mod leaf;
pub mod public_inputs;

use mp2_common::{
    digest::Digest, eth::EventLogInfo, group_hashing::map_to_curve_point, types::GFp,
};
use plonky2::field::types::Field;

/// Calculate `metadata_digest = D(address || signature || topics)` for receipt leaf.
/// Topics is an array of 5 values (some are dummies), each being `column_id`, `rel_byte_offset` (from the start of the log)
/// and `len`.
pub fn compute_receipt_leaf_metadata_digest(event: &EventLogInfo) -> Digest {
    let topics_flat = event
        .topics
        .iter()
        .chain(event.data.iter())
        .flat_map(|t| [t.column_id, t.rel_byte_offset, t.len])
        .collect::<Vec<usize>>();

    let mut out = Vec::new();
    out.push(event.size);
    out.extend_from_slice(&event.address.0.map(|byte| byte as usize));
    out.push(event.add_rel_offset);
    out.extend_from_slice(&event.event_signature.map(|byte| byte as usize));
    out.push(event.sig_rel_offset);
    out.extend_from_slice(&topics_flat);

    let data = out
        .into_iter()
        .map(GFp::from_canonical_usize)
        .collect::<Vec<_>>();
    map_to_curve_point(&data)
}
