pub mod leaf;
pub mod public_inputs;

use alloy::{consensus::TxReceipt, primitives::IntoLogData};

use mp2_common::{
    digest::Digest,
    eth::{EventLogInfo, ReceiptProofInfo},
    group_hashing::map_to_curve_point,
    types::GFp,
    utils::{Packer, ToFields},
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

/// Calculate `value_digest` for receipt leaf.
pub fn compute_receipt_leaf_value_digest(receipt_proof_info: &ReceiptProofInfo) -> Digest {
    let receipt = receipt_proof_info.to_receipt().unwrap();
    let gas_used = receipt.cumulative_gas_used();

    // Only use events that we are indexing
    let address = receipt_proof_info.event_log_info.address;
    let sig = receipt_proof_info.event_log_info.event_signature;

    let index_digest = map_to_curve_point(&[GFp::from_canonical_u64(receipt_proof_info.tx_index)]);

    let gas_digest = map_to_curve_point(&[GFp::ZERO, GFp::from_noncanonical_u128(gas_used)]);

    receipt
        .logs()
        .iter()
        .cloned()
        .filter_map(|log| {
            let log_address = log.address;
            let log_data = log.to_log_data();
            let (topics, data) = log_data.split();

            if log_address == address && topics[0].0 == sig {
                let topics_field = topics
                    .iter()
                    .skip(1)
                    .map(|fixed| fixed.0.pack(mp2_common::utils::Endianness::Big).to_fields())
                    .collect::<Vec<_>>();
                let data_fixed_bytes = data
                    .chunks(32)
                    .map(|chunk| chunk.pack(mp2_common::utils::Endianness::Big).to_fields())
                    .take(2)
                    .collect::<Vec<_>>();

                Some(
                    topics_field
                        .iter()
                        .chain(data_fixed_bytes.iter())
                        .enumerate()
                        .fold(gas_digest, |acc, (i, fixed)| {
                            let mut values = vec![GFp::from_canonical_usize(i) + GFp::ONE];
                            values.extend_from_slice(fixed);
                            acc + map_to_curve_point(&values)
                        }),
                )
            } else {
                None
            }
        })
        .fold(index_digest, |acc, p| acc + p)
}
