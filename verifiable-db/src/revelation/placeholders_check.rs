//! Check the placeholder identifiers and values with the specified `final_placeholder_hash`,
//! compute and return the `num_placeholders` and the `placeholder_ids_hash`.

use crate::query::computational_hash_ids::PlaceholderIdentifier;
use alloy::primitives::U256;
use itertools::Itertools;
use mp2_common::{
    array::ToField,
    poseidon::{empty_poseidon_hash, H},
    types::CBuilder,
    u256::{CircuitBuilderU256, UInt256Target, WitnessWriteU256},
    utils::{SelectHashBuilder, ToFields, ToTargets},
    F,
};
use plonky2::{
    hash::hash_types::{HashOut, HashOutTarget},
    iop::{
        target::{BoolTarget, Target},
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::config::Hasher,
};
use serde::{Deserialize, Serialize};
use std::{array, iter::once};

#[derive(Debug, Clone, Serialize, Deserialize)]
/// Data structure representing a placeholder target to be checked in the `check_placeholders` gadget
pub(crate) struct CheckedPlaceholderTarget {
    id: Target,
    value: UInt256Target,
    // expected position of the placeholder in placeholder ids and placeholder values arrays
    pos: Target,
}

impl CheckedPlaceholderTarget {
    pub(crate) fn new(b: &mut CBuilder) -> Self {
        Self {
            id: b.add_virtual_target(),
            value: b.add_virtual_u256_unsafe(), // unsafe is ok since these targets are enforced to be equal to other UInt256Target allocated with safe
            pos: b.add_virtual_target(),
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
/// Data structure representing a placeholder target to be checked in the `check_placeholders` gadget
pub(crate) struct CheckedPlaceholder {
    pub(crate) id: F,
    pub(crate) value: U256,
    pub(crate) pos: F,
}

impl CheckedPlaceholder {
    pub(crate) fn assign(&self, pw: &mut PartialWitness<F>, wires: &CheckedPlaceholderTarget) {
        pw.set_target(wires.id, self.id);
        pw.set_target(wires.pos, self.pos);
        pw.set_u256_target(&wires.value, self.value);
    }
}

/// Number of placeholders being hashed to include query bounds in the placeholder hash
pub(crate) const NUM_SECONDARY_INDEX_PLACEHOLDERS: usize = 4;

/// This gadget checks that the placeholders identifiers and values employed to
/// compute the `final_placeholder_hash` are found in placeholder_ids and
/// placeholder_values arrays respectively.
/// This method also computes the hash of the placeholder_ids, which is needed
/// to compute the public inputs of the proof, and the number of actual
/// placeholders expected for the query.
/// The general idea is to give the individual placeholders values, which might
/// repetition in the query, and recompute the placeholder hash from these values.
pub(crate) fn check_placeholders<const PH: usize, const PP: usize>(
    b: &mut CBuilder,
    is_placeholder_valid: &[BoolTarget; PH],
    placeholder_ids: &[Target; PH],
    placeholder_values: &[UInt256Target; PH],
    to_be_checked_placeholder: &[CheckedPlaceholderTarget; PP],
    secondary_query_bound_placeholder: &[CheckedPlaceholderTarget;
         NUM_SECONDARY_INDEX_PLACEHOLDERS], // placeholder pairs corresponding to query bounds for secondary index
    final_placeholder_hash: &HashOutTarget,
) -> (Target, HashOutTarget) {
    // Check the first 4 placeholder identifiers as constants.
    [
        PlaceholderIdentifier::MinQueryOnIdx1,
        PlaceholderIdentifier::MaxQueryOnIdx1,
    ]
    .iter()
    .enumerate()
    .for_each(|(i, id)| {
        let expected_id = b.constant(id.to_field());
        b.connect(placeholder_ids[i], expected_id);
    });

    let mut num_placeholders = b.zero();
    let mut placeholder_ids_hash = b.constant_hash(*empty_poseidon_hash());
    for i in 0..PH {
        // Enforce that the last invalid items found in placeholder_ids and
        // placeholder_values are the same as placeholder_ids[0] and
        // placeholder_values[0] respectively.
        let current_id = b.select(
            is_placeholder_valid[i],
            placeholder_ids[i],
            placeholder_ids[0],
        );
        let current_value = b.select_u256(
            is_placeholder_valid[i],
            &placeholder_values[i],
            &placeholder_values[0],
        );
        b.connect(current_id, placeholder_ids[i]);
        b.enforce_equal_u256(&current_value, &placeholder_values[i]);

        // Accumulate the number of placeholders.
        num_placeholders = b.add(num_placeholders, is_placeholder_valid[i].target);

        // Add current placeholder id to placeholder_ids_hash if the current placeholder is valid.
        let inputs = placeholder_ids_hash
            .to_targets()
            .into_iter()
            .chain(placeholder_ids[i].to_targets())
            .collect();
        let new_hash = b.hash_n_to_hash_no_pad::<H>(inputs);
        placeholder_ids_hash =
            b.select_hash(is_placeholder_valid[i], &new_hash, &placeholder_ids_hash);
    }

    // Pad the placeholder_ids to the next power of two for random_access.
    let mut padded_placeholder_ids = placeholder_ids.to_vec();
    let mut padded_placeholder_values = placeholder_values.to_vec();
    let pad_len = PH.next_power_of_two();
    assert!(
        pad_len <= 64,
        "random_access function cannot handle more than 64 elements"
    );
    padded_placeholder_ids.resize(pad_len, placeholder_ids[0]);
    padded_placeholder_values.resize(pad_len, placeholder_values[0].clone());

    let mut check_placeholder_pair = |id: &Target, value, pos| {
        // Check that the pair (id, value) is same as:
        // (placeholder_ids[pos], placeholder_values[pos])
        let expected_id = b.random_access(pos, padded_placeholder_ids.clone());
        let expected_value = b.random_access_u256(pos, &padded_placeholder_values);
        b.connect(*id, expected_id);
        b.enforce_equal_u256(value, &expected_value);
    };

    // Check the placeholder hash of proof is computed only from expected placeholder values.
    let mut placeholder_hash_payload = vec![];
    for i in 0..PP {
        // Accumulate the placeholder identifiers and values for computing the
        // placeholder hash.
        let CheckedPlaceholderTarget { id, value, pos } = &to_be_checked_placeholder[i];
        let payload = once(*id).chain(value.to_targets());
        placeholder_hash_payload.extend(payload);

        check_placeholder_pair(id, value, *pos);
    }

    // check placeholders related to secondary index bounds
    for i in 0..2 {
        let CheckedPlaceholderTarget { id, value, pos } = &secondary_query_bound_placeholder[i];
        check_placeholder_pair(id, value, *pos);
    }

    // Re-compute the placeholder hash from placeholder_pairs and minmum,
    // maximum query bounds. Then check it should be same with the specified
    // final placeholder hash.
    let [min_i1, max_i1] = array::from_fn(|i| &placeholder_values[i]);
    let placeholder_hash = b.hash_n_to_hash_no_pad::<H>(placeholder_hash_payload);
    // first_item = H(placeholder_hash || min_i2 || max_i2)
    let inputs = placeholder_hash
        .to_targets()
        .into_iter()
        .chain(
            secondary_query_bound_placeholder
                .iter()
                .flat_map(|placeholder| {
                    let mut placeholder_targets = vec![placeholder.id];
                    placeholder_targets.extend_from_slice(&placeholder.value.to_targets());
                    placeholder_targets
                }),
        )
        .collect_vec();
    let first_item = b.hash_n_to_hash_no_pad::<H>(inputs);
    // final_placeholder_hash = H(first_item || min_i1 || max_i1)
    let inputs = first_item
        .to_targets()
        .into_iter()
        .chain(min_i1.to_targets())
        .chain(max_i1.to_targets())
        .collect_vec();
    let expected_final_placeholder_hash = b.hash_n_to_hash_no_pad::<H>(inputs);
    b.connect_hashes(*final_placeholder_hash, expected_final_placeholder_hash);

    (num_placeholders, placeholder_ids_hash)
}

/// Compute the hash of placeholder ids provided as input, in the same way as it is computed in the `check_placeholders`
/// gadget
pub(crate) fn placeholder_ids_hash<I: IntoIterator<Item = PlaceholderIdentifier>>(
    placeholder_ids: I,
) -> HashOut<F> {
    placeholder_ids
        .into_iter()
        .fold(*empty_poseidon_hash(), |acc, id| {
            let inputs = acc
                .to_fields()
                .into_iter()
                .chain(once(id.to_field()))
                .collect_vec();
            H::hash_no_pad(&inputs)
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::revelation::tests::TestPlaceholders;
    use mp2_common::{u256::WitnessWriteU256, C, D, F};
    use mp2_test::circuit::{run_circuit, UserCircuit};
    use plonky2::{
        field::types::Field,
        iop::witness::{PartialWitness, WitnessWrite},
    };

    #[derive(Clone, Debug)]
    pub(crate) struct TestPlaceholdersWires<const PH: usize, const PP: usize> {
        is_placeholder_valid: [BoolTarget; PH],
        placeholder_ids: [Target; PH],
        placeholder_values: [UInt256Target; PH],
        to_be_checked_placeholders: [CheckedPlaceholderTarget; PP],
        secondary_query_bound_placeholders:
            [CheckedPlaceholderTarget; NUM_SECONDARY_INDEX_PLACEHOLDERS],
        final_placeholder_hash: HashOutTarget,
        exp_placeholder_ids_hash: HashOutTarget,
        exp_num_placeholders: Target,
    }

    impl<const PH: usize, const PP: usize> UserCircuit<F, D> for TestPlaceholders<PH, PP> {
        type Wires = TestPlaceholdersWires<PH, PP>;

        fn build(b: &mut CBuilder) -> Self::Wires {
            let is_placeholder_valid = array::from_fn(|_| b.add_virtual_bool_target_unsafe());
            let placeholder_ids = b.add_virtual_target_arr();
            let placeholder_values = array::from_fn(|_| b.add_virtual_u256_unsafe());
            let to_be_checked_placeholders = array::from_fn(|_| CheckedPlaceholderTarget {
                id: b.add_virtual_target(),
                value: b.add_virtual_u256_unsafe(),
                pos: b.add_virtual_target(),
            });
            let secondary_query_bound_placeholders = array::from_fn(|_| CheckedPlaceholderTarget {
                id: b.add_virtual_target(),
                value: b.add_virtual_u256_unsafe(),
                pos: b.add_virtual_target(),
            });
            let [final_placeholder_hash, exp_placeholder_ids_hash] =
                array::from_fn(|_| b.add_virtual_hash());
            let exp_num_placeholders = b.add_virtual_target();

            // Invoke the `check_placeholders` function.
            let (num_placeholders, placeholder_ids_hash) = check_placeholders(
                b,
                &is_placeholder_valid,
                &placeholder_ids,
                &placeholder_values,
                &to_be_checked_placeholders,
                &secondary_query_bound_placeholders,
                &final_placeholder_hash,
            );

            // Check the returned `num_placeholders` and `placeholder_ids_hash`.
            b.connect(num_placeholders, exp_num_placeholders);
            b.connect_hashes(placeholder_ids_hash, exp_placeholder_ids_hash);

            Self::Wires {
                is_placeholder_valid,
                placeholder_ids,
                placeholder_values,
                to_be_checked_placeholders,
                secondary_query_bound_placeholders,
                final_placeholder_hash,
                exp_placeholder_ids_hash,
                exp_num_placeholders,
            }
        }

        fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
            wires
                .is_placeholder_valid
                .iter()
                .enumerate()
                .for_each(|(i, t)| pw.set_bool_target(*t, i < self.num_placeholders));
            pw.set_target_arr(&wires.placeholder_ids, &self.placeholder_ids);
            wires
                .placeholder_values
                .iter()
                .zip(self.placeholder_values)
                .for_each(|(t, v)| pw.set_u256_target(t, v));
            wires
                .to_be_checked_placeholders
                .iter()
                .zip(&self.to_be_checked_placeholders)
                .for_each(|(t, v)| v.assign(pw, t));
            wires
                .secondary_query_bound_placeholders
                .iter()
                .zip(&self.secondary_query_bound_placeholders)
                .for_each(|(t, v)| v.assign(pw, t));
            [
                (wires.final_placeholder_hash, self.final_placeholder_hash),
                (wires.exp_placeholder_ids_hash, self.placeholder_ids_hash),
            ]
            .iter()
            .for_each(|(t, v)| pw.set_hash_target(*t, *v));
            pw.set_target(
                wires.exp_num_placeholders,
                F::from_canonical_usize(self.num_placeholders),
            );
        }
    }

    #[test]
    fn test_revelation_placeholders_check_with_all_valid_placeholders() {
        const PH: usize = 10;
        const PP: usize = 20;
        const NUM_PLACEHOLDERS: usize = 10;

        // Generate the testing placeholders.
        let test_circuit: TestPlaceholders<PH, PP> = TestPlaceholders::sample(NUM_PLACEHOLDERS);

        // Prove for the test circuit.
        run_circuit::<F, D, C, _>(test_circuit);
    }

    #[test]
    fn test_revelation_placeholders_check_including_invalid_placeholders() {
        const PH: usize = 15;
        const PP: usize = 20;
        const NUM_PLACEHOLDERS: usize = 10;

        // Generate the testing placeholders.
        let test_circuit: TestPlaceholders<PH, PP> = TestPlaceholders::sample(NUM_PLACEHOLDERS);

        // Prove for the test circuit.
        run_circuit::<F, D, C, _>(test_circuit);
    }
}
