//! Check the placeholder identifiers and values with the specified `final_placeholder_hash`,
//! compute and return the `num_placeholders` and the `placeholder_ids_hash`.

use crate::query::{
    aggregation::QueryBounds,
    computational_hash_ids::PlaceholderIdentifier,
    universal_circuit::{
        universal_circuit_inputs::{PlaceholderId, Placeholders},
        universal_query_gadget::QueryBound,
    },
};
use alloy::primitives::U256;
use anyhow::{ensure, Result};
use itertools::Itertools;
use mp2_common::{
    array::ToField,
    poseidon::{empty_poseidon_hash, H},
    serialization::{
        deserialize_array, deserialize_long_array, serialize_array, serialize_long_array,
    },
    types::CBuilder,
    u256::{CircuitBuilderU256, UInt256Target, WitnessWriteU256},
    utils::{FromFields, SelectHashBuilder, ToFields, ToTargets},
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
use std::{
    array,
    iter::{once, repeat},
};

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
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct CheckPlaceholderInputWires<const PH: usize, const PP: usize> {
    #[serde(
        serialize_with = "serialize_array",
        deserialize_with = "deserialize_array"
    )]
    pub(crate) is_placeholder_valid: [BoolTarget; PH],
    #[serde(
        serialize_with = "serialize_array",
        deserialize_with = "deserialize_array"
    )]
    pub(crate) placeholder_ids: [Target; PH],
    #[serde(
        serialize_with = "serialize_array",
        deserialize_with = "deserialize_array"
    )]
    pub(crate) placeholder_values: [UInt256Target; PH],
    #[serde(
        serialize_with = "serialize_long_array",
        deserialize_with = "deserialize_long_array"
    )]
    pub(crate) to_be_checked_placeholders: [CheckedPlaceholderTarget; PP],
    pub(crate) secondary_query_bound_placeholders:
        [CheckedPlaceholderTarget; NUM_SECONDARY_INDEX_PLACEHOLDERS],
}

pub(crate) struct CheckPlaceholderWires<const PH: usize, const PP: usize> {
    pub(crate) input_wires: CheckPlaceholderInputWires<PH, PP>,
    pub(crate) num_placeholders: Target,
    pub(crate) placeholder_id_hash: HashOutTarget,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct CheckPlaceholderGadget<const PH: usize, const PP: usize> {
    /// Real number of the valid placeholders
    pub(crate) num_placeholders: usize,
    /// Array of the placeholder identifiers that can be employed in the query:
    /// - The first 4 items are expected to be constant identifiers of the query
    ///   bounds `MIN_I1, MAX_I1` and  `MIN_I2, MAX_I2`
    /// - The following `num_placeholders - 4` values are expected to be the
    ///   identifiers of the placeholders employed in the query
    /// - The remaining `PH - num_placeholders` items are expected to be the
    ///   same as `placeholders_ids[0]`
    #[serde(
        serialize_with = "serialize_long_array",
        deserialize_with = "deserialize_long_array"
    )]
    pub(crate) placeholder_ids: [F; PH],
    /// Array of the placeholder values that can be employed in the query:
    /// - The first 4 values are expected to be the bounds `MIN_I1, MAX_I1` and
    ///   `MIN_I2, MAX_I2` found in the query for the primary and secondary
    ///   indexed columns
    /// - The following `num_placeholders - 4` values are expected to be the
    ///   values for the placeholders employed in the query
    /// - The remaining `PH - num_placeholders` values are expected to be the
    ///   same as `placeholder_values[0]`
    #[serde(
        serialize_with = "serialize_long_array",
        deserialize_with = "deserialize_long_array"
    )]
    pub(crate) placeholder_values: [U256; PH],
    /// Placeholders data to be provided to `check_placeholder` gadget to
    /// check that placeholders employed in universal query circuit matches
    /// with the `placeholder_values` exposed as public input by this proof
    #[serde(
        serialize_with = "serialize_long_array",
        deserialize_with = "deserialize_long_array"
    )]
    pub(crate) to_be_checked_placeholders: [CheckedPlaceholder; PP],
    /// Placeholders data related to the placeholders employed in the
    /// universal query circuit to hash the query bounds for the secondary
    /// index; they are provided as well to `check_placeholder` gadget to
    /// check the correctness of the placeholders employed for query bounds
    pub(crate) secondary_query_bound_placeholders:
        [CheckedPlaceholder; NUM_SECONDARY_INDEX_PLACEHOLDERS],
}

/// Number of placeholders being hashed to include query bounds in the placeholder hash
pub(crate) const NUM_SECONDARY_INDEX_PLACEHOLDERS: usize = 4;

impl<const PH: usize, const PP: usize> CheckPlaceholderGadget<PH, PP> {
    pub(crate) fn new(
        query_bounds: &QueryBounds,
        placeholders: &Placeholders,
        placeholder_hash_ids: [PlaceholderId; PP],
    ) -> Result<Self> {
        let num_placeholders = placeholders.len();
        ensure!(
            num_placeholders <= PH,
            "number of placeholders provided is more than the maximum number of placeholders"
        );
        // get placeholder ids from `placeholders` in the order expected by the circuit
        let placeholder_ids = placeholders.ids();
        let (padded_placeholder_ids, padded_placeholder_values): (Vec<F>, Vec<_>) = placeholder_ids
            .iter()
            .map(|id| (*id, placeholders.get(id).unwrap()))
            // pad placeholder ids and values with the first items in the arrays, as expected by the circuit
            .chain(repeat((
                PlaceholderIdentifier::MinQueryOnIdx1,
                placeholders
                    .get(&PlaceholderIdentifier::MinQueryOnIdx1)
                    .unwrap(),
            )))
            .take(PH)
            .map(|(id, value)| {
                let id: F = id.to_field();
                (id, value)
            })
            .unzip();
        let compute_checked_placeholder_for_id = |placeholder_id: PlaceholderIdentifier| {
            let value = placeholders.get(&placeholder_id)?;
            // locate placeholder with id `placeholder_id` in `padded_placeholder_ids`
            let pos = padded_placeholder_ids
                .iter()
                .find_position(|&&id| id == placeholder_id.to_field());
            ensure!(
                pos.is_some(),
                "placeholder with id {:?} not found in padded placeholder ids",
                placeholder_id
            );
            // sanity check: `padded_placeholder_values[pos] = value`
            assert_eq!(
                padded_placeholder_values[pos.unwrap().0],
                value,
                "placehoder values doesn't match for id {:?}",
                placeholder_id
            );
            Ok(CheckedPlaceholder {
                id: placeholder_id.to_field(),
                value,
                pos: pos.unwrap().0.to_field(),
            })
        };
        let to_be_checked_placeholders = placeholder_hash_ids
            .into_iter()
            .map(compute_checked_placeholder_for_id)
            .collect::<Result<Vec<_>>>()?;
        // compute placeholders data to be hashed for secondary query bounds
        let min_query_secondary =
            QueryBound::new_secondary_index_bound(placeholders, query_bounds.min_query_secondary())
                .unwrap();
        let max_query_secondary =
            QueryBound::new_secondary_index_bound(placeholders, query_bounds.max_query_secondary())
                .unwrap();
        let secondary_query_bound_placeholders = [min_query_secondary, max_query_secondary]
            .into_iter()
            .flat_map(|query_bound| {
                [
                    compute_checked_placeholder_for_id(PlaceholderId::from_fields(&[query_bound
                        .operation
                        .placeholder_ids[0]])),
                    compute_checked_placeholder_for_id(PlaceholderId::from_fields(&[query_bound
                        .operation
                        .placeholder_ids[1]])),
                ]
            })
            .collect::<Result<Vec<_>>>()?;

        Ok(Self {
            num_placeholders,
            placeholder_ids: padded_placeholder_ids.try_into().unwrap(),
            placeholder_values: padded_placeholder_values.try_into().unwrap(),
            to_be_checked_placeholders: to_be_checked_placeholders.try_into().unwrap(),
            secondary_query_bound_placeholders: secondary_query_bound_placeholders
                .try_into()
                .unwrap(),
        })
    }

    pub(crate) fn build(
        b: &mut CBuilder,
        final_placeholder_hash: &HashOutTarget,
    ) -> CheckPlaceholderWires<PH, PP> {
        let is_placeholder_valid = array::from_fn(|_| b.add_virtual_bool_target_safe());
        let placeholder_ids = b.add_virtual_target_arr();
        // `placeholder_values` are exposed as public inputs to the Solidity contract
        // which will not do range-check.
        let placeholder_values = array::from_fn(|_| b.add_virtual_u256());
        let to_be_checked_placeholders = array::from_fn(|_| CheckedPlaceholderTarget::new(b));
        let secondary_query_bound_placeholders =
            array::from_fn(|_| CheckedPlaceholderTarget::new(b));
        let (num_placeholders, placeholder_id_hash) = check_placeholders(
            b,
            &is_placeholder_valid,
            &placeholder_ids,
            &placeholder_values,
            &to_be_checked_placeholders,
            &secondary_query_bound_placeholders,
            final_placeholder_hash,
        );

        CheckPlaceholderWires::<PH, PP> {
            input_wires: CheckPlaceholderInputWires::<PH, PP> {
                is_placeholder_valid,
                placeholder_ids,
                placeholder_values,
                to_be_checked_placeholders,
                secondary_query_bound_placeholders,
            },
            num_placeholders,
            placeholder_id_hash,
        }
    }

    pub(crate) fn assign(
        &self,
        pw: &mut PartialWitness<F>,
        wires: &CheckPlaceholderInputWires<PH, PP>,
    ) {
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
    }
    // Return the query bounds on the primary index, taken from the placeholder values
    #[cfg(test)] // used only in test for now
    pub(crate) fn primary_query_bounds(&self) -> (U256, U256) {
        (self.placeholder_values[0], self.placeholder_values[1])
    }
}

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
    for item in to_be_checked_placeholder.iter().take(PP) {
        // Accumulate the placeholder identifiers and values for computing the
        // placeholder hash.
        let CheckedPlaceholderTarget { id, value, pos } = item;
        let payload = once(*id).chain(value.to_targets());
        placeholder_hash_payload.extend(payload);

        check_placeholder_pair(id, value, *pos);
    }

    // check placeholders related to secondary index bounds
    for item in secondary_query_bound_placeholder.iter().take(2) {
        let CheckedPlaceholderTarget { id, value, pos } = item;
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
    use mp2_common::{C, D, F};
    use mp2_test::circuit::{run_circuit, UserCircuit};
    use plonky2::{
        field::types::Field,
        iop::witness::{PartialWitness, WitnessWrite},
    };

    #[derive(Clone, Debug)]
    pub(crate) struct TestPlaceholdersWires<const PH: usize, const PP: usize> {
        input_wires: CheckPlaceholderInputWires<PH, PP>,
        final_placeholder_hash: HashOutTarget,
        exp_placeholder_ids_hash: HashOutTarget,
        exp_num_placeholders: Target,
    }

    impl<const PH: usize, const PP: usize> UserCircuit<F, D> for TestPlaceholders<PH, PP> {
        type Wires = TestPlaceholdersWires<PH, PP>;

        fn build(b: &mut CBuilder) -> Self::Wires {
            let [final_placeholder_hash, exp_placeholder_ids_hash] =
                array::from_fn(|_| b.add_virtual_hash());
            let exp_num_placeholders = b.add_virtual_target();

            // Invoke the `check_placeholders` function.
            let check_placeholder_wires = CheckPlaceholderGadget::build(b, &final_placeholder_hash);

            // Check the returned `num_placeholders` and `placeholder_ids_hash`.
            b.connect(
                check_placeholder_wires.num_placeholders,
                exp_num_placeholders,
            );
            b.connect_hashes(
                check_placeholder_wires.placeholder_id_hash,
                exp_placeholder_ids_hash,
            );

            Self::Wires {
                input_wires: check_placeholder_wires.input_wires,
                final_placeholder_hash,
                exp_placeholder_ids_hash,
                exp_num_placeholders,
            }
        }

        fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
            self.check_placeholder_inputs.assign(pw, &wires.input_wires);
            [
                (wires.final_placeholder_hash, self.final_placeholder_hash),
                (wires.exp_placeholder_ids_hash, self.placeholder_ids_hash),
            ]
            .iter()
            .for_each(|(t, v)| pw.set_hash_target(*t, *v));
            pw.set_target(
                wires.exp_num_placeholders,
                F::from_canonical_usize(self.check_placeholder_inputs.num_placeholders),
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
