//! The public inputs of the query revelation circuits

use alloy::primitives::U256;
use itertools::Itertools;
use mp2_common::{
    keccak::PACKED_HASH_LEN,
    poseidon::FLATTEN_POSEIDON_LEN,
    public_inputs::{PublicInputCommon, PublicInputRange},
    types::CBuilder,
    u256::{UInt256Target, NUM_LIMBS},
    utils::{FromFields, FromTargets},
    F,
};
use plonky2::{
    field::types::Field,
    iop::target::{BoolTarget, Target},
};
use std::iter::once;

// This is the final public inputs exported for Groth16 proving. It's aligned with Uint256,
// and the fields are restricted within the range of Uint32 for sha256 in plonky2x.
// L: maximum number of results
// S: maximum number of items in each result
// PH: maximum number of unique placeholder IDs and values bound for query
pub enum RevelationPublicInputs {
    /// `H`: Keccak hash [F; 8] - Hash of the blockchain corresponding to the latest
    /// block inserted in the tree employed for this query
    OriginalBlockHash,
    /// `C` : Poseidon Hash [F; 8] (Flattened to Uint32 fields) - Computational hash
    /// representing the computation performed to compute results of the query
    FlatComputationalHash,
    /// `placeholder_values` : [Uint256; PH] - Array corresponding to the
    /// placeholder values employed for the current query
    PlaceholderValues,
    /// `result_values` : [[Uint256; S]; L] - Two-dimensional array of L results of
    /// the query and each result has S values
    ResultValues,
    /// `num_placeholders` : F - Number (<= PH) of placeholder values actually
    /// employed in the query
    NumPlaceholders,
    /// `num_results`: F - Number of actual results found in the results array
    NumResults,
    /// `entry_count`: F - Number of matching entries found by the query.
    /// NOTE: it's considered as an Uint32 for now (cannot be out of range of Uint32).
    EntryCount,
    /// `overflow` : F - Boolean flag specifying whether an overflow errors
    /// occurred during arithmetic operations
    Overflow,
    /// `query_limit` : F - Limit value specified in the query
    QueryLimit,
    /// `query_offset` : F - Offset value specified in the query
    QueryOffset,
}

// L: maximum number of results
// S: maximum number of items in each result
// PH: maximum number of unique placeholder IDs and values bound for query
#[derive(Clone, Debug)]
pub struct PublicInputs<'a, T, const L: usize, const S: usize, const PH: usize> {
    original_block_hash: &'a [T],
    flat_computational_hash: &'a [T],
    placeholder_values: &'a [T],
    result_values: &'a [T],
    num_placeholders: &'a T,
    num_results: &'a T,
    entry_count: &'a T,
    overflow: &'a T,
    query_limit: &'a T,
    query_offset: &'a T,
}

const NUM_PUBLIC_INPUTS: usize = RevelationPublicInputs::QueryOffset as usize + 1;

impl<'a, T: Clone, const L: usize, const S: usize, const PH: usize> PublicInputs<'a, T, L, S, PH> {
    const PI_RANGES: [PublicInputRange; NUM_PUBLIC_INPUTS] = [
        Self::to_range(RevelationPublicInputs::OriginalBlockHash),
        Self::to_range(RevelationPublicInputs::FlatComputationalHash),
        Self::to_range(RevelationPublicInputs::PlaceholderValues),
        Self::to_range(RevelationPublicInputs::ResultValues),
        Self::to_range(RevelationPublicInputs::NumPlaceholders),
        Self::to_range(RevelationPublicInputs::NumResults),
        Self::to_range(RevelationPublicInputs::EntryCount),
        Self::to_range(RevelationPublicInputs::Overflow),
        Self::to_range(RevelationPublicInputs::QueryLimit),
        Self::to_range(RevelationPublicInputs::QueryOffset),
    ];

    const SIZES: [usize; NUM_PUBLIC_INPUTS] = [
        // Original block hash
        PACKED_HASH_LEN,
        // Computational hash (Flattened)
        FLATTEN_POSEIDON_LEN,
        // Placeholder values
        NUM_LIMBS * PH,
        // Result values of the query
        NUM_LIMBS * L * S,
        // Number of placeholders
        1,
        // Number of results
        1,
        // Matching entry count
        1,
        // overflow
        1,
        // Limit value specified in the query
        1,
        // Offset value specified in the query
        1,
    ];

    pub(crate) const fn to_range(pi: RevelationPublicInputs) -> PublicInputRange {
        let mut i = 0;
        let mut offset = 0;
        let pi_pos = pi as usize;
        while i < pi_pos {
            offset += Self::SIZES[i];
            i += 1;
        }
        offset..offset + Self::SIZES[pi_pos]
    }

    pub(crate) const fn total_len() -> usize {
        Self::to_range(RevelationPublicInputs::QueryOffset).end
    }

    pub(crate) fn to_original_block_hash_raw(&self) -> &[T] {
        self.original_block_hash
    }

    pub(crate) fn to_flat_computational_hash_raw(&self) -> &[T] {
        self.flat_computational_hash
    }

    pub(crate) fn to_placeholder_values_raw(&self) -> &[T] {
        self.placeholder_values
    }

    pub(crate) fn to_result_values_raw(&self) -> &[T] {
        self.result_values
    }

    pub(crate) fn to_num_placeholders_raw(&self) -> &T {
        self.num_placeholders
    }

    pub(crate) fn to_num_results_raw(&self) -> &T {
        self.num_results
    }

    pub(crate) fn to_entry_count_raw(&self) -> &T {
        self.entry_count
    }

    pub(crate) fn to_overflow_raw(&self) -> &T {
        self.overflow
    }

    pub(crate) fn to_query_limit_raw(&self) -> &T {
        self.query_limit
    }

    pub(crate) fn to_query_offset_raw(&self) -> &T {
        self.query_offset
    }

    pub fn from_slice(input: &'a [T]) -> Self {
        assert!(
            input.len() >= Self::total_len(),
            "Input slice too short to build revelation public inputs, must be at least {} elements",
            Self::total_len(),
        );

        Self {
            original_block_hash: &input[Self::PI_RANGES[0].clone()],
            flat_computational_hash: &input[Self::PI_RANGES[1].clone()],
            placeholder_values: &input[Self::PI_RANGES[2].clone()],
            result_values: &input[Self::PI_RANGES[3].clone()],
            num_placeholders: &input[Self::PI_RANGES[4].clone()][0],
            num_results: &input[Self::PI_RANGES[5].clone()][0],
            entry_count: &input[Self::PI_RANGES[6].clone()][0],
            overflow: &input[Self::PI_RANGES[7].clone()][0],
            query_limit: &input[Self::PI_RANGES[8].clone()][0],
            query_offset: &input[Self::PI_RANGES[9].clone()][0],
        }
    }

    pub fn new(
        original_block_hash: &'a [T],
        flat_computational_hash: &'a [T],
        placeholder_values: &'a [T],
        result_values: &'a [T],
        num_placeholders: &'a [T],
        num_results: &'a [T],
        entry_count: &'a [T],
        overflow: &'a [T],
        query_limit: &'a [T],
        query_offset: &'a [T],
    ) -> Self {
        Self {
            original_block_hash,
            flat_computational_hash,
            placeholder_values,
            result_values,
            num_placeholders: &num_placeholders[0],
            num_results: &num_results[0],
            entry_count: &entry_count[0],
            overflow: &overflow[0],
            query_limit: &query_limit[0],
            query_offset: &query_offset[0],
        }
    }

    pub fn to_vec(&self) -> Vec<T> {
        self.original_block_hash
            .iter()
            .chain(self.flat_computational_hash.iter())
            .chain(self.placeholder_values.iter())
            .chain(self.result_values.iter())
            .chain(once(self.num_placeholders))
            .chain(once(self.num_results))
            .chain(once(self.entry_count))
            .chain(once(self.overflow))
            .chain(once(self.query_limit))
            .chain(once(self.query_offset))
            .cloned()
            .collect_vec()
    }
}

impl<const L: usize, const S: usize, const PH: usize> PublicInputCommon
    for PublicInputs<'_, Target, L, S, PH>
{
    const RANGES: &'static [PublicInputRange] = &Self::PI_RANGES;

    fn register_args(&self, cb: &mut CBuilder) {
        cb.register_public_inputs(self.original_block_hash);
        cb.register_public_inputs(self.flat_computational_hash);
        cb.register_public_inputs(self.placeholder_values);
        cb.register_public_inputs(self.result_values);
        cb.register_public_input(*self.num_placeholders);
        cb.register_public_input(*self.num_results);
        cb.register_public_input(*self.entry_count);
        cb.register_public_input(*self.overflow);
        cb.register_public_input(*self.query_limit);
        cb.register_public_input(*self.query_offset);
    }
}

impl<const L: usize, const S: usize, const PH: usize> PublicInputs<'_, Target, L, S, PH> {
    pub fn original_block_hash_target(&self) -> [Target; PACKED_HASH_LEN] {
        self.to_original_block_hash_raw().try_into().unwrap()
    }

    pub fn flat_computational_hash_target(&self) -> [Target; FLATTEN_POSEIDON_LEN] {
        self.to_flat_computational_hash_raw().try_into().unwrap()
    }

    pub fn placeholder_values_target(&self) -> [UInt256Target; PH] {
        self.to_placeholder_values_raw()
            .chunks(NUM_LIMBS)
            .map(UInt256Target::from_targets)
            .collect_vec()
            .try_into()
            .unwrap()
    }

    pub fn result_values_target(&self) -> [[UInt256Target; S]; L] {
        self.to_result_values_raw()
            .chunks(NUM_LIMBS * S)
            .map(|targets| {
                targets
                    .chunks(NUM_LIMBS)
                    .map(UInt256Target::from_targets)
                    .collect_vec()
                    .try_into()
                    .unwrap()
            })
            .collect_vec()
            .try_into()
            .unwrap()
    }

    pub fn num_placeholders_target(&self) -> Target {
        *self.to_num_placeholders_raw()
    }

    pub fn num_results_target(&self) -> Target {
        *self.to_num_results_raw()
    }

    pub fn entry_count_target(&self) -> Target {
        *self.to_entry_count_raw()
    }

    pub fn overflow_flag_target(&self) -> BoolTarget {
        BoolTarget::new_unsafe(*self.to_overflow_raw())
    }

    pub fn query_limit_target(&self) -> Target {
        *self.to_query_limit_raw()
    }

    pub fn query_offset_target(&self) -> Target {
        *self.to_query_offset_raw()
    }
}

impl<const L: usize, const S: usize, const PH: usize> PublicInputs<'_, F, L, S, PH> {
    pub fn original_block_hash(&self) -> [F; PACKED_HASH_LEN] {
        self.to_original_block_hash_raw().try_into().unwrap()
    }

    pub fn flat_computational_hash(&self) -> [F; FLATTEN_POSEIDON_LEN] {
        self.to_flat_computational_hash_raw().try_into().unwrap()
    }

    pub fn placeholder_values(&self) -> [U256; PH] {
        self.to_placeholder_values_raw()
            .chunks(NUM_LIMBS)
            .map(U256::from_fields)
            .collect_vec()
            .try_into()
            .unwrap()
    }

    pub fn result_values(&self) -> [[U256; S]; L] {
        self.to_result_values_raw()
            .chunks(NUM_LIMBS * S)
            .map(|fields| {
                fields
                    .chunks(NUM_LIMBS)
                    .map(U256::from_fields)
                    .collect_vec()
                    .try_into()
                    .unwrap()
            })
            .collect_vec()
            .try_into()
            .unwrap()
    }

    pub fn num_placeholders(&self) -> F {
        *self.to_num_placeholders_raw()
    }

    pub fn num_results(&self) -> F {
        *self.to_num_results_raw()
    }

    pub fn entry_count(&self) -> F {
        *self.to_entry_count_raw()
    }

    pub fn overflow_flag(&self) -> bool {
        let overflow = *self.to_overflow_raw();
        if overflow == F::ONE {
            return true;
        }
        if overflow == F::ZERO {
            return false;
        }
        unreachable!("Overflow flag public input different from 0 or 1")
    }

    pub fn query_limit(&self) -> F {
        *self.to_query_limit_raw()
    }

    pub fn query_offset(&self) -> F {
        *self.to_query_offset_raw()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mp2_common::{public_inputs::PublicInputCommon, utils::ToFields, C, D, F};
    use mp2_test::{
        circuit::{run_circuit, UserCircuit},
        utils::random_vector,
    };
    use plonky2::{
        iop::{
            target::Target,
            witness::{PartialWitness, WitnessWrite},
        },
        plonk::circuit_builder::CircuitBuilder,
    };
    use std::slice;

    // L: maximum number of results
    // S: maximum number of items in each result
    // PH: maximum number of unique placeholder IDs and values bound for query
    const L: usize = 5;
    const S: usize = 10;
    const PH: usize = 10;

    type PI<'a> = PublicInputs<'a, F, L, S, PH>;
    type PITargets<'a> = PublicInputs<'a, Target, L, S, PH>;

    const PI_LEN: usize = crate::revelation::PI_LEN::<L, S, PH>;

    #[derive(Clone, Debug)]
    struct TestPublicInputs<'a> {
        pis: &'a [F],
    }

    impl UserCircuit<F, D> for TestPublicInputs<'_> {
        type Wires = Vec<Target>;

        fn build(c: &mut CircuitBuilder<F, D>) -> Self::Wires {
            let targets = c.add_virtual_target_arr::<PI_LEN>();
            let pi_targets = PITargets::from_slice(targets.as_slice());
            pi_targets.register_args(c);
            pi_targets.to_vec()
        }

        fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
            pw.set_target_arr(wires, self.pis)
        }
    }

    #[test]
    fn test_revelation_public_inputs() {
        let pis_raw = random_vector::<u32>(PI_LEN).to_fields();

        // Use the public inputs in test circuit.
        let test_circuit = TestPublicInputs { pis: &pis_raw };
        let proof = run_circuit::<F, D, C, _>(test_circuit);
        assert_eq!(proof.public_inputs, pis_raw);

        // Check if the public inputs are constructed correctly.
        let pis = PI::from_slice(&proof.public_inputs);
        assert_eq!(
            &pis_raw[PI::to_range(RevelationPublicInputs::OriginalBlockHash)],
            pis.to_original_block_hash_raw(),
        );
        assert_eq!(
            &pis_raw[PI::to_range(RevelationPublicInputs::FlatComputationalHash)],
            pis.to_flat_computational_hash_raw(),
        );
        assert_eq!(
            &pis_raw[PI::to_range(RevelationPublicInputs::NumPlaceholders)],
            slice::from_ref(pis.to_num_placeholders_raw()),
        );
        assert_eq!(
            &pis_raw[PI::to_range(RevelationPublicInputs::PlaceholderValues)],
            pis.to_placeholder_values_raw(),
        );
        assert_eq!(
            &pis_raw[PI::to_range(RevelationPublicInputs::EntryCount)],
            slice::from_ref(pis.to_entry_count_raw()),
        );
        assert_eq!(
            &pis_raw[PI::to_range(RevelationPublicInputs::Overflow)],
            slice::from_ref(pis.to_overflow_raw()),
        );
        assert_eq!(
            &pis_raw[PI::to_range(RevelationPublicInputs::NumResults)],
            slice::from_ref(pis.to_num_results_raw()),
        );
        assert_eq!(
            &pis_raw[PI::to_range(RevelationPublicInputs::ResultValues)],
            pis.to_result_values_raw(),
        );
        assert_eq!(
            &pis_raw[PI::to_range(RevelationPublicInputs::QueryLimit)],
            slice::from_ref(pis.to_query_limit_raw()),
        );
    }
}
