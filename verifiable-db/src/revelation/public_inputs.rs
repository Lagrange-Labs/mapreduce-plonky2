//! The public inputs of the query revelation circuits

use alloy::primitives::U256;
use itertools::Itertools;
use mp2_common::{
    keccak::PACKED_HASH_LEN,
    public_inputs::{PublicInputCommon, PublicInputRange},
    types::CBuilder,
    u256::{UInt256Target, NUM_LIMBS},
    utils::{FromFields, FromTargets},
    F,
};
use plonky2::{
    field::types::Field,
    hash::hash_types::{HashOut, HashOutTarget, NUM_HASH_OUT_ELTS},
    iop::target::{BoolTarget, Target},
};
use std::iter::once;

// L: maximum number of results
// S: maximum number of items in each result
// PH: maximum number of placeholders
// PD: maximum number of paddings
pub enum RevelationPublicInputs {
    /// `H`: Hash (keccak) - Hash of the blockchain corresponding to the latest
    /// block inserted in the tree employed for this query
    OriginalBlockHash,
    /// `C` : Hash (poseidon) - Computational hash representing the computation
    /// performed to compute results of the query
    ComputationalHash,
    /// `num_placeholders` : F - Number (<= PH) of placeholder values actually
    /// employed in the query
    NumPlaceholders,
    /// `placeholder_values` : [Uint256; PH] - Array corresponding to the
    /// placeholder values employed for the current query
    PlaceholderValues,
    /// `entry_count`: F - Number of matching entries found by the query.
    /// NOTE: it's considered as an Uint32 for now (cannot be out of range of Uint32).
    EntryCount,
    /// `overflow` : F - Boolean flag specifying whether an overflow errors
    /// occurred during arithmetic operations
    Overflow,
    /// `num_results`: F - number of actual results found in the results array
    NumResults,
    /// `result_values` : [Uint256; L * S] - Array of L results of the query and
    /// each result has S values
    ResultValues,
    /// `padding_values` : [Uint256; PD] - Dummy values to be added as public inputs
    PaddingValues,
}

// L: maximum number of results
// S: maximum number of items in each result
// PH: maximum number of placeholders
// PD: maximum number of paddings
#[derive(Clone, Debug)]
pub struct PublicInputs<'a, T, const L: usize, const S: usize, const PH: usize, const PD: usize> {
    original_block_hash: &'a [T],
    computational_hash: &'a [T],
    num_placeholders: &'a T,
    placeholder_values: &'a [T],
    entry_count: &'a T,
    overflow: &'a T,
    num_results: &'a T,
    result_values: &'a [T],
    padding_values: &'a [T],
}

const NUM_PUBLIC_INPUTS: usize = RevelationPublicInputs::PaddingValues as usize + 1;

impl<'a, T: Clone, const L: usize, const S: usize, const PH: usize, const PD: usize>
    PublicInputs<'a, T, L, S, PH, PD>
{
    const PI_RANGES: [PublicInputRange; NUM_PUBLIC_INPUTS] = [
        Self::to_range(RevelationPublicInputs::OriginalBlockHash),
        Self::to_range(RevelationPublicInputs::ComputationalHash),
        Self::to_range(RevelationPublicInputs::NumPlaceholders),
        Self::to_range(RevelationPublicInputs::PlaceholderValues),
        Self::to_range(RevelationPublicInputs::EntryCount),
        Self::to_range(RevelationPublicInputs::Overflow),
        Self::to_range(RevelationPublicInputs::NumResults),
        Self::to_range(RevelationPublicInputs::ResultValues),
        Self::to_range(RevelationPublicInputs::PaddingValues),
    ];

    const SIZES: [usize; NUM_PUBLIC_INPUTS] = [
        // Original block hash
        PACKED_HASH_LEN,
        // Computational hash
        NUM_HASH_OUT_ELTS,
        // Number of placeholders
        1,
        // Placeholder values
        NUM_LIMBS * PH,
        // Matching entry count
        1,
        // overflow
        1,
        // Number of results
        1,
        // Result values of the query
        NUM_LIMBS * L * S,
        // Padding values of the public inputs
        NUM_LIMBS * PD,
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
        Self::to_range(RevelationPublicInputs::PaddingValues).end
    }

    pub(crate) fn to_original_block_hash_raw(&self) -> &[T] {
        self.original_block_hash
    }

    pub(crate) fn to_computational_hash_raw(&self) -> &[T] {
        self.computational_hash
    }

    pub(crate) fn to_num_placeholders_raw(&self) -> &T {
        self.num_placeholders
    }

    pub(crate) fn to_placeholder_values_raw(&self) -> &[T] {
        self.placeholder_values
    }

    pub(crate) fn to_entry_count_raw(&self) -> &T {
        self.entry_count
    }

    pub(crate) fn to_overflow_raw(&self) -> &T {
        self.overflow
    }

    pub(crate) fn to_num_results_raw(&self) -> &T {
        self.num_results
    }

    pub(crate) fn to_result_values_raw(&self) -> &[T] {
        self.result_values
    }

    pub(crate) fn to_padding_values_raw(&self) -> &[T] {
        self.padding_values
    }

    pub fn from_slice(input: &'a [T]) -> Self {
        assert!(
            input.len() >= Self::total_len(),
            "Input slice too short to build revelation public inputs, must be at least {} elements",
            Self::total_len(),
        );

        Self {
            original_block_hash: &input[Self::PI_RANGES[0].clone()],
            computational_hash: &input[Self::PI_RANGES[1].clone()],
            num_placeholders: &input[Self::PI_RANGES[2].clone()][0],
            placeholder_values: &input[Self::PI_RANGES[3].clone()],
            entry_count: &input[Self::PI_RANGES[4].clone()][0],
            overflow: &input[Self::PI_RANGES[5].clone()][0],
            num_results: &input[Self::PI_RANGES[6].clone()][0],
            result_values: &input[Self::PI_RANGES[7].clone()],
            padding_values: &input[Self::PI_RANGES[8].clone()],
        }
    }

    pub fn new(
        original_block_hash: &'a [T],
        computational_hash: &'a [T],
        num_placeholders: &'a [T],
        placeholder_values: &'a [T],
        entry_count: &'a [T],
        overflow: &'a [T],
        num_results: &'a [T],
        result_values: &'a [T],
        padding_values: &'a [T],
    ) -> Self {
        Self {
            original_block_hash,
            computational_hash,
            num_placeholders: &num_placeholders[0],
            placeholder_values,
            entry_count: &entry_count[0],
            overflow: &overflow[0],
            num_results: &num_results[0],
            result_values,
            padding_values,
        }
    }

    pub fn to_vec(&self) -> Vec<T> {
        self.original_block_hash
            .iter()
            .chain(self.computational_hash.iter())
            .chain(once(self.num_placeholders))
            .chain(self.placeholder_values.iter())
            .chain(once(self.entry_count))
            .chain(once(self.overflow))
            .chain(once(self.num_results))
            .chain(self.result_values.iter())
            .chain(self.padding_values.iter())
            .cloned()
            .collect_vec()
    }
}

impl<'a, const L: usize, const S: usize, const PH: usize, const PD: usize> PublicInputCommon
    for PublicInputs<'a, Target, L, S, PH, PD>
{
    const RANGES: &'static [PublicInputRange] = &Self::PI_RANGES;

    fn register_args(&self, cb: &mut CBuilder) {
        cb.register_public_inputs(self.original_block_hash);
        cb.register_public_inputs(self.computational_hash);
        cb.register_public_input(*self.num_placeholders);
        cb.register_public_inputs(self.placeholder_values);
        cb.register_public_input(*self.entry_count);
        cb.register_public_input(*self.overflow);
        cb.register_public_input(*self.num_results);
        cb.register_public_inputs(self.result_values);
        cb.register_public_inputs(self.padding_values);
    }
}

impl<'a, const L: usize, const S: usize, const PH: usize, const PD: usize>
    PublicInputs<'a, Target, L, S, PH, PD>
{
    pub fn original_block_hash_target(&self) -> [Target; PACKED_HASH_LEN] {
        self.to_original_block_hash_raw().try_into().unwrap()
    }

    pub fn computational_hash_target(&self) -> HashOutTarget {
        HashOutTarget::try_from(self.to_computational_hash_raw()).unwrap()
    }

    pub fn num_placeholders_target(&self) -> Target {
        *self.to_num_placeholders_raw()
    }

    pub fn placeholder_values_target(&self) -> [UInt256Target; PH] {
        self.to_placeholder_values_raw()
            .chunks(NUM_LIMBS)
            .map(UInt256Target::from_targets)
            .collect_vec()
            .try_into()
            .unwrap()
    }

    pub fn entry_count_target(&self) -> Target {
        *self.to_entry_count_raw()
    }

    pub fn overflow_flag_target(&self) -> BoolTarget {
        BoolTarget::new_unsafe(*self.to_overflow_raw())
    }

    pub fn num_results_target(&self) -> Target {
        *self.to_num_results_raw()
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

    pub fn padding_values_target(&self) -> [UInt256Target; PD] {
        self.to_padding_values_raw()
            .chunks(NUM_LIMBS)
            .map(UInt256Target::from_targets)
            .collect_vec()
            .try_into()
            .unwrap()
    }
}

impl<'a, const L: usize, const S: usize, const PH: usize, const PD: usize>
    PublicInputs<'a, F, L, S, PH, PD>
{
    pub fn original_block_hash(&self) -> [F; PACKED_HASH_LEN] {
        self.to_original_block_hash_raw().try_into().unwrap()
    }

    pub fn computational_hash(&self) -> HashOut<F> {
        HashOut::try_from(self.to_computational_hash_raw()).unwrap()
    }

    pub fn num_placeholders(&self) -> F {
        *self.to_num_placeholders_raw()
    }

    pub fn placeholder_values(&self) -> [U256; PH] {
        self.to_placeholder_values_raw()
            .chunks(NUM_LIMBS)
            .map(U256::from_fields)
            .collect_vec()
            .try_into()
            .unwrap()
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

    pub fn num_results(&self) -> F {
        *self.to_num_results_raw()
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

    pub fn padding_values(&self) -> [U256; PD] {
        self.to_padding_values_raw()
            .chunks(NUM_LIMBS)
            .map(U256::from_fields)
            .collect_vec()
            .try_into()
            .unwrap()
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

    // L: maximum number of results
    // S: maximum number of items in each result
    // PH: maximum number of placeholders
    // PD: maximum number of paddings
    const L: usize = 5;
    const S: usize = 10;
    const PH: usize = 10;
    const PD: usize = 10;

    type PI<'a> = PublicInputs<'a, F, L, S, PH, PD>;
    type PITargets<'a> = PublicInputs<'a, Target, L, S, PH, PD>;

    const PI_LEN: usize = crate::revelation::PI_LEN::<L, S, PH, PD>;

    #[derive(Clone, Debug)]
    struct TestPublicInputs<'a> {
        pis: &'a [F],
    }

    impl<'a> UserCircuit<F, D> for TestPublicInputs<'a> {
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
        let pis_raw: Vec<_> = random_vector::<u32>(PI_LEN).to_fields();
        let pis = PI::from_slice(pis_raw.as_slice());

        // Check if the public inputs are constructed correctly.
        assert_eq!(
            &pis_raw[PI::to_range(RevelationPublicInputs::OriginalBlockHash)],
            pis.to_original_block_hash_raw(),
        );
        assert_eq!(
            &pis_raw[PI::to_range(RevelationPublicInputs::ComputationalHash)],
            pis.to_computational_hash_raw(),
        );
        assert_eq!(
            &pis_raw[PI::to_range(RevelationPublicInputs::NumPlaceholders)],
            &[*pis.to_num_placeholders_raw()],
        );
        assert_eq!(
            &pis_raw[PI::to_range(RevelationPublicInputs::PlaceholderValues)],
            pis.to_placeholder_values_raw(),
        );
        assert_eq!(
            &pis_raw[PI::to_range(RevelationPublicInputs::EntryCount)],
            &[*pis.to_entry_count_raw()],
        );
        assert_eq!(
            &pis_raw[PI::to_range(RevelationPublicInputs::Overflow)],
            &[*pis.to_overflow_raw()],
        );
        assert_eq!(
            &pis_raw[PI::to_range(RevelationPublicInputs::NumResults)],
            &[*pis.to_num_results_raw()],
        );
        assert_eq!(
            &pis_raw[PI::to_range(RevelationPublicInputs::ResultValues)],
            pis.to_result_values_raw(),
        );
        assert_eq!(
            &pis_raw[PI::to_range(RevelationPublicInputs::PaddingValues)],
            pis.to_padding_values_raw(),
        );

        // Use the public inputs in test circuit.
        let test_circuit = TestPublicInputs { pis: &pis_raw };
        let proof = run_circuit::<F, D, C, _>(test_circuit);
        assert_eq!(proof.public_inputs, pis_raw);
    }
}
