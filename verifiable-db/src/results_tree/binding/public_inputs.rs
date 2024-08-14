//! Public inputs of the circuit for binding results tree to the original tree

use itertools::Itertools;
use mp2_common::{
    public_inputs::{PublicInputCommon, PublicInputRange},
    types::CBuilder,
    utils::TryIntoBool,
    F,
};
use plonky2::{
    hash::hash_types::{HashOut, HashOutTarget, NUM_HASH_OUT_ELTS},
    iop::target::{BoolTarget, Target},
};
use std::iter::once;

/// Public inputs of the circuit for binding results tree to the original tree
pub enum ResultsBindingPublicInputs {
    /// `result_tree_hash`: `hash` - Hash of the constructed results tree
    ResultsTreeHash,
    /// `original_tree_hash`: `hash` - Hash of the original tree over which the query
    /// was executed
    OriginalTreeHash,
    /// `computational_hash` : `hash` - Computational hash representing the operations
    /// performed to execute the query
    ComputationalHash,
    /// `placeholder_hash` : `hash` - Placeholder hash
    PlaceholderHash,
    /// `entry_count`: F - Number of matching entries found by the query
    /// NOTE: it's considered as an Uint32 for now (cannot be out of range of Uint32).
    EntryCount,
    /// `overflow` : `bool` - Flag specifying whether an overflow errors occurred during
    /// arithmetic operations
    Overflow,
}

#[derive(Clone, Debug)]
pub struct PublicInputs<'a, T> {
    results_tree_hash: &'a [T],
    original_tree_hash: &'a [T],
    computational_hash: &'a [T],
    placeholder_hash: &'a [T],
    entry_count: &'a T,
    overflow: &'a T,
}

const NUM_PUBLIC_INPUTS: usize = ResultsBindingPublicInputs::Overflow as usize + 1;

impl<'a, T: Clone> PublicInputs<'a, T> {
    const PI_RANGES: [PublicInputRange; NUM_PUBLIC_INPUTS] = [
        Self::to_range(ResultsBindingPublicInputs::ResultsTreeHash),
        Self::to_range(ResultsBindingPublicInputs::OriginalTreeHash),
        Self::to_range(ResultsBindingPublicInputs::ComputationalHash),
        Self::to_range(ResultsBindingPublicInputs::PlaceholderHash),
        Self::to_range(ResultsBindingPublicInputs::EntryCount),
        Self::to_range(ResultsBindingPublicInputs::Overflow),
    ];

    const SIZES: [usize; NUM_PUBLIC_INPUTS] = [
        // Results tree hash
        NUM_HASH_OUT_ELTS,
        // Original tree hash
        NUM_HASH_OUT_ELTS,
        // Computational hash
        NUM_HASH_OUT_ELTS,
        // Placeholder hash
        NUM_HASH_OUT_ELTS,
        // Entry count
        1,
        // Overflow flag
        1,
    ];

    pub(crate) const fn to_range(pi: ResultsBindingPublicInputs) -> PublicInputRange {
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
        Self::to_range(ResultsBindingPublicInputs::Overflow).end
    }

    pub(crate) fn to_results_tree_hash_raw(&self) -> &[T] {
        self.results_tree_hash
    }

    pub(crate) fn to_original_tree_hash_raw(&self) -> &[T] {
        self.original_tree_hash
    }

    pub(crate) fn to_computational_hash_raw(&self) -> &[T] {
        self.computational_hash
    }

    pub(crate) fn to_placeholder_hash_raw(&self) -> &[T] {
        self.placeholder_hash
    }

    pub(crate) fn to_entry_count_raw(&self) -> &T {
        self.entry_count
    }

    pub(crate) fn to_overflow_raw(&self) -> &T {
        self.overflow
    }

    pub fn from_slice(input: &'a [T]) -> Self {
        assert!(
            input.len() >= Self::total_len(),
            "Input slice too short to build results binding public inputs, must be at least {} elements",
            Self::total_len(),
        );
        Self {
            results_tree_hash: &input[Self::PI_RANGES[0].clone()],
            original_tree_hash: &input[Self::PI_RANGES[1].clone()],
            computational_hash: &input[Self::PI_RANGES[2].clone()],
            placeholder_hash: &input[Self::PI_RANGES[3].clone()],
            entry_count: &input[Self::PI_RANGES[4].clone()][0],
            overflow: &input[Self::PI_RANGES[5].clone()][0],
        }
    }

    pub fn new(
        results_tree_hash: &'a [T],
        original_tree_hash: &'a [T],
        computational_hash: &'a [T],
        placeholder_hash: &'a [T],
        entry_count: &'a [T],
        overflow: &'a [T],
    ) -> Self {
        Self {
            results_tree_hash,
            original_tree_hash,
            computational_hash,
            placeholder_hash,
            entry_count: &entry_count[0],
            overflow: &overflow[0],
        }
    }

    pub fn to_vec(&self) -> Vec<T> {
        self.results_tree_hash
            .iter()
            .chain(self.original_tree_hash.iter())
            .chain(self.computational_hash.iter())
            .chain(self.placeholder_hash.iter())
            .chain(once(self.entry_count))
            .chain(once(self.overflow))
            .cloned()
            .collect_vec()
    }
}

impl<'a> PublicInputCommon for PublicInputs<'a, Target> {
    const RANGES: &'static [PublicInputRange] = &Self::PI_RANGES;

    fn register_args(&self, cb: &mut CBuilder) {
        cb.register_public_inputs(self.results_tree_hash);
        cb.register_public_inputs(self.original_tree_hash);
        cb.register_public_inputs(self.computational_hash);
        cb.register_public_inputs(self.placeholder_hash);
        cb.register_public_input(*self.entry_count);
        cb.register_public_input(*self.overflow);
    }
}

impl<'a> PublicInputs<'a, Target> {
    pub fn results_tree_hash_target(&self) -> HashOutTarget {
        HashOutTarget::try_from(self.to_results_tree_hash_raw()).unwrap()
    }

    pub fn original_tree_hash_target(&self) -> HashOutTarget {
        HashOutTarget::try_from(self.to_original_tree_hash_raw()).unwrap()
    }

    pub fn computational_hash_target(&self) -> HashOutTarget {
        HashOutTarget::try_from(self.to_computational_hash_raw()).unwrap()
    }

    pub fn placeholder_hash_target(&self) -> HashOutTarget {
        HashOutTarget::try_from(self.to_placeholder_hash_raw()).unwrap()
    }

    pub fn entry_count_target(&self) -> Target {
        *self.to_entry_count_raw()
    }

    pub fn overflow_flag_target(&self) -> BoolTarget {
        BoolTarget::new_unsafe(*self.to_overflow_raw())
    }
}

impl<'a> PublicInputs<'a, F> {
    pub fn results_tree_hash(&self) -> HashOut<F> {
        HashOut::try_from(self.to_results_tree_hash_raw()).unwrap()
    }

    pub fn original_tree_hash(&self) -> HashOut<F> {
        HashOut::try_from(self.to_original_tree_hash_raw()).unwrap()
    }

    pub fn computational_hash(&self) -> HashOut<F> {
        HashOut::try_from(self.to_computational_hash_raw()).unwrap()
    }

    pub fn placeholder_hash(&self) -> HashOut<F> {
        HashOut::try_from(self.to_placeholder_hash_raw()).unwrap()
    }

    pub fn entry_count(&self) -> F {
        *self.to_entry_count_raw()
    }

    pub fn overflow_flag(&self) -> bool {
        (*self.to_overflow_raw())
            .try_into_bool()
            .expect("overflow flag public input different from 0 or 1")
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

    #[derive(Clone, Debug)]
    struct TestPublicInputs<'a> {
        pis: &'a [F],
    }

    impl<'a> UserCircuit<F, D> for TestPublicInputs<'a> {
        type Wires = Vec<Target>;

        fn build(c: &mut CircuitBuilder<F, D>) -> Self::Wires {
            let targets: [_; PublicInputs::<Target>::total_len()] = c.add_virtual_target_arr();
            let pi_targets = PublicInputs::<Target>::from_slice(targets.as_slice());
            pi_targets.register_args(c);
            pi_targets.to_vec()
        }

        fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
            pw.set_target_arr(wires, self.pis)
        }
    }

    #[test]
    fn test_results_binding_public_inputs() {
        let pis_raw = random_vector::<u32>(PublicInputs::<F>::total_len()).to_fields();

        // Use public inputs in circuit.
        let test_circuit = TestPublicInputs { pis: &pis_raw };
        let proof = run_circuit::<F, D, C, _>(test_circuit);
        assert_eq!(proof.public_inputs, pis_raw);

        // Check public inputs are constructed correctly.
        let pis = PublicInputs::<F>::from_slice(&proof.public_inputs);
        assert_eq!(
            &pis_raw[PublicInputs::<F>::to_range(ResultsBindingPublicInputs::ResultsTreeHash)],
            pis.to_results_tree_hash_raw(),
        );
        assert_eq!(
            &pis_raw[PublicInputs::<F>::to_range(ResultsBindingPublicInputs::OriginalTreeHash)],
            pis.to_original_tree_hash_raw(),
        );
        assert_eq!(
            &pis_raw[PublicInputs::<F>::to_range(ResultsBindingPublicInputs::ComputationalHash)],
            pis.to_computational_hash_raw(),
        );
        assert_eq!(
            &pis_raw[PublicInputs::<F>::to_range(ResultsBindingPublicInputs::PlaceholderHash)],
            pis.to_placeholder_hash_raw(),
        );
        assert_eq!(
            &pis_raw[PublicInputs::<F>::to_range(ResultsBindingPublicInputs::EntryCount)],
            slice::from_ref(pis.to_entry_count_raw()),
        );
        assert_eq!(
            &pis_raw[PublicInputs::<F>::to_range(ResultsBindingPublicInputs::Overflow)],
            slice::from_ref(pis.to_overflow_raw()),
        );
    }
}
