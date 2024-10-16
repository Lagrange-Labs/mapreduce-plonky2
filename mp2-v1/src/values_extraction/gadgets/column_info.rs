//! Column information for values extraction

use itertools::{zip_eq, Itertools};
use mp2_common::{
    group_hashing::map_to_curve_point,
    poseidon::H,
    types::{CBuilder, MAPPING_LEAF_VALUE_LEN},
    F,
};
use plonky2::{
    field::types::{Field, Sample},
    iop::{target::Target, witness::WitnessWrite},
    plonk::config::Hasher,
};
use plonky2_ecgfp5::curve::curve::Point;
use rand::{thread_rng, Rng};
use serde::{Deserialize, Serialize};
use std::{array, iter::once};

/// Column info
#[derive(Clone, Debug, Default, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct ColumnInfo {
    /// Slot information of the variable
    pub(crate) slot: F,
    /// Column identifier
    pub(crate) identifier: F,
    /// The offset in bytes where to extract this column in a given EVM word
    pub(crate) byte_offset: F,
    /// The starting offset in `byte_offset` of the bits to be extracted for this column.
    /// The column bits will start at `byte_offset * 8 + bit_offset`.
    pub(crate) bit_offset: F,
    /// The length (in bits) of the field to extract in the EVM word
    pub(crate) length: F,
    /// At which EVM word is this column extracted from. For simple variables,
    /// this value should always be 0. For structs that spans more than one EVM word
    // that value should be depending on which section of the struct we are in.
    pub(crate) evm_word: F,
}

impl ColumnInfo {
    pub fn new(
        slot: u8,
        identifier: u64,
        byte_offset: usize,
        bit_offset: usize,
        length: usize,
        evm_word: usize,
    ) -> Self {
        let slot = F::from_canonical_u8(slot);
        let identifier = F::from_canonical_u64(identifier);
        let [byte_offset, bit_offset, length, evm_word] =
            [byte_offset, bit_offset, length, evm_word].map(F::from_canonical_usize);

        Self {
            slot,
            identifier,
            byte_offset,
            bit_offset,
            length,
            evm_word,
        }
    }

    /// Create a sample column info. It could be used in integration tests.
    pub fn sample() -> Self {
        let rng = &mut thread_rng();

        let bit_offset = F::from_canonical_u8(rng.gen_range(0..8));
        let length: usize = rng.gen_range(1..=MAPPING_LEAF_VALUE_LEN);
        let max_byte_offset = MAPPING_LEAF_VALUE_LEN - length.div_ceil(8);
        let byte_offset = F::from_canonical_usize(rng.gen_range(0..=max_byte_offset));
        let length = F::from_canonical_usize(length);
        let [slot, identifier, evm_word] = array::from_fn(|_| F::rand());

        Self {
            slot,
            identifier,
            byte_offset,
            bit_offset,
            length,
            evm_word,
        }
    }
    /// Compute the column information digest.
    pub fn digest(&self) -> Point {
        // metadata = H(info.slot || info.evm_word || info.byte_offset || info.bit_offset || info.length)
        let inputs = vec![
            self.slot,
            self.evm_word,
            self.byte_offset,
            self.bit_offset,
            self.length,
        ];
        let metadata = H::hash_no_pad(&inputs);

        // digest = D(mpt_metadata || info.identifier)
        let inputs = metadata
            .elements
            .into_iter()
            .chain(once(self.identifier))
            .collect_vec();
        map_to_curve_point(&inputs)
    }

    pub fn slot(&self) -> F {
        self.slot
    }

    pub fn identifier(&self) -> F {
        self.identifier
    }

    pub fn byte_offset(&self) -> F {
        self.byte_offset
    }

    pub fn bit_offset(&self) -> F {
        self.bit_offset
    }

    pub fn length(&self) -> F {
        self.length
    }

    pub fn evm_word(&self) -> F {
        self.evm_word
    }
}

/// Column info target
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ColumnInfoTarget {
    pub(crate) slot: Target,
    pub(crate) identifier: Target,
    pub(crate) byte_offset: Target,
    pub(crate) bit_offset: Target,
    pub(crate) length: Target,
    pub(crate) evm_word: Target,
}

pub trait CircuitBuilderColumnInfo {
    /// Add a virtual column info target.
    fn add_virtual_column_info(&mut self) -> ColumnInfoTarget;
}

impl CircuitBuilderColumnInfo for CBuilder {
    fn add_virtual_column_info(&mut self) -> ColumnInfoTarget {
        let [slot, identifier, byte_offset, bit_offset, length, evm_word] =
            array::from_fn(|_| self.add_virtual_target());

        ColumnInfoTarget {
            slot,
            identifier,
            byte_offset,
            bit_offset,
            length,
            evm_word,
        }
    }
}

pub trait WitnessWriteColumnInfo {
    fn set_column_info_target(&mut self, target: &ColumnInfoTarget, value: &ColumnInfo);

    fn set_column_info_target_arr(&mut self, targets: &[ColumnInfoTarget], values: &[ColumnInfo]) {
        zip_eq(targets, values)
            .for_each(|(target, value)| self.set_column_info_target(target, value));
    }
}

impl<T: WitnessWrite<F>> WitnessWriteColumnInfo for T {
    fn set_column_info_target(&mut self, target: &ColumnInfoTarget, value: &ColumnInfo) {
        [
            (target.slot, value.slot),
            (target.identifier, value.identifier),
            (target.byte_offset, value.byte_offset),
            (target.bit_offset, value.bit_offset),
            (target.length, value.length),
            (target.evm_word, value.evm_word),
        ]
        .into_iter()
        .for_each(|(t, v)| self.set_target(t, v));
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use mp2_common::{C, D};
    use mp2_test::circuit::{run_circuit, UserCircuit};
    use plonky2::iop::witness::PartialWitness;

    impl ColumnInfo {
        fn to_vec(&self) -> Vec<F> {
            vec![
                self.slot,
                self.identifier,
                self.byte_offset,
                self.bit_offset,
                self.length,
                self.evm_word,
            ]
        }
    }

    impl ColumnInfoTarget {
        fn to_vec(&self) -> Vec<Target> {
            vec![
                self.slot,
                self.identifier,
                self.byte_offset,
                self.bit_offset,
                self.length,
                self.evm_word,
            ]
        }
    }

    #[derive(Clone, Debug)]
    struct TestColumnInfoCircuit {
        column_info: ColumnInfo,
    }

    impl UserCircuit<F, D> for TestColumnInfoCircuit {
        type Wires = ColumnInfoTarget;

        fn build(b: &mut CBuilder) -> Self::Wires {
            let column_info = b.add_virtual_column_info();

            // Register as public inputs to check equivalence.
            b.register_public_inputs(&column_info.to_vec());

            column_info
        }

        fn prove(&self, pw: &mut PartialWitness<F>, column_info_target: &ColumnInfoTarget) {
            pw.set_column_info_target(column_info_target, &self.column_info);
        }
    }

    #[test]
    fn test_values_extraction_column_info() {
        let column_info = ColumnInfo::sample();
        let expected_pi = column_info.to_vec();

        let test_circuit = TestColumnInfoCircuit { column_info };

        let proof = run_circuit::<F, D, C, _>(test_circuit);
        assert_eq!(proof.public_inputs, expected_pi);
    }
}
