//! Column information for values extraction

use itertools::zip_eq;
use mp2_common::{types::CBuilder, F};
use plonky2::iop::{target::Target, witness::WitnessWrite};
use serde::{Deserialize, Serialize};
use std::array;

/// Column info
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct ColumnInfo {
    /// Slot information of the variable
    // TODO: Check if it needs to be PACKED_HASH_LEN bytes array instead.
    slot: F,
    /// Column identifier
    identifier: F,
    /// The offset in bytes where to extract this column in a given EVM word
    byte_offset: F,
    /// The starting offset in `byte_offset` of the bits to be extracted for this column.
    /// The column bits will start at `byte_offset * 8 + bit_offset`.
    bit_offset: F,
    /// The length (in bits) of the field to extract in the EVM word
    length: F,
    /// At which EVM word is this column extracted from. For simple variables,
    /// this value should always be 0. For structs that spans more than one EVM word
    // that value should be depending on which section of the struct we are in.
    evm_word: F,
}

/// Column info target
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct ColumnInfoTarget {
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
