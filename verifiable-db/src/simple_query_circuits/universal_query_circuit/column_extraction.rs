use ethers::types::U256;
use mp2_common::{
    serialization::{
        deserialize_array, deserialize_long_array, serialize_array, serialize_long_array,
    },
    u256::{UInt256Target, WitnessWriteU256},
    D, F,
};
use plonky2::{
    hash::hash_types::HashOutTarget,
    iop::{
        target::{BoolTarget, Target},
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::circuit_builder::CircuitBuilder,
};
use serde::{Deserialize, Serialize};

/// Input wires for the column extraction component
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ColumnExtractionInputWires<const MAX_NUM_COLUMNS: usize> {
    /// values of the columns for the current row
    #[serde(
        serialize_with = "serialize_array",
        deserialize_with = "deserialize_array"
    )]
    pub(crate) column_values: [UInt256Target; MAX_NUM_COLUMNS],
    /// integer identifier associated to each of the columns
    #[serde(
        serialize_with = "serialize_array",
        deserialize_with = "deserialize_array"
    )]
    pub(crate) column_ids: [Target; MAX_NUM_COLUMNS],
    /// array of flags specifying the number of columns of the row;
    /// that is, if the row has m <= MAX_NUM_COLUMNS columns,
    /// then the first m flags are true, while the remaining MAX_NUM_COLUMNS-m are false
    #[serde(
        serialize_with = "serialize_array",
        deserialize_with = "deserialize_array"
    )]
    is_real_column: [BoolTarget; MAX_NUM_COLUMNS],
}
/// Input + output wires for the column extraction component
pub(crate) struct ColumnExtractionWires<const MAX_NUM_COLUMNS: usize> {
    pub(crate) input_wires: ColumnExtractionInputWires<MAX_NUM_COLUMNS>,
    /// Hash of the cells tree
    pub(crate) tree_hash: HashOutTarget,
    /// Computational hash associated to the extraction of each of the `MAX_NUM_COLUMNS` columns
    pub(crate) column_hash: [HashOutTarget; MAX_NUM_COLUMNS],
}
/// Witness input values for column extraction component
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ColumnExtractionInputs<const MAX_NUM_COLUMNS: usize> {
    #[serde(
        serialize_with = "serialize_long_array",
        deserialize_with = "deserialize_long_array"
    )]
    column_values: [U256; MAX_NUM_COLUMNS],
    #[serde(
        serialize_with = "serialize_long_array",
        deserialize_with = "deserialize_long_array"
    )]
    column_ids: [F; MAX_NUM_COLUMNS],
    #[serde(
        serialize_with = "serialize_long_array",
        deserialize_with = "deserialize_long_array"
    )]
    is_real_column: [bool; MAX_NUM_COLUMNS],
}

impl<const MAX_NUM_COLUMNS: usize> ColumnExtractionInputs<MAX_NUM_COLUMNS> {
    pub(crate) fn build(b: &mut CircuitBuilder<F, D>) -> ColumnExtractionWires<MAX_NUM_COLUMNS> {
        todo!()
    }

    pub(crate) fn assign(
        &self,
        pw: &mut PartialWitness<F>,
        wires: &ColumnExtractionInputWires<MAX_NUM_COLUMNS>,
    ) {
        self.column_values
            .iter()
            .zip(wires.column_values.iter())
            .for_each(|(v, t)| pw.set_u256_target(t, *v));

        pw.set_target_arr(wires.column_ids.as_slice(), self.column_ids.as_slice());
        self.is_real_column
            .iter()
            .zip(wires.is_real_column.iter())
            .for_each(|(v, t)| pw.set_bool_target(*t, *v));
    }
}
