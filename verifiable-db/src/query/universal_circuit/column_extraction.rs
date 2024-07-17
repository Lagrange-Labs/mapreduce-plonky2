use super::{cells::build_cells_tree, COLUMN_INDEX_NUM};
use crate::query::computational_hash_ids::{Extraction, Identifiers};
use alloy::primitives::U256;
use mp2_common::{
    poseidon::empty_poseidon_hash,
    serialization::{
        deserialize_array, deserialize_long_array, serialize_array, serialize_long_array,
    },
    types::CBuilder,
    u256::{CircuitBuilderU256, UInt256Target, WitnessWriteU256},
    utils::SelectHashBuilder,
    F,
};
use plonky2::{
    hash::hash_types::HashOutTarget,
    iop::{
        target::{BoolTarget, Target},
        witness::{PartialWitness, WitnessWrite},
    },
};
use serde::{Deserialize, Serialize};
use std::array;

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
    real_num_columns: usize,
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
}

impl<const MAX_NUM_COLUMNS: usize> ColumnExtractionInputs<MAX_NUM_COLUMNS> {
    pub(crate) fn build(b: &mut CBuilder) -> ColumnExtractionWires<MAX_NUM_COLUMNS> {
        // Initialize the input wires.
        let input_wires = ColumnExtractionInputWires {
            column_values: b.add_virtual_u256_arr(),
            column_ids: b.add_virtual_target_arr(),
            is_real_column: [0; MAX_NUM_COLUMNS].map(|_| b.add_virtual_bool_target_safe()),
        };

        // Build the column hashes by the input.
        let column_hash = build_column_hash(b, &input_wires);

        // Exclude the first 2 indexed columns to build the cells tree.
        let input_values = &input_wires.column_values[COLUMN_INDEX_NUM..];
        let input_ids = &input_wires.column_ids[COLUMN_INDEX_NUM..];
        let is_real_value = &input_wires.is_real_column[COLUMN_INDEX_NUM..];
        let tree_hash = build_cells_tree(b, input_values, input_ids, is_real_value);

        ColumnExtractionWires {
            tree_hash,
            column_hash,
            input_wires,
        }
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
        wires
            .is_real_column
            .iter()
            .enumerate()
            .for_each(|(i, t)| pw.set_bool_target(*t, i < self.real_num_columns));
    }
}

/// Build the column hashes by the identifiers.
fn build_column_hash<const MAX_NUM_COLUMNS: usize>(
    b: &mut CBuilder,
    input: &ColumnExtractionInputWires<MAX_NUM_COLUMNS>,
) -> [HashOutTarget; MAX_NUM_COLUMNS] {
    let empty_hash = b.constant_hash(*empty_poseidon_hash());

    array::from_fn(|i| {
        // Column identifier hash
        let hash = Identifiers::Extraction(Extraction::Column)
            .prefix_id_hash_circuit(b, vec![input.column_ids[i]]);

        if i < COLUMN_INDEX_NUM {
            hash
        } else {
            b.select_hash(input.is_real_column[i], &hash, &empty_hash)
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use mp2_common::{utils::Fieldable, C, D};
    use mp2_test::{
        cells_tree::{compute_cells_tree_hash, TestCell},
        circuit::{run_circuit, UserCircuit},
    };
    use plonky2::{field::types::Field, hash::hash_types::HashOut, plonk::config::Hasher};

    #[derive(Clone, Debug)]
    struct TestColumnExtractionCircuit<const MAX_NUM_COLUMNS: usize> {
        inputs: ColumnExtractionInputs<MAX_NUM_COLUMNS>,
        column_hash: [HashOut<F>; MAX_NUM_COLUMNS],
        tree_hash: HashOut<F>,
    }

    impl<const MAX_NUM_COLUMNS: usize> UserCircuit<F, D>
        for TestColumnExtractionCircuit<MAX_NUM_COLUMNS>
    {
        // Column extraction wires
        // + expected output column hash
        // + expected output tree hash
        type Wires = (
            ColumnExtractionWires<MAX_NUM_COLUMNS>,
            [HashOutTarget; MAX_NUM_COLUMNS],
            HashOutTarget,
        );

        fn build(b: &mut CBuilder) -> Self::Wires {
            let wires = ColumnExtractionInputs::build(b);
            let column_hash = array::from_fn(|_| b.add_virtual_hash());
            let tree_hash = b.add_virtual_hash();

            // Check the output column hash.
            wires
                .column_hash
                .iter()
                .zip(column_hash)
                .for_each(|(l, r)| b.connect_hashes(*l, r));

            // Check the output tree hash.
            b.connect_hashes(wires.tree_hash, tree_hash);

            (wires, column_hash, tree_hash)
        }

        fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
            self.inputs.assign(pw, &wires.0.input_wires);
            wires
                .1
                .iter()
                .zip(self.column_hash)
                .for_each(|(t, v)| pw.set_hash_target(*t, v));
            pw.set_hash_target(wires.2, self.tree_hash);
        }
    }

    impl<const MAX_NUM_COLUMNS: usize> TestColumnExtractionCircuit<MAX_NUM_COLUMNS> {
        fn new(columns: Vec<TestCell>) -> Self {
            let real_num_columns = columns.len();
            assert!(real_num_columns <= MAX_NUM_COLUMNS);

            // Compute the expected column hash and tree hash.
            let column_hash = compute_column_hash(&columns);
            let tree_hash = compute_cells_tree_hash(&columns[COLUMN_INDEX_NUM..]);

            // Construct the circuit input.
            let (mut column_ids, mut column_values): (Vec<_>, Vec<_>) =
                columns.into_iter().map(|col| (col.id, col.value)).unzip();
            column_ids.resize(MAX_NUM_COLUMNS, F::ZERO);
            column_values.resize(MAX_NUM_COLUMNS, U256::ZERO);
            let column_ids = column_ids.try_into().unwrap();
            let column_values = column_values.try_into().unwrap();
            let inputs = ColumnExtractionInputs {
                real_num_columns,
                column_values,
                column_ids,
            };

            Self {
                inputs,
                column_hash,
                tree_hash,
            }
        }
    }

    /// Compute the column hashes.
    fn compute_column_hash<const MAX_NUM_COLUMNS: usize>(
        columns: &[TestCell],
    ) -> [HashOut<F>; MAX_NUM_COLUMNS] {
        let empty_hash = empty_poseidon_hash();

        array::from_fn(|i| match columns.get(i) {
            Some(TestCell { id, .. }) => {
                Identifiers::Extraction(Extraction::Column).prefix_id_hash(vec![*id])
            }
            None => *empty_hash,
        })
    }

    #[test]
    fn test_query_column_extraction_component() {
        const MAX_NUM_COLUMNS: usize = 15;
        const REAL_NUM_COLUMNS: usize = 11;

        // Generate the random column data.
        let test_cells = [0; REAL_NUM_COLUMNS].map(|_| TestCell::random()).to_vec();

        // Construct the test circuit.
        let test_circuit = TestColumnExtractionCircuit::<MAX_NUM_COLUMNS>::new(test_cells);

        // Prove for the test circuit.
        run_circuit::<F, D, C, _>(test_circuit);
    }
}
