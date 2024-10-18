use super::{cells::build_cells_tree, ComputationalHashTarget, MembershipHashTarget};
use crate::query::computational_hash_ids::{Extraction, Identifiers};
use alloy::primitives::U256;
use mp2_common::{
    poseidon::empty_poseidon_hash,
    serialization::{
        deserialize_array, deserialize_long_array, serialize_array, serialize_long_array,
    },
    types::CBuilder,
    u256::{CircuitBuilderU256, UInt256Target, WitnessWriteU256},
    utils::HashBuilder,
    F,
};
use plonky2::iop::{
    target::{BoolTarget, Target},
    witness::{PartialWitness, WitnessWrite},
};
use serde::{Deserialize, Serialize};
use std::array;

/// Input wires for the column extraction component
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct ColumnExtractionInputWires<const MAX_NUM_COLUMNS: usize> {
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
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ColumnExtractionValueWires<const MAX_NUM_COLUMNS: usize> {
    /// Hash of the cells tree
    pub(crate) tree_hash: MembershipHashTarget,
}

pub(crate) struct ColumnExtractionHashWires<const MAX_NUM_COLUMNS: usize> {
    pub(crate) input_wires: ColumnExtractionInputWires<MAX_NUM_COLUMNS>,
    /// Computational hash associated to the extraction of each of the `MAX_NUM_COLUMNS` columns
    pub(crate) column_hash: [ComputationalHashTarget; MAX_NUM_COLUMNS],
}

/// Input + output wires for the column extraction component
pub(crate) struct ColumnExtractionWires<const MAX_NUM_COLUMNS: usize> {
    pub(crate) value_wires: ColumnExtractionValueWires<MAX_NUM_COLUMNS>,
    pub(crate) hash_wires: ColumnExtractionHashWires<MAX_NUM_COLUMNS>,
}
/// Witness input values for column extraction component
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ColumnExtractionInputs<const MAX_NUM_COLUMNS: usize> {
    pub(crate) real_num_columns: usize,
    #[serde(
        serialize_with = "serialize_long_array",
        deserialize_with = "deserialize_long_array"
    )]
    pub(crate) column_ids: [F; MAX_NUM_COLUMNS],
}

impl<const MAX_NUM_COLUMNS: usize> ColumnExtractionInputs<MAX_NUM_COLUMNS> {
    pub(crate) fn build_column_values(b: &mut CBuilder) -> [UInt256Target; MAX_NUM_COLUMNS] {
        b.add_virtual_u256_arr_unsafe()
    }

    pub(crate) fn build_tree_hash(
        b: &mut CBuilder,
        column_values: &[UInt256Target; MAX_NUM_COLUMNS],
        input_wires: &ColumnExtractionInputWires<MAX_NUM_COLUMNS>,
    ) -> ColumnExtractionValueWires<MAX_NUM_COLUMNS> {
        // Exclude the first 2 indexed columns to build the cells tree.
        let input_values = &column_values[2..];
        let input_ids = &input_wires.column_ids[2..];
        let is_real_value = &input_wires.is_real_column[2..];
        let tree_hash = build_cells_tree(b, input_values, input_ids, is_real_value);

        ColumnExtractionValueWires { tree_hash }
    }

    pub(crate) fn build_hash(b: &mut CBuilder) -> ColumnExtractionHashWires<MAX_NUM_COLUMNS> {
        // Initialize the input wires.
        let input_wires = ColumnExtractionInputWires {
            column_ids: b.add_virtual_target_arr(),
            is_real_column: [0; MAX_NUM_COLUMNS].map(|_| b.add_virtual_bool_target_safe()),
        };

        // Build the column hashes by the input.
        let column_hash = build_column_hash(b, &input_wires);

        ColumnExtractionHashWires {
            input_wires,
            column_hash,
        }
    }

    pub(crate) fn build(
        b: &mut CBuilder,
        column_values: &[UInt256Target; MAX_NUM_COLUMNS],
    ) -> ColumnExtractionWires<MAX_NUM_COLUMNS> {
        let hash_wires = Self::build_hash(b);
        let value_wires = Self::build_tree_hash(b, column_values, &hash_wires.input_wires);

        ColumnExtractionWires {
            value_wires,
            hash_wires,
        }
    }

    pub(crate) fn assign(
        &self,
        pw: &mut PartialWitness<F>,
        wires: &ColumnExtractionInputWires<MAX_NUM_COLUMNS>,
    ) {
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
) -> [ComputationalHashTarget; MAX_NUM_COLUMNS] {
    let empty_hash = b.constant_hash(*empty_poseidon_hash());

    array::from_fn(|i| {
        // Column identifier hash
        let hash = Identifiers::Extraction(Extraction::Column)
            .prefix_id_hash_circuit(b, vec![input.column_ids[i]]);

        if i < 2 {
            hash
        } else {
            b.select_hash(input.is_real_column[i], &hash, &empty_hash)
        }
    })
}

#[cfg(test)]
mod tests {
    use crate::query::universal_circuit::{ComputationalHash, MembershipHash};

    use super::*;
    use mp2_common::{C, D};
    use mp2_test::{
        cells_tree::{compute_cells_tree_hash, TestCell},
        circuit::{run_circuit, UserCircuit},
    };
    use plonky2::field::types::Field;

    #[derive(Clone, Debug)]
    struct TestColumnExtractionCircuit<const MAX_NUM_COLUMNS: usize> {
        inputs: ColumnExtractionInputs<MAX_NUM_COLUMNS>,
        column_values: [U256; MAX_NUM_COLUMNS],
        column_hash: [ComputationalHash; MAX_NUM_COLUMNS],
        tree_hash: MembershipHash,
    }

    impl<const MAX_NUM_COLUMNS: usize> UserCircuit<F, D>
        for TestColumnExtractionCircuit<MAX_NUM_COLUMNS>
    {
        // Column extraction wires
        // + column values
        // + expected output column hash
        // + expected output tree hash
        type Wires = (
            ColumnExtractionWires<MAX_NUM_COLUMNS>,
            [UInt256Target; MAX_NUM_COLUMNS],
            [ComputationalHashTarget; MAX_NUM_COLUMNS],
            MembershipHashTarget,
        );

        fn build(b: &mut CBuilder) -> Self::Wires {
            let column_values = ColumnExtractionInputs::build_column_values(b);
            let wires = ColumnExtractionInputs::build(b, &column_values);
            let column_hash = array::from_fn(|_| b.add_virtual_hash());
            let tree_hash = b.add_virtual_hash();

            // Check the output column hash.
            wires
                .hash_wires
                .column_hash
                .iter()
                .zip(column_hash)
                .for_each(|(l, r)| b.connect_hashes(*l, r));

            // Check the output tree hash.
            b.connect_hashes(wires.value_wires.tree_hash, tree_hash);

            (wires, column_values, column_hash, tree_hash)
        }

        fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
            pw.set_u256_target_arr(&wires.1, &self.column_values);
            self.inputs.assign(pw, &wires.0.hash_wires.input_wires);
            wires
                .2
                .iter()
                .zip(self.column_hash)
                .for_each(|(t, v)| pw.set_hash_target(*t, v));
            pw.set_hash_target(wires.3, self.tree_hash);
        }
    }

    impl<const MAX_NUM_COLUMNS: usize> TestColumnExtractionCircuit<MAX_NUM_COLUMNS> {
        async fn new(columns: Vec<TestCell>) -> Self {
            let real_num_columns = columns.len();
            assert!(real_num_columns <= MAX_NUM_COLUMNS);

            // Compute the expected column hash and tree hash.
            let column_hash = compute_column_hash(&columns);
            let tree_hash = compute_cells_tree_hash(columns[2..].to_vec()).await;

            // Construct the circuit input.
            let (mut column_ids, mut column_values): (Vec<_>, Vec<_>) =
                columns.into_iter().map(|col| (col.id, col.value)).unzip();
            column_ids.resize(MAX_NUM_COLUMNS, F::ZERO);
            column_values.resize(MAX_NUM_COLUMNS, U256::ZERO);
            let column_ids = column_ids.try_into().unwrap();
            let column_values = column_values.try_into().unwrap();
            let inputs = ColumnExtractionInputs {
                real_num_columns,
                column_ids,
            };

            Self {
                inputs,
                column_values,
                column_hash,
                tree_hash,
            }
        }
    }

    /// Compute the column hashes.
    fn compute_column_hash<const MAX_NUM_COLUMNS: usize>(
        columns: &[TestCell],
    ) -> [ComputationalHash; MAX_NUM_COLUMNS] {
        let empty_hash = empty_poseidon_hash();

        array::from_fn(|i| match columns.get(i) {
            Some(TestCell { id, .. }) => {
                Identifiers::Extraction(Extraction::Column).prefix_id_hash(vec![*id])
            }
            None => *empty_hash,
        })
    }

    #[tokio::test]
    async fn test_query_column_extraction_component() {
        const MAX_NUM_COLUMNS: usize = 15;
        const REAL_NUM_COLUMNS: usize = 11;

        // Generate the random column data.
        let test_cells = [0; REAL_NUM_COLUMNS].map(|_| TestCell::random()).to_vec();

        // Construct the test circuit.
        let test_circuit = TestColumnExtractionCircuit::<MAX_NUM_COLUMNS>::new(test_cells).await;

        // Prove for the test circuit.
        run_circuit::<F, D, C, _>(test_circuit);
    }
}
