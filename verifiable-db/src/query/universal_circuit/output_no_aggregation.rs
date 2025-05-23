use crate::{
    query::computational_hash_ids::{AggregationOperation, Identifiers, Output},
    CBuilder, F,
};
use anyhow::ensure;
use itertools::Itertools;
use mp2_common::{
    array::ToField,
    group_hashing::CircuitBuilderGroupHashing,
    serialization::{
        deserialize_array, deserialize_long_array, serialize_array, serialize_long_array,
    },
    u256::{CircuitBuilderU256, UInt256Target},
    utils::ToTargets,
};
use plonky2::iop::{
    target::{BoolTarget, Target},
    witness::{PartialWitness, WitnessWrite},
};
use plonky2_ecgfp5::gadgets::curve::{CircuitBuilderEcGFp5, CurveTarget};
use serde::{Deserialize, Serialize};
use std::{
    array,
    iter::{self, repeat},
};

use super::{
    cells::build_cells_tree,
    universal_query_gadget::{
        OutputComponent, OutputComponentHashWires, OutputComponentValueWires,
    },
    ComputationalHashTarget,
};

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
/// Input wires for output component for queries without results aggregation
pub struct InputWires<const MAX_NUM_RESULTS: usize> {
    /// Selectors employed to choose which item, among the inputs ones,
    /// should be employed to compute the i-th result to be returned
    #[serde(
        serialize_with = "serialize_array",
        deserialize_with = "deserialize_array"
    )]
    selector: [Target; MAX_NUM_RESULTS],
    /// Integer identifiers of the `MAX_NUM_RESULTS` output items to be returned
    #[serde(
        serialize_with = "serialize_array",
        deserialize_with = "deserialize_array"
    )]
    ids: [Target; MAX_NUM_RESULTS],
    /// Array of Boolean flags encoding the actual number of output items;
    /// that is, if the query specifies to return s <= MAX_NUM_RESULTS items per record,
    /// then the first s flags of this array are true,
    /// while the remaining MAX_NUM_RESULTS-s entries are false
    #[serde(
        serialize_with = "serialize_array",
        deserialize_with = "deserialize_array"
    )]
    is_output_valid: [BoolTarget; MAX_NUM_RESULTS],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HashWires<const MAX_NUM_RESULTS: usize> {
    /// input wires of the component
    input_wires: InputWires<MAX_NUM_RESULTS>,

    /// Computational hash representing all the computation done in the query circuit
    output_hash: ComputationalHashTarget,
    /// Identifiers of the aggregation operations to be returned as public inputs
    ops_ids: [Target; MAX_NUM_RESULTS],
}

#[derive(Clone, Debug)]
pub struct ValueWires<const MAX_NUM_RESULTS: usize> {
    /// The first output value computed by this component; it is a `CurveTarget` since
    /// it corresponds to the accumulator of all the results of the query
    first_output_value: CurveTarget,
    /// Remaining output values; for this component, they are basically dummy values
    output_values: Vec<UInt256Target>,
}

/// Witness input values for output component for queries without results aggregation
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Circuit<const MAX_NUM_RESULTS: usize> {
    valid_num_outputs: usize,
    #[serde(
        serialize_with = "serialize_long_array",
        deserialize_with = "deserialize_long_array"
    )]
    selector: [F; MAX_NUM_RESULTS],
    #[serde(
        serialize_with = "serialize_long_array",
        deserialize_with = "deserialize_long_array"
    )]
    ids: [F; MAX_NUM_RESULTS],
}

impl<const MAX_NUM_RESULTS: usize> OutputComponentValueWires for ValueWires<MAX_NUM_RESULTS> {
    type FirstT = CurveTarget;

    fn first_output_value(&self) -> Self::FirstT {
        self.first_output_value
    }

    fn other_output_values(&self) -> &[UInt256Target] {
        &self.output_values
    }
}

impl<const MAX_NUM_RESULTS: usize> OutputComponentHashWires for HashWires<MAX_NUM_RESULTS> {
    type InputWires = InputWires<MAX_NUM_RESULTS>;

    fn ops_ids(&self) -> &[Target] {
        self.ops_ids.as_slice()
    }

    fn computational_hash(&self) -> ComputationalHashTarget {
        self.output_hash
    }

    fn input_wires(&self) -> Self::InputWires {
        self.input_wires.clone()
    }
}

impl<const MAX_NUM_RESULTS: usize> OutputComponent<MAX_NUM_RESULTS> for Circuit<MAX_NUM_RESULTS> {
    type HashWires = HashWires<MAX_NUM_RESULTS>;
    type ValueWires = ValueWires<MAX_NUM_RESULTS>;

    fn assign(&self, pw: &mut PartialWitness<F>, wires: &InputWires<MAX_NUM_RESULTS>) {
        pw.set_target_arr(wires.selector.as_slice(), self.selector.as_slice());
        pw.set_target_arr(wires.ids.as_slice(), self.ids.as_slice());
        wires
            .is_output_valid
            .iter()
            .enumerate()
            .for_each(|(i, t)| pw.set_bool_target(*t, i < self.valid_num_outputs));
    }

    fn new(selector: &[F], ids: &[F], num_outputs: usize) -> anyhow::Result<Self> {
        ensure!(selector.len() == num_outputs,
            "Output component without aggregation: Number of selectors different from number of actual outputs");
        ensure!(ids.len() == num_outputs,
            "Output component without aggregation: Number of output ids different from number of actual outputs");
        let selectors = selector
            .iter()
            .chain(repeat(&F::default()))
            .take(MAX_NUM_RESULTS)
            .cloned()
            .collect_vec();
        let output_ids = ids
            .iter()
            .chain(repeat(&F::default()))
            .take(MAX_NUM_RESULTS)
            .cloned()
            .collect_vec();
        Ok(Self {
            valid_num_outputs: num_outputs,
            selector: selectors.try_into().unwrap(),
            ids: output_ids.try_into().unwrap(),
        })
    }

    fn output_variant() -> Output {
        Output::NoAggregation
    }

    fn build_values<const NUM_OUTPUT_VALUES: usize>(
        b: &mut CBuilder,
        possible_output_values: [UInt256Target; NUM_OUTPUT_VALUES],
        predicate_value: &BoolTarget,
        input_wires: &<Self::HashWires as OutputComponentHashWires>::InputWires,
    ) -> Self::ValueWires {
        let u256_zero = b.zero_u256();
        let curve_zero = b.curve_zero();

        // Build the output items to be returned.
        let output_items: [_; MAX_NUM_RESULTS] = array::from_fn(|i| {
            b.random_access_u256(input_wires.selector[i], &possible_output_values)
        });

        // Compute the cells tree of the all output items to be returned for the given record.
        let tree_hash = build_cells_tree(
            b,
            &output_items[2..],
            &input_wires.ids[2..],
            &input_wires.is_output_valid[2..],
        );

        // Compute the accumulator including the indexed items:
        // second_item = is_output_valid[1] ? output_items[1] : 0
        // accumulator = D(ids[0] || output_items[0] || ids[1] || second_item || tree_hash)
        let second_item =
            b.select_u256(input_wires.is_output_valid[1], &output_items[1], &u256_zero);
        let inputs: Vec<_> = iter::once(input_wires.ids[0])
            .chain(output_items[0].to_targets())
            .chain(iter::once(input_wires.ids[1]))
            .chain(second_item.to_targets())
            .chain(tree_hash.to_targets())
            .collect();
        let accumulator = b.map_to_curve_point(&inputs);

        // Expose the accumulator only if the results for this record have to be
        // included in the query results.
        let first_output_value = b.curve_select(*predicate_value, accumulator, curve_zero);

        // Set the remaining outputs to dummy values.
        let output_values = vec![u256_zero; MAX_NUM_RESULTS - 1];

        ValueWires {
            first_output_value,
            output_values,
        }
    }

    fn build_hash<const NUM_OUTPUT_VALUES: usize>(
        b: &mut CBuilder,
        possible_output_hash: [ComputationalHashTarget; NUM_OUTPUT_VALUES],
        predicate_hash: &ComputationalHashTarget,
    ) -> Self::HashWires {
        // Initialize the input wires.
        let input_wires = InputWires {
            selector: b.add_virtual_target_arr(),
            ids: b.add_virtual_target_arr(),
            is_output_valid: [0; MAX_NUM_RESULTS].map(|_| b.add_virtual_bool_target_safe()),
        };

        // Compute the computational hash representing the accumulation of the items.
        let output_hash = Self::output_variant().output_hash_circuit(
            b,
            predicate_hash,
            &possible_output_hash,
            &input_wires.selector,
            &input_wires.ids,
            &input_wires.is_output_valid,
        );

        // For the no aggregation operations, the first value in V contains the
        // accumulator, while the other slots are filled by the dummy zero values.
        // So the circuit claims that there is no aggregation operation on the
        // first value in V, while all the other values can be simply summed up.
        let [op_id, op_sum] = [AggregationOperation::IdOp, AggregationOperation::SumOp]
            .map(|op| b.constant(Identifiers::AggregationOperations(op).to_field()));
        let ops_ids: Vec<_> = iter::once(op_id)
            .chain(iter::repeat_n(op_sum, MAX_NUM_RESULTS - 1))
            .collect();
        let ops_ids = ops_ids.try_into().unwrap();

        HashWires {
            input_wires,
            output_hash,
            ops_ids,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::query::{
        computational_hash_ids::ComputationalHashCache,
        universal_circuit::{universal_circuit_inputs::OutputItem, ComputationalHash},
    };

    use super::*;
    use crate::{C, D};
    use alloy::primitives::U256;
    use mp2_common::{group_hashing::map_to_curve_point, u256::WitnessWriteU256, utils::ToFields};
    use mp2_test::{
        cells_tree::{compute_cells_tree_hash, TestCell},
        circuit::{run_circuit, UserCircuit},
    };
    use plonky2::field::types::{Field, PrimeField64, Sample};
    use plonky2_ecgfp5::{curve::curve::Point, gadgets::curve::PartialWitnessCurve};
    use rand::{thread_rng, Rng};

    impl<const MAX_NUM_RESULTS: usize> Circuit<MAX_NUM_RESULTS> {
        /// Sample an output circuit.
        fn sample<const NUM_COLUMNS: usize>(valid_num_outputs: usize) -> Self {
            let mut rng = thread_rng();

            // Generate a random index from the length of (Column values + 1 item result).
            let selector = array::from_fn(|_| {
                F::from_canonical_usize(rng.gen_range(0..NUM_COLUMNS + valid_num_outputs))
            });
            let ids = array::from_fn(|_| F::from_canonical_u32(rng.gen()));

            Self {
                valid_num_outputs,
                selector,
                ids,
            }
        }
    }

    #[derive(Clone, Debug)]
    struct TestOutputWires<const NUM_COLUMNS: usize, const MAX_NUM_RESULTS: usize> {
        column_values: [UInt256Target; NUM_COLUMNS],
        column_hash: [ComputationalHashTarget; NUM_COLUMNS],
        item_values: [UInt256Target; MAX_NUM_RESULTS],
        item_hash: [ComputationalHashTarget; MAX_NUM_RESULTS],
        predicate_value: BoolTarget,
        predicate_hash: ComputationalHashTarget,
    }

    #[derive(Clone, Debug)]
    struct TestOutput<const NUM_COLUMNS: usize, const MAX_NUM_RESULTS: usize> {
        column_values: [U256; NUM_COLUMNS],
        column_hash: [ComputationalHash; NUM_COLUMNS],
        item_values: [U256; MAX_NUM_RESULTS],
        item_hash: [ComputationalHash; MAX_NUM_RESULTS],
        predicate_value: bool,
        predicate_hash: ComputationalHash,
    }

    impl<const NUM_COLUMNS: usize, const MAX_NUM_RESULTS: usize>
        TestOutput<NUM_COLUMNS, MAX_NUM_RESULTS>
    {
        /// Sample a test output.
        fn sample(predicate_value: bool) -> Self {
            let mut rng = thread_rng();

            let column_values = array::from_fn(|_| U256::from_limbs(rng.gen::<[u64; 4]>()));
            let column_hash = array::from_fn(|_| ComputationalHash::sample(&mut rng));
            let item_values = array::from_fn(|_| U256::from_limbs(rng.gen::<[u64; 4]>()));
            let item_hash = array::from_fn(|_| ComputationalHash::sample(&mut rng));
            let predicate_hash = ComputationalHash::sample(&mut rng);

            Self {
                column_values,
                column_hash,
                item_values,
                item_hash,
                predicate_value,
                predicate_hash,
            }
        }

        fn build(b: &mut CBuilder) -> TestOutputWires<NUM_COLUMNS, MAX_NUM_RESULTS> {
            let column_values = b.add_virtual_u256_arr();
            let column_hash = [0; NUM_COLUMNS].map(|_| b.add_virtual_hash());
            let item_values = b.add_virtual_u256_arr();
            let item_hash = [0; MAX_NUM_RESULTS].map(|_| b.add_virtual_hash());
            let predicate_value = b.add_virtual_bool_target_safe();
            let predicate_hash = b.add_virtual_hash();

            TestOutputWires {
                column_values,
                column_hash,
                item_values,
                item_hash,
                predicate_value,
                predicate_hash,
            }
        }

        fn assign(
            &self,
            pw: &mut PartialWitness<F>,
            wires: &TestOutputWires<NUM_COLUMNS, MAX_NUM_RESULTS>,
        ) {
            self.column_values
                .iter()
                .zip(wires.column_values.iter())
                .for_each(|(v, t)| pw.set_u256_target(t, *v));
            self.column_hash
                .iter()
                .zip(wires.column_hash.iter())
                .for_each(|(v, t)| pw.set_hash_target(*t, *v));
            self.item_values
                .iter()
                .zip(wires.item_values.iter())
                .for_each(|(v, t)| pw.set_u256_target(t, *v));
            self.item_hash
                .iter()
                .zip(wires.item_hash.iter())
                .for_each(|(v, t)| pw.set_hash_target(*t, *v));
            pw.set_bool_target(wires.predicate_value, self.predicate_value);
            pw.set_hash_target(wires.predicate_hash, self.predicate_hash);
        }
    }

    #[derive(Clone, Debug)]
    struct TestExpectedWires {
        first_output_value: CurveTarget,
        output_hash: ComputationalHashTarget,
    }

    #[derive(Clone, Debug)]
    struct TestExpected {
        first_output_value: Point,
        output_hash: ComputationalHash,
    }

    impl TestExpected {
        /// Compute the expected values by the input and output.
        async fn new<const NUM_COLUMNS: usize, const MAX_NUM_RESULTS: usize>(
            c: &Circuit<MAX_NUM_RESULTS>,
            output: &TestOutput<NUM_COLUMNS, MAX_NUM_RESULTS>,
        ) -> Self {
            let u256_zero = U256::ZERO;
            let curve_zero = Point::NEUTRAL;
            let selectors = c
                .selector
                .iter()
                .map(|s| s.to_canonical_u64() as usize)
                .collect_vec();

            // Construct the output items to be returned.
            let possible_input_values = output
                .column_values
                .iter()
                .chain(&output.item_values)
                .cloned()
                .collect_vec();
            let output_items: Vec<_> = (0..c.valid_num_outputs)
                .map(|i| possible_input_values[selectors[i]])
                .collect();

            // Compute the cells tree root hash of the all output items.
            let cells: Vec<_> = output_items
                .into_iter()
                .zip(c.ids)
                .map(|(value, id)| TestCell {
                    id,
                    value,
                    ..Default::default()
                })
                .collect();
            let tree_hash = compute_cells_tree_hash((cells[2..]).to_vec()).await;

            // Compute the first output value only for predicate value.
            let first_output_value = if output.predicate_value {
                let second_item = if c.valid_num_outputs > 1 {
                    cells[1].value
                } else {
                    u256_zero
                };
                let inputs: Vec<_> = iter::once(cells[0].id)
                    .chain(cells[0].value.to_fields())
                    .chain(iter::once(cells[1].id))
                    .chain(second_item.to_fields())
                    .chain(tree_hash.to_fields())
                    .collect();
                map_to_curve_point(&inputs)
            } else {
                curve_zero
            };

            // Compute the computational output hash.
            // first, we compute the output items from the randomly chosen selectors
            let output_items = selectors
                .iter()
                .take(c.valid_num_outputs)
                .map(|&s| {
                    if s < NUM_COLUMNS {
                        OutputItem::Column(s)
                    } else {
                        // need to subtract `NUM_COLUMNS` since the outputs of result operations that could be used as
                        // output values are appended to the set of columns in the circuit, so the selector `s` for
                        // the i-th computed output value will be equal to `s = NUM_COLUMNS+i`
                        OutputItem::ComputedValue(s - NUM_COLUMNS)
                    }
                })
                .collect_vec();
            let output_hash = Circuit::<MAX_NUM_RESULTS>::output_variant()
                .output_hash(
                    &output.predicate_hash,
                    &mut ComputationalHashCache::new_from_column_hash(
                        NUM_COLUMNS,
                        &output.column_hash,
                    )
                    .unwrap(),
                    &[], // unused since we already place all column hash in the cache
                    &output.item_hash,
                    &output_items,
                    &c.ids,
                )
                .unwrap();

            Self {
                first_output_value,
                output_hash,
            }
        }

        fn build(b: &mut CBuilder) -> TestExpectedWires {
            let first_output_value = b.add_virtual_curve_target();
            let output_hash = b.add_virtual_hash();

            TestExpectedWires {
                first_output_value,
                output_hash,
            }
        }

        fn assign(&self, pw: &mut PartialWitness<F>, wires: &TestExpectedWires) {
            pw.set_curve_target(
                wires.first_output_value,
                self.first_output_value.to_weierstrass(),
            );
            pw.set_hash_target(wires.output_hash, self.output_hash);
        }
    }

    #[derive(Clone, Debug)]
    struct TestOutputNoAggregationCircuit<const NUM_COLUMNS: usize, const MAX_NUM_RESULTS: usize> {
        c: Circuit<MAX_NUM_RESULTS>,
        output: TestOutput<NUM_COLUMNS, MAX_NUM_RESULTS>,
        expected: TestExpected,
    }

    impl<const NUM_COLUMNS: usize, const MAX_NUM_RESULTS: usize> UserCircuit<F, D>
        for TestOutputNoAggregationCircuit<NUM_COLUMNS, MAX_NUM_RESULTS>
    where
        [(); NUM_COLUMNS + MAX_NUM_RESULTS]:,
    {
        // Circuit wires + output wires + expected wires
        type Wires = (
            InputWires<MAX_NUM_RESULTS>,
            TestOutputWires<NUM_COLUMNS, MAX_NUM_RESULTS>,
            TestExpectedWires,
        );

        fn build(b: &mut CBuilder) -> Self::Wires {
            let u256_zero = b.zero_u256();

            let expected = TestExpected::build(b);
            let output = TestOutput::build(b);
            let possible_output_values = output
                .column_values
                .iter()
                .chain(output.item_values.iter())
                .cloned()
                .collect_vec();
            let possible_output_hash = output
                .column_hash
                .iter()
                .chain(output.item_hash.iter())
                .cloned()
                .collect_vec();
            let wires = Circuit::build::<{ NUM_COLUMNS + MAX_NUM_RESULTS }>(
                b,
                possible_output_values.try_into().unwrap(),
                possible_output_hash.try_into().unwrap(),
                &output.predicate_value,
                &output.predicate_hash,
            );

            // Check the first output value and the output hash as expected.
            b.connect_curve_points(
                wires.value_wires.first_output_value,
                expected.first_output_value,
            );
            b.connect_hashes(wires.hash_wires.output_hash, expected.output_hash);

            // Check the remaining output values must be all zeros.
            wires
                .value_wires
                .output_values
                .iter()
                .for_each(|t| b.enforce_equal_u256(t, &u256_zero));

            // Check the first OP is ID, and the remainings are SUM.
            let [op_id, op_sum] = [AggregationOperation::IdOp, AggregationOperation::SumOp]
                .map(|op| b.constant(Identifiers::AggregationOperations(op).to_field()));
            b.connect(wires.hash_wires.ops_ids[0], op_id);
            wires.hash_wires.ops_ids[1..]
                .iter()
                .for_each(|t| b.connect(*t, op_sum));

            (wires.hash_wires.input_wires, output, expected)
        }

        fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
            self.c.assign(pw, &wires.0);
            self.output.assign(pw, &wires.1);
            self.expected.assign(pw, &wires.2);
        }
    }

    impl<const NUM_COLUMNS: usize, const MAX_NUM_RESULTS: usize>
        TestOutputNoAggregationCircuit<NUM_COLUMNS, MAX_NUM_RESULTS>
    {
        async fn sample(predicate_value: bool, valid_num_outputs: usize) -> Self {
            let c = Circuit::<MAX_NUM_RESULTS>::sample::<NUM_COLUMNS>(valid_num_outputs);
            let output = TestOutput::sample(predicate_value);
            let expected = TestExpected::new(&c, &output).await;

            Self {
                c,
                output,
                expected,
            }
        }
    }

    #[tokio::test]
    async fn test_query_no_aggregation_output_with_predicated() {
        const NUM_COLUMNS: usize = 5;
        const MAX_NUM_RESULTS: usize = 13;
        const NUM_VALID_OUTPUTS: usize = 13;

        let test_circuit = TestOutputNoAggregationCircuit::<NUM_COLUMNS, MAX_NUM_RESULTS>::sample(
            true,
            NUM_VALID_OUTPUTS,
        )
        .await;

        run_circuit::<F, D, C, _>(test_circuit);
    }

    #[tokio::test]
    async fn test_query_no_aggregation_output_with_no_predicated() {
        const NUM_COLUMNS: usize = 11;
        const MAX_NUM_RESULTS: usize = 9;
        const NUM_VALID_OUTPUTS: usize = 5;

        let test_circuit = TestOutputNoAggregationCircuit::<NUM_COLUMNS, MAX_NUM_RESULTS>::sample(
            false,
            NUM_VALID_OUTPUTS,
        )
        .await;

        run_circuit::<F, D, C, _>(test_circuit);
    }
}
