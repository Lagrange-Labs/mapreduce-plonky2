use std::{
    array,
    iter::{once, repeat},
};

use alloy::primitives::U256;
use itertools::Itertools;
use mp2_common::{
    array::ToField,
    serialization::{
        deserialize_array, deserialize_long_array, serialize_array, serialize_long_array,
    },
    types::CBuilder,
    u256::{CircuitBuilderU256, UInt256Target},
    D, F,
};
use plonky2::{
    field::types::Field,
    hash::hash_types::HashOutTarget,
    iop::{
        target::{BoolTarget, Target},
        witness::{PartialWitness, WitnessWrite},
    },
};
use serde::{Deserialize, Serialize};

use crate::query::computational_hash_ids::{AggregationOperation, Identifiers, Output};

use super::universal_query_circuit::{OutputComponent, OutputComponentWires};

use anyhow::{ensure, Result};

#[derive(Clone, Debug, Serialize, Deserialize)]
/// Input wires for output with aggregation component
pub struct InputWires<const MAX_NUM_RESULTS: usize> {
    /// Selectors employed to choose which item, among the inputs ones,
    /// should be employed to compute the i-th result to be returned
    #[serde(
        serialize_with = "serialize_array",
        deserialize_with = "deserialize_array"
    )]
    selector: [Target; MAX_NUM_RESULTS],
    /// Identifiers of the aggregations operations to be performed on
    /// each of the `MAX_NUM_RESULTS` output items
    #[serde(
        serialize_with = "serialize_array",
        deserialize_with = "deserialize_array"
    )]
    agg_ops: [Target; MAX_NUM_RESULTS],
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

#[derive(Clone, Debug)]
/// Input + output wires for output component for queries with result aggregation
pub struct Wires<const MAX_NUM_RESULTS: usize> {
    input_wires: InputWires<MAX_NUM_RESULTS>,
    /// Output values computed by this component
    output_values: [UInt256Target; MAX_NUM_RESULTS],
    /// Computational hash representing all the computation done in the query circuit
    output_hash: HashOutTarget,
}
/// Input witness values for output component for queries with result aggregation
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Circuit<const MAX_NUM_RESULTS: usize> {
    #[serde(
        serialize_with = "serialize_long_array",
        deserialize_with = "deserialize_long_array"
    )]
    selector: [F; MAX_NUM_RESULTS],
    #[serde(
        serialize_with = "serialize_long_array",
        deserialize_with = "deserialize_long_array"
    )]
    agg_ops: [F; MAX_NUM_RESULTS],
    num_valid_outputs: usize,
}

impl<const MAX_NUM_RESULTS: usize> OutputComponentWires for Wires<MAX_NUM_RESULTS> {
    type FirstT = UInt256Target;

    type InputWires = InputWires<MAX_NUM_RESULTS>;

    fn ops_ids(&self) -> &[Target] {
        self.input_wires.agg_ops.as_slice()
    }

    fn first_output_value(&self) -> Self::FirstT {
        self.output_values[0].clone()
    }

    fn other_output_values(&self) -> &[UInt256Target] {
        &self.output_values[1..]
    }

    fn computational_hash(&self) -> HashOutTarget {
        self.output_hash
    }

    fn input_wires(&self) -> Self::InputWires {
        self.input_wires.clone()
    }
}

impl<const MAX_NUM_RESULTS: usize> OutputComponent<MAX_NUM_RESULTS> for Circuit<MAX_NUM_RESULTS> {
    type Wires = Wires<MAX_NUM_RESULTS>;

    fn build(
        b: &mut CBuilder,
        column_values: &[UInt256Target],
        column_hash: &[HashOutTarget],
        item_values: [UInt256Target; MAX_NUM_RESULTS],
        item_hash: [HashOutTarget; MAX_NUM_RESULTS],
        predicate_value: &BoolTarget,
        predicate_hash: &HashOutTarget,
    ) -> Self::Wires {
        let selector = b.add_virtual_target_arr::<MAX_NUM_RESULTS>();
        let agg_ops = b.add_virtual_target_arr::<MAX_NUM_RESULTS>();
        let is_output_valid = array::from_fn(|_| b.add_virtual_bool_target_safe());
        let u256_max = b.constant_u256(U256::MAX);
        let zero = b.zero_u256();
        let min_op_identifier = b.constant(AggregationOperation::MinOp.to_field());

        let mut output_values = vec![];

        let possible_output_values = column_values
            .iter()
            .cloned()
            .chain(item_values.into_iter())
            .collect_vec();

        for i in 0..MAX_NUM_RESULTS {
            // ToDo: random accesses over different iterations can be done with a single operation if we introduce an ad-hoc gate
            let output_value = b.random_access_u256(selector[i], &possible_output_values);

            // If `predicate_value` is true, then expose the value to be aggregated;
            // Otherwise use the identity for the aggregation operation.
            // The identity is 0 except for "MIN", where the identity is the biggest
            // possible value in the domain, i.e. 2^256-1.
            let is_agg_ops_min = b.is_equal(agg_ops[i], min_op_identifier);
            let identity_value = b.select_u256(is_agg_ops_min, &u256_max, &zero);
            let actual_output_value =
                b.select_u256(*predicate_value, &output_value, &identity_value);
            output_values.push(actual_output_value);
        }

        let output_hash = Self::output_variant().output_hash_circuit(
            b,
            predicate_hash,
            column_hash,
            &item_hash,
            &selector,
            &agg_ops,
            &is_output_valid,
        );

        Wires {
            input_wires: InputWires {
                selector,
                agg_ops,
                is_output_valid,
            },
            output_values: output_values.try_into().unwrap(),
            output_hash,
        }
    }

    fn assign(&self, pw: &mut PartialWitness<F>, wires: &InputWires<MAX_NUM_RESULTS>) {
        pw.set_target_arr(wires.selector.as_slice(), self.selector.as_slice());
        pw.set_target_arr(wires.agg_ops.as_slice(), self.agg_ops.as_slice());
        wires
            .is_output_valid
            .iter()
            .enumerate()
            .for_each(|(i, t)| pw.set_bool_target(*t, i < self.num_valid_outputs));
    }

    fn new(selector: &[F], ids: &[F], num_outputs: usize) -> Result<Self> {
        ensure!(selector.len() == num_outputs,
            "Output component with aggregation: Number of selectors different from number of actual outputs");
        ensure!(ids.len() == num_outputs,
            "Output component with aggregation: Number of aggregation operations different from number of actual outputs");
        let selectors = selector
            .into_iter()
            .chain(repeat(&F::default()))
            .take(MAX_NUM_RESULTS)
            .cloned()
            .collect_vec();
        let agg_ops = ids
            .into_iter()
            .chain(repeat(&AggregationOperation::default().to_field()))
            .take(MAX_NUM_RESULTS)
            .cloned()
            .collect_vec();
        Ok(Self {
            selector: selectors.try_into().unwrap(),
            agg_ops: agg_ops.try_into().unwrap(),
            num_valid_outputs: num_outputs,
        })
    }

    fn output_variant() -> Output {
        Output::Aggregation
    }
}

#[cfg(test)]
mod tests {
    use std::{array, iter::repeat};

    use alloy::primitives::U256;
    use itertools::Itertools;
    use mp2_common::{
        array::ToField,
        poseidon::empty_poseidon_hash,
        u256::{CircuitBuilderU256, UInt256Target, WitnessWriteU256},
        C, D, F,
    };
    use mp2_test::{
        circuit::{run_circuit, UserCircuit},
        utils::{gen_random_field_hash, gen_random_u256},
    };
    use plonky2::{
        field::types::Field,
        hash::hash_types::{HashOut, HashOutTarget},
        iop::{
            target::{BoolTarget, Target},
            witness::{PartialWitness, WitnessWrite},
        },
        plonk::circuit_builder::CircuitBuilder,
    };
    use rand::{thread_rng, Rng};

    use crate::query::{
        computational_hash_ids::{AggregationOperation, ComputationalHashCache, Output},
        universal_circuit::universal_query_circuit::{
            OutputComponent, OutputComponentWires, OutputItem,
        },
    };

    use super::{Circuit, InputWires};

    #[derive(Clone, Debug)]
    struct TestOutputComponentWires<
        const MAX_NUM_COLUMNS: usize,
        const MAX_NUM_RESULTS: usize,
        const ACTUAL_NUM_RESULTS: usize,
    > {
        column_values: [UInt256Target; MAX_NUM_COLUMNS],
        column_hash: [HashOutTarget; MAX_NUM_COLUMNS],
        item_values: [UInt256Target; MAX_NUM_RESULTS],
        item_hash: [HashOutTarget; MAX_NUM_RESULTS],
        predicate_value: BoolTarget,
        predicate_hash: HashOutTarget,
        component: InputWires<MAX_NUM_RESULTS>,
        expected_output_values: [UInt256Target; ACTUAL_NUM_RESULTS],
        expected_ops_ids: [Target; ACTUAL_NUM_RESULTS],
        expected_output_hash: HashOutTarget,
    }
    #[derive(Clone, Debug)]
    struct TestOutputComponentInputs<
        const MAX_NUM_COLUMNS: usize,
        const MAX_NUM_RESULTS: usize,
        const ACTUAL_NUM_RESULTS: usize,
    > {
        column_values: [U256; MAX_NUM_COLUMNS],
        column_hash: [HashOut<F>; MAX_NUM_COLUMNS],
        item_values: [U256; ACTUAL_NUM_RESULTS],
        item_hash: [HashOut<F>; ACTUAL_NUM_RESULTS],
        predicate_value: bool,
        predicate_hash: HashOut<F>,
        component: Circuit<MAX_NUM_RESULTS>,
        expected_outputs: [U256; ACTUAL_NUM_RESULTS],
        expected_ops_ids: [F; ACTUAL_NUM_RESULTS],
        expected_output_hash: HashOut<F>,
    }

    impl<
            const MAX_NUM_COLUMNS: usize,
            const MAX_NUM_RESULTS: usize,
            const ACTUAL_NUM_RESULTS: usize,
        > UserCircuit<F, D>
        for TestOutputComponentInputs<MAX_NUM_COLUMNS, MAX_NUM_RESULTS, ACTUAL_NUM_RESULTS>
    {
        type Wires = TestOutputComponentWires<MAX_NUM_COLUMNS, MAX_NUM_RESULTS, ACTUAL_NUM_RESULTS>;

        fn build(c: &mut CircuitBuilder<F, D>) -> Self::Wires {
            let column_values = c.add_virtual_u256_arr::<MAX_NUM_COLUMNS>();
            let column_hash = c.add_virtual_hashes(MAX_NUM_COLUMNS);
            let item_values = c.add_virtual_u256_arr::<MAX_NUM_RESULTS>();
            let item_hash = c.add_virtual_hashes(MAX_NUM_RESULTS);
            let predicate_value = c.add_virtual_bool_target_safe();
            let predicate_hash = c.add_virtual_hash();
            let wires = Circuit::<MAX_NUM_RESULTS>::build(
                c,
                &column_values,
                &column_hash,
                item_values.clone(),
                item_hash.clone().try_into().unwrap(),
                &predicate_value,
                &predicate_hash,
            );

            let expected_output_values = c.add_virtual_u256_arr::<ACTUAL_NUM_RESULTS>();
            let expected_ops_ids = c.add_virtual_target_arr::<ACTUAL_NUM_RESULTS>();
            let expected_output_hash = c.add_virtual_hash();

            expected_output_values
                .iter()
                .zip(wires.output_values.iter())
                .for_each(|(expected, actual)| c.enforce_equal_u256(expected, actual));

            expected_ops_ids
                .iter()
                .zip(wires.ops_ids().iter())
                .for_each(|(expected, actual)| c.connect(*expected, *actual));
            c.connect_hashes(expected_output_hash, wires.output_hash);

            Self::Wires {
                column_values,
                column_hash: column_hash.try_into().unwrap(),
                item_values,
                item_hash: item_hash.try_into().unwrap(),
                predicate_value,
                predicate_hash,
                component: wires.input_wires,
                expected_output_values,
                expected_ops_ids,
                expected_output_hash,
            }
        }

        fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
            self.column_values
                .iter()
                .zip(wires.column_values.iter())
                .for_each(|(value, target)| pw.set_u256_target(target, *value));
            self.column_hash
                .iter()
                .zip(wires.column_hash.iter())
                .for_each(|(value, target)| pw.set_hash_target(*target, *value));
            self.item_values
                .iter()
                .chain(repeat(&U256::ZERO))
                .take(MAX_NUM_RESULTS)
                .zip(wires.item_values.iter())
                .for_each(|(value, target)| pw.set_u256_target(target, *value));
            self.item_hash
                .iter()
                .chain(repeat(empty_poseidon_hash()))
                .take(MAX_NUM_RESULTS)
                .zip(wires.item_hash.iter())
                .for_each(|(value, target)| pw.set_hash_target(*target, *value));
            self.expected_outputs
                .iter()
                .zip(wires.expected_output_values.iter())
                .for_each(|(value, target)| pw.set_u256_target(target, *value));
            self.expected_ops_ids
                .iter()
                .zip(wires.expected_ops_ids.iter())
                .for_each(|(value, target)| pw.set_target(*target, *value));
            pw.set_bool_target(wires.predicate_value, self.predicate_value);
            pw.set_hash_target(wires.predicate_hash, self.predicate_hash);
            pw.set_hash_target(wires.expected_output_hash, self.expected_output_hash);
            self.component.assign(pw, &wires.component)
        }
    }

    impl<
            const MAX_NUM_COLUMNS: usize,
            const MAX_NUM_RESULTS: usize,
            const ACTUAL_NUM_RESULTS: usize,
        > TestOutputComponentInputs<MAX_NUM_COLUMNS, MAX_NUM_RESULTS, ACTUAL_NUM_RESULTS>
    {
        fn new(
            column_values: [U256; MAX_NUM_COLUMNS],
            column_hash: [HashOut<F>; MAX_NUM_COLUMNS],
            item_values: [U256; ACTUAL_NUM_RESULTS],
            item_hash: [HashOut<F>; ACTUAL_NUM_RESULTS],
            predicate_value: bool,
            predicate_hash: HashOut<F>,
            selectors: [usize; ACTUAL_NUM_RESULTS],
            agg_ops: [F; ACTUAL_NUM_RESULTS],
        ) -> Self {
            let possible_input_values = column_values.into_iter().chain(item_values).collect_vec();
            let output_values = (0..ACTUAL_NUM_RESULTS)
                .map(|i| {
                    if predicate_value {
                        possible_input_values[selectors[i]]
                    } else if agg_ops[i] == AggregationOperation::MinOp.to_field() {
                        U256::MAX
                    } else {
                        U256::ZERO
                    }
                })
                .collect_vec();
            let output_items = selectors
                .iter()
                .map(|&s| {
                    if s < MAX_NUM_COLUMNS {
                        OutputItem::Column(s)
                    } else {
                        OutputItem::ComputedValue(s - MAX_NUM_COLUMNS)
                    }
                })
                .collect_vec();
            let output_hash = Circuit::<MAX_NUM_RESULTS>::output_variant()
                .output_hash(
                    &predicate_hash,
                    &mut ComputationalHashCache::<MAX_NUM_COLUMNS>::new_from_column_hash(
                        &column_hash,
                    )
                    .unwrap(),
                    &[], // unused since we already place all column hash in the cache
                    &item_hash,
                    &output_items,
                    &agg_ops,
                )
                .unwrap();
            Self {
                column_values,
                column_hash,
                item_values,
                item_hash,
                predicate_value,
                predicate_hash,
                component: Circuit::<MAX_NUM_RESULTS>::new(
                    &selectors.into_iter().map(|s| s.to_field()).collect_vec(),
                    &agg_ops,
                    ACTUAL_NUM_RESULTS,
                )
                .unwrap(),
                expected_outputs: output_values.try_into().unwrap(),
                expected_ops_ids: agg_ops,
                expected_output_hash: output_hash,
            }
        }
    }

    fn test_output_component<const MAX_NUM_RESULTS: usize, const ACTUAL_NUM_RESULTS: usize>(
        predicate_value: bool,
        agg_ops: [AggregationOperation; ACTUAL_NUM_RESULTS],
    ) {
        const MAX_NUM_COLUMNS: usize = 20;
        let rng = &mut thread_rng();
        let column_values = array::from_fn(|_| gen_random_u256(rng));
        let column_hash = array::from_fn(|_| gen_random_field_hash());
        let item_values = array::from_fn(|_| gen_random_u256(rng));
        let item_hash = array::from_fn(|_| gen_random_field_hash());
        let predicate_hash = gen_random_field_hash();
        let selectors = array::from_fn(|_| rng.gen_range(0..MAX_NUM_COLUMNS + ACTUAL_NUM_RESULTS));
        let agg_ops = array::from_fn(|i| agg_ops[i].to_field());
        let circuit =
            TestOutputComponentInputs::<MAX_NUM_COLUMNS, MAX_NUM_RESULTS, ACTUAL_NUM_RESULTS>::new(
                column_values,
                column_hash,
                item_values,
                item_hash,
                predicate_value,
                predicate_hash,
                selectors,
                agg_ops,
            );

        run_circuit::<F, D, C, _>(circuit);
    }

    fn test_agg_ops() -> Vec<AggregationOperation> {
        vec![
            AggregationOperation::SumOp,
            AggregationOperation::MaxOp,
            AggregationOperation::MinOp,
            AggregationOperation::CountOp,
            AggregationOperation::AvgOp,
        ]
    }

    #[test]
    fn test_output_component_matching_record() {
        const MAX_NUM_RESULTS: usize = 10;
        const ACTUAL_NUM_RESULTS: usize = 5;
        let agg_ops = test_agg_ops();
        test_output_component::<MAX_NUM_RESULTS, ACTUAL_NUM_RESULTS>(
            true,
            agg_ops.try_into().unwrap(),
        );
    }

    #[test]
    fn test_output_component_non_matching_record() {
        const MAX_NUM_RESULTS: usize = 10;
        const ACTUAL_NUM_RESULTS: usize = 5;
        let agg_ops = test_agg_ops();
        test_output_component::<MAX_NUM_RESULTS, ACTUAL_NUM_RESULTS>(
            false,
            agg_ops.try_into().unwrap(),
        );
    }

    #[test]
    fn test_output_component_max_num_result() {
        const MAX_NUM_RESULTS: usize = 10;
        const ACTUAL_NUM_RESULTS: usize = 10;
        let agg_ops = test_agg_ops();
        test_output_component::<MAX_NUM_RESULTS, ACTUAL_NUM_RESULTS>(
            false,
            array::from_fn(|i| agg_ops.get(i).copied().unwrap_or_default()),
        );
    }
}