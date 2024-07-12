use std::{array, iter::once};

use ethers::types::U256;
use itertools::Itertools;
use mp2_common::{
    serialization::{
        deserialize_array, deserialize_long_array, serialize_array, serialize_long_array,
    }, u256::{CircuitBuilderU256, UInt256Target}, D, F
};
use plonky2::{
    hash::hash_types::HashOutTarget,
    iop::{
        target::{BoolTarget, Target},
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::circuit_builder::CircuitBuilder,
    field::types::Field,
};
use serde::{Deserialize, Serialize};

use crate::simple_query_circuits::ComputationalHashIdentifiers;

use super::universal_query_circuit::{OutputComponent, OutputComponentWires};

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

    fn get_ops_ids(&self) -> &[Target] {
        self.input_wires.agg_ops.as_slice()
    }

    fn get_first_output_value(&self) -> Self::FirstT {
        self.output_values[0].clone()
    }

    fn get_other_output_values(&self) -> &[UInt256Target] {
        &self.output_values[1..]
    }

    fn get_computational_hash(&self) -> HashOutTarget {
        self.output_hash
    }

    fn get_input_wires(&self) -> Self::InputWires {
        self.input_wires.clone()
    }
}

impl<const MAX_NUM_RESULTS: usize> OutputComponent for Circuit<MAX_NUM_RESULTS> {
    type Wires = Wires<MAX_NUM_RESULTS>;

    fn build(
        b: &mut CircuitBuilder<F, D>,
        column_values: &[UInt256Target],
        column_hash: &[HashOutTarget],
        item_values: &[UInt256Target],
        item_hash: &[HashOutTarget],
        predicate_value: &BoolTarget,
        predicate_hash: &HashOutTarget,
    ) -> Self::Wires {
        let selector = b.add_virtual_target_arr::<MAX_NUM_RESULTS>();
        let agg_ops = b.add_virtual_target_arr::<MAX_NUM_RESULTS>();
        let is_output_valid = array::from_fn(|_| 
            b.add_virtual_bool_target_safe()
        );
        let u256_max = b.constant_u256(U256::MAX);
        let zero = b.zero_u256();
        let min_op_identifier = b.constant(
            F::from_canonical_usize(
                ComputationalHashIdentifiers::MinAggOp as usize,
            )
        );

        let mut output_values = vec![];

        for i in 0..MAX_NUM_RESULTS {
            // choose the value to be returned for the current item among all the possible 
		    // extracted columns and the i-th item computed by selected item components
            let possible_output_values = column_values.iter()
                .chain(once(&item_values[i]))
                .cloned()
                .collect_vec();
            let output_value = b.random_access_u256(selector[i], &possible_output_values);
            
            // If `predicate_value` is true, then expose the value to be aggregated;
            // Otherwise use the identity for the aggregation operation.
            // The identity is 0 except for "MIN", where the identity is the biggest
            // possible value in the domain, i.e. 2^256-1.
            let is_agg_ops_min = b.is_equal(agg_ops[i], min_op_identifier);
            let identity_value = b.select_u256(
                is_agg_ops_min, 
                &u256_max,
                &zero,
            );
            let actual_output_value = b.select_u256(
                *predicate_value, 
                &output_value, 
                &identity_value,
            );
            output_values.push(actual_output_value);
        }

        let output_hash = ComputationalHashIdentifiers::output_with_aggregation_hash_circuit(
            b, 
            predicate_hash, 
            column_hash, 
            item_hash.try_into().unwrap(), 
            &selector, 
            &agg_ops, 
            &is_output_valid
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
        wires.is_output_valid.iter()
            .enumerate()
            .for_each(|(i, t)| pw.set_bool_target(
                *t, 
                i < self.num_valid_outputs
            ));
    }
}
