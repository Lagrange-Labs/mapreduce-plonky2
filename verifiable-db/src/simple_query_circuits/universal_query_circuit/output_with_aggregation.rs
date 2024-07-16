use mp2_common::{
    serialization::{
        deserialize_array, deserialize_long_array, serialize_array, serialize_long_array,
    },
    types::CBuilder,
    u256::UInt256Target,
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
    #[serde(
        serialize_with = "serialize_long_array",
        deserialize_with = "deserialize_long_array"
    )]
    is_output_valid: [bool; MAX_NUM_RESULTS],
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
        _b: &mut CBuilder,
        _column_values: &[UInt256Target],
        _column_hash: &[HashOutTarget],
        _item_values: &[UInt256Target],
        _item_hash: &[HashOutTarget],
        _predicate_value: &BoolTarget,
        _predicate_hash: &HashOutTarget,
    ) -> Self::Wires {
        todo!()
    }

    fn assign(&self, pw: &mut PartialWitness<F>, wires: &InputWires<MAX_NUM_RESULTS>) {
        pw.set_target_arr(wires.selector.as_slice(), self.selector.as_slice());
        pw.set_target_arr(wires.agg_ops.as_slice(), self.agg_ops.as_slice());
        self.is_output_valid
            .iter()
            .zip(wires.is_output_valid.iter())
            .for_each(|(v, t)| pw.set_bool_target(*t, *v));
    }
}
