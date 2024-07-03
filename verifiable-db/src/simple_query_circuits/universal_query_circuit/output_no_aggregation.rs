use mp2_common::{
    serialization::{
        deserialize_array, deserialize_long_array, serialize_array, serialize_long_array,
    },
    u256::UInt256Target,
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
use plonky2_ecgfp5::gadgets::curve::CurveTarget;
use serde::{Deserialize, Serialize};

use super::universal_query_circuit::{OutputComponent, OutputComponentWires};
#[derive(Clone, Debug, Serialize, Deserialize)]
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

/// Input + output wires for output component for queries without results aggregation
pub struct Wires<const MAX_NUM_RESULTS: usize> {
    input_wires: InputWires<MAX_NUM_RESULTS>,
    first_output_value: CurveTarget,
    output_values: Vec<UInt256Target>,
    output_hash: HashOutTarget,
    ops_ids: [Target; MAX_NUM_RESULTS],
}
/// Witness input values for output component for queries without results aggregation
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
    ids: [F; MAX_NUM_RESULTS],
    #[serde(
        serialize_with = "serialize_long_array",
        deserialize_with = "deserialize_long_array"
    )]
    is_output_valid: [bool; MAX_NUM_RESULTS],
}

impl<const MAX_NUM_RESULTS: usize> OutputComponentWires for Wires<MAX_NUM_RESULTS> {
    type FirstT = CurveTarget;

    type InputWires = InputWires<MAX_NUM_RESULTS>;

    fn get_ops_ids(&self) -> &[Target] {
        self.ops_ids.as_slice()
    }

    fn get_first_output_value(&self) -> Self::FirstT {
        self.first_output_value
    }

    fn get_other_output_values(&self) -> &[UInt256Target] {
        &self.output_values.as_slice()
    }

    fn get_computational_hash(&self) -> HashOutTarget {
        self.output_hash
    }

    fn get_input_wires(&self) -> Self::InputWires {
        todo!()
    }
}

impl<const MAX_NUM_RESULTS: usize> OutputComponent for Circuit<MAX_NUM_RESULTS> {
    type Wires = Wires<MAX_NUM_RESULTS>;

    fn build(
        b: &CircuitBuilder<F, D>,
        column_values: &[UInt256Target],
        column_hash: &[HashOutTarget],
        item_values: &[UInt256Target],
        item_hash: &[HashOutTarget],
        predicate_value: &BoolTarget,
        predicate_hash: &HashOutTarget,
    ) -> Self::Wires {
        todo!()
    }

    fn assign(&self, pw: &mut PartialWitness<F>, wires: &InputWires<MAX_NUM_RESULTS>) {
        pw.set_target_arr(wires.selector.as_slice(), self.selector.as_slice());
        pw.set_target_arr(wires.ids.as_slice(), self.ids.as_slice());
        self.is_output_valid
            .iter()
            .zip(wires.is_output_valid.iter())
            .for_each(|(v, t)| pw.set_bool_target(*t, *v));
    }
}
