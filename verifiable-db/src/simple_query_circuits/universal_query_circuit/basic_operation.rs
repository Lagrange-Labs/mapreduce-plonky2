use ethers::types::U256;
use mp2_common::{
    u256::{UInt256Target, WitnessWriteU256},
    D, F,
};
use plonky2::{
    hash::hash_types::HashOutTarget,
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::circuit_builder::CircuitBuilder,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
/// Input wires for basic operation component
pub struct BasicOperationInputWires {
    /// value to be employed for constant operand, if any, in the basic operation
    value_operand: UInt256Target,
    /// value to be employed in case the current operation involves a placeholder
    pub(crate) placeholder_value: UInt256Target,
    /// identifier of the placeholder employed in the current operation
    pub(crate) placeholder_id: Target,
    /// selector value employed to choose the inputs for the first operand
    /// among the list of possible input values and hashes
    first_input_selector: Target,
    /// selector value employed to choose the inputs for the second operand
    /// among the list of possible input values and hashes
    second_input_selector: Target,
    /// selector value employed to specify which operation is actually computed
    /// by this instance of the component, among all the supported operations
    op_selector: Target,
}

/// Input + output wires for basic operation component
pub struct BasicOperationWires {
    pub(crate) input_wires: BasicOperationInputWires,
    pub(crate) output_value: UInt256Target,
    pub(crate) output_hash: HashOutTarget,
    pub(crate) num_overflows: Target,
}
/// Witness input values for basic operation component
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BasicOperationInputs {
    value_operand: U256,
    placeholder_value: U256,
    placeholder_id: F,
    first_input_selector: F,
    second_input_selector: F,
    op_selector: F,
}

impl BasicOperationInputs {
    pub(crate) fn build(
        b: &mut CircuitBuilder<F, D>,
        input_values: &[UInt256Target],
        input_hash: &[HashOutTarget],
        num_overflows: Target,
    ) -> BasicOperationWires {
        todo!()
    }

    pub(crate) fn assign(&self, pw: &mut PartialWitness<F>, wires: &BasicOperationInputWires) {
        pw.set_u256_target(&wires.value_operand, self.value_operand);
        pw.set_u256_target(&wires.placeholder_value, self.placeholder_value);
        pw.set_target(wires.placeholder_id, self.placeholder_id);
        pw.set_target(wires.first_input_selector, self.first_input_selector);
        pw.set_target(wires.second_input_selector, self.second_input_selector);
        pw.set_target(wires.op_selector, self.op_selector);
    }
}
