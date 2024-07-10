use std::iter::{once, repeat};

use ethers::types::U256;
use itertools::Itertools;
use mp2_common::{
    array::Targetable,
    poseidon::empty_poseidon_hash,
    u256::{CircuitBuilderU256, UInt256Target, WitnessWriteU256},
    utils::ToTargets,
    CHasher, D, F,
};
use plonky2::{
    field::types::Field,
    hash::{hash_types::HashOutTarget, hashing::hash_n_to_hash_no_pad},
    iop::{
        target::{self, Target},
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::circuit_builder::CircuitBuilder,
    util::log2_ceil,
};
use serde::{Deserialize, Serialize};

use crate::simple_query_circuits::ComputationalHashIdentifiers;

use anyhow::{Error, Result};

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
    // Return the constant integer identifiers associated to each operation supported
    // by the basic operation component
    pub(crate) fn op_identifiers() -> Vec<usize> {
        let mut op_identifiers = vec![
            ComputationalHashIdentifiers::AddOp as usize,
            ComputationalHashIdentifiers::SubOp as usize,
            ComputationalHashIdentifiers::MulOp as usize,
            ComputationalHashIdentifiers::DivOp as usize,
            ComputationalHashIdentifiers::ModOp as usize,
            ComputationalHashIdentifiers::LessThanOp as usize,
            ComputationalHashIdentifiers::GreaterThanOp as usize,
            ComputationalHashIdentifiers::EqOp as usize,
            ComputationalHashIdentifiers::NeOp as usize,
            ComputationalHashIdentifiers::LessThanOrEqOp as usize,
            ComputationalHashIdentifiers::GreaterThanOrEqOp as usize,
            ComputationalHashIdentifiers::AndOp as usize,
            ComputationalHashIdentifiers::OrOp as usize,
            ComputationalHashIdentifiers::NotOp as usize,
            ComputationalHashIdentifiers::XorOp as usize,
        ];
        op_identifiers.sort();
        // double-check that the identifiers are all consecutive, as this
        // is assumed by the circuit for efficiency
        assert_eq!(
            op_identifiers.last().unwrap() - op_identifiers.first().unwrap(),
            op_identifiers.len()-1,
            "ComputationalHashIdentifiers of basic operations are not consecutive; please, ensure these variants to be declared consecutively in ComputationalHashIdentifers enum",
        );
        op_identifiers
    }

    /// Compute the selector associated to the input operation `op` to be provided to
    /// the basic operation component; Return an error if `op` is not an identifier
    /// of a basic operation supported in the component
    pub fn compute_op_selector(op: ComputationalHashIdentifiers) -> Result<usize> {
        let op_identifiers = Self::op_identifiers();
        op_identifiers
            .into_iter()
            .enumerate()
            .find_map(|(i, id)| {
                if id == op.clone() as usize {
                    Some(i)
                } else {
                    None
                }
            })
            .ok_or(Error::msg(format!(
                "{:?} is not a valid identifier of a supported operation",
                op
            )))
    }

    // Compute the integer identifier of the operation being performed
    // from the `op_selector` input wire of the basic operation component
    pub(crate) fn op_hash_identifier(op_selector: Target, b: &mut CircuitBuilder<F, D>) -> Target {
        // assume that the integer identifiers of the operations supported
        // by the basic operation component are all consecutive integers
        let op_identifier_offset = b.constant(F::from_canonical_usize(Self::op_identifiers()[0]));
        b.add(op_selector, op_identifier_offset)
    }

    pub(crate) fn build(
        b: &mut CircuitBuilder<F, D>,
        input_values: &[UInt256Target],
        input_hash: &[HashOutTarget],
        num_overflows: Target,
    ) -> BasicOperationWires {
        let zero = b.zero();
        let additional_operands = b.add_virtual_u256_arr::<2>();
        let value_operand = &additional_operands[0];
        let placeholder_value = &additional_operands[1];
        let possible_input_values = input_values
            .into_iter()
            .chain([value_operand, placeholder_value].into_iter())
            .cloned()
            .collect_vec();
        let first_input_selector = b.add_virtual_target();
        let second_input_selector = b.add_virtual_target();
        let placeholder_id = b.add_virtual_target();
        let op_selector = b.add_virtual_target();
        //ToDO: these 2 random accesses could be done with a single operation, if we add an ad-hoc gate
        let first_input =
            b.random_access_u256(first_input_selector, possible_input_values.as_slice());
        let second_input =
            b.random_access_u256(second_input_selector, possible_input_values.as_slice());
        let value_hash = b.hash_n_to_hash_no_pad::<CHasher>(value_operand.to_targets());
        let placeholder_id_hash = b.hash_n_to_hash_no_pad::<CHasher>(vec![placeholder_id]);
        // Compute the vector of computational hashes associated to each entry in `possible_input_values`.
        // The vector is padded to the next power of 2 to safely use `random_access_hash` gadget
        let pad_len = log2_ceil(input_hash.len() + 2); // length of the padded vector of computational hashes
        let empty_poseidon_hash = b.constant_hash(*empty_poseidon_hash()); // employed for padding
        let possible_input_hash = input_hash
            .into_iter()
            .chain([&value_hash, &placeholder_id_hash].into_iter())
            .cloned()
            .chain(repeat(empty_poseidon_hash))
            .take(pad_len)
            .collect_vec();
        let first_input_hash =
            b.random_access_hash(first_input_selector, possible_input_hash.clone());
        let second_input_hash = b.random_access_hash(second_input_selector, possible_input_hash);

        // compute results for all the operations

        // arithmetic operations
        let (add_res, add_overflow) = b.add_u256(&first_input, &second_input);
        let (sub_res, sub_overflow) = b.sub_u256(&first_input, &second_input);
        let is_div_or_mod = {
            // determine if the actual operation to be performed is division or modulo.
            let div_selector = b.constant(F::from_canonical_usize(
                Self::compute_op_selector(ComputationalHashIdentifiers::DivOp).unwrap(),
            ));
            let mod_selector = b.constant(F::from_canonical_usize(
                Self::compute_op_selector(ComputationalHashIdentifiers::ModOp).unwrap(),
            ));
            // Given the `op_selector` for the actual operation, we compute
            // `prod = (op_selector-div_selector)*(op_selector-mod_selector)`.
            // Then, the operation is division or modulo iff `prod == 0``
            let div_diff = b.sub(op_selector, div_selector);
            let mod_diff = b.sub(op_selector, mod_selector);
            let prod = b.mul(div_diff, mod_diff);
            b.is_equal(prod, zero)
        };
        let (mul_res, div_res, mod_res, mul_overflow, div_overflow, div_by_zero) =
            first_input.mul_div_u256(&second_input, b, is_div_or_mod);
        // number of errors occurred during division/mod operation
        let div_error = b.add(div_overflow.target, div_by_zero.target);

        // comparison operations
        let lt_res = b.add_virtual_bool_target_unsafe();
        b.connect(lt_res.target, sub_overflow.0); // first_input < second_input iff first_input - second_input underflows
        let eq_res = b.is_zero(&sub_res); // first_input == second_input iff first_input - second_input == 0
        let lteq_res = b.or(lt_res, eq_res);
        let gt_res = b.not(lteq_res);
        let gteq_res = b.not(lt_res);
        let ne_res = b.not(eq_res);

        // Boolean operations: assume input values are either 0 or 1, so we can only
        // computed over the least significant limb
        let first_input_bool = b.add_virtual_bool_target_unsafe();
        b.connect(
            first_input_bool.target,
            first_input.to_targets().last().unwrap().to_target(),
        );
        let second_input_bool = b.add_virtual_bool_target_unsafe();
        b.connect(
            second_input_bool.target,
            second_input.to_targets().last().unwrap().to_target(),
        );
        let and_res = b.and(first_input_bool, second_input_bool);
        let or_res = b.or(first_input_bool, second_input_bool);
        let not_res = b.not(first_input_bool);
        let xor_res = b.sub(or_res.target, and_res.target);
        let xor_res_bool = b.add_virtual_bool_target_unsafe();
        b.connect(xor_res_bool.target, xor_res);

        const NUM_SUPPORTED_OPS: usize = 15;
        let mut possible_output_values = vec![b.zero_u256(); NUM_SUPPORTED_OPS];
        let mut possible_overflows_occurred = vec![b.zero(); log2_ceil(NUM_SUPPORTED_OPS)]; // pad `possible_overflows_occurred` to next power of 2 to safely use random access gadget
                                                                                            // fill `possible_output_values` and `possible_overflows_occurred` with the results of all the
                                                                                            // supported operation, placing such results in the position of the vector corresponding to
                                                                                            // the given operation
        let add_position = Self::compute_op_selector(ComputationalHashIdentifiers::AddOp).unwrap();
        possible_output_values[add_position] = add_res;
        possible_overflows_occurred[add_position] = add_overflow.to_target();
        let sub_position = Self::compute_op_selector(ComputationalHashIdentifiers::SubOp).unwrap();
        possible_output_values[sub_position] = sub_res;
        possible_overflows_occurred[sub_position] = sub_overflow.to_target();
        let mul_position = Self::compute_op_selector(ComputationalHashIdentifiers::MulOp).unwrap();
        possible_output_values[mul_position] = mul_res;
        possible_overflows_occurred[mul_position] = mul_overflow.target;
        let div_position = Self::compute_op_selector(ComputationalHashIdentifiers::DivOp).unwrap();
        possible_output_values[div_position] = div_res;
        possible_overflows_occurred[div_position] = div_error;
        let mod_position = Self::compute_op_selector(ComputationalHashIdentifiers::ModOp).unwrap();
        possible_output_values[mod_position] = mod_res;
        possible_overflows_occurred[mod_position] = div_error;
        // all other operations have no possible overflow error
        possible_output_values
            [Self::compute_op_selector(ComputationalHashIdentifiers::LessThanOp).unwrap()] =
            UInt256Target::new_from_bool_target(b, lt_res);
        possible_output_values
            [Self::compute_op_selector(ComputationalHashIdentifiers::LessThanOrEqOp).unwrap()] =
            UInt256Target::new_from_bool_target(b, lteq_res);
        possible_output_values
            [Self::compute_op_selector(ComputationalHashIdentifiers::GreaterThanOp).unwrap()] =
            UInt256Target::new_from_bool_target(b, gt_res);
        possible_output_values
            [Self::compute_op_selector(ComputationalHashIdentifiers::GreaterThanOrEqOp).unwrap()] =
            UInt256Target::new_from_bool_target(b, gteq_res);
        possible_output_values
            [Self::compute_op_selector(ComputationalHashIdentifiers::EqOp).unwrap()] =
            UInt256Target::new_from_bool_target(b, eq_res);
        possible_output_values
            [Self::compute_op_selector(ComputationalHashIdentifiers::NeOp).unwrap()] =
            UInt256Target::new_from_bool_target(b, ne_res);
        possible_output_values
            [Self::compute_op_selector(ComputationalHashIdentifiers::AndOp).unwrap()] =
            UInt256Target::new_from_bool_target(b, and_res);
        possible_output_values
            [Self::compute_op_selector(ComputationalHashIdentifiers::OrOp).unwrap()] =
            UInt256Target::new_from_bool_target(b, or_res);
        possible_output_values
            [Self::compute_op_selector(ComputationalHashIdentifiers::NotOp).unwrap()] =
            UInt256Target::new_from_bool_target(b, not_res);
        possible_output_values
            [Self::compute_op_selector(ComputationalHashIdentifiers::XorOp).unwrap()] =
            UInt256Target::new_from_bool_target(b, xor_res_bool);

        // choose the proper output values and overflows error occurred depending on the
        // operation to be performed in the current instance of basic operation component
        let output_value = b.random_access_u256(op_selector, &possible_output_values);

        let overflows_occurred = b.random_access(op_selector, possible_overflows_occurred);

        // compute identifier of computed operation to be employed in computational hash
        let op_hash_identifier = Self::op_hash_identifier(op_selector, b);
        // compute computational hash associated to the operation being computed
        let output_hash = b.hash_n_to_hash_no_pad::<CHasher>(
            once(op_hash_identifier)
                .chain(first_input_hash.to_targets().into_iter())
                .chain(second_input_hash.to_targets().into_iter())
                .collect(),
        );

        let input_wires = BasicOperationInputWires {
            value_operand: value_operand.clone(),
            placeholder_value: placeholder_value.clone(),
            placeholder_id,
            first_input_selector,
            second_input_selector,
            op_selector,
        };

        BasicOperationWires {
            input_wires,
            output_value,
            output_hash,
            num_overflows: b.add(num_overflows, overflows_occurred),
        }
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
