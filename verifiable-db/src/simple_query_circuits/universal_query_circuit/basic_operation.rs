use ethers::types::U256;
use itertools::Itertools;
use mp2_common::{
    array::{Targetable, ToField},
    u256::{CircuitBuilderU256, UInt256Target, WitnessWriteU256},
    D, F,
};
use plonky2::{
    field::types::Field,
    hash::hash_types::HashOutTarget,
    iop::{
        target::{BoolTarget, Target},
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::circuit_builder::CircuitBuilder,
    util::log2_ceil,
};
use serde::{Deserialize, Serialize};

use anyhow::{Error, Result};

use crate::simple_query_circuits::computational_hash_ids::{Identifiers, Operation};

#[derive(Clone, Debug, Serialize, Deserialize)]
/// Input wires for basic operation component
pub struct BasicOperationInputWires {
    /// value to be employed for constant operand, if any, in the basic operation
    constant_operand: UInt256Target,
    /// value to be employed in case the current operation involves placeholders
    pub(crate) placeholder_values: [UInt256Target; 2],
    /// identifier of the placeholder employed in the current operation
    pub(crate) placeholder_ids: [Target; 2],
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
    constant_operand: U256,
    placeholder_values: [U256; 2],
    placeholder_ids: [F; 2],
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
        let zero = b.zero();
        let additional_operands = b.add_virtual_u256_arr::<3>();
        let constant_operand = &additional_operands[0];
        let placeholder_values = &additional_operands[1..];
        let possible_input_values = input_values
            .into_iter()
            .chain(additional_operands.iter())
            .cloned()
            .collect_vec();
        let first_input_selector = b.add_virtual_target();
        let second_input_selector = b.add_virtual_target();
        let placeholder_ids = b.add_virtual_target_arr::<2>();
        let op_selector = b.add_virtual_target();
        //TODO: these 2 random accesses could be done with a single operation, if we add an ad-hoc gate
        let first_input =
            b.random_access_u256(first_input_selector, possible_input_values.as_slice());
        let second_input =
            b.random_access_u256(second_input_selector, possible_input_values.as_slice());

        // compute results for all the operations

        // arithmetic operations
        let (add_res, add_overflow) = b.add_u256(&first_input, &second_input);
        let (sub_res, sub_overflow) = b.sub_u256(&first_input, &second_input);
        let is_div_or_mod = {
            // determine if the actual operation to be performed is division or modulo.
            let div_selector = b.constant(Operation::DivOp.to_field());
            let mod_selector = b.constant(Operation::ModOp.to_field());
            // Given the `op_selector` for the actual operation, we compute
            // `prod = (op_selector-div_selector)*(op_selector-mod_selector)`.
            // Then, the operation is division or modulo iff `prod == 0``
            let div_diff = b.sub(op_selector, div_selector);
            let mod_diff = b.sub(op_selector, mod_selector);
            let prod = b.mul(div_diff, mod_diff);
            b.is_equal(prod, zero)
        };
        let (mul_res, div_res, mod_res, mul_overflow, div_by_zero) =
            first_input.mul_div_u256(&second_input, b, is_div_or_mod);

        // comparison operations
        let lt_res = b.add_virtual_bool_target_unsafe();
        b.connect(lt_res.target, sub_overflow.0); // first_input < second_input iff first_input - second_input underflows
        let eq_res = b.is_zero(&sub_res); // first_input == second_input iff first_input - second_input == 0
        let lteq_res = b.or(lt_res, eq_res);
        let gt_res = b.not(lteq_res);
        let gteq_res = b.not(lt_res);
        let ne_res = b.not(eq_res);

        // Boolean operations: assume input values are either 0 or 1, so we can only
        // compute over the least significant limb
        let first_input_bool = first_input.to_bool_target();
        let second_input_bool = second_input.to_bool_target();
        let and_res = b.and(first_input_bool, second_input_bool);
        let or_res = b.or(first_input_bool, second_input_bool);
        let not_res = b.not(first_input_bool);
        let xor_res = b.sub(or_res.target, and_res.target);
        let xor_res_bool = BoolTarget::new_unsafe(xor_res);

        // The number of operations computed by this "gadget" in total. This is required to select
        // the output from all the outputs computed by each operation.
        const NUM_SUPPORTED_OPS: usize = std::mem::variant_count::<Operation>();
        let mut possible_output_values = vec![b.zero_u256(); NUM_SUPPORTED_OPS];
        // length of `possible_overflows_occurred` must be a power of 2 to safely use random access gadget
        let mut possible_overflows_occurred = vec![b.zero(); 1 << log2_ceil(NUM_SUPPORTED_OPS)];
        // fill `possible_output_values` and `possible_overflows_occurred` with the results of all the
        // supported operation, placing such results in the position of the vector corresponding to
        // the given operation
        let add_position = Operation::AddOp.index();
        possible_output_values[add_position] = add_res;
        possible_overflows_occurred[add_position] = add_overflow.to_target();
        let sub_position = Operation::SubOp.index();
        possible_output_values[sub_position] = sub_res;
        possible_overflows_occurred[sub_position] = sub_overflow.to_target();
        let mul_position = Operation::MulOp.index();
        possible_output_values[mul_position] = mul_res;
        possible_overflows_occurred[mul_position] = mul_overflow.target;
        let div_position = Operation::DivOp.index();
        possible_output_values[div_position] = div_res;
        possible_overflows_occurred[div_position] = div_by_zero.target;
        let mod_position = Operation::ModOp.index();
        possible_output_values[mod_position] = mod_res;
        possible_overflows_occurred[mod_position] = div_by_zero.target;
        // all other operations have no possible overflow error
        possible_output_values[Operation::LessThanOp.index()] =
            UInt256Target::new_from_bool_target(b, lt_res);
        possible_output_values[Operation::LessThanOrEqOp.index()] =
            UInt256Target::new_from_bool_target(b, lteq_res);
        possible_output_values[Operation::GreaterThanOp.index()] =
            UInt256Target::new_from_bool_target(b, gt_res);
        possible_output_values[Operation::GreaterThanOrEqOp.index()] =
            UInt256Target::new_from_bool_target(b, gteq_res);
        possible_output_values[Operation::EqOp.index()] =
            UInt256Target::new_from_bool_target(b, eq_res);
        possible_output_values[Operation::NeOp.index()] =
            UInt256Target::new_from_bool_target(b, ne_res);
        possible_output_values[Operation::AndOp.index()] =
            UInt256Target::new_from_bool_target(b, and_res);
        possible_output_values[Operation::OrOp.index()] =
            UInt256Target::new_from_bool_target(b, or_res);
        possible_output_values[Operation::NotOp.index()] =
            UInt256Target::new_from_bool_target(b, not_res);
        possible_output_values[Operation::XorOp.index()] =
            UInt256Target::new_from_bool_target(b, xor_res_bool);

        // choose the proper output values and overflows error occurred depending on the
        // operation to be performed in the current instance of basic operation component
        let output_value = b.random_access_u256(op_selector, &possible_output_values);

        assert!(
            possible_overflows_occurred.len() <= 64,
            "random access gadget works only for arrays with at most 64 elements"
        );
        let overflows_occurred = b.random_access(op_selector, possible_overflows_occurred);

        // compute computational hash associated to the operation being computed
        let output_hash = Operation::basic_operation_hash_circuit(
            b,
            input_hash,
            constant_operand,
            placeholder_ids,
            first_input_selector,
            second_input_selector,
            op_selector,
        );

        let input_wires = BasicOperationInputWires {
            constant_operand: constant_operand.clone(),
            placeholder_values: placeholder_values.to_vec().try_into().unwrap(),
            placeholder_ids,
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
        pw.set_u256_target(&wires.constant_operand, self.constant_operand);
        pw.set_u256_target(&wires.placeholder_values[0], self.placeholder_values[0]);
        pw.set_u256_target(&wires.placeholder_values[1], self.placeholder_values[1]);
        pw.set_target_arr(&wires.placeholder_ids, &self.placeholder_ids);
        pw.set_target(wires.first_input_selector, self.first_input_selector);
        pw.set_target(wires.second_input_selector, self.second_input_selector);
        pw.set_target(wires.op_selector, self.op_selector);
    }
}

#[cfg(test)]
mod tests {
    use std::array;

    use ethers::types::U256;
    use mp2_common::{
        array::ToField,
        default_config,
        u256::{CircuitBuilderU256, UInt256Target, WitnessWriteU256},
        C, D, F,
    };
    use mp2_test::{
        circuit::{run_circuit, UserCircuit},
        utils::{gen_random_field_hash, gen_random_u256},
    };
    use plonky2::{
        field::types::{Field, PrimeField64},
        hash::hash_types::{HashOut, HashOutTarget},
        iop::{
            target::Target,
            witness::{PartialWitness, WitnessWrite},
        },
        plonk::circuit_builder::CircuitBuilder,
    };
    use rand::{thread_rng, Rng};

    use crate::simple_query_circuits::computational_hash_ids::{Identifiers, Operation};

    use super::{BasicOperationInputWires, BasicOperationInputs};

    #[derive(Clone, Debug)]
    struct TestBasicOperationComponent<const NUM_INPUTS: usize> {
        input_values: [U256; NUM_INPUTS],
        input_hash: [HashOut<F>; NUM_INPUTS],
        component: BasicOperationInputs,
        expected_result: U256,
        expected_hash: HashOut<F>,
        num_errors: usize,
    }

    struct TestBasicOperationWires<const NUM_INPUTS: usize> {
        input_values: [UInt256Target; NUM_INPUTS],
        input_hash: [HashOutTarget; NUM_INPUTS],
        component_wires: BasicOperationInputWires,
        expected_result: UInt256Target,
        expected_hash: HashOutTarget,
        num_errors: Target,
    }

    impl<const NUM_INPUTS: usize> UserCircuit<F, D> for TestBasicOperationComponent<NUM_INPUTS> {
        type Wires = TestBasicOperationWires<NUM_INPUTS>;

        fn build(c: &mut CircuitBuilder<F, D>) -> Self::Wires {
            let input_values = c.add_virtual_u256_arr::<NUM_INPUTS>();
            let input_hash = c.add_virtual_hashes(NUM_INPUTS);
            let num_overflows = c.zero();
            let wires = BasicOperationInputs::build(
                c,
                input_values.as_slice(),
                input_hash.as_slice(),
                num_overflows,
            );
            let expected_result = c.add_virtual_u256();
            let expected_hash = c.add_virtual_hash();
            let num_errors = c.add_virtual_target();

            c.enforce_equal_u256(&expected_result, &wires.output_value);
            c.connect_hashes(expected_hash, wires.output_hash);
            c.connect(wires.num_overflows, num_errors);

            Self::Wires {
                input_values,
                input_hash: input_hash.try_into().unwrap(),
                component_wires: wires.input_wires,
                expected_result,
                expected_hash,
                num_errors,
            }
        }

        fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
            self.input_values
                .iter()
                .zip(wires.input_values.iter())
                .for_each(|(val, target)| pw.set_u256_target(target, *val));

            self.input_hash
                .iter()
                .zip(wires.input_hash.iter())
                .for_each(|(val, target)| pw.set_hash_target(*target, *val));

            pw.set_target(wires.num_errors, F::from_canonical_usize(self.num_errors));
            self.component.assign(pw, &wires.component_wires);
            pw.set_u256_target(&wires.expected_result, self.expected_result);
            pw.set_hash_target(wires.expected_hash, self.expected_hash);
        }
    }

    // Function to test the basic operation identifier by `op_identifier`. The 2 closures `gen_u256_input`
    // and `compute_result` are employed to compute input values for the operation and to compute the
    // result from the selected input values, respectively.
    fn test_basic_operation<
        const NUM_INPUTS: usize,
        R: Rng,
        GenInputFn: Fn(&mut R) -> U256,
        RFn: Fn(U256, U256) -> (U256, bool),
    >(
        gen_u256_input: GenInputFn,
        rng: &mut R,
        op_identifier: Operation,
        compute_result: RFn,
    ) {
        let input_values = array::from_fn(|_| gen_u256_input(rng));
        let constant_operand = gen_u256_input(rng);
        let placeholder_values = array::from_fn(|_| gen_u256_input(rng));
        let input_hash = array::from_fn(|_| gen_random_field_hash());
        let placeholder_ids = array::from_fn(|_| F::from_canonical_u8(rng.gen()));
        let first_input_selector = F::from_canonical_usize(rng.gen_range(0..NUM_INPUTS + 2));
        let second_input_selector = F::from_canonical_usize(rng.gen_range(0..NUM_INPUTS + 2));
        let op_selector = op_identifier.to_field();

        let component = BasicOperationInputs {
            constant_operand,
            placeholder_values,
            placeholder_ids,
            first_input_selector,
            second_input_selector,
            op_selector,
        };

        // compute expected outputs
        let first_input = match first_input_selector.to_canonical_u64() as usize {
            a if a < NUM_INPUTS => input_values[a],
            a if a == NUM_INPUTS => constant_operand,
            a if a == NUM_INPUTS + 1 => placeholder_values[0],
            a if a == NUM_INPUTS + 2 => placeholder_values[1],
            a => panic!(
                "sampled second input selector too big: max {}, sampled {}",
                NUM_INPUTS + 2,
                a
            ),
        };

        let second_input = match second_input_selector.to_canonical_u64() as usize {
            a if a < NUM_INPUTS => input_values[a],
            a if a == NUM_INPUTS => constant_operand,
            a if a == NUM_INPUTS + 1 => placeholder_values[0],
            a if a == NUM_INPUTS + 2 => placeholder_values[1],
            a => panic!(
                "sampled second input selector too big: max {}, sampled {}",
                NUM_INPUTS + 2,
                a
            ),
        };

        let (expected_result, arithmetic_error) = compute_result(first_input, second_input);
        let expected_hash = Operation::basic_operation_hash(
            &input_hash,
            constant_operand,
            placeholder_ids,
            first_input_selector,
            second_input_selector,
            op_selector,
        );

        let test_circuit = TestBasicOperationComponent::<NUM_INPUTS> {
            input_values,
            input_hash,
            component,
            expected_result,
            expected_hash,
            num_errors: arithmetic_error as usize,
        };
        run_circuit::<F, D, C, _>(test_circuit);
    }

    const TEST_NUM_INPUTS: usize = 20;

    #[test]
    fn test_add() {
        test_basic_operation::<TEST_NUM_INPUTS, _, _, _>(
            gen_random_u256,
            &mut thread_rng(),
            Operation::AddOp,
            |a, b| a.overflowing_add(b),
        )
    }

    #[test]
    fn test_sub() {
        test_basic_operation::<TEST_NUM_INPUTS, _, _, _>(
            gen_random_u256,
            &mut thread_rng(),
            Operation::SubOp,
            |a, b| a.overflowing_sub(b),
        )
    }

    #[test]
    fn test_mul() {
        test_basic_operation::<TEST_NUM_INPUTS, _, _, _>(
            gen_random_u256,
            &mut thread_rng(),
            Operation::MulOp,
            |a, b| a.overflowing_mul(b),
        )
    }

    #[test]
    fn test_div() {
        test_basic_operation::<TEST_NUM_INPUTS, _, _, _>(
            gen_random_u256,
            &mut thread_rng(),
            Operation::DivOp,
            |a, b| match a.checked_div(b) {
                Some(res) => (res, false),
                None => (U256::zero(), true),
            },
        )
    }

    #[test]
    fn test_mod() {
        test_basic_operation::<TEST_NUM_INPUTS, _, _, _>(
            gen_random_u256,
            &mut thread_rng(),
            Operation::ModOp,
            |a, b| {
                if b.is_zero() {
                    (a, true)
                } else {
                    (a.div_mod(b).1, false)
                }
            },
        )
    }

    #[test]
    fn test_mod_by_zero() {
        test_basic_operation::<TEST_NUM_INPUTS, _, _, _>(
            |_| U256::zero(),
            &mut thread_rng(),
            Operation::ModOp,
            |a, b| {
                if b.is_zero() {
                    (a, true)
                } else {
                    (a.div_mod(b).1, false)
                }
            },
        )
    }

    #[test]
    fn test_div_by_zero() {
        test_basic_operation::<TEST_NUM_INPUTS, _, _, _>(
            |_| U256::zero(),
            &mut thread_rng(),
            Operation::DivOp,
            |a, b| match a.checked_div(b) {
                Some(res) => (res, false),
                None => (U256::zero(), true),
            },
        )
    }

    #[test]
    fn test_mul_by_zero() {
        test_basic_operation::<TEST_NUM_INPUTS, _, _, _>(
            |_| U256::zero(),
            &mut thread_rng(),
            Operation::MulOp,
            |a, b| a.overflowing_mul(b),
        )
    }

    #[test]
    fn test_less_than() {
        test_basic_operation::<TEST_NUM_INPUTS, _, _, _>(
            gen_random_u256,
            &mut thread_rng(),
            Operation::LessThanOp,
            |a, b| (U256::from((a < b) as u128), false),
        )
    }

    #[test]
    fn test_less_or_equal_than() {
        test_basic_operation::<TEST_NUM_INPUTS, _, _, _>(
            gen_random_u256,
            &mut thread_rng(),
            Operation::LessThanOrEqOp,
            |a, b| (U256::from((a <= b) as u128), false),
        )
    }

    #[test]
    fn test_greater_or_equal_than() {
        test_basic_operation::<TEST_NUM_INPUTS, _, _, _>(
            gen_random_u256,
            &mut thread_rng(),
            Operation::GreaterThanOrEqOp,
            |a, b| (U256::from((a >= b) as u128), false),
        )
    }

    #[test]
    fn test_greater_than() {
        test_basic_operation::<TEST_NUM_INPUTS, _, _, _>(
            gen_random_u256,
            &mut thread_rng(),
            Operation::GreaterThanOp,
            |a, b| (U256::from((a > b) as u128), false),
        )
    }

    #[test]
    fn test_is_equal() {
        test_basic_operation::<TEST_NUM_INPUTS, _, _, _>(
            gen_random_u256,
            &mut thread_rng(),
            Operation::EqOp,
            |a, b| (U256::from((a == b) as u128), false),
        )
    }

    #[test]
    fn test_is_not_equal() {
        test_basic_operation::<TEST_NUM_INPUTS, _, _, _>(
            gen_random_u256,
            &mut thread_rng(),
            Operation::NeOp,
            |a, b| (U256::from((a != b) as u128), false),
        )
    }
    // Generate a `U256` representing a random bit
    fn gen_random_u256_bit<R: Rng>(rng: &mut R) -> U256 {
        let bit: bool = rng.gen();
        U256::from(bit as u128)
    }

    #[test]
    fn test_and() {
        test_basic_operation::<TEST_NUM_INPUTS, _, _, _>(
            gen_random_u256_bit,
            &mut thread_rng(),
            Operation::AndOp,
            |a, b| (a & b, false),
        )
    }

    #[test]
    fn test_or() {
        test_basic_operation::<TEST_NUM_INPUTS, _, _, _>(
            gen_random_u256_bit,
            &mut thread_rng(),
            Operation::OrOp,
            |a, b| (a | b, false),
        )
    }

    #[test]
    fn test_not() {
        test_basic_operation::<TEST_NUM_INPUTS, _, _, _>(
            gen_random_u256_bit,
            &mut thread_rng(),
            Operation::NotOp,
            |a, b| {
                (
                    !a & U256::one(), // b is unused since Not is a unary operation
                    false,
                )
            },
        )
    }

    #[test]
    fn test_xor() {
        test_basic_operation::<TEST_NUM_INPUTS, _, _, _>(
            gen_random_u256_bit,
            &mut thread_rng(),
            Operation::XorOp,
            |a, b| (a ^ b, false),
        )
    }

    #[test]
    fn basic_operation_component_cost() {
        let mut b = CircuitBuilder::<F, D>::new(default_config());
        const NUM_INPUTS: usize = 50;
        let input_values = b.add_virtual_u256_arr::<NUM_INPUTS>();
        let input_hash = b.add_virtual_hashes(NUM_INPUTS);
        let num_overflows = b.zero();
        let num_gates_pre_build = b.num_gates();
        BasicOperationInputs::build(
            &mut b,
            input_values.as_slice(),
            input_hash.as_slice(),
            num_overflows,
        );
        // Change expected cost if there were changes to `BasicOperationInputs::build` that affect the cost
        let expected_cost = 78;
        assert_eq!(b.num_gates() - num_gates_pre_build, expected_cost);
    }
}
