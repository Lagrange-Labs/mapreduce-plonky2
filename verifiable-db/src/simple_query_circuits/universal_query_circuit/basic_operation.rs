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
        target::{self, BoolTarget, Target},
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::circuit_builder::CircuitBuilder,
    util::log2_ceil,
};
use serde::{Deserialize, Serialize};

use anyhow::{Error, Result};

use crate::simple_query_circuits::computational_hash_ids::ComputationalHashIdentifiers;

#[derive(Clone, Debug, Serialize, Deserialize)]
/// Input wires for basic operation component
pub struct BasicOperationInputWires {
    /// value to be employed for constant operand, if any, in the basic operation
    constant_operand: UInt256Target,
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
    constant_operand: U256,
    placeholder_value: U256,
    placeholder_id: F,
    first_input_selector: F,
    second_input_selector: F,
    op_selector: F,
}

impl BasicOperationInputs {
    // Check that the computational hash identifiers of supported basic operations
    // match the assumptions needed in the circuit. Return the highest identifier
    // of supported basic operations
    pub(crate) fn check_op_identifiers() -> usize {
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
        // double-check that the identifiers are all consecutive and start
        // from 0, as this is assumed by the circuit for efficiency
        assert_eq!(
            *op_identifiers.first().unwrap(),
            0,
            "ComputationHashIdentifiers of basic operations should be placed at the beginning of the ComputationHashIdentifiers enum"
        );
        let highest_identifier = *op_identifiers.last().unwrap();
        assert_eq!(
            highest_identifier,
            op_identifiers.len()-1,
            "ComputationalHashIdentifiers of basic operations are not consecutive; please, ensure these variants to be declared consecutively in ComputationalHashIdentifers enum",
        );
        highest_identifier
    }

    /// Compute the selector associated to the input operation `op` to be provided to
    /// the basic operation component; Return an error if `op` is not an identifier
    /// of a basic operation supported in the component
    pub fn compute_op_selector(op: ComputationalHashIdentifiers) -> Result<usize> {
        let highest_identifier = Self::check_op_identifiers();
        let op_identifier = op as usize;
        if op_identifier <= highest_identifier {
            Ok(op_identifier)
        } else {
            Err(Error::msg(format!(
                "{:?} is not a valid identifier of a supported operation",
                op
            )))?
        }
    }

    pub(crate) fn build(
        b: &mut CircuitBuilder<F, D>,
        input_values: &[UInt256Target],
        input_hash: &[HashOutTarget],
        num_overflows: Target,
    ) -> BasicOperationWires {
        let zero = b.zero();
        let additional_operands = b.add_virtual_u256_arr::<2>();
        let constant_operand = &additional_operands[0];
        let placeholder_value = &additional_operands[1];
        let possible_input_values = input_values
            .into_iter()
            .chain([constant_operand, placeholder_value].into_iter())
            .cloned()
            .collect_vec();
        let first_input_selector = b.add_virtual_target();
        let second_input_selector = b.add_virtual_target();
        let placeholder_id = b.add_virtual_target();
        let op_selector = b.add_virtual_target();
        //TODO: these 2 random accesses could be done with a single operation, if we add an ad-hoc gate
        let first_input =
            b.random_access_u256(first_input_selector, possible_input_values.as_slice());
        let second_input =
            b.random_access_u256(second_input_selector, possible_input_values.as_slice());
        let constant_operand_hash =
            b.hash_n_to_hash_no_pad::<CHasher>(constant_operand.to_targets());
        let placeholder_id_hash = b.hash_n_to_hash_no_pad::<CHasher>(vec![placeholder_id]);
        // Compute the vector of computational hashes associated to each entry in `possible_input_values`.
        // The vector is padded to the next power of 2 to safely use `random_access_hash` gadget
        let pad_len = 1 << log2_ceil(input_hash.len() + 2); // length of the padded vector of computational hashes
        let empty_poseidon_hash = b.constant_hash(*empty_poseidon_hash()); // employed for padding
        let possible_input_hash = input_hash
            .into_iter()
            .chain([&constant_operand_hash, &placeholder_id_hash].into_iter())
            .cloned()
            .chain(repeat(empty_poseidon_hash))
            .take(pad_len)
            .collect_vec();
        assert!(
            possible_input_hash.len() <= 64,
            "random access gadget works only for arrays with at most 64 elements"
        );
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
        const NUM_SUPPORTED_OPS: usize = 15;
        let mut possible_output_values = vec![b.zero_u256(); NUM_SUPPORTED_OPS];
        // length of `possible_overflows_occurred` must be a power of 2 to safely use random access gadget
        let mut possible_overflows_occurred = vec![b.zero(); 1 << log2_ceil(NUM_SUPPORTED_OPS)];
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
        possible_overflows_occurred[div_position] = div_by_zero.target;
        let mod_position = Self::compute_op_selector(ComputationalHashIdentifiers::ModOp).unwrap();
        possible_output_values[mod_position] = mod_res;
        possible_overflows_occurred[mod_position] = div_by_zero.target;
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

        assert!(
            possible_overflows_occurred.len() <= 64,
            "random access gadget works only for arrays with at most 64 elements"
        );
        let overflows_occurred = b.random_access(op_selector, possible_overflows_occurred);

        // compute identifier of computed operation to be employed in computational hash
        // compute computational hash associated to the operation being computed
        let output_hash = b.hash_n_to_hash_no_pad::<CHasher>(
            once(op_selector)
                .chain(first_input_hash.to_targets().into_iter())
                .chain(second_input_hash.to_targets().into_iter())
                .collect(),
        );

        let input_wires = BasicOperationInputWires {
            constant_operand: constant_operand.clone(),
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
        pw.set_u256_target(&wires.constant_operand, self.constant_operand);
        pw.set_u256_target(&wires.placeholder_value, self.placeholder_value);
        pw.set_target(wires.placeholder_id, self.placeholder_id);
        pw.set_target(wires.first_input_selector, self.first_input_selector);
        pw.set_target(wires.second_input_selector, self.second_input_selector);
        pw.set_target(wires.op_selector, self.op_selector);
    }
}

#[cfg(test)]
mod tests {
    use std::{array, iter::once};

    use ethers::types::U256;
    use itertools::Itertools;
    use mp2_common::{
        default_config,
        u256::{CircuitBuilderU256, UInt256Target, WitnessWriteU256},
        utils::{ToFields, ToTargets},
        CHasher, C, D, F,
    };
    use mp2_test::{
        circuit::{run_circuit, UserCircuit},
        utils::{gen_random_field_hash, gen_random_u256, random_vector},
    };
    use plonky2::{
        field::types::{Field, PrimeField64},
        gadgets::arithmetic,
        hash::{
            hash_types::{HashOut, HashOutTarget},
            hashing::hash_n_to_hash_no_pad,
        },
        iop::{
            target::Target,
            witness::{PartialWitness, WitnessWrite},
        },
        plonk::{
            circuit_builder::CircuitBuilder,
            config::{GenericHashOut, Hasher},
        },
    };
    use rand::{thread_rng, Rng};

    use crate::simple_query_circuits::computational_hash_ids::ComputationalHashIdentifiers;

    use super::{BasicOperationInputWires, BasicOperationInputs};

    type HashPermutation = <CHasher as Hasher<F>>::Permutation;

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
        op_identifier: ComputationalHashIdentifiers,
        compute_result: RFn,
    ) {
        let input_values = array::from_fn(|_| gen_u256_input(rng));
        let constant_operand = gen_u256_input(rng);
        let placeholder_value = gen_u256_input(rng);
        let input_hash = array::from_fn(|_| gen_random_field_hash());
        let placeholder_id = F::from_canonical_u8(rng.gen());
        let first_input_selector = F::from_canonical_usize(rng.gen_range(0..NUM_INPUTS + 2));
        let second_input_selector = F::from_canonical_usize(rng.gen_range(0..NUM_INPUTS + 2));
        let op_selector = F::from_canonical_usize(
            BasicOperationInputs::compute_op_selector(op_identifier)
                .expect("Invalid operation identifier provided as input"),
        );

        let component = BasicOperationInputs {
            constant_operand,
            placeholder_value,
            placeholder_id,
            first_input_selector,
            second_input_selector,
            op_selector,
        };

        // compute expected outputs
        let constant_operand_hash =
            hash_n_to_hash_no_pad::<_, HashPermutation>(&constant_operand.to_fields());
        let placeholder_hash = hash_n_to_hash_no_pad::<_, HashPermutation>(&[placeholder_id]);
        let (first_input, first_hash) = match first_input_selector.to_noncanonical_u64() as usize {
            a if a < NUM_INPUTS => (input_values[a], input_hash[a]),
            a if a == NUM_INPUTS => (constant_operand, constant_operand_hash),
            a if a == NUM_INPUTS + 1 => (placeholder_value, placeholder_hash),
            a => panic!(
                "sampled second input selector too big: max {}, sampled {}",
                NUM_INPUTS + 2,
                a
            ),
        };

        let (second_input, second_hash) = match second_input_selector.to_noncanonical_u64() as usize
        {
            a if a < NUM_INPUTS => (input_values[a], input_hash[a]),
            a if a == NUM_INPUTS => (constant_operand, constant_operand_hash),
            a if a == NUM_INPUTS + 1 => (placeholder_value, placeholder_hash),
            a => panic!(
                "sampled second input selector too big: max {}, sampled {}",
                NUM_INPUTS + 2,
                a
            ),
        };

        let (expected_result, arithmetic_error) = compute_result(first_input, second_input);
        let expected_hash = hash_n_to_hash_no_pad::<_, HashPermutation>(
            &once(F::from_canonical_usize(op_identifier as usize))
                .chain(first_hash.to_vec().into_iter())
                .chain(second_hash.to_vec().into_iter())
                .collect_vec(),
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
            ComputationalHashIdentifiers::AddOp,
            |a, b| a.overflowing_add(b),
        )
    }

    #[test]
    fn test_sub() {
        test_basic_operation::<TEST_NUM_INPUTS, _, _, _>(
            gen_random_u256,
            &mut thread_rng(),
            ComputationalHashIdentifiers::SubOp,
            |a, b| a.overflowing_sub(b),
        )
    }

    #[test]
    fn test_mul() {
        test_basic_operation::<TEST_NUM_INPUTS, _, _, _>(
            gen_random_u256,
            &mut thread_rng(),
            ComputationalHashIdentifiers::MulOp,
            |a, b| a.overflowing_mul(b),
        )
    }

    #[test]
    fn test_div() {
        test_basic_operation::<TEST_NUM_INPUTS, _, _, _>(
            gen_random_u256,
            &mut thread_rng(),
            ComputationalHashIdentifiers::DivOp,
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
            ComputationalHashIdentifiers::ModOp,
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
            ComputationalHashIdentifiers::ModOp,
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
            ComputationalHashIdentifiers::DivOp,
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
            ComputationalHashIdentifiers::MulOp,
            |a, b| a.overflowing_mul(b),
        )
    }

    #[test]
    fn test_less_than() {
        test_basic_operation::<TEST_NUM_INPUTS, _, _, _>(
            gen_random_u256,
            &mut thread_rng(),
            ComputationalHashIdentifiers::LessThanOp,
            |a, b| (U256::from((a < b) as u128), false),
        )
    }

    #[test]
    fn test_less_or_equal_than() {
        test_basic_operation::<TEST_NUM_INPUTS, _, _, _>(
            gen_random_u256,
            &mut thread_rng(),
            ComputationalHashIdentifiers::LessThanOrEqOp,
            |a, b| (U256::from((a <= b) as u128), false),
        )
    }

    #[test]
    fn test_greater_or_equal_than() {
        test_basic_operation::<TEST_NUM_INPUTS, _, _, _>(
            gen_random_u256,
            &mut thread_rng(),
            ComputationalHashIdentifiers::GreaterThanOrEqOp,
            |a, b| (U256::from((a >= b) as u128), false),
        )
    }

    #[test]
    fn test_greater_than() {
        test_basic_operation::<TEST_NUM_INPUTS, _, _, _>(
            gen_random_u256,
            &mut thread_rng(),
            ComputationalHashIdentifiers::GreaterThanOp,
            |a, b| (U256::from((a > b) as u128), false),
        )
    }

    #[test]
    fn test_is_equal() {
        test_basic_operation::<TEST_NUM_INPUTS, _, _, _>(
            gen_random_u256,
            &mut thread_rng(),
            ComputationalHashIdentifiers::EqOp,
            |a, b| (U256::from((a == b) as u128), false),
        )
    }

    #[test]
    fn test_is_not_equal() {
        test_basic_operation::<TEST_NUM_INPUTS, _, _, _>(
            gen_random_u256,
            &mut thread_rng(),
            ComputationalHashIdentifiers::NeOp,
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
            ComputationalHashIdentifiers::AndOp,
            |a, b| (a & b, false),
        )
    }

    #[test]
    fn test_or() {
        test_basic_operation::<TEST_NUM_INPUTS, _, _, _>(
            gen_random_u256_bit,
            &mut thread_rng(),
            ComputationalHashIdentifiers::OrOp,
            |a, b| (a | b, false),
        )
    }

    #[test]
    fn test_not() {
        test_basic_operation::<TEST_NUM_INPUTS, _, _, _>(
            gen_random_u256_bit,
            &mut thread_rng(),
            ComputationalHashIdentifiers::NotOp,
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
            ComputationalHashIdentifiers::XorOp,
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
        let expected_cost = 76;
        assert_eq!(b.num_gates() - num_gates_pre_build, expected_cost);
    }
}
