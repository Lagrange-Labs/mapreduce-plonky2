//! Gadget for U256 arithmetic, with overflow checking
//!

use std::{
    array::{self, from_fn as create_array},
    iter::{once, repeat},
    ops::Mul,
    usize,
};

use crate::{
    array::{Array, Targetable},
    serialization::{
        circuit_data_serialization::SerializableRichField, FromBytes, SerializationError, ToBytes,
    },
    utils::{Endianness, FromFields, FromTargets, Packer, ToFields, ToTargets},
};
use anyhow::{ensure, Result};
use ethers::types::U256;
use itertools::Itertools;
use plonky2::{
    field::{extension::Extendable, packed::PackedField},
    gates::gate::Gate,
    hash::hash_types::RichField,
    iop::{
        generator::{GeneratedValues, SimpleGenerator},
        target::{BoolTarget, Target},
        witness::{PartitionWitness, Witness, WitnessWrite},
    },
    plonk::{circuit_builder::CircuitBuilder, circuit_data::CommonCircuitData},
    util::{
        log2_ceil,
        serialization::{Buffer, IoResult, Read, Write},
    },
};
use plonky2_crypto::u32::{
    arithmetic_u32::{CircuitBuilderU32, U32Target},
    gates::range_check_u32::U32RangeCheckGate,
    range_check::range_check_u32_circuit,
    witness::WitnessU32,
};
use serde::{Deserialize, Serialize};

/// Number of limbs employed to represent a 256-bit unsigned integer
pub const NUM_LIMBS: usize = 8;

/// Circuit representation of u256
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct UInt256Target([U32Target; NUM_LIMBS]);

pub trait CircuitBuilderU256<F: SerializableRichField<D>, const D: usize> {
    /// Add a UInt256Target without any range-check on the limbs
    fn add_virtual_u256_unsafe(&mut self) -> UInt256Target;

    /// Add a UInt256Target while enforcing that all the limbs are range-checked
    fn add_virtual_u256(&mut self) -> UInt256Target;

    /// Add `N` `UInt256Target`s while enforcing that all the limbs are range-checked.
    /// It may require less constraints than allocating each target individually
    fn add_virtual_u256_arr<const N: usize>(&mut self) -> [UInt256Target; N];

    /// Register a UInt256Target as public input
    fn register_public_input_u256(&mut self, target: &UInt256Target);

    /// Return the constant target representing 0_u256
    fn zero_u256(&mut self) -> UInt256Target;

    /// Returns the constant target representing 1_u256
    fn one_u256(&mut self) -> UInt256Target;

    /// Returns the constant target representing the `U256` `value` provided as input
    fn constant_u256(&mut self, value: U256) -> UInt256Target;

    /// Add 2 UInt256Target, returning the addition modulo 2^256 and the carry
    fn add_u256(
        &mut self,
        left: &UInt256Target,
        right: &UInt256Target,
    ) -> (UInt256Target, U32Target);

    /// Subtract 2 UInt256Target, returning the difference modulo 2^256 and the borrow, if any
    fn sub_u256(
        &mut self,
        left: &UInt256Target,
        right: &UInt256Target,
    ) -> (UInt256Target, U32Target);

    /// Multiply 2 UInt256Target, returning the product and a flag specifying whether
    /// overflow has occurred or not
    fn mul_u256(
        &mut self,
        left: &UInt256Target,
        right: &UInt256Target,
    ) -> (UInt256Target, BoolTarget);

    /// Divide 2 UInt256Target, returning the quotient and the remainder; it also returns a flag specifying
    /// whether a division by zero error has occurred
    fn div_u256(
        &mut self,
        left: &UInt256Target,
        right: &UInt256Target,
    ) -> (UInt256Target, UInt256Target, BoolTarget);

    /// Compute a `BoolTarget` being true if and only `left < right`
    fn is_less_than_u256(&mut self, left: &UInt256Target, right: &UInt256Target) -> BoolTarget;

    /// Compute a `BoolTarget` being true if and only the 2 input UInt256Target are equal
    fn is_equal_u256(&mut self, left: &UInt256Target, right: &UInt256Target) -> BoolTarget;

    /// Return  true iff  `left <= right`
    fn is_less_or_equal_than_u256(
        &mut self,
        left: &UInt256Target,
        right: &UInt256Target,
    ) -> BoolTarget;

    /// Compute a `BoolTarget` being true if and only if the input UInt256Target is zero
    fn is_zero(&mut self, target: &UInt256Target) -> BoolTarget;

    /// Enforce equality between 2 UInt256Target
    fn enforce_equal_u256(&mut self, left: &UInt256Target, right: &UInt256Target);

    fn select_u256(
        &mut self,
        cond: BoolTarget,
        left: &UInt256Target,
        right: &UInt256Target,
    ) -> UInt256Target;

    /// Return the element in the `inputs` array with position `access_index`  
    fn random_access_u256(
        &mut self,
        access_index: Target,
        inputs: &[UInt256Target],
    ) -> UInt256Target;
}

pub trait WitnessWriteU256<F: RichField> {
    fn set_u256_target(&mut self, target: &UInt256Target, value: U256);
}

pub trait WitnessReadU256<F: RichField> {
    fn get_u256_target(&self, target: &UInt256Target) -> U256;
}

impl<F: SerializableRichField<D>, const D: usize> CircuitBuilderU256<F, D>
    for CircuitBuilder<F, D>
{
    fn add_virtual_u256_unsafe(&mut self) -> UInt256Target {
        UInt256Target(array::from_fn(|_| self.add_virtual_u32_target()))
    }

    fn add_virtual_u256(&mut self) -> UInt256Target {
        self.add_virtual_u256_arr::<1>()[0].clone()
    }

    fn add_virtual_u256_arr<const N: usize>(&mut self) -> [UInt256Target; N] {
        let targets = array::from_fn(|_| self.add_virtual_u256_unsafe());
        // add range-checks for the targets. First compute how many `u32` limbs we can pack in
        // a single `U32RangeCheckGate`
        let mut num_limbs_per_gate = 0;
        while U32RangeCheckGate::<F, D>::new(num_limbs_per_gate).num_wires()
            <= self.config.num_wires
            && num_limbs_per_gate <= N * NUM_LIMBS
        {
            num_limbs_per_gate += 1;
        }
        if num_limbs_per_gate > 0 {
            targets
                .iter()
                .flat_map(|t| t.0.to_vec())
                .chunks(num_limbs_per_gate - 1)
                .into_iter()
                .for_each(|t_chunk| range_check_u32_circuit(self, t_chunk.collect_vec()));
        } else {
            // cannot use range-check u32 gate with current circuit config, fallback to simple Plonky2 range-check
            targets
                .iter()
                .flat_map(|t| t.0.to_vec())
                .for_each(|t| self.range_check(t.0, 32));
        }
        targets
    }

    fn register_public_input_u256(&mut self, target: &UInt256Target) {
        target
            .0
            .iter()
            .rev() // register in big-endian order
            .for_each(|t| self.register_public_input(t.0));
    }

    fn add_u256(
        &mut self,
        left: &UInt256Target,
        right: &UInt256Target,
    ) -> (UInt256Target, U32Target) {
        let mut carry = self.zero_u32();
        let result_limbs = left
            .0
            .iter()
            .zip(right.0.iter())
            .map(|(left_limb, right_limb)| {
                let to_add_limbs = vec![*left_limb, *right_limb];
                let (result, new_carry) = self.add_u32s_with_carry(&to_add_limbs.as_slice(), carry);
                carry = new_carry;
                result
            })
            .collect_vec();
        (
            UInt256Target(
                result_limbs
                    .try_into()
                    .expect("Output result with different number of limbs than input operands"),
            ),
            carry,
        )
    }

    fn zero_u256(&mut self) -> UInt256Target {
        let zero = self.zero_u32();
        UInt256Target([zero; NUM_LIMBS])
    }

    fn one_u256(&mut self) -> UInt256Target {
        let zero = self.zero_u32();
        let mut arr = [zero; NUM_LIMBS];
        arr[0] = U32Target(self.one());
        UInt256Target(arr)
    }

    fn mul_u256(
        &mut self,
        left: &UInt256Target,
        right: &UInt256Target,
    ) -> (UInt256Target, BoolTarget) {
        // we implement schoolbook multiplication over 32-bit limbs

        // this vector stores the intermediate products to be added together for each limb
        let mut tmp_res = vec![vec![]; NUM_LIMBS];
        let zero = self.zero();
        let mut sum_carries = zero; // accumulate all the carries to check for overflows; it is safe
                                    // to sum carries as they are all 32-bit integers, therefore by summing them we never overflow the
                                    // native field
                                    // iterate over each limb of the right operand and multiply with each limb of left operand
        for i in 0..NUM_LIMBS {
            // first, we compute the carry, if any, coming from previous limbs multiplications
            let mut carry = match tmp_res[i].len() {
                0 => self.zero_u32(),
                1 => tmp_res[i][0],
                _ => {
                    // we sum up intermediate results for the current limb coming from previous limbs
                    // products
                    let (res, carry) = self.add_many_u32(&tmp_res[i]);
                    // the carry is either:
                    // - Moved to the intermediate results for the next limb, if it is not an overflowing limn
                    // - accumulated in sum of carries to be checked for overflow, otherwise
                    if i + 1 < NUM_LIMBS {
                        tmp_res[i + 1].push(carry);
                    } else {
                        sum_carries = self.add(sum_carries, carry.0);
                    }
                    res
                }
            };
            // now we can erase intermediate results for the current limb
            tmp_res[i] = vec![];
            // then, we multiply the current limb of `right` with all the limbs of `left`
            for j in 0..NUM_LIMBS {
                if i + j >= NUM_LIMBS {
                    // product of these limbs must be checked for overflow instead of being
                    // placed in intermediate results
                    // to check for overflow, we determine whether the product of current limb is
                    // 0 or not; since each limb is a 32-bit integer, we can check this over
                    // the product computed in the native field, for efficiency
                    let prod = self.mul(left.0[j].0, right.0[i].0);
                    let is_zero = self.is_equal(prod, zero);
                    let is_not_zero = self.not(is_zero);
                    // add `is_not_zero` to the accumulator of carries
                    sum_carries = self.add(sum_carries, is_not_zero.target);
                } else {
                    // we compute the product of these limbs, over 32-bit integers, splitting the
                    // result between the least significant 32 bits and the most significant ones,
                    // which represent the carry to be propagated to the next iteration
                    let (res, next_carry) = self.mul_add_u32(left.0[j], right.0[i], carry);
                    // we add the product to the intermediate results for the corresponding limb
                    tmp_res[i + j].push(res);
                    // we propagate next_carry to the next iteration
                    carry = next_carry;
                }
            }
            // we accumulate the carry of the last `mul_add_u32` operation of the previous loop to the
            // ones that need to be checked for overflow
            sum_carries = self.add(sum_carries, carry.0);
        }
        // at this point, intermediate results vector should contain the `NUM_LIMBS` limbs
        // of the results of the multiplication
        let res = tmp_res
            .iter()
            .map(|res| {
                assert_eq!(res.len(), 1);
                res[0]
            })
            .collect_vec()
            .try_into()
            .unwrap();
        // compute overflow flag by checking whether sum of carries is 0 or not
        let is_zero = self.is_equal(sum_carries, zero);
        let overflow = self.not(is_zero);

        (UInt256Target(res), overflow)
    }

    fn sub_u256(
        &mut self,
        left: &UInt256Target,
        right: &UInt256Target,
    ) -> (UInt256Target, U32Target) {
        let mut borrow = self.zero_u32();
        let res = left
            .0
            .iter()
            .zip(right.0.iter())
            .map(|(left_limb, right_limb)| {
                let (res, new_borrow) = self.sub_u32(*left_limb, *right_limb, borrow);
                borrow = new_borrow;
                res
            })
            .collect_vec()
            .try_into()
            .unwrap();

        (UInt256Target(res), borrow)
    }

    fn div_u256(
        &mut self,
        left: &UInt256Target,
        right: &UInt256Target,
    ) -> (UInt256Target, UInt256Target, BoolTarget) {
        let _true = self._true();
        let _false = self._false();

        let (_, quotient, remainder, _, is_zero) = left.mul_div_u256(right, self, _true);

        (quotient, remainder, is_zero)
    }

    fn enforce_equal_u256(&mut self, left: &UInt256Target, right: &UInt256Target) {
        left.0
            .iter()
            .zip(right.0.iter())
            .for_each(|(left_limb, right_limb)| {
                self.connect(left_limb.0, right_limb.0);
            })
    }

    fn is_equal_u256(&mut self, left: &UInt256Target, right: &UInt256Target) -> BoolTarget {
        let _false = self._false();
        left.0
            .iter()
            .zip(right.0.iter())
            .fold(_false, |is_eq, (left_limb, right_limb)| {
                let is_limb_equal = self.is_equal(left_limb.0, right_limb.0);
                self.or(is_eq, is_limb_equal)
            })
    }

    fn is_less_or_equal_than_u256(
        &mut self,
        left: &UInt256Target,
        right: &UInt256Target,
    ) -> BoolTarget {
        let a = self.is_less_than_u256(left, right);
        let b = self.is_equal_u256(left, right);
        self.or(a, b)
    }

    fn is_zero(&mut self, target: &UInt256Target) -> BoolTarget {
        // since each limb is a 32-bit number, we can sum up the limbs without overflowing the native field.
        // Therefore, for efficiency we determine whether `target` is zero by summing up its limbs and
        // checking whether the sum is zero or not
        let zero = self.zero();
        let limbs_sum = target
            .0
            .iter()
            .fold(zero, |sum, limb| self.add(sum, limb.0));
        self.is_equal(limbs_sum, zero)
    }

    fn is_less_than_u256(&mut self, left: &UInt256Target, right: &UInt256Target) -> BoolTarget {
        // left < right iff left - right requires a borrow
        let (_, borrow) = self.sub_u256(left, right);
        BoolTarget::new_unsafe(borrow.0)
    }
    fn select_u256(
        &mut self,
        cond: BoolTarget,
        left: &UInt256Target,
        right: &UInt256Target,
    ) -> UInt256Target {
        let limbs = create_array(|i| U32Target(self.select(cond, left.0[i].0, right.0[i].0)));
        UInt256Target(limbs)
    }

    fn random_access_u256(
        &mut self,
        access_index: Target,
        inputs: &[UInt256Target],
    ) -> UInt256Target {
        // compute padded length of inputs to safely use the
        // `random_access` gadget (must be a power of 2)
        let pad_len = 1 << log2_ceil(inputs.len());
        UInt256Target(create_array(|i| {
            let ith_limbs = inputs
                .iter()
                .map(|u256_t| u256_t.0[i].to_target())
                .chain(repeat(self.zero()))
                .take(pad_len)
                .collect_vec();
            U32Target(self.random_access(access_index, ith_limbs))
        }))
    }
    
    fn constant_u256(&mut self, value: U256) -> UInt256Target {
        let value_be_targets = value.to_fields().into_iter().map(|limb| 
            self.constant(limb)
        ).collect_vec();
        UInt256Target::from_targets(value_be_targets.as_slice())
    }
}

impl<T: WitnessWrite<F>, F: RichField> WitnessWriteU256<F> for T {
    fn set_u256_target(&mut self, target: &UInt256Target, value: U256) {
        let limbs = value.to_fields();
        target
            .0
            .iter()
            .zip(limbs.into_iter().rev()) // reverse since targets are in little-endian order
            .for_each(|(t, v)| self.set_target(t.0, v));
    }
}

impl<T: WitnessU32<F>, F: RichField> WitnessReadU256<F> for T {
    fn get_u256_target(&self, target: &UInt256Target) -> U256 {
        let bytes = target
            .0
            .iter()
            .flat_map(|t| {
                let (low, high) = self.get_u32_target(*t);
                assert_eq!(high, 0); // check it is a 32-bit limb
                low.to_le_bytes().to_vec()
            })
            .collect_vec();
        U256::from_little_endian(&bytes)
    }
}

impl UInt256Target {
    /// Build a new `UInt256Target` from its limbs, provided in big-endian order
    pub fn new_from_be_limbs(limbs: &[U32Target]) -> Result<Self> {
        Ok(UInt256Target(
            limbs
                .iter()
                .rev()
                .map(|t| *t)
                .collect_vec()
                .try_into()
                .map_err(|_| {
                    anyhow::Error::msg(format!(
                        "invalid number of input limbs provided, expected {}, got {}",
                        NUM_LIMBS,
                        limbs.len()
                    ))
                })?,
        ))
    }

    /// Build a new `UInt256Target` from its limbs in target, provided in big-endian order
    pub fn new_from_be_target_limbs(limbs: &[Target]) -> Result<Self> {
        ensure!(limbs.len() == NUM_LIMBS, "limbs len size != {}", NUM_LIMBS);
        Ok(UInt256Target(
            limbs
                .iter()
                .rev()
                .map(|t| U32Target(*t))
                .collect_vec()
                .try_into()
                .map_err(|_| {
                    anyhow::Error::msg(format!(
                        "invalid number of input limbs provided, expected {}, got {}",
                        NUM_LIMBS,
                        limbs.len()
                    ))
                })?,
        ))
    }
    /// Initialize a `UInt256Target` from a target representing a single bit
    pub fn new_from_bool_target<F: SerializableRichField<D>, const D: usize>(
        b: &mut CircuitBuilder<F, D>,
        target: BoolTarget,
    ) -> Self {
        let limbs = repeat(b.zero_u32())
            .take(NUM_LIMBS - 1)
            .chain(once(U32Target::from_target(target.target)))
            .collect_vec();
        Self::new_from_be_limbs(&limbs).unwrap()
    }

    /// Utility function employed to implement multiplication, division and remainder of
    /// `Self` values with a single u256 multiplier. The function returns 3 results,
    /// which correspond to:
    /// - The result of the multiplication, if the input flag `is_div == false`, a dummy value otherwise
    /// - The results of the divisions (i.e., quotient and remainder), if the input flag `is_div == true`, dummy values otherwise
    /// - A flag specifying whether an overflow has occurred in the multiplication operations
    /// - A flag specyifng whether a division by zero was performed
    pub fn mul_div_u256<F: SerializableRichField<D>, const D: usize>(
        &self,
        other: &Self,
        b: &mut CircuitBuilder<F, D>,
        is_div: BoolTarget,
    ) -> (Self, Self, Self, BoolTarget, BoolTarget) {
        let _true = b._true();
        let _false = b._false();
        let zero = b.zero();

        // enforce that other is not zero
        let is_zero = b.is_zero(other);
        let quotient = b.add_virtual_u256();
        let remainder = b.add_virtual_u256();
        b.add_simple_generator(UInt256DivGenerator {
            dividend: self.clone(),
            divisor: other.clone(),
            quotient: quotient.clone(),
            remainder: remainder.clone(),
            is_div,
        });
        // enforce that remainder < other, if other != 0 and is_div == true;
        // this is equivalent to assert_eq!(other == 0 OR (NOT is_div) OR remainder < other, true)
        // which is equivalent to assert_eq!(other != 0 AND is_div AND remainder >= other, false).
        // We can compute the left expression with only 2 arithmetic operations as follows.
        // first, we compute other != 0 AND is_div as is_div * (1 - is_zero) = is_div - is_div*is_zero
        let antecedent = b.arithmetic(
            F::NEG_ONE,
            F::ONE,
            is_div.target,
            is_zero.target,
            is_div.target,
        );
        // then, we compute the whole proposition as antecedent AND (NOT remainder < other)
        let is_less_than = b.is_less_than_u256(&remainder, other);
        let should_be_false = b.arithmetic(
            F::NEG_ONE,
            F::ONE,
            antecedent,
            is_less_than.target,
            antecedent,
        );
        b.connect(should_be_false, _false.target);
        // compute multiplication: if is_div == false, then prod = self*other;
        // otherwise, prod = quotient*other, as we need to later check that quotient*other + remainder == self
        let mul_input = if let Some(val) = b.target_as_constant(is_div.target) {
            if val == F::ONE {
                &quotient
            } else {
                self
            }
        } else {
            &b.select_u256(is_div, &quotient, self)
        };
        let (prod, mul_overflow) = b.mul_u256(mul_input, other);
        let (computed_dividend, carry) = b.add_u256(&prod, &remainder);
        b.enforce_equal_u256(self, &computed_dividend);

        // if is_div == true, enforce both mul_overflow and carry are zero
        // this is equivalent to enforce that is_div == false OR mul_overflow == 0,
        // which is equivalent to enforce that NOT(is_div AND mul_overflow != 0),
        // which is equivalent to enforce that is_div*mul_overflow == 0
        let enforce_no_mul_overflow = b.and(is_div, mul_overflow);
        b.connect(enforce_no_mul_overflow.target, _false.target);
        let enforce_no_add_overflow = b.mul(is_div.target, carry.to_target());
        b.connect(enforce_no_add_overflow, zero);

        (prod, quotient, remainder, mul_overflow, is_zero)
    }

    /// Utility function for serialization of UInt256Target
    fn write_to_bytes(&self, buffer: &mut Vec<u8>) {
        // write targets in big-endian order
        for i in (0..NUM_LIMBS).rev() {
            buffer
                .write_target(self.0[i].0)
                .expect("Writing to a byte-vector cannot fail.");
        }
    }
    /// Utility function for deserialization of UInt256Target
    fn read_from_buffer(buffer: &mut Buffer) -> IoResult<Self> {
        Ok(UInt256Target(
            (0..NUM_LIMBS)
                .map(|_| buffer.read_target().map(|t| U32Target(t)))
                .rev() // targets are serialized in big-endian order, so we need to reverse them to get little-endian
                .collect::<Result<Vec<_>, _>>()?
                .try_into()
                .unwrap(),
        ))
    }
}

impl ToTargets for UInt256Target {
    fn to_targets(&self) -> Vec<Target> {
        Into::<Vec<Target>>::into(self)
    }
}

impl FromTargets for UInt256Target {
    // Expects big endian limbs as the standard format for IO
    fn from_targets(t: &[Target]) -> Self {
        Self::new_from_be_target_limbs(&t[..NUM_LIMBS]).unwrap()
    }
}

impl From<Array<U32Target, NUM_LIMBS>> for UInt256Target {
    fn from(value: Array<U32Target, NUM_LIMBS>) -> Self {
        UInt256Target::new_from_be_limbs(value.arr.as_slice()).unwrap()
    }
}

impl<'a> From<&'a UInt256Target> for Vec<Target> {
    fn from(value: &'a UInt256Target) -> Self {
        value.0.iter().map(|u32_t| u32_t.0).rev().collect_vec()
    }
}

impl ToBytes for UInt256Target {
    fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        self.write_to_bytes(&mut buffer);
        buffer
    }
}

impl FromBytes for UInt256Target {
    fn from_bytes(bytes: &[u8]) -> std::result::Result<Self, SerializationError> {
        let mut buffer = Buffer::new(bytes);
        Ok(Self::read_from_buffer(&mut buffer)?)
    }
}

impl<F: RichField> ToFields<F> for U256 {
    /// Return the 32-bit limbs representing a u256 as field elements, in big-endian order    
    fn to_fields(&self) -> Vec<F> {
        let mut bytes = [0u8; 32];
        self.to_big_endian(&mut bytes);
        let limbs = bytes.pack(Endianness::Big).to_fields();
        assert_eq!(limbs.len(), NUM_LIMBS);
        limbs
    }
}

impl<F: RichField> FromFields<F> for U256 {
    fn from_fields(t: &[F]) -> Self {
        U256::from(U256PubInputs::try_from(t).unwrap())
    }
}
/// Struct to wrap a set of public inputs representing a single U256
pub struct U256PubInputs<'a, F: RichField>(&'a [F]);

impl<'a, F: RichField> TryFrom<&'a [F]> for U256PubInputs<'a, F> {
    type Error = anyhow::Error;

    fn try_from(value: &'a [F]) -> std::result::Result<Self, Self::Error> {
        ensure!(
            value.len() == NUM_LIMBS,
            "invalid number of limbs provided as input, expected {}, got {}",
            NUM_LIMBS,
            value.len()
        );
        Ok(U256PubInputs(value))
    }
}

impl<'a, F: RichField> From<U256PubInputs<'a, F>> for U256 {
    fn from(value: U256PubInputs<'a, F>) -> Self {
        let bytes = value
            .0
            .iter()
            .flat_map(|f| (f.to_canonical_u64() as u32).to_be_bytes())
            .collect_vec();
        U256::from_big_endian(&bytes)
    }
}

/// Generator employed to fill witness values needed for division of UInt256Targets
#[derive(Clone, Debug, Default)]
pub struct UInt256DivGenerator {
    dividend: UInt256Target,
    divisor: UInt256Target,
    quotient: UInt256Target,
    remainder: UInt256Target,
    is_div: BoolTarget,
}

impl<F: SerializableRichField<D>, const D: usize> SimpleGenerator<F, D> for UInt256DivGenerator {
    fn id(&self) -> String {
        "UInt256DivGenerator".to_string()
    }

    fn dependencies(&self) -> Vec<Target> {
        [&self.dividend, &self.divisor]
            .into_iter()
            .flat_map::<Vec<Target>, _>(|u256_t| u256_t.into())
            .chain(once(self.is_div.target))
            .collect_vec()
    }

    fn run_once(&self, witness: &PartitionWitness<F>, out_buffer: &mut GeneratedValues<F>) {
        let dividend = witness.get_u256_target(&self.dividend);
        let divisor = witness.get_u256_target(&self.divisor);
        let is_div = witness.get_bool_target(self.is_div);

        let (quotient, remainder) = if is_div {
            if divisor.is_zero() {
                (U256::zero(), dividend)
            } else {
                dividend.div_mod(divisor)
            }
        } else {
            // if is_div == false, then we assign input values to satisfy the
            // constraint dividend*divisor + remainder == dividend, which is
            // needed when is_div == true
            let remainder = dividend
                .overflowing_sub(dividend.overflowing_mul(divisor).0)
                .0;
            // safety check
            assert_eq!(
                dividend
                    .overflowing_mul(divisor)
                    .0
                    .overflowing_add(remainder)
                    .0,
                dividend
            );
            (U256::one(), remainder)
        };

        out_buffer.set_u256_target(&self.quotient, quotient);
        out_buffer.set_u256_target(&self.remainder, remainder);
    }

    fn serialize(&self, dst: &mut Vec<u8>, _common_data: &CommonCircuitData<F, D>) -> IoResult<()> {
        self.dividend.write_to_bytes(dst);
        self.divisor.write_to_bytes(dst);
        self.quotient.write_to_bytes(dst);
        self.remainder.write_to_bytes(dst);
        dst.write_target_bool(self.is_div);

        Ok(())
    }

    fn deserialize(src: &mut Buffer, _common_data: &CommonCircuitData<F, D>) -> IoResult<Self>
    where
        Self: Sized,
    {
        let dividend = UInt256Target::read_from_buffer(src)?;
        let divisor = UInt256Target::read_from_buffer(src)?;
        let quotient = UInt256Target::read_from_buffer(src)?;
        let remainder = UInt256Target::read_from_buffer(src)?;
        let is_div = src.read_target_bool()?;

        Ok(Self {
            dividend,
            divisor,
            quotient,
            remainder,
            is_div,
        })
    }
}

#[cfg(test)]
mod tests {

    use core::num;

    use ethers::types::U256;
    use mp2_test::circuit::{run_circuit, UserCircuit};
    use plonky2::{
        field::types::Field,
        iop::witness::PartialWitness,
        plonk::{
            circuit_builder::CircuitBuilder,
            circuit_data::{CircuitConfig, CircuitData},
            config::PoseidonGoldilocksConfig,
            proof::ProofWithPublicInputs,
        },
    };
    use rand::{thread_rng, Rng};
    use serde::{Deserialize, Serialize};

    use crate::{
        default_config,
        serialization::{deserialize, serialize},
        types::GFp,
        u256::{U256PubInputs, NUM_LIMBS},
    };

    use super::{CircuitBuilderU256, UInt256Target, WitnessWriteU256};

    const D: usize = 2;
    type F = GFp;
    type C = PoseidonGoldilocksConfig;

    #[derive(Clone, Debug)]
    struct TestCreateOne;

    impl UserCircuit<F, D> for TestCreateOne {
        type Wires = ();

        fn build(c: &mut CircuitBuilder<F, D>) -> Self::Wires {
            let input = c.one_u256();
            c.register_public_input_u256(&input);
            ()
        }

        fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {}
    }

    #[derive(Clone, Debug)]
    struct TestOperationsCircuit {
        left: U256,
        right: U256,
    }

    impl UserCircuit<F, D> for TestOperationsCircuit {
        type Wires = (UInt256Target, UInt256Target);

        fn build(c: &mut CircuitBuilder<F, D>) -> Self::Wires {
            let left = c.add_virtual_u256_unsafe();
            let right = c.add_virtual_u256_unsafe();
            (left, right)
        }

        fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
            pw.set_u256_target(&wires.0, self.left);
            pw.set_u256_target(&wires.1, self.right);
        }
    }

    #[derive(Clone, Debug)]
    struct TestAddCircuit(TestOperationsCircuit);

    impl UserCircuit<F, D> for TestAddCircuit {
        type Wires = <TestOperationsCircuit as UserCircuit<F, D>>::Wires;

        fn build(c: &mut CircuitBuilder<F, D>) -> Self::Wires {
            let (left, right) = TestOperationsCircuit::build(c);
            let (res, carry) = c.add_u256(&left, &right);
            c.register_public_input_u256(&res);
            c.register_public_input(carry.0);
            (left, right)
        }

        fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
            self.0.prove(pw, wires)
        }
    }

    #[derive(Clone, Debug)]
    struct TestSubCircuit(TestOperationsCircuit);

    impl UserCircuit<F, D> for TestSubCircuit {
        type Wires = <TestOperationsCircuit as UserCircuit<F, D>>::Wires;

        fn build(c: &mut CircuitBuilder<F, D>) -> Self::Wires {
            let (left, right) = TestOperationsCircuit::build(c);
            let (res, borrow) = c.sub_u256(&left, &right);
            c.register_public_input_u256(&res);
            c.register_public_input(borrow.0);
            (left, right)
        }

        fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
            self.0.prove(pw, wires)
        }
    }

    #[derive(Clone, Debug)]
    struct TestMulCircuit(TestOperationsCircuit);

    impl UserCircuit<F, D> for TestMulCircuit {
        type Wires = <TestOperationsCircuit as UserCircuit<F, D>>::Wires;

        fn build(c: &mut CircuitBuilder<F, D>) -> Self::Wires {
            let (left, right) = TestOperationsCircuit::build(c);
            let (res, carry) = c.mul_u256(&left, &right);
            c.register_public_input_u256(&res);
            c.register_public_input(carry.target);
            (left, right)
        }

        fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
            self.0.prove(pw, wires)
        }
    }

    #[derive(Clone, Debug)]
    struct TestDivCircuit(TestOperationsCircuit);

    impl UserCircuit<F, D> for TestDivCircuit {
        type Wires = <TestOperationsCircuit as UserCircuit<F, D>>::Wires;

        fn build(c: &mut CircuitBuilder<F, D>) -> Self::Wires {
            let (left, right) = TestOperationsCircuit::build(c);
            let (quotient, remainder, div_zero) = c.div_u256(&left, &right);
            c.register_public_input_u256(&quotient);
            c.register_public_input_u256(&remainder);
            c.register_public_input(div_zero.target);
            (left, right)
        }

        fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
            self.0.prove(pw, wires)
        }
    }

    #[derive(Clone, Debug)]
    struct TestEqCircuit(TestOperationsCircuit);

    impl UserCircuit<F, D> for TestEqCircuit {
        type Wires = <TestOperationsCircuit as UserCircuit<F, D>>::Wires;

        fn build(c: &mut CircuitBuilder<F, D>) -> Self::Wires {
            let (left, right) = TestOperationsCircuit::build(c);
            let is_eq = c.is_equal_u256(&left, &right);
            c.register_public_input(is_eq.target);
            (left, right)
        }

        fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
            self.0.prove(pw, wires)
        }
    }

    #[derive(Clone, Debug)]
    struct TestLessThanCircuit(TestOperationsCircuit);

    impl UserCircuit<F, D> for TestLessThanCircuit {
        type Wires = <TestOperationsCircuit as UserCircuit<F, D>>::Wires;

        fn build(c: &mut CircuitBuilder<F, D>) -> Self::Wires {
            let (left, right) = TestOperationsCircuit::build(c);
            let is_eq = c.is_less_than_u256(&left, &right);
            c.register_public_input(is_eq.target);
            (left, right)
        }

        fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
            self.0.prove(pw, wires)
        }
    }

    #[derive(Clone, Debug)]
    struct TestLessOrEqualThanCircuit(TestOperationsCircuit);

    impl UserCircuit<F, D> for TestLessOrEqualThanCircuit {
        type Wires = <TestOperationsCircuit as UserCircuit<F, D>>::Wires;

        fn build(c: &mut CircuitBuilder<F, D>) -> Self::Wires {
            let (left, right) = TestOperationsCircuit::build(c);
            let is_eq = c.is_less_or_equal_than_u256(&left, &right);
            c.register_public_input(is_eq.target);
            (left, right)
        }

        fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
            self.0.prove(pw, wires)
        }
    }

    #[derive(Clone, Debug)]
    struct TestIsZeroCircuit(U256);

    impl UserCircuit<F, D> for TestIsZeroCircuit {
        type Wires = UInt256Target;

        fn build(c: &mut CircuitBuilder<F, D>) -> Self::Wires {
            let input = c.add_virtual_u256_unsafe();
            let is_zero = c.is_zero(&input);
            c.register_public_input(is_zero.target);
            input
        }

        fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
            pw.set_u256_target(&wires, self.0);
        }
    }

    fn check_result(
        result: U256,
        carry: bool,
        proof: &ProofWithPublicInputs<F, C, D>,
        test_case: &str,
    ) {
        let proven_res =
            U256::from(U256PubInputs::try_from(&proof.public_inputs[..NUM_LIMBS]).unwrap());
        // check that result is the same as the one exposed by the proof
        assert_eq!(
            result, proven_res,
            "result not correct for test: {}",
            test_case
        );
        // check carry
        if carry {
            assert_eq!(
                GFp::ONE,
                proof.public_inputs[NUM_LIMBS],
                "carry not correct for test: {}",
                test_case
            )
        } else {
            assert_eq!(
                GFp::ZERO,
                proof.public_inputs[NUM_LIMBS],
                "carry not correct for test: {}",
                test_case
            )
        }
    }

    fn gen_random_u256<R: Rng>(rng: &mut R) -> U256 {
        let bytes: [u8; 32] = rng.gen();
        U256::from_little_endian(bytes.as_slice())
    }

    #[test]
    fn test_u256_add() {
        let rng = &mut thread_rng();
        // generate left and right operand for add
        let left = gen_random_u256(rng);
        let right = gen_random_u256(rng);

        let circuit = TestAddCircuit(TestOperationsCircuit { left, right });

        let proof = run_circuit::<F, D, C, _>(circuit);

        let (res, carry) = left.overflowing_add(right);
        check_result(res, carry, &proof, "add");

        // check addition by 0
        let zero = U256::zero();
        let circuit = TestAddCircuit(TestOperationsCircuit { left, right: zero });

        let proof = run_circuit::<F, D, C, _>(circuit);
        check_result(left, false, &proof, "add by 0");

        // check addition by itself is equal to double
        let circuit = TestAddCircuit(TestOperationsCircuit { left: right, right });
        let proof = run_circuit::<F, D, C, _>(circuit);
        let (res, carry) = right.overflowing_add(right);
        check_result(res, carry, &proof, "double");
    }

    #[test]
    fn test_u256_sub() {
        let rng = &mut thread_rng();
        // generate left and right operand for sub
        let left = gen_random_u256(rng);
        let right = gen_random_u256(rng);
        let circuit = TestSubCircuit(TestOperationsCircuit { left, right });

        let proof = run_circuit::<F, D, C, _>(circuit);

        let (res, borrow) = left.overflowing_sub(right);
        check_result(res, borrow, &proof, "sub");

        // test subtraction by zero
        let circuit = TestSubCircuit(TestOperationsCircuit {
            left,
            right: U256::zero(),
        });

        let proof = run_circuit::<F, D, C, _>(circuit);
        check_result(left, false, &proof, "sub by 0");

        // test subtraction by itself
        let circuit = TestSubCircuit(TestOperationsCircuit { left, right: left });
        let proof = run_circuit::<F, D, C, _>(circuit);
        check_result(U256::zero(), false, &proof, "sub by itself");

        // test negation
        let circuit = TestSubCircuit(TestOperationsCircuit {
            left: U256::zero(),
            right,
        });

        let proof = run_circuit::<F, D, C, _>(circuit);
        let res = U256::max_value() - right + U256::one();
        check_result(res, true, &proof, "negation");
    }

    #[test]
    fn test_u256_mul() {
        let rng = &mut thread_rng();
        // generate left and right operand for mul
        let left = gen_random_u256(rng);
        let right = gen_random_u256(rng);

        let circuit = TestMulCircuit(TestOperationsCircuit { left, right });

        let proof = run_circuit::<F, D, C, _>(circuit);
        let (res, overflow) = left.overflowing_mul(right);
        check_result(res, overflow, &proof, "mul");

        // test multiplication by 0
        let circuit = TestMulCircuit(TestOperationsCircuit {
            left,
            right: U256::zero(),
        });

        let proof = run_circuit::<F, D, C, _>(circuit);
        check_result(U256::zero(), false, &proof, "mul by 0");

        // test multiplication by 1
        let circuit = TestMulCircuit(TestOperationsCircuit {
            left,
            right: U256::one(),
        });

        let proof = run_circuit::<F, D, C, _>(circuit);
        check_result(left, false, &proof, "mul by 1");

        // the previous multiplication will most likely overflow, so let's have a test where
        // we know the multiplication does not overflow
        let left = U256::from(rng.gen::<u128>());
        let right = U256::from(rng.gen::<u128>());
        let circuit = TestMulCircuit(TestOperationsCircuit { left, right });

        let proof = run_circuit::<F, D, C, _>(circuit);
        let (res, overflow) = left.overflowing_mul(right);
        assert!(!overflow);
        check_result(res, overflow, &proof, "mul no overflow");
    }

    #[test]
    fn test_u256_div() {
        // function to check the correctness of division results
        let check_div_result = |quotient: U256,
                                remainder: U256,
                                div_zero: bool,
                                proof: &ProofWithPublicInputs<F, C, D>,
                                test_case: &str| {
            // check that quotient is the same as the one exposed by the proof
            let proven_quotient =
                U256::from(U256PubInputs::try_from(&proof.public_inputs[..NUM_LIMBS]).unwrap());
            assert_eq!(
                quotient, proven_quotient,
                "quotient not correct for test: {}",
                test_case
            );
            // check that remainder is the same as the one exposed by the proof
            let proven_remainder = U256::from(
                U256PubInputs::try_from(&proof.public_inputs[NUM_LIMBS..2 * NUM_LIMBS]).unwrap(),
            );
            assert_eq!(
                remainder, proven_remainder,
                "remainder not correct for test: {}",
                test_case
            );
            // check division by zero flag
            if div_zero {
                assert_eq!(
                    GFp::ONE,
                    proof.public_inputs[2 * NUM_LIMBS],
                    "div by zero flag not correct for test: {}",
                    test_case
                )
            } else {
                assert_eq!(
                    GFp::ZERO,
                    proof.public_inputs[2 * NUM_LIMBS],
                    "div by zero flag not correct for test: {}",
                    test_case
                )
            }
        };

        let rng = &mut thread_rng();
        // generate left and right operand for div
        let left = gen_random_u256(rng);
        let right = gen_random_u256(rng);

        let circuit = TestDivCircuit(TestOperationsCircuit { left, right });
        let proof = run_circuit::<F, D, C, _>(circuit);
        let (quotient, remainder) = left.div_mod(right);
        check_div_result(quotient, remainder, right.is_zero(), &proof, "div");

        // test division by 0
        let circuit = TestDivCircuit(TestOperationsCircuit {
            left,
            right: U256::zero(),
        });
        let proof = run_circuit::<F, D, C, _>(circuit);
        check_div_result(U256::zero(), left, true, &proof, "div by 0");

        // test division by 1
        let circuit = TestDivCircuit(TestOperationsCircuit {
            left,
            right: U256::one(),
        });
        let proof = run_circuit::<F, D, C, _>(circuit);
        check_div_result(left, U256::zero(), false, &proof, "div by 1");

        // check div is inverse operation of mul
        let left = U256::from(rng.gen::<u128>());
        let right = U256::from(rng.gen::<u128>());
        let (prod, overflow) = left.overflowing_mul(right);
        assert!(!overflow);
        // now check that prod/right=left
        let circuit = TestDivCircuit(TestOperationsCircuit { left: prod, right });
        let proof = run_circuit::<F, D, C, _>(circuit);
        check_div_result(left, U256::zero(), false, &proof, "div after mul");
    }

    #[test]
    fn test_u256_eq() {
        let rng = &mut thread_rng();
        // generate left and right operand for eq
        let left = gen_random_u256(rng);
        let right = gen_random_u256(rng);
        let circuit = TestEqCircuit(TestOperationsCircuit { left, right });
        let proof = run_circuit::<F, D, C, _>(circuit);
        if left == right {
            assert_eq!(F::ONE, proof.public_inputs[0]);
        } else {
            assert_eq!(F::ZERO, proof.public_inputs[0]);
        }

        // check that an item is equal to itself
        let circuit = TestEqCircuit(TestOperationsCircuit { left, right: left });
        let proof = run_circuit::<F, D, C, _>(circuit);
        assert_eq!(F::ONE, proof.public_inputs[0]);
    }

    #[test]
    fn test_u256_is_less_than() {
        let rng = &mut thread_rng();
        // generate left and right operand for less than
        let left = gen_random_u256(rng);
        let right = gen_random_u256(rng);
        let circuit = TestLessThanCircuit(TestOperationsCircuit { left, right });
        let proof = run_circuit::<F, D, C, _>(circuit);
        if left < right {
            assert_eq!(F::ONE, proof.public_inputs[0]);
        } else {
            assert_eq!(F::ZERO, proof.public_inputs[0]);
        }

        // test left == right
        let circuit = TestLessThanCircuit(TestOperationsCircuit { left, right: left });
        let proof = run_circuit::<F, D, C, _>(circuit);
        assert_eq!(F::ZERO, proof.public_inputs[0]);

        // test zero is always less than any other non-zero item
        let circuit = TestLessThanCircuit(TestOperationsCircuit {
            left: U256::zero(),
            right,
        });
        let proof = run_circuit::<F, D, C, _>(circuit);
        if right.is_zero() {
            assert_eq!(F::ZERO, proof.public_inputs[0]);
        } else {
            assert_eq!(F::ONE, proof.public_inputs[0]);
        }

        // test that an item is never less than zero
        let circuit = TestLessThanCircuit(TestOperationsCircuit {
            left,
            right: U256::zero(),
        });
        let proof = run_circuit::<F, D, C, _>(circuit);
        assert_eq!(F::ZERO, proof.public_inputs[0]);
    }

    #[test]
    fn test_u256_is_less_or_equal_than() {
        let rng = &mut thread_rng();
        // generate left and right operand for less than
        let left = gen_random_u256(rng);
        let right = gen_random_u256(rng);
        let circuit = TestLessOrEqualThanCircuit(TestOperationsCircuit { left, right });
        let proof = run_circuit::<F, D, C, _>(circuit);
        if left <= right {
            assert_eq!(F::ONE, proof.public_inputs[0]);
        } else {
            assert_eq!(F::ZERO, proof.public_inputs[0]);
        }

        // test left == right
        let circuit = TestLessOrEqualThanCircuit(TestOperationsCircuit { left, right: left });
        let proof = run_circuit::<F, D, C, _>(circuit);
        assert_eq!(F::ONE, proof.public_inputs[0]);
    }

    #[test]
    fn test_u256_is_zero() {
        let rng = &mut thread_rng();
        // generate input operand for is zero
        let input = gen_random_u256(rng);

        let circuit = TestIsZeroCircuit(input);
        let proof = run_circuit::<F, D, C, _>(circuit);
        if input.is_zero() {
            assert_eq!(F::ONE, proof.public_inputs[0]);
        } else {
            assert_eq!(F::ZERO, proof.public_inputs[0]);
        }

        // test with zero
        let circuit = TestIsZeroCircuit(U256::zero());
        let proof = run_circuit::<F, D, C, _>(circuit);
        assert_eq!(F::ONE, proof.public_inputs[0]);
    }

    #[test]
    fn test_serialization_with_u256_div() {
        let mut b = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        let wires = TestDivCircuit::build(&mut b);
        let data = b.build();

        // helper struct used to easily serialzie circut data for div circuit
        #[derive(Serialize, Deserialize)]
        struct TestDivParams {
            #[serde(serialize_with = "serialize", deserialize_with = "deserialize")]
            data: CircuitData<F, C, D>,
        }

        let params = TestDivParams { data };

        // serialize and deserialize circuit data
        let serialized_params = bincode::serialize(&params).unwrap();
        let params: TestDivParams = bincode::deserialize(&serialized_params).unwrap();

        // use deserialized parameters to generate a proof
        let circuit = TestDivCircuit(TestOperationsCircuit {
            left: U256::zero(),
            right: U256::one(),
        });
        let mut pw = PartialWitness::new();
        circuit.prove(&mut pw, &wires);
        let proof = params.data.prove(pw).unwrap();
        params.data.verify(proof).unwrap();
    }

    #[test]
    fn test_u256_one() {
        let circuit = TestCreateOne;
        let proof = run_circuit::<F, D, C, _>(circuit);
        let found = U256::from(U256PubInputs::try_from(proof.public_inputs.as_slice()).unwrap());
        let exp = U256::one();
        assert_eq!(found, exp);
    }

    #[test]
    fn range_check_cost() {
        let mut b = CircuitBuilder::<F, D>::new(default_config());
        let num_gates_pre_range_check = b.num_gates();
        let _ = b.add_virtual_u256();
        let num_gates = b.num_gates() - num_gates_pre_range_check;
        assert_eq!(num_gates, 2);
        // allocate 2 u256 targets at the same time is cheaper than allocating individually 2 u256 targets
        let _ = b.add_virtual_u256_arr::<2>();
        let num_gates = b.num_gates() - num_gates;
        assert_eq!(num_gates, 3);
    }
}
