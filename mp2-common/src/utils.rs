use std::array::from_fn as create_array;

use alloy::primitives::{B256, U256};
use anyhow::{anyhow, Result};
use itertools::Itertools;
use plonky2::field::extension::Extendable;
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::hash::hash_types::{HashOut, HashOutTarget, RichField, NUM_HASH_OUT_ELTS};
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::VerifierCircuitData;
use plonky2::plonk::config::{GenericConfig, GenericHashOut, Hasher};
use plonky2_crypto::u32::arithmetic_u32::U32Target;
use plonky2_ecdsa::gadgets::biguint::BigUintTarget;

use plonky2_ecgfp5::gadgets::{base_field::QuinticExtensionTarget, curve::CurveTarget};
use sha3::Digest;
use sha3::Keccak256;

use crate::serialization::circuit_data_serialization::SerializableRichField;
use crate::{
    array::Targetable,
    group_hashing::EXTENSION_DEGREE,
    poseidon::{HashableField, H},
    types::HashOutput,
    ProofTuple,
};

const TWO_POWER_8: usize = 256;
const TWO_POWER_16: usize = 65536;
const TWO_POWER_24: usize = 16777216;

// check that the closure $f actually panics, printing $msg as error message if the function
// did not panic; this macro is employed in tests in place of #[should_panic] to ensure that a
// panic occurred in the expected function rather than in other parts of the test
#[macro_export]
macro_rules! check_panic {
    ($f: expr, $msg: expr) => {{
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe($f));
        assert!(result.is_err(), $msg);
    }};
}

pub use check_panic;

pub fn verify_proof_tuple<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
>(
    proof: &ProofTuple<F, C, D>,
) -> Result<()> {
    let vcd = VerifierCircuitData {
        verifier_only: proof.1.clone(),
        common: proof.2.clone(),
    };
    vcd.verify(proof.0.clone())
}

/// Allows to write directly a vector of integers into a partial witness
pub trait IntTargetWriter {
    fn set_int_targets<T: Into<u32> + Clone>(&mut self, t: &[Target], v: &[T]);
}
impl<F: RichField> IntTargetWriter for PartialWitness<F> {
    fn set_int_targets<T: Into<u32> + Clone>(&mut self, t: &[Target], v: &[T]) {
        assert_eq!(t.len(), v.len());
        for i in 0..t.len() {
            self.set_target(t[i], F::from_canonical_u32(v[i].clone().into()));
        }
    }
}

// Returns the index where the subvector starts in v, if any.
pub fn find_index_subvector(v: &[u8], sub: &[u8]) -> Option<usize> {
    v.windows(sub.len()).position(|s| s == sub)
}

/// Compute the keccak256 hash of the given data.
/// NOTE: probably should have two modules for circuit related stuff and non-circuit related stuff
pub fn keccak256(data: &[u8]) -> Vec<u8> {
    let mut hasher = Keccak256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

/// Transform the bits to a number target.
pub fn bits_to_num<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    bits: &[BoolTarget],
) -> Target {
    let mut res = builder.zero();
    let mut e2 = builder.one();
    for bit in bits {
        res = builder.mul_add(e2, bit.target, res);
        e2 = builder.add(e2, e2);
    }
    res
}

/// Returns the bits of the given number. Will panic if `n >= F::BITS`
pub fn num_to_bits<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    n: usize,
    x: Target,
) -> Vec<BoolTarget> {
    if n < F::BITS {
        // safe to use `split_le`
        return builder.split_le(x, n);
    }
    // ToDo: handle the conversion if `n == F::BITS` and `F` is Goldilocks field

    panic!("cannot call this method with n > F::BITS");
}

/// Enforce that the given input target is less than 2^n; it is an optimized version
/// of Plonky2 range-check, as it does not enforce any constraint if the target is
/// a constant in the circuit
pub fn range_check_optimized<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    target: Target,
    n: usize,
) {
    if let Some(value) = builder.target_as_constant(target) {
        assert!(F::to_canonical_u64(&value) < (1u64 << n))
    } else {
        builder.range_check(target, n)
    }
}

/// Returns true if a < b in the first n bits, False otherwise.
/// Will panic if `n >= F::BITS-1`
pub fn less_than<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    a: Target,
    b: Target,
    n: usize,
) -> BoolTarget {
    // enforce that a < 2^n and b < 2^n
    range_check_optimized(builder, a, n);
    range_check_optimized(builder, b, n);
    less_than_unsafe(builder, a, b, n)
}

/// Returns true if a < b in the first n bits, False otherwise.
///
/// Will panic if `n >= F::BITS-1`.
/// This variant is unsafe since it assumes that `a < 2^n` and `b < 2^n`;
/// undefined behavior may occur if this assumption is not ensured by the
/// caller
pub fn less_than_unsafe<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    a: Target,
    b: Target,
    n: usize,
) -> BoolTarget {
    assert!(n < F::BITS - 1);

    let power_of_two = builder.constant(F::from_canonical_u64(1 << n));

    let mut lin_pol = builder.add(a, power_of_two);
    // 2^n + a - b
    lin_pol = builder.sub(lin_pol, b);

    let binary = num_to_bits(builder, n + 1, lin_pol);
    // bin(2^n + a - b)[n] == false is correct only when a < b otherwise
    // 2^n + a - b > 2^n so binary[n] will be set
    builder.not(binary[n])
}
/// Returns true if a > b in the first n bits. False otherwise.
/// Will panic if `n >= F::BITS-1`
pub fn greater_than<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    a: Target,
    b: Target,
    n: usize,
) -> BoolTarget {
    less_than(builder, b, a, n)
}

/// Returns true if a > b in the first n bits, False otherwise.
///
/// Will panic if `n >= F::BITS-1`.
/// This variant is unsafe since it assumes that `a < 2^n` and `b < 2^n`;
/// undefined behavior may occur if this assumption is not ensured by the
/// caller
pub fn greater_than_unsafe<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    a: Target,
    b: Target,
    n: usize,
) -> BoolTarget {
    less_than_unsafe(builder, b, a, n)
}

/// Returns true if a <= b in the first n bits. False otherwise.
/// Will panic if `n >= F::BITS-1`
pub fn less_than_or_equal_to<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    a: Target,
    b: Target,
    n: usize,
) -> BoolTarget {
    // enforce that a < 2^n and b < 2^n
    range_check_optimized(builder, a, n);
    range_check_optimized(builder, b, n);
    let one = builder.one();
    let b_plus_1 = builder.add(b, one);
    less_than_unsafe(builder, a, b_plus_1, n)
}

/// Returns true if a <= b in the first n bits, False otherwise.
///
/// Will panic if `n >= F::BITS-1`.
/// This variant is unsafe since it assumes that `a < 2^n` and `b < 2^n`;
/// undefined behavior may occur if this assumption is not ensured by the
/// caller
pub fn less_than_or_equal_to_unsafe<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    a: Target,
    b: Target,
    n: usize,
) -> BoolTarget {
    let one = builder.one();
    let b_plus_1 = builder.add(b, one);
    less_than_unsafe(builder, a, b_plus_1, n)
}
/// Returns true if a >= b in the first n bits. False otherwise.
/// Will panic if `n >= F::BITS-1`
pub fn greater_than_or_equal_to<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    a: Target,
    b: Target,
    n: usize,
) -> BoolTarget {
    // enforce that a < 2^n and b < 2^n
    range_check_optimized(builder, a, n);
    range_check_optimized(builder, b, n);
    let one = builder.one();
    let a_plus_1 = builder.add(a, one);
    less_than(builder, b, a_plus_1, n)
}

/// Returns true if a >= b in the first n bits, False otherwise.
///
/// Will panic if `n >= F::BITS-1`.
/// This variant is unsafe since it assumes that `a < 2^n` and `b < 2^n`;
/// undefined behavior may occur if this assumption is not ensured by the
/// caller
pub fn greater_than_or_equal_to_unsafe<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    a: Target,
    b: Target,
    n: usize,
) -> BoolTarget {
    let one = builder.one();
    let a_plus_1 = builder.add(a, one);
    less_than_unsafe(builder, b, a_plus_1, n)
}

// taken from rust doc https://doc.rust-lang.org/std/primitive.u32.html#method.from_be_bytes
pub fn read_le_u32(input: &mut &[u8]) -> u32 {
    let (int_bytes, rest) = input.split_at(std::mem::size_of::<u32>());
    *input = rest;
    u32::from_le_bytes(int_bytes.try_into().unwrap())
}

/// Convert a list of elements to a curve point.
pub fn convert_slice_to_curve_point<T: Copy>(s: &[T]) -> ([T; 5], [T; 5], T) {
    // 5 F for each coordinates + 1 bool flag
    assert!(s.len() > 2 * EXTENSION_DEGREE);

    let x = s[..EXTENSION_DEGREE].try_into().unwrap();
    let y = s[EXTENSION_DEGREE..2 * EXTENSION_DEGREE]
        .try_into()
        .unwrap();
    let flag = s[2 * EXTENSION_DEGREE];

    (x, y, flag)
}

/// Convert a tuple of point to a curve target.
pub fn convert_point_to_curve_target(point: ([Target; 5], [Target; 5], Target)) -> CurveTarget {
    let (x, y, is_inf) = point;

    let x = QuinticExtensionTarget(x);
    let y = QuinticExtensionTarget(y);
    let flag = BoolTarget::new_unsafe(is_inf);

    CurveTarget(([x, y], flag))
}

/// Hash left and right children to one value.
pub fn hash_two_to_one<F: RichField, H: Hasher<F>>(
    left: HashOutput,
    right: HashOutput,
) -> HashOutput {
    let [left, right] = [left, right].map(|bytes| H::Hash::from_bytes((&bytes).into()));
    HashOutput::try_from(H::two_to_one(left, right).to_bytes()).unwrap()
}

/// Pack the inputs (according to endianness) then compute the Poseidon hash value.
pub fn pack_and_compute_poseidon_value<F: HashableField>(
    inputs: &[u8],
    endianness: Endianness,
) -> HashOut<F> {
    assert!(
        inputs.len() % 4 == 0,
        "Inputs must be a multiple of 4 bytes"
    );

    let packed: Vec<_> = inputs.pack(endianness).to_fields();

    H::hash_no_pad(&packed)
}

/// Pack the inputs (according to endianness) then compute the Poseidon hash target.
pub fn pack_and_compute_poseidon_target<F: HashableField + Extendable<D>, const D: usize>(
    b: &mut CircuitBuilder<F, D>,
    inputs: &[Target],
    endianness: Endianness,
) -> HashOutTarget {
    assert!(
        inputs.len() % 4 == 0,
        "Inputs must be a multiple of 4 bytes"
    );

    let packed = inputs.pack(b, endianness);

    b.hash_n_to_hash_no_pad::<H>(packed)
}

pub trait HashBuilder {
    /// Select `first_hash` or `second_hash` as output depending on the Boolean `cond`
    fn select_hash(
        &mut self,
        cond: BoolTarget,
        first_hash: &HashOutTarget,
        second_hash: &HashOutTarget,
    ) -> HashOutTarget;

    /// Determine whether `first_hash == second_hash`
    fn hash_eq(&mut self, first_hash: &HashOutTarget, second_hash: &HashOutTarget) -> BoolTarget;
}

impl<F: RichField + Extendable<D>, const D: usize> HashBuilder for CircuitBuilder<F, D> {
    fn select_hash(
        &mut self,
        cond: BoolTarget,
        first_hash: &HashOutTarget,
        second_hash: &HashOutTarget,
    ) -> HashOutTarget {
        HashOutTarget::from_vec(
            first_hash
                .elements
                .into_iter()
                .zip(second_hash.elements)
                .map(|(first, second)| self.select(cond, first, second))
                .collect_vec(),
        )
    }

    fn hash_eq(&mut self, first_hash: &HashOutTarget, second_hash: &HashOutTarget) -> BoolTarget {
        let _true = self._true();
        first_hash
            .elements
            .iter()
            .zip(second_hash.elements.iter())
            .fold(_true, |acc, (first, second)| {
                let is_eq = self.is_equal(*first, *second);
                self.and(acc, is_eq)
            })
    }
}

pub trait SelectTarget {
    /// Return `first` if `cond` is true, `second` otherwise
    fn select<F: SerializableRichField<D>, const D: usize>(
        b: &mut CircuitBuilder<F, D>,
        cond: &BoolTarget,
        first: &Self,
        second: &Self,
    ) -> Self;
}

pub trait ToFields<F: RichField> {
    fn to_fields(&self) -> Vec<F>;
}

impl<F: RichField> ToFields<F> for &[u8] {
    fn to_fields(&self) -> Vec<F> {
        self.iter().map(|x| F::from_canonical_u8(*x)).collect()
    }
}
impl<F: RichField> ToFields<F> for &[u32] {
    fn to_fields(&self) -> Vec<F> {
        self.iter().map(|x| F::from_canonical_u32(*x)).collect()
    }
}

impl<F: RichField> ToFields<F> for HashOut<F> {
    fn to_fields(&self) -> Vec<F> {
        self.elements.to_vec()
    }
}

pub trait Fieldable<F: RichField> {
    fn to_field(&self) -> F;
}

impl<F: RichField> Fieldable<F> for u8 {
    fn to_field(&self) -> F {
        F::from_canonical_u8(*self)
    }
}
impl<F: RichField, T: Fieldable<F>> ToFields<F> for Vec<T> {
    fn to_fields(&self) -> Vec<F> {
        self.iter().map(|x| x.to_field()).collect()
    }
}

impl<F: RichField, const N: usize, T: Fieldable<F>> ToFields<F> for [T; N] {
    fn to_fields(&self) -> Vec<F> {
        self.iter().map(|x| x.to_field()).collect()
    }
}

impl<F: RichField> ToFields<F> for HashOutput {
    fn to_fields(&self) -> Vec<F> {
        Vec::<u8>::from(self).pack(Endianness::Little).to_fields()
    }
}

impl<F: RichField> Fieldable<F> for u32 {
    fn to_field(&self) -> F {
        F::from_canonical_u32(*self)
    }
}

impl<F: RichField> Fieldable<F> for u64 {
    fn to_field(&self) -> F {
        F::from_canonical_u64(*self)
    }
}

pub trait FromTargets {
    /// Number of targets necessary to instantiate `Self`
    const NUM_TARGETS: usize;

    /// Number of targets in `t` must be at least `Self::NUM_TARGETS`
    fn from_targets(t: &[Target]) -> Self;
}

impl FromTargets for HashOutTarget {
    const NUM_TARGETS: usize = NUM_HASH_OUT_ELTS;

    fn from_targets(t: &[Target]) -> Self {
        HashOutTarget {
            elements: create_array(|i| t[i]),
        }
    }
}

pub trait ToTargets {
    fn to_targets(&self) -> Vec<Target>;
}

impl ToTargets for Vec<Target> {
    fn to_targets(&self) -> Vec<Target> {
        self.clone()
    }
}

impl ToTargets for &[Target] {
    fn to_targets(&self) -> Vec<Target> {
        self.to_vec()
    }
}

impl ToTargets for BigUintTarget {
    fn to_targets(&self) -> Vec<Target> {
        self.limbs.iter().map(|u| u.0).collect()
    }
}

pub trait TargetsConnector {
    fn connect_targets<T: ToTargets>(&mut self, e1: T, e2: T);
    fn is_equal_targets<T: ToTargets>(&mut self, e1: T, e2: T) -> BoolTarget;
}

impl<F: RichField + Extendable<D>, const D: usize> TargetsConnector for CircuitBuilder<F, D> {
    fn connect_targets<T: ToTargets>(&mut self, e1: T, e2: T) {
        for (l1, l2) in e1.to_targets().into_iter().zip(e2.to_targets()) {
            self.connect(l1, l2);
        }
    }
    fn is_equal_targets<T: ToTargets>(&mut self, e1: T, e2: T) -> BoolTarget {
        let mut cond = self._true();
        for (l1, l2) in e1.to_targets().into_iter().zip(e2.to_targets()) {
            let eq = self.is_equal(l1, l2);
            cond = self.and(cond, eq);
        }
        cond
    }
}

impl<T: Targetable> ToTargets for T {
    fn to_targets(&self) -> Vec<Target> {
        vec![self.to_target()]
    }
}

impl ToTargets for HashOutTarget {
    fn to_targets(&self) -> Vec<Target> {
        self.elements.to_vec()
    }
}

impl ToTargets for &HashOutTarget {
    fn to_targets(&self) -> Vec<Target> {
        self.elements.to_vec()
    }
}

pub trait FromFields<F> {
    fn from_fields(t: &[F]) -> Self;
}

pub trait TryIntoBool {
    /// Convert `self` to `bool`, if `self` can be represented as a bool
    fn try_into_bool(&self) -> Result<bool>;
}

impl<F: PackableRichField> TryIntoBool for F {
    fn try_into_bool(&self) -> Result<bool> {
        if *self == F::ZERO {
            Ok(false)
        } else if *self == F::ONE {
            Ok(true)
        } else {
            Err(anyhow!("input field element is not a Boolean value"))
        }
    }
}

impl TryIntoBool for U256 {
    fn try_into_bool(&self) -> Result<bool> {
        if *self == U256::ZERO {
            Ok(false)
        } else if *self == U256::from(1) {
            Ok(true)
        } else {
            Err(anyhow!("input U256 value is not a Boolean value"))
        }
    }
}

/// Implement `Packer` and `ToBool` for `RichField`.
///
/// Fields that want to be packed with `Packer` have to implement
/// this trait (trivial implementation). Currently implemented only
/// for Goldilocks
pub trait PackableRichField: RichField {}

impl PackableRichField for GoldilocksField {}

#[derive(Clone, Copy, Debug)]
pub enum Endianness {
    Big,
    Little,
}

pub trait Packer {
    type T;
    fn pack(&self, endianness: Endianness) -> Vec<Self::T>;
}

impl Packer for B256 {
    type T = u32;
    fn pack(&self, endianness: Endianness) -> Vec<u32> {
        self.0.pack(endianness)
    }
}

impl Packer for &[u8] {
    type T = u32;
    fn pack(&self, endianness: Endianness) -> Vec<u32> {
        match endianness {
            Endianness::Big => {
                let pad_len = if self.len() % 4 == 0 {
                    0
                } else {
                    4 - (self.len() % 4)
                };
                let mut d = vec![0u8; pad_len];
                d.extend_from_slice(self);
                let mut converted = Vec::new();
                let chunks_iter = d.chunks_exact(4);
                // check that there are no chunks left to be converted
                assert_eq!(chunks_iter.remainder().len(), 0);
                for chunk in chunks_iter {
                    converted.push(u32::from_be_bytes(chunk.try_into().unwrap()));
                }
                converted
            }
            Endianness::Little => {
                let mut d = self.to_vec();
                if self.len() % 4 != 0 {
                    d.resize(self.len() + (4 - (self.len() % 4)), 0);
                }
                let mut converted = Vec::new();
                for chunk in d.chunks_exact(4) {
                    converted.push(u32::from_le_bytes(chunk.try_into().unwrap()));
                }
                converted
            }
        }
    }
}

impl<F: PackableRichField> Packer for &[F] {
    type T = F;

    fn pack(&self, endianness: Endianness) -> Vec<Self::T> {
        // convert field elements to u8
        self.iter()
            .map(|f| f.to_canonical_u64() as u8)
            .collect_vec()
            .pack(endianness)
            .into_iter()
            .map(|el| F::from_canonical_u32(el))
            .collect_vec()
    }
}

impl Packer for Vec<u8> {
    type T = u32;
    fn pack(&self, endianness: Endianness) -> Vec<u32> {
        self.as_slice().pack(endianness)
    }
}

impl<F: PackableRichField> Packer for Vec<F> {
    type T = F;

    fn pack(&self, endianness: Endianness) -> Vec<F> {
        self.as_slice().pack(endianness)
    }
}

impl<const N: usize> Packer for &[u8; N] {
    type T = u32;
    fn pack(&self, endianness: Endianness) -> Vec<u32> {
        self.as_slice().pack(endianness)
    }
}

impl<F: PackableRichField, const N: usize> Packer for &[F; N] {
    type T = F;

    fn pack(&self, endianness: Endianness) -> Vec<F> {
        self.as_slice().pack(endianness)
    }
}

impl<const N: usize> Packer for [u8; N] {
    type T = u32;
    fn pack(&self, endianness: Endianness) -> Vec<u32> {
        self.as_slice().pack(endianness)
    }
}

impl<F: PackableRichField, const N: usize> Packer for [F; N] {
    type T = F;

    fn pack(&self, endianness: Endianness) -> Vec<F> {
        self.as_slice().pack(endianness)
    }
}

pub trait PackerTarget<F: RichField + Extendable<D>, const D: usize, OutT> {
    fn pack(&self, b: &mut CircuitBuilder<F, D>, endianness: Endianness) -> Vec<OutT>;
}

impl<F: RichField + Extendable<D>, const D: usize> PackerTarget<F, D, U32Target> for Vec<Target> {
    /// Pack a slice of targets assumed to represent byte values into a vector of `U32Target`,
    /// each representing the `u32` value given by packing 4 input byte targets, employing
    /// the endianness encoding specified as input.
    fn pack(&self, b: &mut CircuitBuilder<F, D>, endianness: Endianness) -> Vec<U32Target> {
        let zero = b.zero();
        match endianness {
            Endianness::Big => {
                let pad_len = if self.len() % 4 == 0 {
                    0
                } else {
                    4 - (self.len() % 4)
                };
                let mut d = vec![zero; pad_len + self.len()];
                d[pad_len..].copy_from_slice(self);
                let chunks = d.chunks_exact(4);
                // check that `d` has no additional data to be packed
                assert_eq!(chunks.remainder().len(), 0);
                chunks
                    .map(|chunk| {
                        // big-endian packing in each chunk: we multiply the previously accumulated
                        // targets in the chunk by 256 at each step. Thus, after 4 steps, the first
                        // target has been multiplied by TWO_POWER_24, the second one by TWO_POWER_16,
                        // the third one by TWO_POWER_8 while the last one is never multiplied to a
                        // constant
                        U32Target(chunk.iter().fold(zero, |res, el| {
                            b.mul_const_add(F::from_canonical_usize(TWO_POWER_8), res, *el)
                        }))
                    })
                    .collect_vec()
            }
            Endianness::Little => {
                let mut padded = self.to_vec();
                if self.len() % 4 != 0 {
                    padded.resize(self.len() + (4 - (self.len() % 4)), zero);
                }

                // constants to convert [u8; 4] to u32
                // u32 = u8[0] + u8[1] * 2^8 + u8[2] * 2^16 + u8[3] * 2^24
                let two_power_8: Target = b.constant(F::from_canonical_usize(TWO_POWER_8));
                let two_power_16: Target = b.constant(F::from_canonical_usize(TWO_POWER_16));
                let two_power_24: Target = b.constant(F::from_canonical_usize(TWO_POWER_24));

                // convert padded node to u32
                (0..padded.len())
                    .step_by(4)
                    .map(|i| {
                        // u8[0]
                        let mut x = padded[i];
                        // u8[1]
                        let mut y = padded[i + 1];
                        // u8[0] + u8[1] * 2^8
                        x = b.mul_add(y, two_power_8, x);
                        // u8[2]
                        y = padded[i + 2];
                        // u8[0] + u8[1] * 2^8 + u8[2] * 2^16
                        x = b.mul_add(y, two_power_16, x);
                        // u8[3]
                        y = padded[i + 3];
                        // u8[0] + u8[1] * 2^8 + u8[2] * 2^16 + u8[3] * 2^24
                        x = b.mul_add(y, two_power_24, x);

                        U32Target(x)
                    })
                    .collect_vec()
            }
        }
    }
}

impl<F: RichField + Extendable<D>, const D: usize, OutT, PackerT: Clone> PackerTarget<F, D, OutT>
    for &[PackerT]
where
    Vec<PackerT>: PackerTarget<F, D, OutT>,
{
    fn pack(&self, b: &mut CircuitBuilder<F, D>, endianness: Endianness) -> Vec<OutT> {
        self.to_vec().pack(b, endianness)
    }
}

impl<F: RichField + Extendable<D>, const D: usize, OutT, PackerT: Clone, const N: usize>
    PackerTarget<F, D, OutT> for &[PackerT; N]
where
    Vec<PackerT>: PackerTarget<F, D, OutT>,
{
    fn pack(&self, b: &mut CircuitBuilder<F, D>, endianness: Endianness) -> Vec<OutT> {
        self.as_slice().pack(b, endianness)
    }
}

impl<F: RichField + Extendable<D>, const D: usize, OutT, PackerT: Clone, const N: usize>
    PackerTarget<F, D, OutT> for [PackerT; N]
where
    Vec<PackerT>: PackerTarget<F, D, OutT>,
{
    fn pack(&self, b: &mut CircuitBuilder<F, D>, endianness: Endianness) -> Vec<OutT> {
        self.as_slice().pack(b, endianness)
    }
}

impl<F: RichField + Extendable<D>, const D: usize> PackerTarget<F, D, Target> for Vec<Target> {
    fn pack(&self, b: &mut CircuitBuilder<F, D>, endianness: Endianness) -> Vec<Target> {
        let packed_targets: Vec<U32Target> = self.pack(b, endianness);
        packed_targets.into_iter().map(|t| t.0).collect_vec()
    }
}

pub trait SliceConnector {
    fn connect_slice(&mut self, x: &[Target], y: &[Target]);
}

impl<F: RichField + Extendable<D>, const D: usize> SliceConnector for CircuitBuilder<F, D> {
    fn connect_slice(&mut self, x: &[Target], y: &[Target]) {
        if x.len() != y.len() {
            panic!("only call connect_slice with equal length");
        }
        for (xx, yy) in x.iter().zip(y.iter()) {
            self.connect(*xx, *yy)
        }
    }
}

#[cfg(test)]
mod test {
    use super::{bits_to_num, Packer, ToFields};
    use crate::utils::{
        greater_than, greater_than_or_equal_to, less_than, less_than_or_equal_to, num_to_bits,
        Endianness, PackerTarget,
    };
    use crate::{C, D, F};
    use alloy::primitives::Address;
    use anyhow::Result;
    use plonky2::field::goldilocks_field::GoldilocksField;
    use plonky2::field::types::Field;
    use plonky2::iop::target::Target;
    use plonky2::iop::witness::{PartialWitness, WitnessWrite};
    use plonky2::plonk::circuit_builder::CircuitBuilder;
    use plonky2::plonk::circuit_data::CircuitConfig;
    use rand::{thread_rng, Rng, RngCore};

    #[test]
    fn test_pack() {
        // XXX TODO Address::random() fails
        let addr = Address::from_slice(&thread_rng().gen::<[u8; 20]>());
        let _: Vec<GoldilocksField> = addr.0.as_slice().pack(Endianness::Big).to_fields();
    }

    fn test_convert_u8_to_u32_with_size<const SIZE: usize>() {
        let mut rng = rand::thread_rng();

        // Generate a random array of bytes
        let mut data = vec![0u8; SIZE];
        rng.fill_bytes(&mut data);

        // instantiate a circuit which packs u8 into u32 with both endianness orders
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let inputs = builder.add_virtual_target_arr::<SIZE>();
        let le_u32_targets = inputs.pack(&mut builder, Endianness::Little);
        let be_u32_targets = inputs.pack(&mut builder, Endianness::Big);
        le_u32_targets
            .into_iter()
            .for_each(|t| builder.register_public_input(t));
        be_u32_targets
            .into_iter()
            .for_each(|t| builder.register_public_input(t));

        let cd = builder.build::<C>();

        let mut pw = PartialWitness::new();
        pw.set_target_arr(inputs.as_slice(), data.to_fields().as_slice());
        let proof = cd.prove(pw).unwrap();

        let expected_output_len = if SIZE % 4 != 0 {
            (SIZE + (4 - (SIZE % 4))) / 4
        } else {
            SIZE / 4
        };
        let u32_slice = data.pack(Endianness::Little);

        // Check if the length of the u32 slice is correct
        assert_eq!(u32_slice.len(), expected_output_len);

        assert_eq!(
            proof.public_inputs[..u32_slice.len()],
            u32_slice.to_fields()
        );

        let u32_slice = data.pack(Endianness::Big);

        // Check if the length of the u32 slice is correct
        assert_eq!(u32_slice.len(), expected_output_len);

        assert_eq!(
            proof.public_inputs[u32_slice.len()..],
            u32_slice.to_fields()
        );
    }

    #[test]
    fn test_convert_u8_to_u32() {
        test_convert_u8_to_u32_with_size::<42>();
        test_convert_u8_to_u32_with_size::<60>();
    }

    #[test]
    fn test_bits_to_num() -> Result<()> {
        let config = CircuitConfig::standard_recursion_config();
        let pw = PartialWitness::new();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let number = builder.constant(F::from_canonical_usize(1986));
        let t = builder._true();
        let f = builder._false();

        let bits_array = [f, t, f, f, f, f, t, t, t, t, t];
        let one = builder.one();
        let zero = builder.zero();

        let public_input_array = [zero, one, zero, zero, zero, zero, one, one, one, one, one];

        let nums = bits_to_num(&mut builder, &bits_array);

        builder.connect(number, nums);
        builder.register_public_input(number);
        builder.register_public_inputs(&public_input_array);

        let data = builder.build::<C>();
        let proof = data.prove(pw)?;
        data.verify(proof)
    }

    #[test]
    fn test_num_to_bits_valid() -> Result<()> {
        let config = CircuitConfig::standard_recursion_config();
        let pw = PartialWitness::new();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let x = F::from_canonical_usize(0b110100000); // 416 = 1532 in base 6.
        let xt = builder.constant(x);

        let mut bits = [1, 1, 0, 1, 0, 0, 0, 0, 0];
        bits.reverse();
        let mut bits_target_input: Vec<Target> = vec![];

        let bits_target = num_to_bits(&mut builder, 9, xt);

        for i in 0..bits_target.len() {
            bits_target_input.push(builder.constant(F::from_canonical_u64(bits[i])));
            builder.connect(bits_target_input[i], bits_target[i].target);
        }

        builder.register_public_input(xt);
        builder.register_public_inputs(&bits_target_input);

        let data = builder.build::<C>();
        let proof = data.prove(pw)?;
        data.verify(proof)
    }

    #[test]
    fn test_less_than() -> Result<()> {
        let config = CircuitConfig::standard_recursion_config();
        let pw = PartialWitness::new();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let a_val = 5u64;
        let b_val = 10u64;
        let a = builder.constant(F::from_canonical_u64(a_val));
        let b = builder.constant(F::from_canonical_u64(b_val));
        let n = 4;

        let result = less_than(&mut builder, a, b, n);

        builder.register_public_input(a);
        builder.register_public_input(b);
        builder.register_public_input(result.target);

        let data = builder.build::<C>();
        let proof = data.prove(pw)?;
        let expected_res = if a_val % (1 << n) < b_val % (1 << n) {
            F::ONE
        } else {
            F::ZERO
        };
        assert_eq!(proof.public_inputs[2], expected_res);
        data.verify(proof)
    }

    #[test]
    fn test_greater_than() -> Result<()> {
        let config = CircuitConfig::standard_recursion_config();
        let pw = PartialWitness::new();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let a = builder.constant(F::from_canonical_u64(10u64));
        let b = builder.constant(F::from_canonical_u64(5u64));
        let n = 4;

        let result = greater_than(&mut builder, a, b, n);
        let one = builder.one();
        builder.connect(result.target, one);

        builder.register_public_input(a);
        builder.register_public_input(b);
        builder.register_public_input(result.target);

        let data = builder.build::<C>();
        let proof = data.prove(pw)?;
        data.verify(proof)
    }

    #[test]
    fn test_less_than_or_equal_to() -> Result<()> {
        let config = CircuitConfig::standard_recursion_config();
        let pw = PartialWitness::new();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let a = builder.constant(F::from_canonical_u64(10u64));
        let b = builder.constant(F::from_canonical_u64(10u64));
        let n = 4;

        let result = less_than_or_equal_to(&mut builder, a, b, n);
        let one = builder.one();
        builder.connect(result.target, one);

        builder.register_public_input(a);
        builder.register_public_input(b);
        builder.register_public_input(result.target);

        let data = builder.build::<C>();
        let proof = data.prove(pw)?;
        data.verify(proof)
    }

    #[test]
    fn test_greater_than_or_equal_to() -> Result<()> {
        let config = CircuitConfig::standard_recursion_config();
        let pw = PartialWitness::new();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let a = builder.constant(F::from_canonical_u64(10u64));
        let b = builder.constant(F::from_canonical_u64(10u64));
        let n = 4;

        let result = greater_than_or_equal_to(&mut builder, a, b, n);
        let one = builder.one();
        builder.connect(result.target, one);

        builder.register_public_input(a);
        builder.register_public_input(b);
        builder.register_public_input(result.target);

        let data = builder.build::<C>();
        let proof = data.prove(pw)?;
        data.verify(proof)
    }
}
