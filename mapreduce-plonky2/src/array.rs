use anyhow::{anyhow, Result};
use plonky2::{
    field::{extension::Extendable, types::Field},
    hash::hash_types::RichField,
    iop::{
        target::{BoolTarget, Target},
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::circuit_builder::CircuitBuilder,
};
use plonky2_crypto::u32::arithmetic_u32::U32Target;
use recursion_framework::serialization::{deserialize_long_array, serialize_long_array, FromBytes};
use serde::{Deserialize, Serialize};
use std::{array::from_fn as create_array, fmt::Debug, ops::Index};

use crate::utils::{less_than, less_than_or_equal_to};

/// Utility trait to convert any value into its field representation equivalence
pub(crate) trait ToField<F: RichField> {
    fn to_field(&self) -> F;
}

impl<F: RichField> ToField<F> for u8 {
    fn to_field(&self) -> F {
        F::from_canonical_u8(*self)
    }
}
impl<F: RichField> ToField<F> for u32 {
    fn to_field(&self) -> F {
        F::from_canonical_u32(*self)
    }
}
impl<F: RichField> ToField<F> for usize {
    fn to_field(&self) -> F {
        F::from_canonical_usize(*self)
    }
}
/// VectorWire contains the wires representing an array of dynamic length
/// up to MAX_LEN. This is useful when you don't know the exact size in advance
/// of your data, for example in hashing MPT nodes.
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct VectorWire<T: Targetable + Clone + Serialize, const MAX_LEN: usize>
where
    for<'d> T: Deserialize<'d>,
{
    #[serde(bound(deserialize = "T: for <'a>Deserialize<'a>"))]
    pub arr: Array<T, MAX_LEN>,
    pub real_len: Target,
}

/// A fixed buffer array containing dynammic length data. This structs contains
/// the values that are assigned inside a VectorWire.
#[derive(Clone, Debug, Copy)]
pub struct Vector<F, const MAX_LEN: usize> {
    // hardcoding to be bytes srently only use case
    pub arr: [F; MAX_LEN],
    pub real_len: usize,
}

impl<T: Default + Clone + Debug, const MAX_LEN: usize> Vector<T, MAX_LEN> {
    /// Utility wrapper around vector of bytes
    pub(crate) fn to_fields<F: RichField>(&self) -> Vector<F, MAX_LEN>
    where
        T: ToField<F>,
    {
        Vector {
            arr: self
                .arr
                .iter()
                .map(|x| x.to_field())
                .collect::<Vec<_>>()
                .try_into()
                .unwrap(),
            real_len: self.real_len,
        }
    }
    pub fn from_vec(d: &[T]) -> Result<Self> {
        let fields = d
            .iter()
            .cloned()
            .chain(std::iter::repeat(T::default()))
            .take(MAX_LEN) // pad to MAX_LEN with zeros
            .collect::<Vec<_>>();
        let len = d.len();
        Ok(Self {
            arr: fields.try_into().map_err(|e| anyhow!("{:?}", e))?,
            real_len: len,
        })
    }
    pub fn empty() -> Self {
        Self {
            arr: create_array(|_| T::default()),
            real_len: 0,
        }
    }
}

impl<F: RichField, const MAX_LEN: usize> Vector<F, MAX_LEN> {}

impl<const SIZE: usize, T: Targetable + Clone + Serialize> Index<usize> for VectorWire<T, SIZE>
where
    for<'de> T: Deserialize<'de>,
{
    type Output = T;
    fn index(&self, index: usize) -> &Self::Output {
        self.arr.index(index)
    }
}

impl<const MAX_LEN: usize, T: Targetable + Clone + Serialize> VectorWire<T, MAX_LEN>
where
    for<'de> T: Deserialize<'de>,
{
    pub fn new<F, const D: usize>(b: &mut CircuitBuilder<F, D>) -> Self
    where
        F: RichField + Extendable<D>,
    {
        let real_len = b.add_virtual_target();
        let arr = Array::<T, MAX_LEN>::new(b);
        Self { arr, real_len }
    }
    pub(crate) fn assign<F: RichField, V: ToField<F>>(
        &self,
        pw: &mut PartialWitness<F>,
        value: &Vector<V, MAX_LEN>,
    ) {
        pw.set_target(self.real_len, F::from_canonical_usize(value.real_len));
        self.arr
            .assign(pw, &create_array(|i| value.arr[i].to_field()));
    }
}
impl<const MAX_LEN: usize> VectorWire<Target, MAX_LEN> {
    // Asserts the full vector is composed of bytes. The array must be
    // filled with valid bytes after the `real_len` pointer.
    pub fn assert_bytes<F: RichField + Extendable<D>, const D: usize>(
        &self,
        b: &mut CircuitBuilder<F, D>,
    ) {
        self.arr.assert_bytes(b)
    }

    /// Reads the vector up to its real len, and left pad the result up to PAD_LEN.
    /// For example, if given vector is [77, 66, 0, 0] with real_len = 2
    /// the output is [0, 0, 77, 66].
    /// It returns an array because the result does not respect the VectorWire semantic anymore,
    /// i.e. real_len should be read from the right side. This is still useful as it allows
    /// for example one to read the integer in big endian format from this array without
    /// knowing the real length. In general, it allows converting from BE or LE easily without much trouble.
    /// WARNING : PAD_LEN MUST be greater or equal than the real length of the vector, otherwise,
    /// the result is not guaranteed to be correct.
    /// NOTE: The reason this function exists is because when extracting value from MPT leaf node
    /// we read always 32 bytes, but there is no guarantee that what comes after the data is zero
    /// padded. This function ensures the data is left padded with zeros so the value extracted
    /// is still in big endian and correctly left padded.
    pub fn normalize_left<F: RichField + Extendable<D>, const D: usize, const PAD_LEN: usize>(
        &self,
        b: &mut CircuitBuilder<F, D>,
    ) -> Array<Target, PAD_LEN> {
        let zero = b.zero();
        let pad_t = b.constant(F::from_canonical_usize(PAD_LEN));
        Array {
            arr: create_array(|i| {
                let it = b.constant(F::from_canonical_usize(i));
                let jt = b.sub(pad_t, it);
                let is_lt =
                    less_than_or_equal_to(b, jt, self.real_len, (MAX_LEN.ilog2() + 1) as usize);
                let idx = b.sub(self.real_len, jt);
                let val = self.arr.value_at_failover(b, idx);
                b.select(is_lt, val, zero)
            }),
        }
    }
}

/// Fixed size array in circuit of any type (Target or U32Target for example!)
/// of N elements.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Array<T: Clone + Serialize, const N: usize>
where
    for<'d> T: Deserialize<'d>,
{
    // special serialization because serde doesn't implement using const generics
    #[serde(
        serialize_with = "serialize_long_array",
        deserialize_with = "deserialize_long_array"
    )]
    pub(crate) arr: [T; N],
}

impl<T: Targetable + Clone + Serialize, const N: usize> PartialEq for Array<T, N>
where
    for<'d> T: Deserialize<'d>,
{
    fn eq(&self, other: &Self) -> bool {
        self.arr
            .iter()
            .zip(other.arr.iter())
            .all(|(first, second)| first.to_target() == second.to_target())
    }
}

impl<F: Field, const N: usize> Default for Array<F, N> {
    fn default() -> Self {
        Self { arr: [F::ZERO; N] }
    }
}

impl<T: Targetable + Clone + Serialize, const N: usize> Array<T, N>
where
    for<'d> T: Deserialize<'d>,
{
    pub const LEN: usize = N;
}

impl<T: Targetable + Clone + Serialize, const N: usize> Eq for Array<T, N> where
    for<'d> T: Deserialize<'d>
{
}

impl<T: Clone + Serialize, const N: usize> From<[T; N]> for Array<T, N>
where
    for<'de> T: Deserialize<'de>,
{
    fn from(value: [T; N]) -> Self {
        Self { arr: value }
    }
}

impl<T: Clone + Debug + Serialize, const N: usize> TryFrom<Vec<T>> for Array<T, N>
where
    for<'de> T: Deserialize<'de>,
{
    type Error = anyhow::Error;
    fn try_from(value: Vec<T>) -> Result<Self> {
        Ok(Self {
            arr: value
                .try_into()
                .map_err(|e| anyhow!("can't conver to array: {:?}", e))?,
        })
    }
}

impl<T: Clone + Debug + Serialize, const N: usize> TryFrom<&[T]> for Array<T, N>
where
    for<'de> T: Deserialize<'de>,
    T: Copy,
{
    type Error = anyhow::Error;
    fn try_from(value: &[T]) -> Result<Self> {
        anyhow::ensure!(value.len() == N);
        Ok(Self {
            arr: value.try_into().unwrap(),
        })
    }
}

/// Small wrapper trait to handle Target and U32Target in a similar way for arrays
pub trait Targetable: Copy {
    fn to_target(&self) -> Target;
    fn from_target(t: Target) -> Self;
}

impl Targetable for Target {
    fn to_target(&self) -> Target {
        *self
    }
    fn from_target(t: Target) -> Self {
        t
    }
}

impl Targetable for U32Target {
    fn to_target(&self) -> Target {
        self.0
    }
    fn from_target(t: Target) -> Self {
        U32Target(t)
    }
}

impl<T: Clone + Serialize, const SIZE: usize> Index<usize> for Array<T, SIZE>
where
    for<'de> T: Deserialize<'de>,
{
    type Output = T;
    fn index(&self, index: usize) -> &Self::Output {
        self.arr.index(index)
    }
}

impl<const SIZE: usize> Array<Target, SIZE> {
    pub fn assert_bytes<F: RichField + Extendable<D>, const D: usize>(
        &self,
        b: &mut CircuitBuilder<F, D>,
    ) {
        for byte in self.arr {
            b.range_check(byte, 8)
        }
    }
}

impl<T: Targetable + Clone + Serialize, const SIZE: usize> Array<T, SIZE>
where
    for<'de> T: Deserialize<'de>,
{
    /// Creates new wires of the given SIZE.
    pub fn new<F: RichField + Extendable<D>, const D: usize>(b: &mut CircuitBuilder<F, D>) -> Self {
        Self {
            arr: core::array::from_fn(|_| T::from_target(b.add_virtual_target())),
        }
    }

    /// Encapsulate the native array within the Array struct.
    pub fn from_array(arr: [T; SIZE]) -> Self {
        Self { arr }
    }

    pub fn concat<const OTHER_SIZE: usize>(
        &self,
        other: &Array<T, OTHER_SIZE>,
    ) -> Array<T, { SIZE + OTHER_SIZE }> {
        Array {
            arr: create_array(|i| {
                if i < SIZE {
                    self.arr[i]
                } else {
                    other.arr[i - SIZE]
                }
            }),
        }
    }

    pub fn to_targets(&self) -> Array<Target, SIZE> {
        Array {
            arr: create_array(|i| self.arr[i].to_target()),
        }
    }

    /// Assigns each value in the given array to the respective wire in `self`
    pub fn assign<F: RichField>(&self, pw: &mut PartialWitness<F>, array: &[F; SIZE]) {
        #[allow(clippy::needless_range_loop)]
        for i in 0..SIZE {
            pw.set_target(self.arr[i].to_target(), array[i])
        }
    }
    /// Assigns each value in the given array to the respective wire in `self`. Each value is first
    /// converted to a field element.
    pub fn assign_from_data<V: ToField<F>, F: RichField>(
        &self,
        pw: &mut PartialWitness<F>,
        array: &[V; SIZE],
    ) {
        #[allow(clippy::needless_range_loop)]
        for i in 0..SIZE {
            pw.set_target(self.arr[i].to_target(), array[i].to_field())
        }
    }

    /// Assigns a vector of bytes to this array.
    /// NOTE: in circuit, one must call `array.assert_bytes()` to ensure the "byteness" of the input
    /// being assigned to it, if it's expected to be bytes.
    pub fn assign_bytes<F: RichField>(&self, pw: &mut PartialWitness<F>, array: &[u8; SIZE]) {
        self.assign(pw, &create_array(|i| F::from_canonical_u8(array[i])))
    }

    /// Returns the last `TAKE` elements of the array, similar to `skip` on iterators.
    pub fn take_last<F: RichField + Extendable<D>, const D: usize, const TAKE: usize>(
        &self,
    ) -> Array<T, TAKE> {
        Array {
            arr: create_array(|i| self.arr[SIZE - TAKE + i]),
        }
    }

    /// Conditionally select this array if condition is true or the other array
    /// if condition is false. Cost is O(SIZE) call to select()
    pub fn select<F: RichField + Extendable<D>, const D: usize>(
        &self,
        b: &mut CircuitBuilder<F, D>,
        condition: BoolTarget,
        other: &Self,
    ) -> Self {
        Array {
            arr: core::array::from_fn(|i| {
                T::from_target(b.select(
                    condition,
                    self.arr[i].to_target(),
                    other.arr[i].to_target(),
                ))
            }),
        }
    }

    /// Returns true if self[at..at+SUB] == sub, false otherwise.
    /// Cost is O(SIZE * SIZE + SUB) due to SIZE calls to value_at()
    pub fn contains_array<F: RichField + Extendable<D>, const D: usize, const SUB: usize>(
        &self,
        b: &mut CircuitBuilder<F, D>,
        sub: &Array<T, SUB>,
        at: Target,
    ) -> BoolTarget {
        let extracted = self.extract_array::<F, D, SUB>(b, at);
        sub.equals(b, &extracted)
    }

    /// NOTE: this assumes the data always lives at the beginning of the array,
    /// which is true for MPT nodes since we hash from the start of the array.
    /// A malicious prover could disrupt this assumption and circuits using this
    /// function should be aware of this.
    pub fn contains_vector<F: RichField + Extendable<D>, const D: usize, const SUB: usize>(
        &self,
        b: &mut CircuitBuilder<F, D>,
        sub: &VectorWire<T, SUB>,
        at: Target,
    ) -> BoolTarget {
        let mut t = b._true();
        for i in 0..SUB {
            let it = b.constant(F::from_canonical_usize(i));
            let within_range = less_than(
                b,
                it,
                sub.real_len,
                // it's a constant wrt SUB
                // from https://stackoverflow.com/questions/72251467/computing-ceil-of-log2-in-rust
                (usize::BITS - SUB.leading_zeros()) as usize,
            );
            let not_in_range = b.not(within_range);

            let original_idx = b.add(at, it);
            let original_value = self.value_at(b, original_idx);
            let are_equal = b.is_equal(original_value.to_target(), sub.arr.arr[i].to_target());
            let should_be_true = b.and(are_equal, within_range);
            let f = b.or(should_be_true, not_in_range);
            t = b.and(t, f);
        }
        t
    }

    /// Returns true if self == other, false otherwise.
    pub fn equals<F: RichField + Extendable<D>, const D: usize>(
        &self,
        b: &mut CircuitBuilder<F, D>,
        other: &Self,
    ) -> BoolTarget {
        let mut res = b._true();
        for (our, other) in self.arr.iter().zip(other.arr.iter()) {
            let eq = b.is_equal(our.to_target(), other.to_target());
            res = b.and(res, eq);
        }
        res
    }

    /// Enforce this array is equal to another one.
    pub fn enforce_equal<F: RichField + Extendable<D>, const D: usize>(
        &self,
        b: &mut CircuitBuilder<F, D>,
        other: &Self,
    ) {
        self.arr
            .iter()
            .zip(other.arr.iter())
            .for_each(|(our, other)| b.connect(our.to_target(), other.to_target()));
    }

    /// Enforces both array contains the same subslice array[..slice_len].
    pub fn enforce_slice_equals<F: RichField + Extendable<D>, const D: usize>(
        &self,
        b: &mut CircuitBuilder<F, D>,
        other: &Self,
        slice_len: Target,
    ) {
        let tru = b._true();
        for (i, (our, other)) in self.arr.iter().zip(other.arr.iter()).enumerate() {
            let it = b.constant(F::from_canonical_usize(i));
            // TODO: fixed to 6 becaues max nibble len = 64 - TO CHANGE
            let before_end = less_than(b, it, slice_len, 6);
            let eq = b.is_equal(our.to_target(), other.to_target());
            let res = b.select(before_end, eq.target, tru.target);
            b.connect(res, tru.target);
        }
    }

    /// Returns self[at..at+SUB_SIZE].
    /// Cost is O(SIZE * SIZE) due to SIZE calls to value_at()
    /// WARNING: the index `at` must fulfill the condition `self.len() - at >= SUB_SIZE`
    /// If this condition is not met, this function does not guarantee anything on the result.
    pub fn extract_array<F: RichField + Extendable<D>, const D: usize, const SUB_SIZE: usize>(
        &self,
        b: &mut CircuitBuilder<F, D>,
        at: Target,
    ) -> Array<T, SUB_SIZE> {
        let m = b.constant(F::from_canonical_usize(SUB_SIZE));
        let upper_bound = b.add(at, m);
        Array::<T, SUB_SIZE> {
            arr: core::array::from_fn(|i| {
                let i_target = b.constant(F::from_canonical_usize(i));
                let i_plus_n_target = b.add(at, i_target);
                // ((i + offset) <= n + M)
                let lt = less_than_or_equal_to(b, i_plus_n_target, upper_bound, 63);
                // ((i+n) <= n+M) * (i+n)
                let j = b.mul(lt.target, i_plus_n_target);
                // out_val = arr[((i+n)<=n+M) * (i+n)]
                self.value_at(b, j)
            }),
        }
    }

    /// Inneficient method to extract a value from an array but that works
    /// all the time, when b.random_access does not work.
    pub fn value_at_failover<F: RichField + Extendable<D>, const D: usize>(
        &self,
        b: &mut CircuitBuilder<F, D>,
        at: Target,
    ) -> T {
        let mut acc = b.zero();
        for (i, el) in self.arr.iter().enumerate() {
            let i_target = b.constant(F::from_canonical_usize(i));
            let is_eq = b.is_equal(i_target, at);
            // SUM_i (i == n (idx) ) * element
            // -> sum = element
            acc = b.mul_add(is_eq.target, el.to_target(), acc);
        }
        T::from_target(acc)
    }
    /// Extract the value from the array at the index givne by `at`.
    /// Note the cost is O(SIZE) in general, and less for arrays
    /// which are powers of two and <= 64.
    pub fn value_at<F: RichField + Extendable<D>, const D: usize>(
        &self,
        b: &mut CircuitBuilder<F, D>,
        at: Target,
    ) -> T {
        // Only use random_access when SIZE is a power of 2 and smaller than 64
        // see https://stackoverflow.com/a/600306/1202623 for the trick
        if SIZE < RANDOM_ACCESS_SIZE && (SIZE & (SIZE - 1) == 0) {
            // Escape hatch when we can use random_access from plonky2 base
            return T::from_target(b.random_access(
                at,
                self.arr.iter().map(|v| v.to_target()).collect::<Vec<_>>(),
            ));
        } else {
            self.value_at_failover(b, at)
        }
    }

    pub fn reverse(&self) -> Self {
        Self {
            arr: create_array(|i| self.arr[SIZE - 1 - i]),
        }
    }
    pub fn register_as_public_input<F: RichField + Extendable<D>, const D: usize>(
        &self,
        b: &mut CircuitBuilder<F, D>,
    ) {
        b.register_public_inputs(&self.arr.iter().map(|t| t.to_target()).collect::<Vec<_>>());
    }

    pub fn into_vec(&self, real_len: Target) -> VectorWire<T, SIZE> {
        VectorWire {
            arr: self.clone(),
            real_len,
        }
    }
    pub fn last(&self) -> T {
        self.arr[SIZE - 1]
    }
}
/// Returns the size of the array in 32-bit units, rounded up.
pub(crate) const fn L32(a: usize) -> usize {
    if a % 4 != 0 {
        a / 4 + 1
    } else {
        a / 4
    }
}
impl<const SIZE: usize> Array<Target, SIZE> {
    pub fn convert_u8_to_u32<F: RichField + Extendable<D>, const D: usize>(
        &self,
        b: &mut CircuitBuilder<F, D>,
    ) -> Array<U32Target, { L32(SIZE) }>
    where
        [(); L32(SIZE)]:,
    {
        const TWO_POWER_8: usize = 256;
        const TWO_POWER_16: usize = 65536;
        const TWO_POWER_24: usize = 16777216;

        // constants to convert [u8; 4] to u32
        // u32 = u8[0] + u8[1] * 2^8 + u8[2] * 2^16 + u8[3] * 2^24
        let two_power_8: Target = b.constant(F::from_canonical_usize(TWO_POWER_8));
        let two_power_16: Target = b.constant(F::from_canonical_usize(TWO_POWER_16));
        let two_power_24: Target = b.constant(F::from_canonical_usize(TWO_POWER_24));
        let powers = [two_power_8, two_power_16, two_power_24];

        // convert padded node to u32
        Array {
            arr: (0..SIZE)
                .step_by(4)
                .map(|i| {
                    let mut x = self.arr[i];
                    for (i, v) in self.arr[i..].iter().skip(1).take(3).enumerate() {
                        x = b.mul_add(*v, powers[i], x);
                    }
                    U32Target(x)
                })
                .collect::<Vec<_>>()
                .try_into()
                .unwrap(),
        }
    }
}

/// Maximum size of the array where we can call b.random_access() from native
/// Plonky2 API
const RANDOM_ACCESS_SIZE: usize = 64;

#[cfg(test)]
mod test {
    use core::array::from_fn as create_array;
    use plonky2::{
        field::extension::Extendable,
        hash::hash_types::RichField,
        iop::{
            target::{BoolTarget, Target},
            witness::{PartialWitness, WitnessWrite},
        },
        plonk::{
            circuit_builder::CircuitBuilder,
            config::{GenericConfig, PoseidonGoldilocksConfig},
        },
    };
    use plonky2_crypto::u32::arithmetic_u32::U32Target;
    use rand::{thread_rng, Rng};
    use std::panic;

    use crate::{
        array::{Array, ToField, Vector, VectorWire, L32},
        circuit::{test::run_circuit, UserCircuit},
        eth::{left_pad, left_pad32},
        utils::{convert_u8_to_u32_slice, find_index_subvector, test::random_vector},
    };
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    #[test]
    fn test_array_select() {
        const SIZE: usize = 40;
        #[derive(Clone, Debug)]
        struct SelectCircuit<const S: usize> {
            arr: [u8; S],
            arr2: [u8; S],
            cond: bool, // true = arr, false = arr2
        }
        impl<F, const D: usize, const S: usize> UserCircuit<F, D> for SelectCircuit<S>
        where
            F: RichField + Extendable<D>,
        {
            type Wires = (
                Array<Target, S>,
                Array<Target, S>,
                Array<Target, S>,
                BoolTarget,
            );
            fn build(c: &mut CircuitBuilder<F, D>) -> Self::Wires {
                let array = Array::<Target, S>::new(c);
                let array2 = Array::<Target, S>::new(c);
                let exp = Array::<Target, S>::new(c);
                let cond = c.add_virtual_bool_target_safe();
                let selected = array.select(c, cond, &array2);
                let e = exp.equals(c, &selected);
                let t = c._true();
                c.connect(e.target, t.target);
                (array, array2, exp, cond)
            }
            fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
                wires
                    .0
                    .assign(pw, &create_array(|i| F::from_canonical_u8(self.arr[i])));
                wires
                    .1
                    .assign(pw, &create_array(|i| F::from_canonical_u8(self.arr2[i])));
                let selected_array = if self.cond { &self.arr } else { &self.arr2 };
                wires.2.assign(
                    pw,
                    &create_array(|i| F::from_canonical_u8(selected_array[i])),
                );
                pw.set_bool_target(wires.3, self.cond);
            }
        }
        let mut rng = thread_rng();
        let mut arr = [0u8; SIZE];
        rng.fill(&mut arr[..]);
        let mut arr2 = [0u8; SIZE];
        rng.fill(&mut arr2[..]);
        run_circuit::<F, D, C, _>(SelectCircuit {
            arr,
            arr2,
            cond: true,
        });
        run_circuit::<F, D, C, _>(SelectCircuit {
            arr,
            arr2,
            cond: false,
        });
    }
    #[test]
    fn test_convert_u8u32() {
        const SIZE: usize = 80;
        #[derive(Clone, Debug)]
        struct ConvertCircuit<const S: usize>
        where
            [(); L32(S)]:,
        {
            arr: [u8; S],
        }
        impl<F, const D: usize, const S: usize> UserCircuit<F, D> for ConvertCircuit<S>
        where
            F: RichField + Extendable<D>,
            [(); L32(S)]:,
        {
            type Wires = (Array<Target, S>, Array<U32Target, { L32(S) }>);
            fn build(c: &mut CircuitBuilder<F, D>) -> Self::Wires {
                let tr = c._true();
                let origin_u8 = Array::<Target, S>::new(c);

                // Verify `to_u32_array`.
                let to_u32 = origin_u8.convert_u8_to_u32(c);
                let exp_u32 = Array::<U32Target, { L32(S) }>::new(c);
                let is_equal = to_u32.equals(c, &exp_u32);
                c.connect(is_equal.target, tr.target);

                (origin_u8, exp_u32)
            }
            fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
                wires
                    .0
                    .assign(pw, &create_array(|i| F::from_canonical_u8(self.arr[i])));
                let u32arr: [F; L32(S)] = convert_u8_to_u32_slice(&self.arr)
                    .iter()
                    .map(|x| F::from_canonical_u32(*x))
                    .collect::<Vec<_>>()
                    .try_into()
                    .unwrap();
                wires.1.assign(pw, &u32arr);
            }
        }
        let mut rng = thread_rng();
        let mut arr = [0u8; SIZE];
        rng.fill(&mut arr[..]);
        run_circuit::<F, D, C, _>(ConvertCircuit { arr });

        const ODD_SIZE: usize = 3;
        let mut rng = thread_rng();
        let mut arr = [0u8; ODD_SIZE];
        rng.fill(&mut arr[..]);
        run_circuit::<F, D, C, _>(ConvertCircuit { arr });
    }
    #[test]
    fn test_value_at() {
        const SIZE: usize = 80;
        #[derive(Clone, Debug)]
        struct ValueAtCircuit {
            arr: [u8; SIZE],
            idx: usize,
            exp: u8,
        }
        impl<F, const D: usize> UserCircuit<F, D> for ValueAtCircuit
        where
            F: RichField + Extendable<D>,
        {
            type Wires = (Array<Target, SIZE>, Target, Target);
            fn build(c: &mut CircuitBuilder<F, D>) -> Self::Wires {
                let array = Array::<Target, SIZE>::new(c);
                let exp_value = c.add_virtual_target();
                let index = c.add_virtual_target();
                let extracted = array.value_at(c, index);
                c.connect(exp_value, extracted);
                (array, index, exp_value)
            }
            fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
                wires
                    .0
                    .assign(pw, &create_array(|i| F::from_canonical_u8(self.arr[i])));
                pw.set_target(wires.1, F::from_canonical_usize(self.idx));
                pw.set_target(wires.2, F::from_canonical_u8(self.exp));
            }
        }
        let mut rng = thread_rng();
        let mut arr = [0u8; SIZE];
        rng.fill(&mut arr[..]);
        let idx: usize = rng.gen_range(0..SIZE);
        let exp = arr[idx];
        run_circuit::<F, D, C, _>(ValueAtCircuit { arr, idx, exp });
    }

    #[test]
    fn test_extract_array() {
        const SIZE: usize = 80;
        const SUBSIZE: usize = 40;
        #[derive(Clone, Debug)]
        struct ExtractArrayCircuit {
            arr: [u8; SIZE],
            idx: usize,
            exp: [u8; SUBSIZE],
        }
        impl<F, const D: usize> UserCircuit<F, D> for ExtractArrayCircuit
        where
            F: RichField + Extendable<D>,
        {
            type Wires = (Array<Target, SIZE>, Target, Array<Target, SUBSIZE>);
            fn build(c: &mut CircuitBuilder<F, D>) -> Self::Wires {
                let array = Array::<Target, SIZE>::new(c);
                let index = c.add_virtual_target();
                let expected = Array::<Target, SUBSIZE>::new(c);
                let extracted = array.extract_array::<_, _, SUBSIZE>(c, index);
                let are_equal = expected.equals(c, &extracted);
                let tru = c._true();
                c.connect(are_equal.target, tru.target);
                (array, index, expected)
            }
            fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
                wires
                    .0
                    .assign(pw, &create_array(|i| F::from_canonical_u8(self.arr[i])));
                pw.set_target(wires.1, F::from_canonical_usize(self.idx));
                wires
                    .2
                    .assign(pw, &create_array(|i| F::from_canonical_u8(self.exp[i])));
            }
        }
        let mut rng = thread_rng();
        let mut arr = [0u8; SIZE];
        rng.fill(&mut arr[..]);
        let idx: usize = rng.gen_range(0..(SIZE - SUBSIZE));
        let exp = create_array(|i| arr[idx + i]);
        run_circuit::<F, D, C, _>(ExtractArrayCircuit { arr, idx, exp });
    }

    #[test]
    fn test_contains_subarray() {
        #[derive(Clone, Debug)]
        struct ContainsSubarrayCircuit<const S: usize, const SUB: usize> {
            arr: [u8; S],
            idx: usize,
            exp: [u8; SUB],
        }
        impl<F, const D: usize, const S: usize, const SUB: usize> UserCircuit<F, D>
            for ContainsSubarrayCircuit<S, SUB>
        where
            F: RichField + Extendable<D>,
        {
            type Wires = (Array<Target, S>, Target, Array<Target, SUB>);
            fn build(c: &mut CircuitBuilder<F, D>) -> Self::Wires {
                let array = Array::<Target, S>::new(c);
                let index = c.add_virtual_target();
                let sub = Array::<Target, SUB>::new(c);
                let contains = array.contains_array::<_, _, SUB>(c, &sub, index);
                let tru = c._true();
                c.connect(contains.target, tru.target);
                (array, index, sub)
            }
            fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
                wires
                    .0
                    .assign(pw, &create_array(|i| F::from_canonical_u8(self.arr[i])));
                pw.set_target(wires.1, F::from_canonical_usize(self.idx));
                wires
                    .2
                    .assign(pw, &create_array(|i| F::from_canonical_u8(self.exp[i])));
            }
        }
        let mut rng = thread_rng();
        {
            const SIZE: usize = 81;
            const SUBSIZE: usize = 41;
            let mut arr = [0u8; SIZE];
            rng.fill(&mut arr[..]);
            let idx: usize = rng.gen_range(0..(SIZE - SUBSIZE));
            let exp = create_array(|i| arr[idx + i]);
            run_circuit::<F, D, C, _>(ContainsSubarrayCircuit::<SIZE, SUBSIZE> { arr, idx, exp });
        }
        {
            // trying where the subarray is at the end
            const SIZE: usize = 37;
            const SUBSIZE: usize = 32;
            let node = hex::decode(
                "e48200a0a06b4a71765e17649ab73c5e176281619faf173519718e6e95a40a8768685a26c6",
            )
            .unwrap();
            let child_hash =
                hex::decode("6b4a71765e17649ab73c5e176281619faf173519718e6e95a40a8768685a26c6")
                    .unwrap();
            let idx = find_index_subvector(&node, &child_hash).unwrap();
            run_circuit::<F, D, C, _>(ContainsSubarrayCircuit::<SIZE, SUBSIZE> {
                arr: node.try_into().unwrap(),
                idx,
                exp: child_hash.try_into().unwrap(),
            });
        }
        {
            // test when the array is not found
            const SIZE: usize = 81;
            const SUBSIZE: usize = 41;
            let mut arr = [0u8; SIZE];
            rng.fill(&mut arr[..]);
            let idx: usize = rng.gen_range(0..(SIZE - SUBSIZE));
            let exp = create_array(|_| rng.gen::<u8>());
            use std::panic;
            // a bit hardcore method to test for failure but it works for now
            let r = panic::catch_unwind(|| {
                run_circuit::<F, D, C, _>(ContainsSubarrayCircuit::<SIZE, SUBSIZE> {
                    idx,
                    exp,
                    arr,
                })
            });

            assert!(r.is_err());
        }
    }

    #[test]
    fn test_contains_vector() {
        const SIZE: usize = 80;
        #[derive(Clone, Debug)]
        struct ContainsVectorCircuit {
            arr: [u8; SIZE],
            sub: Vec<u8>,
            idx: usize,
            exp: bool,
        }
        impl<F, const D: usize> UserCircuit<F, D> for ContainsVectorCircuit
        where
            F: RichField + Extendable<D>,
        {
            type Wires = (
                Array<Target, SIZE>,
                Target,
                VectorWire<Target, SIZE>,
                BoolTarget,
            );
            fn build(c: &mut CircuitBuilder<F, D>) -> Self::Wires {
                let array = Array::<Target, SIZE>::new(c);
                let index = c.add_virtual_target();
                let expected = c.add_virtual_bool_target_safe();
                let subvector = VectorWire::<Target, SIZE>::new(c);
                let contains = array.contains_vector::<_, _, SIZE>(c, &subvector, index);
                c.connect(contains.target, expected.target);
                (array, index, subvector, expected)
            }
            fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
                wires
                    .0
                    .assign(pw, &create_array(|i| F::from_canonical_u8(self.arr[i])));
                pw.set_target(wires.1, F::from_canonical_usize(self.idx));
                wires
                    .2
                    .assign(pw, &Vector::<u8, SIZE>::from_vec(&self.sub).unwrap());
                pw.set_bool_target(wires.3, self.exp);
            }
        }
        let mut rng = thread_rng();
        let mut arr = [0u8; SIZE];
        rng.fill(&mut arr[..]);
        let random_size: usize = rng.gen_range(1..SIZE);
        let idx: usize = rng.gen_range(0..(SIZE - random_size));
        let sub = arr[idx..idx + random_size].to_vec();

        run_circuit::<F, D, C, _>(ContainsVectorCircuit {
            arr,
            idx,
            sub,
            exp: true,
        });
        run_circuit::<F, D, C, _>(ContainsVectorCircuit {
            arr,
            idx,
            sub: (0..random_size).map(|_| rng.gen()).collect::<Vec<_>>(),
            exp: false,
        });
    }

    #[test]
    fn test_assert_bytes() {
        #[derive(Clone, Debug)]
        struct TestAssertBytes<T, const N: usize> {
            vector: Vec<T>,
        }
        impl<T, F, const D: usize, const N: usize> UserCircuit<F, D> for TestAssertBytes<T, N>
        where
            F: RichField + Extendable<D>,
            T: Clone + ToField<F>,
        {
            type Wires = Array<Target, N>;

            fn build(b: &mut CircuitBuilder<F, D>) -> Self::Wires {
                let arr = Array::<Target, N>::new(b);
                arr.assert_bytes(b);
                arr
            }

            fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
                let fields = self.vector.iter().map(|x| x.to_field()).collect::<Vec<_>>();
                wires.assign(pw, &fields.try_into().unwrap());
            }
        }

        const N: usize = 47;
        let vector = (0..N).map(|_| thread_rng().gen::<u8>()).collect::<Vec<_>>();
        let circuit = TestAssertBytes::<u8, N> { vector };
        run_circuit::<F, D, C, _>(circuit);

        // circuit should fail with non bytes entries
        let vector = (0..N)
            .map(|_| thread_rng().gen::<u32>() + u8::MAX as u32)
            .collect::<Vec<_>>();
        let res = panic::catch_unwind(|| {
            let circuit = TestAssertBytes::<u32, N> { vector };
            run_circuit::<F, D, C, _>(circuit);
        });
        assert!(res.is_err());
    }

    #[test]
    fn test_enforce_slice_equals() {
        #[derive(Clone, Debug)]
        struct TestSliceEqual<const N: usize> {
            arr: [u8; N],
            arr2: [u8; N],
            ptr: usize,
        }

        impl<F, const D: usize, const N: usize> UserCircuit<F, D> for TestSliceEqual<N>
        where
            F: RichField + Extendable<D>,
        {
            type Wires = (Array<Target, N>, Target, Array<Target, N>);

            fn build(c: &mut CircuitBuilder<F, D>) -> Self::Wires {
                let arr = Array::<Target, N>::new(c);
                let ptr = c.add_virtual_target();
                let prefix = Array::<Target, N>::new(c);
                arr.enforce_slice_equals(c, &prefix, ptr);
                (arr, ptr, prefix)
            }

            fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
                wires
                    .0
                    .assign(pw, &create_array(|i| F::from_canonical_u8(self.arr[i])));
                wires
                    .2
                    .assign(pw, &create_array(|i| F::from_canonical_u8(self.arr2[i])));
                pw.set_target(wires.1, F::from_canonical_usize(self.ptr));
            }
        }
        const N: usize = 45;
        let arr: [u8; N] = random_vector(N).try_into().unwrap();
        let mut arr2: [u8; N] = random_vector(N).try_into().unwrap();
        let pointer = thread_rng().gen_range(0..N);
        arr2[0..pointer].copy_from_slice(&arr[0..pointer]);
        let circuit = TestSliceEqual {
            arr,
            arr2,
            ptr: pointer,
        };
        run_circuit::<F, D, C, _>(circuit);

        let res = panic::catch_unwind(|| {
            let circuit = TestSliceEqual {
                arr,
                arr2: random_vector(N).try_into().unwrap(),
                ptr: pointer,
            };
            run_circuit::<F, D, C, _>(circuit);
        });
        assert!(res.is_err());
    }

    #[test]
    fn test_normalize_left() {
        #[derive(Debug, Clone)]
        struct TestNormalizeLeft<const VLEN: usize, const PAD_LEN: usize> {
            input: Vector<u8, VLEN>,
            exp: [u8; PAD_LEN],
        }

        impl<const VLEN: usize, const PAD_LEN: usize> UserCircuit<F, D>
            for TestNormalizeLeft<VLEN, PAD_LEN>
        {
            type Wires = (VectorWire<Target, VLEN>, Array<Target, PAD_LEN>);

            fn build(c: &mut CircuitBuilder<F, D>) -> Self::Wires {
                let vec = VectorWire::new(c);
                let exp_out = Array::<Target, PAD_LEN>::new(c);
                let comp_out: Array<Target, PAD_LEN> = vec.normalize_left(c);
                exp_out.enforce_equal(c, &comp_out);
                (vec, exp_out)
            }

            fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
                wires.0.assign(pw, &self.input);
                wires.1.assign_bytes(pw, &self.exp);
            }
        }

        {
            const VLEN: usize = 4;
            const PAD: usize = 4;
            let inp = [77, 66, 55];
            let exp = [00, 77, 66, 55];
            run_circuit::<F, D, C, _>(TestNormalizeLeft::<VLEN, PAD> {
                input: Vector::from_vec(&inp.to_vec()).unwrap(),
                exp,
            });
        }
        {
            const VLEN: usize = 7;
            const PAD: usize = 5;
            let real_len = 4;
            let real_data = random_vector(real_len);
            // create a vector where the rest of the buffer is filled with garbage, since
            // it is not enforced in circuit what is left _after_ the buffer is zero, this prover
            // does it but it can be anything.
            let inp = Vector {
                arr: real_data
                    .iter()
                    .copied()
                    .chain(std::iter::repeat_with(|| thread_rng().gen()))
                    .take(VLEN)
                    .collect::<Vec<_>>()
                    .try_into()
                    .unwrap(),
                real_len,
            };
            let exp = left_pad::<PAD>(&real_data);
            run_circuit::<F, D, C, _>(TestNormalizeLeft::<VLEN, PAD> { input: inp, exp });
        }
    }
}
