use anyhow::{anyhow, Result};
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::{
        target::{BoolTarget, Target},
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::circuit_builder::CircuitBuilder,
};
use plonky2_crypto::u32::arithmetic_u32::U32Target;
use std::{fmt::Debug, ops::Index};

use crate::utils::{less_than, less_than_or_equal_to, IntTargetWriter};

/// ArrayWire contains the wires representing an array of dynamic length
/// up to MAX_LEN. This is useful when you don't know the exact size in advance
/// of your data, for example in hashing MPT nodes.
#[derive(Debug, Clone)]
pub struct VectorWire<const MAX_LEN: usize> {
    pub arr: Array<Target, MAX_LEN>,
    pub real_len: Target,
}

/// A fixed buffer array containing dynammic length data, the equivalent of
/// `ArrayWire` outside circuit.
#[derive(Clone, Debug, Copy)]
pub struct Vector<const MAX_LEN: usize> {
    // hardcoding to be bytes srently only use case
    pub arr: [u8; MAX_LEN],
    pub real_len: usize,
}

impl<const MAX_LEN: usize> Vector<MAX_LEN> {
    pub fn from_vec(mut d: Vec<u8>) -> Result<Self> {
        let len = d.len();
        d.resize(MAX_LEN, 0);
        Ok(Self {
            arr: d.try_into().map_err(|e| anyhow!("{:?}", e))?,
            real_len: len,
        })
    }
}

impl<const SIZE: usize> Index<usize> for VectorWire<SIZE> {
    type Output = Target;
    fn index(&self, index: usize) -> &Self::Output {
        self.arr.index(index)
    }
}

impl<const MAX_LEN: usize> VectorWire<MAX_LEN> {
    pub fn new<F, const D: usize>(b: &mut CircuitBuilder<F, D>) -> Self
    where
        F: RichField + Extendable<D>,
    {
        let real_len = b.add_virtual_target();
        let arr = Array::<Target, MAX_LEN>::new(b);
        Self { arr, real_len }
    }
    pub fn assign<F: RichField>(&self, pw: &mut PartialWitness<F>, value: &Vector<MAX_LEN>) {
        pw.set_target(self.real_len, F::from_canonical_usize(value.real_len));
        // small hack to specialize Array for assigning u8 inside
        // TODO: find a more elegant / generic way to assign any value into an Array
        pw.set_int_targets(&self.arr.arr, &value.arr);
    }
}

/// Fixed size array in circuit of any type (Target or U32Target for example!)
/// of N elements.
#[derive(Clone, Debug)]
pub struct Array<T, const N: usize> {
    pub(crate) arr: [T; N],
}

impl<T, const N: usize> From<[T; N]> for Array<T, N> {
    fn from(value: [T; N]) -> Self {
        Self { arr: value }
    }
}
impl<T: Debug, const N: usize> TryFrom<Vec<T>> for Array<T, N> {
    type Error = anyhow::Error;
    fn try_from(value: Vec<T>) -> Result<Self> {
        Ok(Self {
            arr: value
                .try_into()
                .map_err(|e| anyhow!("can't conver to array: {:?}", e))?,
        })
    }
}

/// Small wrapper trait to handle Target and U32Target in a similar way for arrays
pub trait Targetable {
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

impl<T, const SIZE: usize> Index<usize> for Array<T, SIZE> {
    type Output = T;
    fn index(&self, index: usize) -> &Self::Output {
        self.arr.index(index)
    }
}

impl<T: Targetable, const SIZE: usize> Array<T, SIZE> {
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

    /// Assigns each value in the given array to the respective wire in `self`
    pub fn assign<F: RichField>(&self, pw: &mut PartialWitness<F>, array: &[F; SIZE]) {
        #[allow(clippy::needless_range_loop)]
        for i in 0..SIZE {
            pw.set_target(self.arr[i].to_target(), array[i])
        }
    }
    pub fn register_as_public_input<F: RichField + Extendable<D>, const D: usize>(
        &self,
        b: &mut CircuitBuilder<F, D>,
    ) {
        b.register_public_inputs(&self.arr.iter().map(|v| v.to_target()).collect::<Vec<_>>());
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
        sub: &VectorWire<SUB>,
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
            let are_equal = b.is_equal(original_value.to_target(), sub.arr.arr[i]);
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

    /// Returns self[at..at+SUB_SIZE].
    /// Cost is O(SIZE * SIZE) due to SIZE calls to value_at()
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
        }
        // Otherwise, need to make it manually
        let mut nums: Vec<Target> = vec![];
        for (i, el) in self.arr.iter().enumerate() {
            let i_target = b.constant(F::from_canonical_usize(i));
            let is_eq = b.is_equal(i_target, at);
            // (i == n (idx) ) * element
            let product = b.mul(is_eq.target, el.to_target());
            nums.push(product);
        }
        // SUM_i (i == n (idx) ) * element
        // -> sum = element
        T::from_target(b.add_many(&nums))
    }
}
impl<const SIZE: usize> Array<Target, SIZE>
where
    [(); SIZE / 4]:,
{
    pub fn convert_u8_to_u32<F: RichField + Extendable<D>, const D: usize>(
        &self,
        b: &mut CircuitBuilder<F, D>,
    ) -> Array<U32Target, { SIZE / 4 }> {
        const TWO_POWER_8: usize = 256;
        const TWO_POWER_16: usize = 65536;
        const TWO_POWER_24: usize = 16777216;

        // constants to convert [u8; 4] to u32
        // u32 = u8[0] + u8[1] * 2^8 + u8[2] * 2^16 + u8[3] * 2^24
        let two_power_8: Target = b.constant(F::from_canonical_usize(TWO_POWER_8));
        let two_power_16: Target = b.constant(F::from_canonical_usize(TWO_POWER_16));
        let two_power_24: Target = b.constant(F::from_canonical_usize(TWO_POWER_24));

        // convert padded node to u32
        Array::<U32Target, { SIZE / 4 }> {
            arr: (0..SIZE)
                .step_by(4)
                .map(|i| {
                    // u8[0]
                    let mut x = self.arr[i];
                    // u8[1]
                    let mut y = self.arr[i + 1];
                    // u8[1] * 2^8
                    y = b.mul(y, two_power_8);
                    // u8[0] + u8[1] * 2^8
                    x = b.add(x, y);
                    // u8[2]
                    y = self.arr[i + 2];
                    // u8[2] * 2^16
                    y = b.mul(y, two_power_16);
                    // u8[0] + u8[1] * 2^8 + u8[2] * 2^16
                    x = b.add(x, y);
                    // u8[3]
                    y = self.arr[i + 3];
                    // u8[3] * 2^24
                    y = b.mul(y, two_power_24);
                    // u8[0] + u8[1] * 2^8 + u8[2] * 2^16 + u8[3] * 2^24
                    x = b.add(x, y);

                    U32Target(x)
                })
                .collect::<Vec<_>>()
                .try_into()
                .unwrap(),
        }
    }
}

//impl<const SIZE:usize> Array<Target,SIZE> {
//    /// extracts a variable length array from this array. The MAX_SUB_SIZE is
//     /// the maximum number of target elements will be extracted into the vector.
//    /// The real_len is used for the VectorWire returned to operate correcctly.
//    /// The difference with extract_array is that extract_array always assume the
//    /// returned array contains data up to the end of the array, which is useful
//    /// when one knows the exact length of data one needs to extract.
//    pub fn extract_vector<
//        F: RichField + Extendable<D>,
//        const D: usize,
//        const MAX_SUB_SIZE: usize,
//    >(
//        &self,
//        b: &mut CircuitBuilder<F, D>,
//        at: Target,
//        real_len: Target,
//    ) -> VectorWire<MAX_SUB_SIZE> {
//        VectorWire {
//            arr: self.extract_array::<F, D, MAX_SUB_SIZE>(b, at),
//            real_len,
//        }
//    }
//}

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

    use crate::{
        array::{Array, Vector, VectorWire},
        circuit::{test::test_simple_circuit, UserCircuit},
        utils::{convert_u8_to_u32_slice, find_index_subvector},
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
        test_simple_circuit::<F, D, C, _>(SelectCircuit {
            arr,
            arr2,
            cond: true,
        });
        test_simple_circuit::<F, D, C, _>(SelectCircuit {
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
            [(); S / 4]:,
        {
            arr: [u8; S],
        }
        impl<F, const D: usize, const S: usize> UserCircuit<F, D> for ConvertCircuit<S>
        where
            F: RichField + Extendable<D>,
            [(); S / 4]:,
        {
            type Wires = (Array<Target, S>, Array<U32Target, { S / 4 }>);
            fn build(c: &mut CircuitBuilder<F, D>) -> Self::Wires {
                let array = Array::<Target, S>::new(c);
                let tou32 = array.convert_u8_to_u32(c);
                let exp_u32 = Array::<U32Target, { S / 4 }>::new(c);
                let tr = c._true();
                let f = tou32.equals(c, &exp_u32);
                c.connect(f.target, tr.target);
                (array, exp_u32)
            }
            fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
                wires
                    .0
                    .assign(pw, &create_array(|i| F::from_canonical_u8(self.arr[i])));
                let u32arr: [F; S / 4] = convert_u8_to_u32_slice(&self.arr)
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
        test_simple_circuit::<F, D, C, _>(ConvertCircuit { arr });
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
        test_simple_circuit::<F, D, C, _>(ValueAtCircuit { arr, idx, exp });
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
        test_simple_circuit::<F, D, C, _>(ExtractArrayCircuit { arr, idx, exp });
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
            test_simple_circuit::<F, D, C, _>(ContainsSubarrayCircuit::<SIZE, SUBSIZE> {
                arr,
                idx,
                exp,
            });
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
            test_simple_circuit::<F, D, C, _>(ContainsSubarrayCircuit::<SIZE, SUBSIZE> {
                arr: node.try_into().unwrap(),
                idx,
                exp: child_hash.try_into().unwrap(),
            });

            //println!("len node = {}", node.len());
            //println!("len child = {}", child_hash.len());
            //println!("idx = {}", idx);
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
            type Wires = (Array<Target, SIZE>, Target, VectorWire<SIZE>, BoolTarget);
            fn build(c: &mut CircuitBuilder<F, D>) -> Self::Wires {
                let array = Array::<Target, SIZE>::new(c);
                let index = c.add_virtual_target();
                let expected = c.add_virtual_bool_target_safe();
                let subvector = VectorWire::<SIZE>::new(c);
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
                    .assign(pw, &Vector::<SIZE>::from_vec(self.sub.clone()).unwrap());
                pw.set_bool_target(wires.3, self.exp);
            }
        }
        let mut rng = thread_rng();
        let mut arr = [0u8; SIZE];
        rng.fill(&mut arr[..]);
        let random_size: usize = rng.gen_range(1..SIZE);
        let idx: usize = rng.gen_range(0..(SIZE - random_size));
        let sub = arr[idx..idx + random_size].to_vec();

        test_simple_circuit::<F, D, C, _>(ContainsVectorCircuit {
            arr,
            idx: 0,
            sub: arr.to_vec(),
            exp: true,
        });
        test_simple_circuit::<F, D, C, _>(ContainsVectorCircuit {
            arr,
            idx,
            sub,
            exp: true,
        });
        test_simple_circuit::<F, D, C, _>(ContainsVectorCircuit {
            arr,
            idx,
            sub: (0..random_size).map(|_| rng.gen()).collect::<Vec<_>>(),
            exp: false,
        });
    }
}
