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

use crate::utils::{less_than_or_equal_to, IntTargetWriter};

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
#[derive(Clone, Debug)]
pub struct Vector<const MAX_LEN: usize> {
    // hardcoding to be bytes srently only use case
    pub arr: [u8; MAX_LEN],
    pub real_len: usize,
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
}
impl<const MAX_LEN: usize> Vector<MAX_LEN> {
    pub fn assign<F: RichField>(&self, pw: &mut PartialWitness<F>, wire: &VectorWire<MAX_LEN>) {
        pw.set_target(wire.real_len, F::from_canonical_usize(self.real_len));
        // small hack to specialize Array for assigning u8 inside
        // TODO: find a more elegant / generic way to assign any value into an Array
        pw.set_int_targets(&wire.arr.arr, &self.arr);
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
    pub fn new<F: RichField + Extendable<D>, const D: usize>(b: &mut CircuitBuilder<F, D>) -> Self {
        Self {
            arr: core::array::from_fn(|_| T::from_target(b.add_virtual_target())),
        }
    }
    pub fn assign<F: RichField + Extendable<D>, const D: usize>(
        &self,
        pw: &mut PartialWitness<F>,
        array: &[F; SIZE],
    ) {
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
        condition: BoolTarget,
        other: &Self,
        b: &mut CircuitBuilder<F, D>,
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
    pub fn contains_subarray<F: RichField + Extendable<D>, const D: usize, const SUB: usize>(
        &self,
        b: &mut CircuitBuilder<F, D>,
        sub: &Array<T, SUB>,
        at: Target,
    ) -> BoolTarget {
        let extracted = self.extract_array::<F, D, SUB>(b, at);
        sub.equals(b, &extracted)
    }

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

    pub fn value_at<F: RichField + Extendable<D>, const D: usize>(
        &self,
        b: &mut CircuitBuilder<F, D>,
        at: Target,
    ) -> T {
        if SIZE < RANDOM_ACCESS_SIZE {
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
            target::Target,
            witness::{PartialWitness, WitnessWrite},
        },
        plonk::{circuit_builder::CircuitBuilder, config::{PoseidonGoldilocksConfig, GenericConfig}},
    };
    use rand::{thread_rng, Rng};

    use crate::{
        array::Array,
        circuit::{test::test_simple_circuit, UserCircuit},
    };
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

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
        const SIZE: usize = 80;
        const SUBSIZE: usize = 40;
        #[derive(Clone, Debug)]
        struct ContainsSubarrayCircuit {
            arr: [u8; SIZE],
            idx: usize,
            exp: [u8; SUBSIZE],
        }
        impl<F, const D: usize> UserCircuit<F, D> for ContainsSubarrayCircuit
        where
            F: RichField + Extendable<D>,
        {
            type Wires = (Array<Target, SIZE>, Target, Array<Target, SUBSIZE>);
            fn build(c: &mut CircuitBuilder<F, D>) -> Self::Wires {
                let array = Array::<Target, SIZE>::new(c);
                let index = c.add_virtual_target();
                let sub = Array::<Target, SUBSIZE>::new(c);
                let contains = array.contains_subarray::<_, _, SUBSIZE>(c, &sub, index);
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
        let mut arr = [0u8; SIZE];
        rng.fill(&mut arr[..]);
        let idx: usize = rng.gen_range(0..(SIZE - SUBSIZE));
        let exp = create_array(|i| arr[idx + i]);
        test_simple_circuit::<F,D,C,_>(ContainsSubarrayCircuit { arr, idx, exp });
    }
}
