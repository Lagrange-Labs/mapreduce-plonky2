//! MPT key gadget

use crate::{
    array::Array,
    keccak::PACKED_HASH_LEN,
    rlp::MAX_KEY_NIBBLE_LEN,
    utils::{less_than, less_than_or_equal_to_unsafe},
};
use core::array::from_fn as create_array;
use eth_trie::Nibbles;
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
use serde::{Deserialize, Serialize};

pub type MPTKeyWire = MPTKeyWireGeneric<MAX_KEY_NIBBLE_LEN>;

/// Calculate the pointer from the MPT key.
pub fn mpt_key_ptr(mpt_key: &[u8]) -> usize {
    let nibbles = Nibbles::from_compact(mpt_key);
    MAX_KEY_NIBBLE_LEN - 1 - nibbles.nibbles().len()
}

/// A structure that keeps a running pointer to the portion of the key the circuit
/// already has proven.
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct MPTKeyWireGeneric<const KEY_LENGTH: usize> {
    /// Represents the full key of the value(s) we're looking at in the MPT trie.
    pub key: Array<Target, KEY_LENGTH>,
    /// Represents which portion of the key we already processed. The pointer
    /// goes _backwards_ since circuit starts proving from the leaf up to the root.
    /// i.e. pointer must be equal to F::NEG_ONE when we reach the root.
    pub pointer: Target,
}

impl<const KEY_LENGTH: usize> MPTKeyWireGeneric<KEY_LENGTH> {
    pub fn current_nibble<F: RichField + Extendable<D>, const D: usize>(
        &self,
        b: &mut CircuitBuilder<F, D>,
    ) -> Target {
        self.key.value_at(b, self.pointer)
    }

    /// move the pointer to the next nibble. In this implementation it is the
    /// _previous_ nibble since we are proving from bottom to up in the trie.
    pub fn advance_by<F: RichField + Extendable<D>, const D: usize>(
        &self,
        b: &mut CircuitBuilder<F, D>,
        len: Target,
    ) -> Self {
        Self {
            key: self.key.clone(),
            pointer: b.sub(self.pointer, len),
        }
    }

    /// Returns self if condition is true, otherwise returns other.
    /// NOTE: it is expected the two keys are the same, it always return
    /// the key from `self`. Only the pointer is selected.
    pub fn select<F: RichField + Extendable<D>, const D: usize>(
        &self,
        b: &mut CircuitBuilder<F, D>,
        condition: BoolTarget,
        other: &Self,
    ) -> Self {
        Self {
            key: self.key.clone(),
            pointer: b.select(condition, self.pointer, other.pointer),
        }
    }

    /// Create a new fresh key wire
    pub fn new<F: RichField + Extendable<D>, const D: usize>(b: &mut CircuitBuilder<F, D>) -> Self {
        Self {
            key: Array::<Target, KEY_LENGTH>::new(b),
            pointer: b.add_virtual_target(),
        }
    }
    /// Assign the key wire to the circuit.
    pub fn assign<F: RichField>(
        &self,
        p: &mut PartialWitness<F>,
        key_nibbles: &[u8; KEY_LENGTH],
        ptr: usize,
    ) {
        let f_nibbles = create_array(|i| F::from_canonical_u8(key_nibbles[i]));
        self.key.assign(p, &f_nibbles);
        p.set_target(self.pointer, F::from_canonical_usize(ptr));
    }

    /// Proves the prefix of this key and other's key up to pointer, not included,
    /// are the same and check both pointers are the same.
    /// i.e. check self.key[0..self.pointer] == other.key[0..other.pointer]
    /// Note how it's not `0..=self.pointer`, we check up to pointer excluded.
    pub fn enforce_prefix_equal<F: RichField + Extendable<D>, const D: usize>(
        &self,
        b: &mut CircuitBuilder<F, D>,
        other: &Self,
    ) {
        b.connect(self.pointer, other.pointer);
        self.key.enforce_slice_equals(b, &other.key, self.pointer);
    }
    /// Similar to `enforce_prefix_equal` but returns a boolean target instead
    /// of enforcing the equality.
    pub fn is_prefix_equal<F: RichField + Extendable<D>, const D: usize>(
        &self,
        b: &mut CircuitBuilder<F, D>,
        other: &Self,
    ) -> BoolTarget {
        let ptr_equal = b.is_equal(self.pointer, other.pointer);
        let key_equal = self.key.is_slice_equals(b, &other.key, self.pointer);
        b.and(ptr_equal, key_equal)
    }

    /// Register the key and pointer as public inputs.
    pub fn register_as_input<F: RichField + Extendable<D>, const D: usize>(
        &self,
        b: &mut CircuitBuilder<F, D>,
    ) {
        self.key.register_as_public_input(b);
        b.register_public_input(self.pointer);
    }

    /// Initialize a new MPTKeyWire from the array of `U32Target`.
    /// It returns a MPTKeyWire with the pointer set to the last nibble, as in an initial
    /// case.
    pub fn init_from_u32_targets<F: RichField + Extendable<D>, const D: usize>(
        b: &mut CircuitBuilder<F, D>,
        arr: &Array<U32Target, PACKED_HASH_LEN>,
    ) -> Self {
        Self {
            key: Array {
                arr: arr
                    .arr
                    .iter()
                    .flat_map(|u32_limb| {
                        // decompose the `U32Target` in 16 limbs of 2 bits each; the output limbs are already range-checked
                        // by the `split_le_base` operation
                        let limbs: [Target; 16] =
                            b.split_le_base::<4>(u32_limb.0, 16).try_into().unwrap();
                        // now we need to pack each pair of 2 bit limbs into a nibble, but for each byte we want nibbles to
                        // be ordered in big-endian
                        limbs
                            .chunks_exact(4)
                            .flat_map(|chunk| {
                                vec![
                                    b.mul_const_add(F::from_canonical_u8(4), chunk[3], chunk[2]),
                                    b.mul_const_add(F::from_canonical_u8(4), chunk[1], chunk[0]),
                                ]
                            })
                            .collect::<Vec<_>>()
                    })
                    .collect::<Vec<_>>()
                    .try_into()
                    .unwrap(),
            },
            pointer: b.constant(F::from_canonical_usize(KEY_LENGTH - 1)),
        }
    }

    /// This function folds the MPT Key down into a single value, it is used in receipts to recover the transaction index.
    pub fn fold_key<F: RichField + Extendable<D>, const D: usize>(
        &self,
        b: &mut CircuitBuilder<F, D>,
    ) -> Target {
        let t = b._true();
        let zero = b.zero();
        let one = b.one();

        // First we check that the pointer is at most 15, other wise the result will not fit in a Target
        // (without overflow)
        let sixteen = b.constant(F::from_canonical_u8(16));
        let check = less_than(b, self.pointer, sixteen, 5);
        b.connect(check.target, t.target);

        // We have to check if the first two nibbles sum to precisely 128, we should
        // always have at least two nibbles otherwise the key was empty.
        let first_nibbles = &self.key.arr[..2];
        let tmp = b.mul(first_nibbles[0], sixteen);
        let tmp = b.add(tmp, first_nibbles[1]);

        let one_two_eight = b.constant(F::from_canonical_u8(128));

        let first_byte_128 = b.is_equal(one_two_eight, tmp);

        // If the pointer is 1 then we should make sure we return zero as the value
        let pointer_is_one = b.is_equal(self.pointer, one);
        let byte_selector = b.and(pointer_is_one, first_byte_128);

        let initial = b.select(byte_selector, zero, tmp);

        let combiner = b.constant(F::from_canonical_u32(1u32 << 8));
        // We fold over the remaining nibbles of the key
        self.key
            .arr
            .chunks(2)
            .enumerate()
            .skip(1)
            .fold(initial, |acc, (i, chunk)| {
                // First we multiply the accumulator by 2^8, then recreate the current byte by multiplying the large_nibble by 16 and adding the current small_nibble
                let tmp = b.mul(chunk[0], sixteen);
                let tmp = b.add(tmp, chunk[1]);

                let tmp_acc = b.mul(acc, combiner);
                let tmp = b.add(tmp_acc, tmp);

                // Convert the index to a target
                let index = b.constant(F::from_canonical_usize(2 * i));

                // If the index is lees than the pointer we return tmp, otherwise we return acc.
                let selector = less_than_or_equal_to_unsafe(b, index, self.pointer, 8);
                b.select(selector, tmp, acc)
            })
    }
}
