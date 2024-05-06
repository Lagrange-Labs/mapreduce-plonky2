//! MPT key gadget

use crate::{array::Array, keccak::PACKED_HASH_LEN, rlp::MAX_KEY_NIBBLE_LEN};
use core::array::from_fn as create_array;
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

/// A structure that keeps a running pointer to the portion of the key the circuit
/// already has proven.
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct MPTKeyWire {
    /// Represents the full key of the value(s) we're looking at in the MPT trie.
    pub key: Array<Target, MAX_KEY_NIBBLE_LEN>,
    /// Represents which portion of the key we already processed. The pointer
    /// goes _backwards_ since circuit starts proving from the leaf up to the root.
    /// i.e. pointer must be equal to F::NEG_ONE when we reach the root.
    pub pointer: Target,
}

impl MPTKeyWire {
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
            key: Array::<Target, MAX_KEY_NIBBLE_LEN>::new(b),
            pointer: b.add_virtual_target(),
        }
    }
    /// Assign the key wire to the circuit.
    pub fn assign<F: RichField>(
        &self,
        p: &mut PartialWitness<F>,
        key_nibbles: &[u8; MAX_KEY_NIBBLE_LEN],
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
                            .chunks(4)
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
            pointer: b.constant(F::from_canonical_usize(MAX_KEY_NIBBLE_LEN - 1)),
        }
    }
}
