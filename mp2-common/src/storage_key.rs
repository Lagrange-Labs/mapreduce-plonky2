//! Module handling the recursive proving of the correct derivation of the MPT path
//! depending on the type of variables the slot is holding (simple unit variable like uint256
//! variable length & composite type like a mapping).

use crate::{
    array::{Array, Vector, VectorWire},
    eth::{left_pad32, StorageSlot},
    keccak::{ByteKeccakWires, InputData, KeccakCircuit, KeccakWires, HASH_LEN},
    mpt_sequential::{MPTKeyWire, PAD_LEN},
    serialization::circuit_data_serialization::SerializableRichField,
    types::{MAPPING_KEY_LEN, MAPPING_LEAF_VALUE_LEN},
    u256::{CircuitBuilderU256, UInt256Target},
    utils::{
        keccak256, unpack_u32_to_u8_target, unpack_u32_to_u8_targets, Endianness, PackerTarget,
        ToTargets,
    },
};
use alloy::primitives::{B256, U256};
use itertools::Itertools;
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::circuit_builder::CircuitBuilder,
};
use plonky2_crypto::u32::arithmetic_u32::{CircuitBuilderU32, U32Target};
use serde::{Deserialize, Serialize};
use std::{
    array,
    iter::{once, repeat},
};

/// One input element length to Keccak
const INPUT_ELEMENT_LEN: usize = 32;
/// The tuple (pair) length of elements to Keccak
const INPUT_TUPLE_LEN: usize = 2 * INPUT_ELEMENT_LEN;
/// The whole padded length for the inputs
const INPUT_PADDED_LEN: usize = PAD_LEN(INPUT_TUPLE_LEN);

/// Wires associated with the MPT key from the Keccak computation of location
// It's only used for mapping slot.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct KeccakMPTWires {
    /// Actual Keccak wires created for the computation of the base for the storage slot
    pub keccak_base: ByteKeccakWires<INPUT_PADDED_LEN>,
    /// Actual Keccak wires created for the computation of the final MPT key
    /// from the location. this is the one to use to look up a key in the
    /// associated MPT trie.
    pub keccak_mpt_key: KeccakWires<{ PAD_LEN(HASH_LEN) }>,
    /// The MPT key derived in circuit from the storage slot in nibbles
    /// TODO: it represents the same information as "exp" but in nibbles.
    /// It doesn't need to be assigned, but is used in the higher level circuits
    pub mpt_key: MPTKeyWire,
}

// The Keccak MPT computation
// It's only used for mapping slot.
struct KeccakMPT;

impl KeccakMPT {
    /// Build the Keccak MPT with no offset (offset = 0).
    fn build<F: RichField + Extendable<D>, const D: usize>(
        b: &mut CircuitBuilder<F, D>,
        inputs: VectorWire<Target, INPUT_PADDED_LEN>,
    ) -> KeccakMPTWires {
        let keccak_base = KeccakCircuit::<{ INPUT_PADDED_LEN }>::hash_to_bytes(b, &inputs);
        let location_offset = keccak_base.output.arr;

        Self::build_location(b, keccak_base, location_offset)
    }

    /// Build the Keccak MPT with a specified offset of Uint32.
    fn build_with_offset<F: SerializableRichField<D> + Extendable<D>, const D: usize>(
        b: &mut CircuitBuilder<F, D>,
        inputs: VectorWire<Target, INPUT_PADDED_LEN>,
        offset: Target,
    ) -> KeccakMPTWires {
        // location = keccak(inputs) + offset
        let keccak_base = KeccakCircuit::<{ INPUT_PADDED_LEN }>::hash_to_bytes(b, &inputs);
        let base = keccak_base.output.arr.pack(b, Endianness::Big);
        let base = UInt256Target::new_from_be_target_limbs(&base).unwrap();
        let offset = UInt256Target::new_from_target_unsafe(b, offset);
        let (location, overflow) = b.add_u256(&base, &offset);
        b.assert_zero(overflow.0);
        let location = unpack_u32_to_u8_targets(b, location.to_targets(), Endianness::Big)
            .try_into()
            .unwrap();

        KeccakMPT::build_location(b, keccak_base, location)
    }

    fn build_location<F: RichField + Extendable<D>, const D: usize>(
        b: &mut CircuitBuilder<F, D>,
        keccak_base: ByteKeccakWires<INPUT_PADDED_LEN>,
        location: [Target; HASH_LEN],
    ) -> KeccakMPTWires {
        // keccak(location)
        let zero = b.zero();
        let arr = repeat(zero)
            .take(PAD_LEN(HASH_LEN) - HASH_LEN)
            .chain(location)
            .collect_vec()
            .try_into()
            .unwrap();
        let hash_len = b.constant(F::from_canonical_usize(HASH_LEN));
        let keccak_mpt_key = KeccakCircuit::<{ PAD_LEN(HASH_LEN) }>::hash_vector(
            b,
            &VectorWire {
                real_len: hash_len,
                arr: Array { arr },
            },
        );

        // Make sure we transform from the bytes to the nibbles.
        // TODO: actually maybe better to give the nibbles directly and pack
        // them into U32 in one go. For the future...
        let mpt_key = MPTKeyWire::init_from_u32_targets(b, &keccak_mpt_key.output_array);

        KeccakMPTWires {
            keccak_base,
            keccak_mpt_key,
            mpt_key,
        }
    }

    fn assign<F: RichField>(
        pw: &mut PartialWitness<F>,
        wires: &KeccakMPTWires,
        inputs: Vec<u8>,
        base: [u8; HASH_LEN],
        offset: u32,
    ) {
        // Assign the Keccak necessary values for base.
        KeccakCircuit::<{ INPUT_PADDED_LEN }>::assign_byte_keccak(
            pw,
            &wires.keccak_base,
            // No need to create a new input wire array since we create it in circuit.
            &InputData::Assigned(
                &Vector::from_vec(&inputs).expect("Can't create vector input for keccak_location"),
            ),
        );

        // location = keccak_base + offset
        let location = U256::from_be_bytes(base)
            .checked_add(U256::from(offset))
            .expect("Keccak base plus offset is overflow for location computation");
        let location: [_; HASH_LEN] = location.to_be_bytes();
        // Assign the keccak necessary values for Keccak MPT:
        // keccak(location)
        KeccakCircuit::<{ PAD_LEN(HASH_LEN) }>::assign(
            pw,
            &wires.keccak_mpt_key,
            &InputData::Assigned(
                &Vector::from_vec(&location).expect("Can't create vector input for keccak_mpt"),
            ),
        )
    }
}

/// Circuit gadget that proves the correct derivation of a MPT key from a simple
/// storage slot.
/// Deriving a MPT key from simple slot is done like:
/// 1. location = left_pad32(slot)
/// 2. mpt_key = keccak(location)
/// WARNING: Currently takes the assumption that the storage slot number fits
/// inside a single byte.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SimpleSlot(pub StorageSlot);

impl SimpleSlot {
    pub fn new(slot: u8) -> Self {
        Self(StorageSlot::Simple(slot as usize))
    }
}

impl From<StorageSlot> for SimpleSlot {
    /// NOTE it can panic - TODO refactor whole slot API to have a single enum
    /// that can deal with both types (and more complex later on)
    fn from(value: StorageSlot) -> Self {
        match value {
            StorageSlot::Simple(slot) if slot <= u8::MAX as usize => SimpleSlot::new(slot as u8),
            _ => panic!("Unvalid use of SimpleSlot"),
        }
    }
}

/// Wires associated with the MPT key derivation logic of simple storage slot
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SimpleSlotWires {
    /// Simple storage slot which is assumed to fit in a single byte
    pub slot: Target,
    /// Wires associated computing the keccak for the MPT key
    pub keccak_mpt: KeccakWires<{ PAD_LEN(INPUT_ELEMENT_LEN) }>,
    /// The MPT key derived in circuit from the storage slot, in NIBBLES
    /// TODO: It doesn't need to be assigned, but is used in the higher level circuits
    pub mpt_key: MPTKeyWire,
}

// TODO: refactor to extract common functions with MappingSlot.
impl SimpleSlot {
    /// Derive the MPT key in circuit according to simple storage slot.
    /// Remember the rules to get the MPT key is as follow:
    /// * location = pad32(slot)
    /// * mpt_key = keccak256(location)
    /// Note the simple slot wire and the contract address wires are NOT range
    /// checked, because they are expected to be given by the verifier.
    /// If that assumption is not true, then the caller should call
    /// `b.range_check(slot, 8)` to ensure its byteness.
    pub fn build<F: RichField + Extendable<D>, const D: usize>(
        b: &mut CircuitBuilder<F, D>,
    ) -> SimpleSlotWires {
        let zero = b.zero();
        let slot = b.add_virtual_target();
        let location = repeat(zero)
            .take(INPUT_ELEMENT_LEN - 1)
            .chain(once(slot))
            .collect_vec()
            .try_into()
            .unwrap();
        // Build the Keccak MPT.
        let keccak_mpt = Self::build_keccak_mpt(b, location);
        // Transform the MPT key to nibbles.
        let mpt_key = MPTKeyWire::init_from_u32_targets(b, &keccak_mpt.output_array);

        SimpleSlotWires {
            slot,
            keccak_mpt,
            mpt_key,
        }
    }

    /// Derive the MPT key with a specified offset in circuit according to simple storage slot.
    /// The rules to get the MPT key with offset is as follow:
    /// location = left_pad32(slot) + offset
    /// mpt_key = keccak256(location)
    /// Note the simple slot wire and the contract address wires are NOT range
    /// checked, because they are expected to be given by the verifier.
    /// If that assumption is not true, then the caller should call
    /// `b.range_check(slot, 8)` to ensure its byteness.
    pub fn build_with_offset<F: RichField + Extendable<D>, const D: usize>(
        b: &mut CircuitBuilder<F, D>,
        offset: Target,
    ) -> SimpleSlotWires {
        let zero = b.zero();
        let slot = b.add_virtual_target();
        // We assume the offset and addition must be within the range of Uint32:
        // addition = offset + slot
        let (addition, overflow) = b.add_u32(U32Target(offset), U32Target(slot));
        b.assert_zero(overflow.0);
        let addition = unpack_u32_to_u8_target(b, addition.0, Endianness::Big);
        let location = repeat(zero)
            .take(INPUT_ELEMENT_LEN - addition.len())
            .chain(addition)
            .collect_vec()
            .try_into()
            .unwrap();
        // Build the Keccak MPT.
        let keccak_mpt = Self::build_keccak_mpt(b, location);
        // Transform the MPT key to nibbles.
        let mpt_key = MPTKeyWire::init_from_u32_targets(b, &keccak_mpt.output_array);

        SimpleSlotWires {
            slot,
            keccak_mpt,
            mpt_key,
        }
    }

    /// Build the Keccak MPT.
    fn build_keccak_mpt<F: RichField + Extendable<D>, const D: usize>(
        b: &mut CircuitBuilder<F, D>,
        location: [Target; INPUT_ELEMENT_LEN],
    ) -> KeccakWires<INPUT_PADDED_LEN> {
        // keccak(location)
        let zero = b.zero();
        let arr = location
            .into_iter()
            .chain(repeat(zero).take(INPUT_PADDED_LEN - INPUT_ELEMENT_LEN))
            .collect_vec()
            .try_into()
            .unwrap();
        let inputs = VectorWire::<Target, INPUT_PADDED_LEN> {
            real_len: b.constant(F::from_canonical_usize(INPUT_ELEMENT_LEN)),
            arr: Array { arr },
        };
        // Build for keccak MPT.
        KeccakCircuit::<INPUT_PADDED_LEN>::hash_vector(b, &inputs)
    }

    pub fn assign<F: RichField>(
        &self,
        pw: &mut PartialWitness<F>,
        wires: &SimpleSlotWires,
        offset: u32,
    ) {
        let slot = match self.0 {
            // Safe downcasting because it's assumed to be u8 in constructor.
            StorageSlot::Simple(slot) => slot as u8,
            _ => panic!("Invalid storage slot type"), // should not happen using constructor
        };
        pw.set_target(wires.slot, F::from_canonical_u8(slot));
        let location = offset
            .checked_add(slot.into())
            .expect("Simple slot plus offset is overflow");
        let inputs = B256::left_padding_from(&location.to_be_bytes()).to_vec();
        KeccakCircuit::assign(
            pw,
            &wires.keccak_mpt,
            // Unwrap safe because input always fixed 32 bytes.
            &InputData::Assigned(&Vector::from_vec(&inputs).unwrap()),
        );
    }
}

/// Circuit gadget that proves the correct derivation of a MPT key from a given mapping slot.
/// Deriving a MPT key from mapping slot is done like:
/// 1. location = keccak(left_pad32(key), left_pad32(slot))
/// 2. mpt_key = keccak(location)
/// WARNING: Currently takes the assumption that the storage slot number fits inside a single byte.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MappingSlot {
    mapping_slot: u8,
    mapping_key: Vec<u8>,
}

impl MappingSlot {
    pub fn new(slot: u8, key: Vec<u8>) -> Self {
        Self {
            mapping_slot: slot,
            mapping_key: key,
        }
    }
}

/// Contains the wires associated with the storage slot's MPT key derivation logic.
/// It's specific only for the mapping slot.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MappingSlotWires {
    /// "input" mapping key which is maxed out at 32 bytes
    pub mapping_key: Array<Target, MAPPING_KEY_LEN>,
    /// "input" mapping slot which is assumed to fit in a single byte
    pub mapping_slot: Target,
    /// Wires associated with the MPT key
    pub keccak_mpt: KeccakMPTWires,
}

/// Contains the wires associated with the MPT key derivation logic of mappings where the value
/// stored in each mapping entry is another mapping (referred to as mapping of mappings).
/// In this case, we refer to the key for the first-layer mapping entry as the outer key,
/// while the key for the mapping stored in the entry mapping is referred to as inner key.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MappingOfMappingsSlotWires {
    /// Mapping slot number which is assumed to fit in a single byte
    pub mapping_slot: Target,
    /// 32 bytes value of the key associated to the node in the mapping
    pub outer_key: Array<Target, MAPPING_KEY_LEN>,
    /// 32 bytes value of the key associated to the second-layer mapping
    /// We are extracting the mapping entry as `mapping[outer_key][inner_key]`.
    pub inner_key: Array<Target, MAPPING_KEY_LEN>,
    /// Keccak computed result referred to the inner mapping slot as
    /// `keccak256(left_pad32(outer_key) || left_pad32(mapping_slot))`
    pub inner_mapping_slot: ByteKeccakWires<INPUT_PADDED_LEN>,
    /// Wires associated with the MPT key
    pub keccak_mpt: KeccakMPTWires,
}

/// Size of the input to the digest and hash function
pub(crate) const MAPPING_INPUT_TOTAL_LEN: usize = MAPPING_KEY_LEN + MAPPING_LEAF_VALUE_LEN;
/// Value but with the padding taken into account.
const MAPPING_INPUT_PADDED_LEN: usize = PAD_LEN(MAPPING_INPUT_TOTAL_LEN);
impl MappingSlot {
    /// Derives the MPT key in circuit according to mapping storage slot
    /// Remember the rules to get the mpt key is as follow:
    /// * location = keccak256(pad32(mapping_key), pad32(mapping_slot))
    /// * mpt_key = keccak256(location)
    /// Note the mapping slot wire is NOT range checked, because it is expected to
    /// be given by the verifier. If that assumption is not true, then the caller
    /// should call `b.range_check(mapping_slot, 8)` to ensure its byteness.
    pub fn mpt_key<F: RichField + Extendable<D>, const D: usize>(
        b: &mut CircuitBuilder<F, D>,
    ) -> MappingSlotWires {
        let mapping_key = Array::<Target, MAPPING_KEY_LEN>::new(b);
        // always ensure whatever goes into hash function, it's bytes
        mapping_key.assert_bytes(b);
        let mapping_slot = b.add_virtual_target();
        let mut input = [b.zero(); MAPPING_INPUT_PADDED_LEN];
        input[0..MAPPING_KEY_LEN].copy_from_slice(&mapping_key.arr);
        input[2 * MAPPING_KEY_LEN - 1] = mapping_slot;

        // keccak(left_pad32(mapping_key), left_pad32(mapping_slot))
        let inputs = VectorWire::<Target, MAPPING_INPUT_PADDED_LEN> {
            real_len: b.constant(F::from_canonical_usize(MAPPING_INPUT_TOTAL_LEN)),
            arr: Array { arr: input },
        };
        // Build for keccak MPT.
        let keccak_mpt = KeccakMPT::build(b, inputs);

        MappingSlotWires {
            mapping_key,
            mapping_slot,
            keccak_mpt,
        }
    }

    /// Derive the MPT key with a specified offset in circuit according to mapping slot
    /// The rules to get the mpt key with offset is as follow:
    /// location = keccak256(pad32(mapping_key), pad32(mapping_slot)) + offset
    /// mpt_key = keccak256(location)
    /// Note the mapping slot wire is NOT range checked, because it is expected to
    /// be given by the verifier. If that assumption is not true, then the caller
    /// should call `b.range_check(mapping_slot, 8)` to ensure its byteness.
    pub fn mpt_key_with_offset<F: SerializableRichField<D> + Extendable<D>, const D: usize>(
        b: &mut CircuitBuilder<F, D>,
        offset: Target,
    ) -> MappingSlotWires {
        let mapping_key = Array::<Target, MAPPING_KEY_LEN>::new(b);
        mapping_key.assert_bytes(b);
        let mapping_slot = b.add_virtual_target();
        let mut input = [b.zero(); MAPPING_INPUT_PADDED_LEN];
        input[0..MAPPING_KEY_LEN].copy_from_slice(&mapping_key.arr);
        input[2 * MAPPING_KEY_LEN - 1] = mapping_slot;

        // keccak(left_pad32(mapping_key), left_pad32(mapping_slot))
        let inputs = VectorWire::<Target, MAPPING_INPUT_PADDED_LEN> {
            real_len: b.constant(F::from_canonical_usize(MAPPING_INPUT_TOTAL_LEN)),
            arr: Array { arr: input },
        };
        // Build for keccak MPT.
        // location = keccak(inputs) + offset
        let keccak_mpt = KeccakMPT::build_with_offset(b, inputs, offset);

        MappingSlotWires {
            mapping_key,
            mapping_slot,
            keccak_mpt,
        }
    }

    /// Derive the MPT key with an inner mapping key and offset in circuit according to
    /// mapping slot.
    /// The rules to get the mpt key with offset is as follow:
    /// inner_mapping_slot = keccak256(left_pad32(outer_key) || left_pad32(mapping_slot))
    /// location = keccak256(left_pad32(inner_key) || inner_mapping_slot) + offset
    /// mpt_key = keccak256(location)
    /// Note the mapping slot wire is NOT range checked, because it is expected to
    /// be given by the verifier. If that assumption is not true, then the caller
    /// should call `b.range_check(mapping_slot, 8)` to ensure its byteness.
    pub fn mpt_key_with_inner_offset<
        F: SerializableRichField<D> + Extendable<D>,
        const D: usize,
    >(
        b: &mut CircuitBuilder<F, D>,
        offset: Target,
    ) -> MappingOfMappingsSlotWires {
        let mapping_slot = b.add_virtual_target();
        let [inner_key, outer_key] = array::from_fn(|_| {
            let key = Array::<Target, MAPPING_KEY_LEN>::new(b);
            key.assert_bytes(b);

            key
        });

        // inner_mapping_slot = keccak256(left_pad32(outer_key) || left_pad32(mapping_slot))
        let mut arr = [b.zero(); MAPPING_INPUT_PADDED_LEN];
        arr[0..MAPPING_KEY_LEN].copy_from_slice(&outer_key.arr);
        arr[2 * MAPPING_KEY_LEN - 1] = mapping_slot;
        let inputs = VectorWire::<Target, MAPPING_INPUT_PADDED_LEN> {
            real_len: b.constant(F::from_canonical_usize(MAPPING_INPUT_TOTAL_LEN)),
            arr: Array { arr },
        };
        let inner_mapping_slot = KeccakCircuit::<{ INPUT_PADDED_LEN }>::hash_to_bytes(b, &inputs);

        // inputs = left_pad32(inner_key) || inner_mapping_slot
        let mut arr = [b.zero(); MAPPING_INPUT_PADDED_LEN];
        arr[..MAPPING_KEY_LEN].copy_from_slice(&inner_key.arr);
        arr[MAPPING_KEY_LEN..2 * MAPPING_KEY_LEN].copy_from_slice(&inner_mapping_slot.output.arr);
        let inputs = VectorWire::<Target, MAPPING_INPUT_PADDED_LEN> {
            real_len: b.constant(F::from_canonical_usize(MAPPING_INPUT_TOTAL_LEN)),
            arr: Array { arr },
        };

        // location = keccak(inputs) + offset
        let keccak_mpt = KeccakMPT::build_with_offset(b, inputs, offset);

        MappingOfMappingsSlotWires {
            mapping_slot,
            inner_key,
            outer_key,
            inner_mapping_slot,
            keccak_mpt,
        }
    }

    pub fn assign_mapping_slot<F: RichField>(
        &self,
        pw: &mut PartialWitness<F>,
        wires: &MappingSlotWires,
        offset: u32,
    ) {
        pw.set_target(wires.mapping_slot, F::from_canonical_u8(self.mapping_slot));

        let padded_slot = left_pad32(&[self.mapping_slot]);
        let mapping_key = left_pad32(&self.mapping_key);
        wires.mapping_key.assign_bytes(pw, &mapping_key);
        // Compute the entire expected array to derive the MPT key:
        // keccak(left_pad32(mapping_key), left_pad32(mapping_slot))
        let inputs = mapping_key.into_iter().chain(padded_slot).collect_vec();
        // Then compute the expected resulting hash for MPT key derivation.
        let base = keccak256(&inputs).try_into().unwrap();
        KeccakMPT::assign(pw, &wires.keccak_mpt, inputs, base, offset);
    }

    pub fn assign_mapping_of_mappings<F: RichField>(
        &self,
        pw: &mut PartialWitness<F>,
        wires: &MappingOfMappingsSlotWires,
        inner_key: &[u8],
        offset: u32,
    ) {
        pw.set_target(wires.mapping_slot, F::from_canonical_u8(self.mapping_slot));

        let padded_slot = left_pad32(&[self.mapping_slot]);
        let outer_key = left_pad32(&self.mapping_key);
        let inner_key = left_pad32(inner_key);
        wires.outer_key.assign_bytes(pw, &outer_key);
        wires.inner_key.assign_bytes(pw, &inner_key);
        // left_pad32(outer_key) || left_pad32(slot)
        let inputs = outer_key.into_iter().chain(padded_slot).collect_vec();
        // Assign the keccak values for inner mapping slot.
        KeccakCircuit::<{ INPUT_PADDED_LEN }>::assign_byte_keccak(
            pw,
            &wires.inner_mapping_slot,
            // No need to create a new input wire array since we create it in circuit.
            &InputData::Assigned(
                &Vector::from_vec(&inputs)
                    .expect("Cannot create vector input for inner mapping slot"),
            ),
        );
        // location = keccak(left_pad32(inner_key) || inner_mapping_slot)
        let inputs = outer_key.into_iter().chain(padded_slot).collect_vec();
        let base = keccak256(&inputs).try_into().unwrap();
        KeccakMPT::assign(pw, &wires.keccak_mpt, inputs, base, offset);
    }
}

#[cfg(test)]
mod test {
    use super::{MappingSlot, MappingSlotWires, SimpleSlot, SimpleSlotWires};
    use crate::{
        array::Array,
        eth::StorageSlot,
        keccak::{HASH_LEN, PACKED_HASH_LEN},
        mpt_sequential::utils::bytes_to_nibbles,
        rlp::MAX_KEY_NIBBLE_LEN,
        utils::{keccak256, Endianness, Packer, ToFields},
        C, D, F,
    };
    use mp2_test::circuit::{run_circuit, UserCircuit};
    use plonky2::{
        field::extension::Extendable,
        hash::hash_types::RichField,
        iop::{target::Target, witness::PartialWitness},
        plonk::circuit_builder::CircuitBuilder,
    };
    use plonky2_crypto::u32::arithmetic_u32::U32Target;

    #[derive(Clone, Debug)]
    struct TestMappingSlot {
        m: MappingSlot,
        // 64 nibbles
        exp_mpt_key_nibbles: Vec<u8>,
        exp_keccak_location: Vec<u8>,
    }
    impl<F, const D: usize> UserCircuit<F, D> for TestMappingSlot
    where
        F: RichField + Extendable<D>,
    {
        type Wires = (
            MappingSlotWires,
            // exp mpt key in nibbles
            Array<Target, MAX_KEY_NIBBLE_LEN>,
            // exp keccak location
            Array<Target, HASH_LEN>,
            // exp mpt key bytes
            Array<U32Target, PACKED_HASH_LEN>,
        );

        fn build(b: &mut CircuitBuilder<F, D>) -> Self::Wires {
            let mapping_slot_wires = MappingSlot::mpt_key(b);
            let exp_key = Array::<Target, MAX_KEY_NIBBLE_LEN>::new(b);
            let good_key = mapping_slot_wires
                .keccak_mpt
                .mpt_key
                .key
                .equals(b, &exp_key);
            let tru = b._true();
            b.connect(tru.target, good_key.target);
            let exp_keccak_location = Array::<Target, HASH_LEN>::new(b);
            let good_keccak_location = mapping_slot_wires
                .keccak_mpt
                .keccak_location
                .output
                .equals(b, &exp_keccak_location);
            b.connect(tru.target, good_keccak_location.target);
            let exp_keccak_mpt = Array::<U32Target, PACKED_HASH_LEN>::new(b);
            let good_keccak_mpt = mapping_slot_wires
                .keccak_mpt
                .keccak_mpt_key
                .output_array
                .equals(b, &exp_keccak_mpt);
            b.connect(tru.target, good_keccak_mpt.target);
            (
                mapping_slot_wires,
                exp_key,
                exp_keccak_location,
                exp_keccak_mpt,
            )
        }

        fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
            // assign the expected mpt key we should see
            wires
                .1
                .assign_bytes(pw, &self.exp_mpt_key_nibbles.clone().try_into().unwrap());
            // assign the  expected location we should see
            wires
                .2
                .assign_bytes(pw, &self.exp_keccak_location.clone().try_into().unwrap());
            let exp_mpt_key_bytes = keccak256(&self.exp_keccak_location);
            wires.3.assign(
                pw,
                &exp_mpt_key_bytes
                    .pack(Endianness::Little)
                    .to_fields()
                    .try_into()
                    .unwrap(),
            );
            self.m.assign(pw, &wires.0);
        }
    }

    #[test]
    fn test_mapping_slot_key_derivation() {
        let mapping_key = hex::decode("1234").unwrap();
        let mapping_slot = 2;
        let slot = StorageSlot::Mapping(mapping_key.clone(), mapping_slot);
        let mpt_key = slot.mpt_key_vec();
        let circuit = TestMappingSlot {
            m: MappingSlot {
                mapping_key,
                mapping_slot: mapping_slot as u8,
            },
            exp_mpt_key_nibbles: bytes_to_nibbles(&mpt_key),
            exp_keccak_location: slot.location().as_slice().to_vec(),
        };
        run_circuit::<F, D, C, _>(circuit);
    }

    #[derive(Clone, Debug)]
    struct TestSimpleSlot {
        slot: u8,
    }

    impl UserCircuit<F, D> for TestSimpleSlot {
        type Wires = (SimpleSlotWires, Array<Target, MAX_KEY_NIBBLE_LEN>);

        fn build(c: &mut CircuitBuilder<F, D>) -> Self::Wires {
            let wires = SimpleSlot::build(c);
            let exp_key = Array::new(c);
            wires.mpt_key.key.enforce_equal(c, &exp_key);
            (wires, exp_key)
        }

        fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
            let eth_slot = StorageSlot::Simple(self.slot as usize);
            let circuit = SimpleSlot::new(self.slot);
            circuit.assign(pw, &wires.0, 0);
            wires.1.assign_bytes(pw, &eth_slot.mpt_nibbles());
        }
    }

    #[test]
    fn test_simple_slot() {
        let circuit = TestSimpleSlot { slot: 8 };
        run_circuit::<F, D, C, _>(circuit);
    }
}
