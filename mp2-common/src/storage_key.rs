//! Module handling the recursive proving of the correct derivation
//! of the MPT path
//!
//! depending on the type of variables the slot is holding (simple unit variable like uint256
//! variable length & composite type like a mapping).

use crate::{
    array::{Array, Vector, VectorWire},
    eth::{left_pad32, StorageSlot},
    keccak::{ByteKeccakWires, InputData, KeccakCircuit, KeccakWires, OutputByteHash, HASH_LEN},
    mpt_sequential::{MPTKeyWire, PAD_LEN},
    serialization::circuit_data_serialization::SerializableRichField,
    types::{MAPPING_KEY_LEN, MAPPING_LEAF_VALUE_LEN},
    u256::{CircuitBuilderU256, UInt256Target, NUM_LIMBS},
    utils::{keccak256, Endianness, PackerTarget},
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
use std::{array, iter::repeat};

/// One input element length to Keccak
const INPUT_ELEMENT_LEN: usize = 32;
/// The tuple (pair) length of elements to Keccak
const INPUT_TUPLE_LEN: usize = 2 * INPUT_ELEMENT_LEN;
/// The whole padded length for the inputs
const INPUT_PADDED_LEN: usize = PAD_LEN(INPUT_TUPLE_LEN);

/// Wires associated with the MPT key from the Keccak computation of location
/// It's used for mapping slot of single value (no EVM offset).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct KeccakMPTWires {
    /// Actual Keccak wires created for the computation of the base for the storage slot
    pub keccak_location: ByteKeccakWires<INPUT_PADDED_LEN>,
    /// Actual Keccak wires created for the computation of the final MPT key
    /// from the location. this is the one to use to look up a key in the
    /// associated MPT trie.
    pub keccak_mpt_key: KeccakWires<{ PAD_LEN(HASH_LEN) }>,
    /// The MPT key derived in circuit from the storage slot in nibbles
    /// TODO: it represents the same information as "exp" but in nibbles.
    /// It doesn't need to be assigned, but is used in the higher level circuits
    pub mpt_key: MPTKeyWire,
}

/// Wires associated with the MPT key from the Keccak computation of location
/// It's used for mapping slot of Struct (has EVM offset).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct KeccakStructMPTWires {
    /// Keccak base information
    pub base: KeccakMPTWires,
    /// The location in bytes
    /// It's used to check if the packed location is correct.
    pub location_bytes: OutputByteHash,
}

// The Keccak MPT computation
// It's used for mapping slot of single value (no EVM offset).
struct KeccakMPT;

impl KeccakMPT {
    /// Build the Keccak MPT with no offset (offset = 0).
    fn build<F: RichField + Extendable<D>, const D: usize>(
        b: &mut CircuitBuilder<F, D>,
        inputs: VectorWire<Target, INPUT_PADDED_LEN>,
    ) -> KeccakMPTWires {
        let keccak_location = KeccakCircuit::<{ INPUT_PADDED_LEN }>::hash_to_bytes(b, &inputs);
        let location_bytes = keccak_location.output.arr;

        Self::build_location(b, keccak_location, location_bytes)
    }

    fn build_location<F: RichField + Extendable<D>, const D: usize>(
        b: &mut CircuitBuilder<F, D>,
        keccak_location: ByteKeccakWires<INPUT_PADDED_LEN>,
        location_bytes: [Target; HASH_LEN],
    ) -> KeccakMPTWires {
        // keccak(location)
        let zero = b.zero();
        let arr = location_bytes
            .into_iter()
            .chain(repeat(zero).take(PAD_LEN(HASH_LEN) - HASH_LEN))
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
            keccak_location,
            keccak_mpt_key,
            mpt_key,
        }
    }

    fn assign<F: RichField>(
        pw: &mut PartialWitness<F>,
        wires: &KeccakMPTWires,
        inputs: Vec<u8>,
        location: [u8; HASH_LEN],
    ) {
        // Assign the Keccak necessary values for base.
        KeccakCircuit::<{ INPUT_PADDED_LEN }>::assign_byte_keccak(
            pw,
            &wires.keccak_location,
            // No need to create a new input wire array since we create it in circuit.
            &InputData::Assigned(
                &Vector::from_vec(&inputs).expect("Can't create vector input for keccak_location"),
            ),
        );
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

// The Keccak Struct MPT computation
// It's used for mapping slot of Struct (has EVM offset).
struct KeccakStructMPT;

impl KeccakStructMPT {
    /// Build the Keccak MPT for Struct (has EVM offset).
    fn build<F: SerializableRichField<D> + Extendable<D>, const D: usize>(
        b: &mut CircuitBuilder<F, D>,
        inputs: VectorWire<Target, INPUT_PADDED_LEN>,
        offset: Target,
    ) -> KeccakStructMPTWires {
        let location_bytes = OutputByteHash::new(b);

        // location = keccak(inputs) + offset
        let keccak_base = KeccakCircuit::<{ INPUT_PADDED_LEN }>::hash_to_bytes(b, &inputs);
        // Do range-check on the output, since these bytes are converted for Uint256 computation
        // (not fed as input to another Keccak directly).
        keccak_base.output.assert_bytes(b);
        let base = keccak_base.output.arr.pack(b, Endianness::Big);
        let base = UInt256Target::new_from_be_target_limbs(&base).unwrap();
        let offset = UInt256Target::new_from_target_unsafe(b, offset);
        let (packed_location, overflow) = b.add_u256(&base, &offset);
        b.assert_zero(overflow.0);

        // Ensure the packed location is correct.
        location_bytes
            .pack(b, Endianness::Big)
            .enforce_equal(b, &packed_location.into());

        let base = KeccakMPT::build_location(b, keccak_base, location_bytes.arr);

        KeccakStructMPTWires {
            base,
            location_bytes,
        }
    }

    fn assign<F: RichField>(
        pw: &mut PartialWitness<F>,
        wires: &KeccakStructMPTWires,
        inputs: Vec<u8>,
        base: [u8; HASH_LEN],
        offset: u32,
    ) {
        // location = keccak_base + offset
        let location = U256::from_be_bytes(base)
            .checked_add(U256::from(offset))
            .expect("Keccak base plus offset is overflow for location computation");
        let location = location.to_be_bytes();

        KeccakMPT::assign(pw, &wires.base, inputs, location);

        wires
            .location_bytes
            .assign(pw, &location.map(F::from_canonical_u8));
    }
}

/// Circuit gadget that proves the correct derivation of a MPT key from a simple
/// storage slot.
/// Deriving a MPT key from simple slot is done like:
/// 1. location = left_pad32(slot)
/// 2. mpt_key = keccak(location)
///    WARNING: Currently takes the assumption that the storage slot number fits
///    inside a single byte.
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

/// Wires associated with the MPT key derivation logic of simple storage slot of single value
// It's used for simple slot of single value (no EVM offset).
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

/// Wires associated with the MPT key derivation logic of simple storage slot of Struct
// It's used for simple slot of Struct (has EVM offset).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SimpleStructSlotWires {
    /// Slot base information
    pub base: SimpleSlotWires,
    /// The location in bytes
    /// It's used to check if the packed location is correct.
    pub location_bytes: OutputByteHash,
}

// TODO: refactor to extract common functions with MappingSlot.
impl SimpleSlot {
    /// Derive the MPT key in circuit according to simple storage slot of single value.
    ///
    /// Remember the rules to get the MPT key is as follow:
    /// location = pad32(slot)
    /// mpt_key = keccak256(location)
    /// Note the simple slot wire and the contract address wires are NOT range
    /// checked, because they are expected to be given by the verifier.
    ///
    /// If that assumption is not true, then the caller should call
    /// `b.range_check(slot, 8)` to ensure its byteness.
    pub fn build_single<F: RichField + Extendable<D>, const D: usize>(
        b: &mut CircuitBuilder<F, D>,
    ) -> SimpleSlotWires {
        let zero = b.zero();
        let slot = b.add_virtual_target();
        let mut location = [zero; INPUT_ELEMENT_LEN];
        location[INPUT_ELEMENT_LEN - 1] = slot;

        Self::build_location(b, slot, location)
    }

    /// Derive the MPT key with a specified offset in circuit according to simple
    /// storage slot of Struct.
    ///
    /// The rules to get the MPT key with offset is as follow:
    /// location = left_pad32(slot) + offset
    /// mpt_key = keccak256(location)
    /// Note the simple slot wire and the contract address wires are NOT range
    /// checked, because they are expected to be given by the verifier.
    /// If that assumption is not true, then the caller should call
    /// `b.range_check(slot, 8)` to ensure its byteness.
    pub fn build_struct<F: RichField + Extendable<D>, const D: usize>(
        b: &mut CircuitBuilder<F, D>,
        offset: Target,
    ) -> SimpleStructSlotWires {
        let zero = b.zero();
        let slot = b.add_virtual_target();
        // We assume the offset and addition must be within the range of Uint32:
        // addition = offset + slot
        let (addition, overflow) = b.add_u32(U32Target(offset), U32Target(slot));
        b.assert_zero(overflow.0);
        let mut packed_location = [U32Target(zero); NUM_LIMBS];
        packed_location[NUM_LIMBS - 1] = addition;

        // Ensure the packed location is correct.
        let location_bytes = OutputByteHash::new(b);
        location_bytes
            .pack(b, Endianness::Big)
            .enforce_equal(b, &packed_location.into());

        let base = Self::build_location(b, slot, location_bytes.arr);

        SimpleStructSlotWires {
            base,
            location_bytes,
        }
    }

    pub fn build_location<F: RichField + Extendable<D>, const D: usize>(
        b: &mut CircuitBuilder<F, D>,
        slot: Target,
        location: [Target; INPUT_ELEMENT_LEN],
    ) -> SimpleSlotWires {
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

    pub fn assign_single<F: RichField>(&self, pw: &mut PartialWitness<F>, wires: &SimpleSlotWires) {
        self.assign_with_offset(pw, wires, 0);
    }

    pub fn assign_struct<F: RichField>(
        &self,
        pw: &mut PartialWitness<F>,
        wires: &SimpleStructSlotWires,
        offset: u32,
    ) {
        let location_bytes = self.assign_with_offset(pw, &wires.base, offset);

        // Assign the location bytes.
        let location_bytes = location_bytes
            .into_iter()
            .map(F::from_canonical_u8)
            .collect_vec()
            .try_into()
            .unwrap();
        wires.location_bytes.assign(pw, &location_bytes);
    }

    // Assign with a specified offset.
    // The offset could be zero for a single value.
    // Return the location bytes as the final input.
    fn assign_with_offset<F: RichField>(
        &self,
        pw: &mut PartialWitness<F>,
        wires: &SimpleSlotWires,
        offset: u32,
    ) -> Vec<u8> {
        let slot = match self.0 {
            // Safe downcasting because it's assumed to be u8 in constructor.
            StorageSlot::Simple(slot) => slot as u8,
            _ => panic!("Invalid storage slot type"), // should not happen using constructor
        };
        pw.set_target(wires.slot, F::from_canonical_u8(slot));
        // Should be same with the slot number if offset is zero.
        let location = offset
            .checked_add(slot.into())
            .expect("Simple slot plus offset is overflow");
        let location_bytes = B256::left_padding_from(&location.to_be_bytes()).to_vec();
        KeccakCircuit::assign(
            pw,
            &wires.keccak_mpt,
            // Unwrap safe because input always fixed 32 bytes.
            &InputData::Assigned(&Vector::from_vec(&location_bytes).unwrap()),
        );

        location_bytes
    }
}

/// Circuit gadget that proves the correct derivation of a MPT key from a given mapping slot.
/// Deriving a MPT key from mapping slot is done like:
/// 1. location = keccak(left_pad32(key), left_pad32(slot))
/// 2. mpt_key = keccak(location)
///    WARNING: Currently takes the assumption that the storage slot number fits inside a single byte.
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
/// It's used for mapping slot of single value (no EVM offset).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MappingSlotWires {
    /// "input" mapping key which is maxed out at 32 bytes
    pub mapping_key: Array<Target, MAPPING_KEY_LEN>,
    /// "input" mapping slot which is assumed to fit in a single byte
    pub mapping_slot: Target,
    /// Wires associated with the MPT key
    pub keccak_mpt: KeccakMPTWires,
}

/// Contains the wires associated with the storage slot's MPT key derivation logic.
/// It's used for mapping slot of Struct (has EVM offset).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MappingStructSlotWires {
    /// "input" mapping key which is maxed out at 32 bytes
    pub mapping_key: Array<Target, MAPPING_KEY_LEN>,
    /// "input" mapping slot which is assumed to fit in a single byte
    pub mapping_slot: Target,
    /// Wires associated with the MPT key
    pub keccak_mpt: KeccakStructMPTWires,
}

/// Contains the wires associated with the MPT key derivation logic of mappings where the value
/// stored in each mapping entry is another mapping (referred to as mapping of mappings).
///
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
    pub keccak_mpt: KeccakStructMPTWires,
}

/// Size of the input to the digest and hash function
pub(crate) const MAPPING_INPUT_TOTAL_LEN: usize = MAPPING_KEY_LEN + MAPPING_LEAF_VALUE_LEN;
/// Value but with the padding taken into account.
const MAPPING_INPUT_PADDED_LEN: usize = PAD_LEN(MAPPING_INPUT_TOTAL_LEN);
impl MappingSlot {
    /// Derives the mpt_key in circuit according to which type of storage slot of single value.
    ///
    /// Remember the rules to get the mpt key is as follow:
    /// location = keccak256(pad32(mapping_key), pad32(mapping_slot))
    /// mpt_key = keccak256(location)
    /// Note the mapping slot wire is NOT range checked, because it is expected to
    /// be given by the verifier. If that assumption is not true, then the caller
    /// should call `b.range_check(mapping_slot,8)` to ensure its byteness.
    pub fn build_single<F: RichField + Extendable<D>, const D: usize>(
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

    /// Derive the MPT key with a specified offset in circuit according to mapping slot of Struct.
    ///
    /// The rules to get the mpt key with offset is as follow:
    /// location = keccak256(pad32(mapping_key), pad32(mapping_slot)) + offset
    /// mpt_key = keccak256(location)
    /// Note the mapping slot wire is NOT range checked, because it is expected to
    /// be given by the verifier. If that assumption is not true, then the caller
    /// should call `b.range_check(mapping_slot, 8)` to ensure its byteness.
    pub fn build_struct<F: SerializableRichField<D> + Extendable<D>, const D: usize>(
        b: &mut CircuitBuilder<F, D>,
        offset: Target,
    ) -> MappingStructSlotWires {
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
        let keccak_mpt = KeccakStructMPT::build(b, inputs, offset);

        MappingStructSlotWires {
            mapping_key,
            mapping_slot,
            keccak_mpt,
        }
    }

    /// Derive the MPT key with an inner mapping key and offset in circuit according to
    /// mapping slot.
    ///
    /// The rules to get the mpt key with offset is as follow:
    /// inner_mapping_slot = keccak256(left_pad32(outer_key) || left_pad32(mapping_slot))
    /// location = keccak256(left_pad32(inner_key) || inner_mapping_slot) + offset
    /// mpt_key = keccak256(location)
    /// Note the mapping slot wire is NOT range checked, because it is expected to
    /// be given by the verifier. If that assumption is not true, then the caller
    /// should call `b.range_check(mapping_slot, 8)` to ensure its byteness.
    pub fn build_mapping_of_mappings<
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
        let keccak_mpt = KeccakStructMPT::build(b, inputs, offset);

        MappingOfMappingsSlotWires {
            mapping_slot,
            inner_key,
            outer_key,
            inner_mapping_slot,
            keccak_mpt,
        }
    }

    pub fn assign_single<F: RichField>(
        &self,
        pw: &mut PartialWitness<F>,
        wires: &MappingSlotWires,
    ) {
        let (inputs, location) =
            self.assign_slot_and_mapping_key(pw, wires.mapping_slot, &wires.mapping_key);

        KeccakMPT::assign(pw, &wires.keccak_mpt, inputs, location);
    }

    pub fn assign_struct<F: RichField>(
        &self,
        pw: &mut PartialWitness<F>,
        wires: &MappingStructSlotWires,
        offset: u32,
    ) {
        let (inputs, location_base) =
            self.assign_slot_and_mapping_key(pw, wires.mapping_slot, &wires.mapping_key);

        KeccakStructMPT::assign(pw, &wires.keccak_mpt, inputs, location_base, offset);
    }

    pub fn assign_mapping_of_mappings<F: RichField>(
        &self,
        pw: &mut PartialWitness<F>,
        wires: &MappingOfMappingsSlotWires,
        inner_key: &[u8],
        offset: u32,
    ) {
        let (inputs, inner_mapping_slot) =
            self.assign_slot_and_mapping_key(pw, wires.mapping_slot, &wires.outer_key);

        let inner_key = left_pad32(inner_key);
        wires.inner_key.assign_bytes(pw, &inner_key);

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
        let inputs = inner_key
            .into_iter()
            .chain(inner_mapping_slot)
            .collect_vec();
        let base = keccak256(&inputs).try_into().unwrap();
        KeccakStructMPT::assign(pw, &wires.keccak_mpt, inputs, base, offset);
    }

    // Assign the slot and mapping key.
    // Return the input and keccak output as base location.
    fn assign_slot_and_mapping_key<F: RichField>(
        &self,
        pw: &mut PartialWitness<F>,
        mapping_slot: Target,
        mapping_key: &Array<Target, MAPPING_KEY_LEN>,
    ) -> (Vec<u8>, [u8; HASH_LEN]) {
        // Pad the slot and mapping key.
        let padded_slot = left_pad32(&[self.mapping_slot]);
        let padded_key = left_pad32(&self.mapping_key);

        // Assign the mapping slot.
        pw.set_target(mapping_slot, F::from_canonical_u8(self.mapping_slot));

        // Assign the mapping key.
        mapping_key.assign_bytes(pw, &padded_key);

        // Compute the entire expected array to derive the MPT key:
        // keccak(left_pad32(mapping_key), left_pad32(mapping_slot))
        let inputs = padded_key.into_iter().chain(padded_slot).collect_vec();

        // Then compute the expected resulting hash for MPT key derivation.
        let base_location = keccak256(&inputs).try_into().unwrap();

        (inputs, base_location)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        array::Array,
        eth::{StorageSlot, StorageSlotNode},
        mpt_sequential::utils::bytes_to_nibbles,
        rlp::MAX_KEY_NIBBLE_LEN,
        types::CBuilder,
        C, D, F,
    };
    use mp2_test::{
        circuit::{run_circuit, UserCircuit},
        utils::random_vector,
    };
    use plonky2::{
        field::types::Field,
        iop::witness::WitnessWrite,
        iop::{target::Target, witness::PartialWitness},
    };
    use rand::{thread_rng, Rng};
    use std::array;

    #[derive(Clone, Debug)]
    struct TestSimpleSlot {
        slot: u8,
    }

    impl UserCircuit<F, D> for TestSimpleSlot {
        type Wires = (SimpleSlotWires, Array<Target, MAX_KEY_NIBBLE_LEN>);

        fn build(b: &mut CBuilder) -> Self::Wires {
            let wires = SimpleSlot::build_single(b);
            let exp_key = Array::new(b);
            wires.mpt_key.key.enforce_equal(b, &exp_key);

            (wires, exp_key)
        }

        fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
            let storage_slot = StorageSlot::Simple(self.slot as usize);
            let circuit = SimpleSlot::new(self.slot);
            circuit.assign_single(pw, &wires.0);
            wires.1.assign_bytes(pw, &storage_slot.mpt_nibbles());
        }
    }

    #[test]
    fn test_simple_single_slot() {
        let rng = &mut thread_rng();
        let slot = rng.gen();

        let circuit = TestSimpleSlot { slot };
        run_circuit::<F, D, C, _>(circuit);
    }

    #[derive(Clone, Debug)]
    struct TestSimpleStructSlot {
        slot: u8,
        evm_offset: u32,
    }

    impl UserCircuit<F, D> for TestSimpleStructSlot {
        // EVM offset + simple slot + expected MPT key
        type Wires = (
            Target,
            SimpleStructSlotWires,
            Array<Target, MAX_KEY_NIBBLE_LEN>,
        );

        fn build(b: &mut CBuilder) -> Self::Wires {
            let evm_offset = b.add_virtual_target();
            let slot = SimpleSlot::build_struct(b, evm_offset);
            let exp_key = Array::new(b);
            slot.base.mpt_key.key.enforce_equal(b, &exp_key);

            (evm_offset, slot, exp_key)
        }

        fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
            let circuit = SimpleSlot::new(self.slot);

            let parent = StorageSlot::Simple(self.slot as usize);
            let storage_slot =
                StorageSlot::Node(StorageSlotNode::new_struct(parent, self.evm_offset));

            pw.set_target(wires.0, F::from_canonical_u32(self.evm_offset));
            circuit.assign_struct(pw, &wires.1, self.evm_offset);
            wires.2.assign_bytes(pw, &storage_slot.mpt_nibbles());
        }
    }

    #[test]
    fn test_simple_struct_slot() {
        let rng = &mut thread_rng();
        let slot = rng.gen();
        let evm_offset = rng.gen();

        let circuit = TestSimpleStructSlot { slot, evm_offset };
        run_circuit::<F, D, C, _>(circuit);
    }

    #[derive(Clone, Debug)]
    struct TestMappingSlot {
        mapping_slot: MappingSlot,
        exp_mpt_key: Vec<u8>,
    }

    impl UserCircuit<F, D> for TestMappingSlot {
        type Wires = (
            // Mapping slot
            MappingSlotWires,
            // Expected MPT key in nibbles
            Array<Target, MAX_KEY_NIBBLE_LEN>,
        );

        fn build(b: &mut CBuilder) -> Self::Wires {
            let mapping_slot = MappingSlot::build_single(b);
            let exp_mpt_key = Array::<Target, MAX_KEY_NIBBLE_LEN>::new(b);

            mapping_slot
                .keccak_mpt
                .mpt_key
                .key
                .enforce_equal(b, &exp_mpt_key);

            (mapping_slot, exp_mpt_key)
        }

        fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
            self.mapping_slot.assign_single(pw, &wires.0);
            wires
                .1
                .assign_bytes(pw, &self.exp_mpt_key.clone().try_into().unwrap());
        }
    }

    #[test]
    fn test_mapping_single_slot() {
        let rng = &mut thread_rng();

        let slot = rng.gen();
        let mapping_key = random_vector(16);
        let storage_slot = StorageSlot::Mapping(mapping_key.clone(), slot);
        let mpt_key = storage_slot.mpt_key_vec();

        let circuit = TestMappingSlot {
            mapping_slot: MappingSlot {
                mapping_key,
                mapping_slot: slot as u8,
            },
            exp_mpt_key: bytes_to_nibbles(&mpt_key),
        };
        run_circuit::<F, D, C, _>(circuit);
    }

    #[derive(Clone, Debug)]
    struct TestMappingStructSlot {
        evm_offset: u32,
        mapping_slot: MappingSlot,
        exp_mpt_key: Vec<u8>,
    }

    impl UserCircuit<F, D> for TestMappingStructSlot {
        type Wires = (
            // EVM offset
            Target,
            // Mapping slot
            MappingStructSlotWires,
            // Expected MPT key in nibbles
            Array<Target, MAX_KEY_NIBBLE_LEN>,
        );

        fn build(b: &mut CBuilder) -> Self::Wires {
            let evm_offset = b.add_virtual_target();
            let mapping_slot = MappingSlot::build_struct(b, evm_offset);
            let exp_mpt_key = Array::<Target, MAX_KEY_NIBBLE_LEN>::new(b);

            mapping_slot
                .keccak_mpt
                .base
                .mpt_key
                .key
                .enforce_equal(b, &exp_mpt_key);

            (evm_offset, mapping_slot, exp_mpt_key)
        }

        fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
            pw.set_target(wires.0, F::from_canonical_u32(self.evm_offset));
            self.mapping_slot
                .assign_struct(pw, &wires.1, self.evm_offset);
            wires
                .2
                .assign_bytes(pw, &self.exp_mpt_key.clone().try_into().unwrap());
        }
    }

    #[test]
    fn test_mapping_struct_slot() {
        let rng = &mut thread_rng();

        let slot = rng.gen();
        let evm_offset = rng.gen();
        let mapping_key = random_vector(16);
        let parent = StorageSlot::Mapping(mapping_key.clone(), slot as usize);
        let storage_slot = StorageSlot::Node(StorageSlotNode::new_struct(parent, evm_offset));
        let mpt_key = storage_slot.mpt_key_vec();

        let circuit = TestMappingStructSlot {
            evm_offset,
            mapping_slot: MappingSlot {
                mapping_key,
                mapping_slot: slot,
            },
            exp_mpt_key: bytes_to_nibbles(&mpt_key),
        };
        run_circuit::<F, D, C, _>(circuit);
    }

    #[derive(Clone, Debug)]
    struct TestMappingOfMappingsSlot {
        evm_offset: u32,
        inner_key: Vec<u8>,
        mapping_slot: MappingSlot,
        exp_mpt_key: Vec<u8>,
    }

    impl UserCircuit<F, D> for TestMappingOfMappingsSlot {
        type Wires = (
            // EVM offset
            Target,
            // Mapping of mappings slot
            MappingOfMappingsSlotWires,
            // Expected MPT key in nibbles
            Array<Target, MAX_KEY_NIBBLE_LEN>,
        );

        fn build(b: &mut CBuilder) -> Self::Wires {
            let evm_offset = b.add_virtual_target();
            let mapping_slot = MappingSlot::build_mapping_of_mappings(b, evm_offset);
            let exp_mpt_key = Array::<Target, MAX_KEY_NIBBLE_LEN>::new(b);

            mapping_slot
                .keccak_mpt
                .base
                .mpt_key
                .key
                .enforce_equal(b, &exp_mpt_key);

            (evm_offset, mapping_slot, exp_mpt_key)
        }

        fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
            pw.set_target(wires.0, F::from_canonical_u32(self.evm_offset));
            self.mapping_slot.assign_mapping_of_mappings(
                pw,
                &wires.1,
                &self.inner_key,
                self.evm_offset,
            );
            wires
                .2
                .assign_bytes(pw, &self.exp_mpt_key.clone().try_into().unwrap());
        }
    }

    #[test]
    fn test_mapping_of_mappings_slot() {
        let rng = &mut thread_rng();

        let slot = rng.gen();
        let evm_offset = rng.gen();
        let [outer_key, inner_key] = array::from_fn(|_| random_vector(16));
        let grand = StorageSlot::Mapping(outer_key.clone(), slot as usize);
        let parent =
            StorageSlot::Node(StorageSlotNode::new_mapping(grand, inner_key.clone()).unwrap());
        let storage_slot = StorageSlot::Node(StorageSlotNode::new_struct(parent, evm_offset));
        let mpt_key = storage_slot.mpt_key_vec();

        let circuit = TestMappingOfMappingsSlot {
            evm_offset,
            inner_key,
            mapping_slot: MappingSlot {
                mapping_key: outer_key,
                mapping_slot: slot,
            },
            exp_mpt_key: bytes_to_nibbles(&mpt_key),
        };
        run_circuit::<F, D, C, _>(circuit);
    }
}
