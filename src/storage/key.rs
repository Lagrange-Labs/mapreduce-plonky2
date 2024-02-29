//! Module handling the recursive proving of mapping entries specically
//! inside a storage trie.

use crate::{
    array::{Array, Vector, VectorWire},
    eth::left_pad32,
    group_hashing::{self, CircuitBuilderGroupHashing},
    keccak::{
        ByteKeccakWires, InputData, KeccakCircuit, KeccakWires, OutputHash, HASH_LEN,
        PACKED_HASH_LEN,
    },
    mpt_sequential::{Circuit as MPTCircuit, MPTKeyWire, PAD_LEN},
    rlp::{decode_fixed_list, MAX_ITEMS_IN_LIST, MAX_KEY_NIBBLE_LEN},
    utils::{convert_u8_targets_to_u32, keccak256, AddressTarget, ADDRESS_LEN},
};
use core::array::from_fn as create_array;
use ethers::types::Address;
use plonky2::{
    field::{extension::Extendable, goldilocks_field::GoldilocksField, types::Field},
    hash::{
        hash_types::{RichField, NUM_HASH_OUT_ELTS},
        keccak,
    },
    iop::{
        target::{BoolTarget, Target},
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::circuit_builder::CircuitBuilder,
};

/// One input element length to Keccak
const INPUT_ELEMENT_LEN: usize = 32;
/// The tuple (pair) length of elements to Keccak
const INPUT_TUPLE_LEN: usize = 2 * INPUT_ELEMENT_LEN;
/// The whole padded length for the inputs
const INPUT_PADDED_LEN: usize = PAD_LEN(INPUT_TUPLE_LEN);

/// Circuit gadget that proves the correct derivation of a MPT key from a simple
/// storage slot.
/// Deriving a MPT key from simple slot is done like:
/// 1. location = keccak(left_pad32(contract_address), left_pad32(slot))
/// 2. mpt_key = keccak(location)
/// WARNING: Currently takes the assumption that the storage slot number fits
/// inside a single byte.
#[derive(Clone, Debug)]
pub struct SimpleSlot {
    /// Simple storage slot
    slot: u8,
    /// Contract address
    contract_address: Address,
}

impl SimpleSlot {
    pub fn new(slot: u8, contract_address: Address) -> Self {
        Self {
            slot,
            contract_address,
        }
    }
}

/// Wires associated with the MPT key derivation logic of simple storage slot
pub struct SimpleSlotWires {
    /// Simple storage slot which is assumed to fit in a single byte
    pub slot: Target,
    /// Contract address used to calculate the "location"
    pub contract_address: AddressTarget,
    /// Actual keccak wires created for the computation of the "location" for
    /// the storage slot
    pub keccak_location: ByteKeccakWires<INPUT_PADDED_LEN>,
    /// Actual keccak wires created for the computation of the final MPT key
    /// from the location. THIS is the one to use to look up a key in the
    /// associated MPT trie.
    pub keccak_mpt: ByteKeccakWires<{ PAD_LEN(HASH_LEN) }>,
    /// The MPT key derived in circuit from the storage slot, in NIBBLES
    /// TODO: it represents the same information as "exp" but in nibbles.
    /// It doesn't need to be assigned, but is used in the higher level circuits
    pub mpt_key: MPTKeyWire,
}

impl SimpleSlot {
    /// Derive the MPT key in circuit according to simple storage slot.
    /// Remember the rules to get the MPT key is as follow:
    /// * location = keccak256(pad32(contract_address), pad32(slot))
    /// * mpt_key = keccak256(location)
    /// Note the simple slot wire is NOT range checked, because it is expected
    /// to be given by the verifier. If that assumption is not true, then the
    /// caller should call `b.range_check(slot, 8)` to ensure its byteness.
    pub fn build<F: RichField + Extendable<D>, const D: usize>(
        b: &mut CircuitBuilder<F, D>,
    ) -> SimpleSlotWires {
        let slot = b.add_virtual_target();
        let contract_address = AddressTarget::new(b);

        // Always ensure whatever goes into hash function, it's bytes.
        contract_address.assert_bytes(b);

        // keccak(left_pad32(contract_address), left_pad32(slot))
        let mut arr = [b.zero(); INPUT_PADDED_LEN];
        arr[INPUT_ELEMENT_LEN - ADDRESS_LEN..INPUT_ELEMENT_LEN]
            .copy_from_slice(&contract_address.arr);
        arr[INPUT_TUPLE_LEN - 1] = slot;
        let vector = VectorWire::<Target, INPUT_PADDED_LEN> {
            real_len: b.constant(F::from_canonical_usize(INPUT_TUPLE_LEN)),
            arr: Array { arr },
        };
        let keccak_location = KeccakCircuit::<{ INPUT_PADDED_LEN }>::hash_to_bytes(b, &vector);
        // keccak(location) - take the output and copy it in a slice large
        // enough for padding.
        let mut padded_location = [b.zero(); PAD_LEN(HASH_LEN)];
        padded_location[0..HASH_LEN].copy_from_slice(&keccak_location.output.arr);
        // TODO : make nice APIs for that in array.rs
        let hash_len = b.constant(F::from_canonical_usize(HASH_LEN));
        let keccak_mpt = KeccakCircuit::<{ PAD_LEN(HASH_LEN) }>::hash_to_bytes(
            b,
            &VectorWire {
                real_len: hash_len,
                arr: Array {
                    arr: padded_location,
                },
            },
        );

        // Make sure we transform from the bytes to the nibbles.
        // TODO: actually maybe better to give the nibbles directly and pack
        // them into U32 in one go. For the future...
        let mpt_key = MPTKeyWire::init_from_bytes(b, &keccak_mpt.output);

        SimpleSlotWires {
            slot,
            contract_address,
            keccak_location,
            keccak_mpt,
            mpt_key,
        }
    }

    pub fn assign<F: RichField>(&self, pw: &mut PartialWitness<F>, wires: &SimpleSlotWires) {
        pw.set_target(wires.slot, F::from_canonical_u8(self.slot));
        wires
            .contract_address
            .assign_bytes(pw, &self.contract_address.0);

        let inputs = self.inputs();
        let exp_location = keccak256(&inputs);

        // Assign the keccak necessary values for keccak_location.
        KeccakCircuit::<{ INPUT_PADDED_LEN }>::assign_byte_keccak(
            pw,
            &wires.keccak_location,
            // no need to create a new input wire array since we create it in circuit
            &InputData::Assigned(
                &Vector::from_vec(&inputs).expect("can't create vector input for keccak_location"),
            ),
        );
        // assign the keccak necessary values for keccak_mpt = H(keccak_location)
        KeccakCircuit::<{ PAD_LEN(HASH_LEN) }>::assign_byte_keccak(
            pw,
            &wires.keccak_mpt,
            &InputData::Assigned(
                &Vector::from_vec(&exp_location).expect("can't create vector input for keccak_mpt"),
            ),
        )
    }

    pub fn mpt_key(&self) -> [u8; HASH_LEN] {
        // location = keccak(inputs)
        let location = keccak256(&self.inputs());

        // mpt_key = keccak(location)
        keccak256(&location).try_into().unwrap()
    }

    fn inputs(&self) -> Vec<u8> {
        // pad32(contract_address) || pad32(slot)
        let padded_contract_address = left_pad32(&self.contract_address.0);
        let padded_slot = left_pad32(&[self.slot]);

        padded_contract_address
            .into_iter()
            .chain(padded_slot)
            .collect()
    }
}

/// Circuit gadget that proves the correct derivation of a MPT key from a given mapping slot and storage slot.
/// Deriving a MPT key from mapping slot is done like:
/// 1. location = keccak(left_pad32(key), left_pad32(slot))
/// 2. mpt_key = keccak(location)
/// WARNING: Currently takes the assumption that the storage slot number fits inside a single byte.
#[derive(Clone, Debug)]
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

/// Contains the wires associated with the storage slot's mpt key
/// derivation logic.
/// NOTE: currently specific only for mapping slots.
pub struct MappingSlotWires {
    /// "input" mapping key which is maxed out at 32 bytes
    pub(super) mapping_key: Array<Target, MAPPING_KEY_LEN>,
    /// "input" mapping slot which is assumed to fit in a single byte
    pub(super) mapping_slot: Target,
    /// Actual keccak wires created for the computation of the "location"
    /// for the mapping storage slot
    pub(super) keccak_location: ByteKeccakWires<MAPPING_INPUT_PADDED_LEN>,
    /// Actual keccak wires created for the computation of the final MPT key
    /// from the location. THIS is the one to use to look up a key in the
    /// associated MPT trie
    pub(super) keccak_mpt: ByteKeccakWires<{ PAD_LEN(HASH_LEN) }>,
    /// The MPT key derived in circuit from the storage slot, in NIBBLES
    /// TODO: it represents the same information as "exp" but in nibbles.
    /// It doesn't need to be assigned, but is used in the higher level circuits
    pub(super) mpt_key: MPTKeyWire,
}

/// Maximum size of the key for a mapping
pub const MAPPING_KEY_LEN: usize = 32;
const MAPPING_INPUT_TOTAL_LEN: usize = 2 * MAPPING_KEY_LEN;
/// Value but with the padding taken into account.
const MAPPING_INPUT_PADDED_LEN: usize = PAD_LEN(MAPPING_INPUT_TOTAL_LEN);
impl MappingSlot {
    /// Derives the mpt_key in circuit according to which type of storage slot
    /// Remember the rules to get the mpt key is as follow:
    /// * location = keccak256(pad32(mapping_key), pad32(mapping_slot))
    /// * mpt_key = keccak256(location)
    /// Note the mapping slot wire is NOT range checked, because it is expected to
    /// be given by the verifier. If that assumption is not true, then the caller
    /// should call `b.range_check(mapping_slot,8)` to ensure its byteness.
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
        let vector = VectorWire::<Target, MAPPING_INPUT_PADDED_LEN> {
            real_len: b.constant(F::from_canonical_usize(MAPPING_INPUT_TOTAL_LEN)),
            arr: Array { arr: input },
        };
        let keccak_location =
            KeccakCircuit::<{ MAPPING_INPUT_PADDED_LEN }>::hash_to_bytes(b, &vector);
        // keccak ( location ) - take the output and copy it in a slice large enough for padding
        let mut padded_location = [b.zero(); PAD_LEN(HASH_LEN)];
        padded_location[0..HASH_LEN].copy_from_slice(&keccak_location.output.arr);
        // TODO : make nice APIs for that in array.rs
        let hash_len = b.constant(F::from_canonical_usize(HASH_LEN));
        let keccak_mpt = KeccakCircuit::<{ PAD_LEN(HASH_LEN) }>::hash_to_bytes(
            b,
            &VectorWire {
                real_len: hash_len,
                arr: Array {
                    arr: padded_location,
                },
            },
        );

        // make sure we transform from the bytes to the nibbles
        // TODO: actually maybe better to give the nibbles directly and pack them into U32
        // in one go. For the future...
        let mpt_key = MPTKeyWire::init_from_bytes(b, &keccak_mpt.output);
        MappingSlotWires {
            mapping_key,
            mapping_slot,
            keccak_location,
            keccak_mpt,
            mpt_key,
        }
    }
    pub fn assign<F: RichField>(&self, pw: &mut PartialWitness<F>, wires: &MappingSlotWires) {
        // first assign the "inputs"
        let padded_mkey = left_pad32(&self.mapping_key);
        let padded_slot = left_pad32(&[self.mapping_slot]);
        // the "padding" is done in circuit for slot
        pw.set_target(wires.mapping_slot, F::from_canonical_u8(self.mapping_slot));
        // already give 32 bytes for the mapping key
        wires.mapping_key.assign_bytes(pw, &padded_mkey);
        // Then compute the entire expected array to derive the mpt key
        // H ( pad32(mapping_key), pad32(mapping_slot))
        let input = padded_mkey
            .into_iter()
            .chain(padded_slot)
            .collect::<Vec<_>>();
        // then compute the expected resulting hash for mpt key derivation.
        let exp_location = keccak256(&input);
        // assign the keccak necessary values for keccak_location
        KeccakCircuit::<{ MAPPING_INPUT_PADDED_LEN }>::assign_byte_keccak(
            pw,
            &wires.keccak_location,
            // no need to create a new input wire array since we create it in circuit
            &InputData::Assigned(
                &Vector::from_vec(&input).expect("can't create vector input for keccak_location"),
            ),
        );
        // assign the keccak necessary values for keccak_mpt = H(keccak_location)
        KeccakCircuit::<{ PAD_LEN(HASH_LEN) }>::assign_byte_keccak(
            pw,
            &wires.keccak_mpt,
            &InputData::Assigned(
                &Vector::from_vec(&exp_location).expect("can't create vector input for keccak_mpt"),
            ),
        )
    }
}

#[cfg(test)]
mod test {
    use std::array::from_fn as create_array;

    use plonky2::{
        field::extension::Extendable,
        hash::hash_types::RichField,
        iop::{target::Target, witness::PartialWitness},
        plonk::{
            circuit_builder::CircuitBuilder,
            config::{GenericConfig, PoseidonGoldilocksConfig},
        },
    };

    use crate::{
        array::Array,
        circuit::{test::run_circuit, UserCircuit},
        eth::StorageSlot,
        keccak::HASH_LEN,
        mpt_sequential::bytes_to_nibbles,
        rlp::MAX_KEY_NIBBLE_LEN,
        utils::keccak256,
    };

    use super::{MappingSlot, MappingSlotWires};

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
            Array<Target, HASH_LEN>,
        );

        fn build(b: &mut CircuitBuilder<F, D>) -> Self::Wires {
            let mapping_slot_wires = MappingSlot::mpt_key(b);
            let exp_key = Array::<Target, MAX_KEY_NIBBLE_LEN>::new(b);
            let good_key = mapping_slot_wires.mpt_key.key.equals(b, &exp_key);
            let tru = b._true();
            b.connect(tru.target, good_key.target);
            let exp_keccak_location = Array::<Target, HASH_LEN>::new(b);
            let good_keccak_location = mapping_slot_wires
                .keccak_location
                .output
                .equals(b, &exp_keccak_location);
            b.connect(tru.target, good_keccak_location.target);
            let exp_keccak_mpt = Array::<Target, HASH_LEN>::new(b);
            let good_keccak_mpt = mapping_slot_wires
                .keccak_mpt
                .output
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
            wires
                .3
                .assign_bytes(pw, &exp_mpt_key_bytes.try_into().unwrap());
            self.m.assign(pw, &wires.0);
        }
    }

    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    #[test]
    fn test_mapping_slot_key_derivation() {
        let mapping_key = hex::decode("1234").unwrap();
        let mapping_slot = 2;
        let slot = StorageSlot::Mapping(mapping_key.clone(), mapping_slot);
        let mpt_key = slot.mpt_key();
        let circuit = TestMappingSlot {
            m: MappingSlot {
                mapping_key,
                mapping_slot: mapping_slot as u8,
            },
            exp_mpt_key_nibbles: bytes_to_nibbles(&mpt_key),
            exp_keccak_location: slot.location().as_bytes().to_vec(),
        };
        run_circuit::<F, D, C, _>(circuit);
    }
}
