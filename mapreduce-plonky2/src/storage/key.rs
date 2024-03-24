//! Module handling the recursive proving of mapping entries specically
//! inside a storage trie.

use crate::{
    array::{Array, Vector, VectorWire},
    eth::{left_pad32, StorageSlot},
    keccak::{ByteKeccakWires, InputData, KeccakCircuit, KeccakWires, HASH_LEN},
    mpt_sequential::{MPTKeyWire, PAD_LEN},
    types::{AddressTarget, ADDRESS_LEN, MAPPING_KEY_LEN},
    utils::keccak256,
};
use ethers::types::Address;
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::circuit_builder::CircuitBuilder,
};
use serde::{Deserialize, Serialize};

use super::mapping::leaf::VALUE_LEN;
/// One input element length to Keccak
const INPUT_ELEMENT_LEN: usize = 32;
/// The tuple (pair) length of elements to Keccak
const INPUT_TUPLE_LEN: usize = 2 * INPUT_ELEMENT_LEN;
/// The whole padded length for the inputs
const INPUT_PADDED_LEN: usize = PAD_LEN(INPUT_TUPLE_LEN);

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
/// Wires associated with the MPT key from the keccak computation of location
pub struct KeccakMPTWires {
    /// Actual keccak wires created for the computation of the "location" for
    /// the storage slot
    pub(crate) keccak_location: ByteKeccakWires<INPUT_PADDED_LEN>,
    /// Actual keccak wires created for the computation of the final MPT key
    /// from the location. THIS is the one to use to look up a key in the
    /// associated MPT trie.
    pub(crate) keccak_mpt_key: KeccakWires<{ PAD_LEN(HASH_LEN) }>,
    /// The MPT key derived in circuit from the storage slot, in NIBBLES
    /// TODO: it represents the same information as "exp" but in nibbles.
    /// It doesn't need to be assigned, but is used in the higher level circuits
    pub(crate) mpt_key: MPTKeyWire,
}

struct KeccakMPT;

impl KeccakMPT {
    fn build<F: RichField + Extendable<D>, const D: usize>(
        b: &mut CircuitBuilder<F, D>,
        inputs: VectorWire<Target, INPUT_PADDED_LEN>,
    ) -> KeccakMPTWires {
        let keccak_location = KeccakCircuit::<{ INPUT_PADDED_LEN }>::hash_to_bytes(b, &inputs);
        // keccak(location) - take the output and copy it in a slice large
        // enough for padding.
        let mut padded_location = [b.zero(); PAD_LEN(HASH_LEN)];
        padded_location[0..HASH_LEN].copy_from_slice(&keccak_location.output.arr);
        let hash_len = b.constant(F::from_canonical_usize(HASH_LEN));
        let keccak_mpt_key = KeccakCircuit::<{ PAD_LEN(HASH_LEN) }>::hash_vector(
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
        location: Vec<u8>,
    ) {
        // Assign the keccak necessary values for keccak_location.
        KeccakCircuit::<{ INPUT_PADDED_LEN }>::assign_byte_keccak(
            pw,
            &wires.keccak_location,
            // No need to create a new input wire array since we create it in circuit.
            &InputData::Assigned(
                &Vector::from_vec(&inputs).expect("Can't create vector input for keccak_location"),
            ),
        );

        // Assign the keccak necessary values for keccak_mpt = H(keccak_location).
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
#[derive(Clone, Debug)]
pub struct SimpleSlot(pub(super) StorageSlot);

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
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SimpleSlotWires {
    /// Simple storage slot which is assumed to fit in a single byte
    pub(crate) slot: Target,
    /// Wires associated computing the keccak for the MPT key
    pub(crate) keccak_mpt: KeccakWires<{ PAD_LEN(INPUT_ELEMENT_LEN) }>,
    /// The MPT key derived in circuit from the storage slot, in NIBBLES
    /// TODO: It doesn't need to be assigned, but is used in the higher level circuits
    pub(crate) mpt_key: MPTKeyWire,
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
        let slot = b.add_virtual_target();

        // keccak(left_pad32(slot))
        let mut arr = [b.zero(); INPUT_PADDED_LEN];
        arr[INPUT_ELEMENT_LEN - 1] = slot;
        let inputs = VectorWire::<Target, INPUT_PADDED_LEN> {
            real_len: b.constant(F::from_canonical_usize(INPUT_ELEMENT_LEN)),
            arr: Array { arr },
        };
        // Build for keccak MPT.
        let keccak_mpt = KeccakCircuit::<INPUT_PADDED_LEN>::hash_vector(b, &inputs);
        // MPT KEY is expressed in nibbles
        let mpt_key = MPTKeyWire::init_from_u32_targets(b, &keccak_mpt.output_array);

        SimpleSlotWires {
            slot,
            keccak_mpt,
            mpt_key,
        }
    }

    pub fn assign<F: RichField>(&self, pw: &mut PartialWitness<F>, wires: &SimpleSlotWires) {
        match self.0 {
            StorageSlot::Simple(slot) => {
                // safe downcasting because it's assumed to be u8 in constructor
                pw.set_target(wires.slot, F::from_canonical_u8(slot as u8))
            }
            _ => panic!("Invalid storage slot type"), // should not happen using constructor
        }
        let input = self.0.location().as_fixed_bytes().to_vec();
        KeccakCircuit::assign(
            pw,
            &wires.keccak_mpt,
            // unwrap safe because input always fixed 32 bytes
            &InputData::Assigned(&Vector::from_vec(&input).unwrap()),
        );
    }
}

/// Circuit gadget that proves the correct derivation of a MPT key from a given mapping slot and storage slot.
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

/// Contains the wires associated with the storage slot's mpt key
/// derivation logic.
/// NOTE: currently specific only for mapping slots.
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct MappingSlotWires {
    /// "input" mapping key which is maxed out at 32 bytes
    pub(crate) mapping_key: Array<Target, MAPPING_KEY_LEN>,
    /// "input" mapping slot which is assumed to fit in a single byte
    pub(crate) mapping_slot: Target,
    /// Wires associated with the MPT key
    pub(crate) keccak_mpt: KeccakMPTWires,
}

/// Size of the input to the digest and hash function
pub(crate) const MAPPING_INPUT_TOTAL_LEN: usize = MAPPING_KEY_LEN + VALUE_LEN;
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
        let inputs = padded_mkey
            .into_iter()
            .chain(padded_slot)
            .collect::<Vec<_>>();
        // then compute the expected resulting hash for mpt key derivation.
        let location = keccak256(&inputs);
        KeccakMPT::assign(pw, &wires.keccak_mpt, inputs, location);
    }
}

#[cfg(test)]
mod test {

    use plonky2::{
        field::extension::Extendable,
        hash::hash_types::RichField,
        iop::{target::Target, witness::PartialWitness},
        plonk::{
            circuit_builder::CircuitBuilder,
            config::{GenericConfig, PoseidonGoldilocksConfig},
        },
    };
    use plonky2_crypto::u32::arithmetic_u32::U32Target;

    use crate::{
        array::Array,
        circuit::{test::run_circuit, UserCircuit},
        eth::StorageSlot,
        keccak::{HASH_LEN, PACKED_HASH_LEN},
        mpt_sequential::bytes_to_nibbles,
        rlp::MAX_KEY_NIBBLE_LEN,
        utils::{convert_u8_slice_to_u32_fields, keccak256},
    };

    use super::{MappingSlot, MappingSlotWires, SimpleSlot, SimpleSlotWires};

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
                &convert_u8_slice_to_u32_fields(&exp_mpt_key_bytes)
                    .try_into()
                    .unwrap(),
            );
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
        let mpt_key = slot.mpt_key_vec();
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
            circuit.assign(pw, &wires.0);
            wires.1.assign_bytes(pw, &eth_slot.mpt_nibbles());
        }
    }

    #[test]
    fn test_simple_slot() {
        let circuit = TestSimpleSlot { slot: 8 };
        run_circuit::<F, D, C, _>(circuit);
    }
}
