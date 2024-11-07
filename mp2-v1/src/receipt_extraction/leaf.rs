//! Module handling the leaf node inside a Receipt Trie

use super::public_inputs::PublicInputArgs;

use mp2_common::{
    array::{Array, Vector, VectorWire},
    eth::{EventLogInfo, LogDataInfo, ReceiptProofInfo},
    group_hashing::CircuitBuilderGroupHashing,
    keccak::{InputData, KeccakCircuit, KeccakWires},
    mpt_sequential::{
        MPTLeafOrExtensionNodeGeneric, ReceiptKeyWire, MAX_RECEIPT_LEAF_VALUE_LEN,
        MAX_TX_KEY_NIBBLE_LEN, PAD_LEN,
    },
    poseidon::H,
    public_inputs::PublicInputCommon,
    types::{CBuilder, GFp},
    utils::{Endianness, PackerTarget},
    D, F,
};
use plonky2::{
    field::types::Field,
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
};

use plonky2_ecgfp5::gadgets::curve::{CircuitBuilderEcGFp5, CurveTarget};

use rlp::Encodable;
use serde::{Deserialize, Serialize};

/// Maximum number of logs per transaction we can process
const MAX_LOGS_PER_TX: usize = 2;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ReceiptLeafWires<const NODE_LEN: usize>
where
    [(); PAD_LEN(NODE_LEN)]:,
{
    /// The event we are monitoring for
    pub event: EventWires,
    /// The node bytes
    pub node: VectorWire<Target, { PAD_LEN(NODE_LEN) }>,
    /// The actual value stored in the node
    pub value: Array<Target, MAX_RECEIPT_LEAF_VALUE_LEN>,
    /// the hash of the node bytes
    pub root: KeccakWires<{ PAD_LEN(NODE_LEN) }>,
    /// The offset of the status of the transaction in the RLP encoded receipt node.
    pub status_offset: Target,
    /// The offsets of the relevant logs inside the node
    pub relevant_logs_offset: VectorWire<Target, MAX_LOGS_PER_TX>,
    /// The key in the MPT Trie
    pub mpt_key: ReceiptKeyWire,
}

/// Contains all the information for an [`Event`] in rlp form
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EventWires {
    /// Size in bytes of the whole event
    size: Target,
    /// Packed contract address to check
    address: Array<Target, 20>,
    /// Byte offset for the address from the beginning of a Log
    add_rel_offset: Target,
    /// Packed event signature,
    event_signature: Array<Target, 32>,
    /// Byte offset from the start of the log to event signature
    sig_rel_offset: Target,
    /// The topics for this Log
    topics: [LogColumn; 3],
    /// The extra data stored by this Log
    data: [LogColumn; 2],
}

/// Contains all the information for a [`Log`] in rlp form
#[derive(Debug, Clone, Serialize, Deserialize, Copy, PartialEq, Eq)]
pub struct LogColumn {
    column_id: Target,
    /// The byte offset from the beggining of the log to this target
    rel_byte_offset: Target,
    /// The length of this topic/data
    len: Target,
}

impl LogColumn {
    /// Convert to an array for metadata digest
    pub fn to_array(&self) -> [Target; 3] {
        [self.column_id, self.rel_byte_offset, self.len]
    }

    /// Assigns a log colum from a [`LogDataInfo`]
    pub fn assign(&self, pw: &mut PartialWitness<GFp>, data: LogDataInfo) {
        pw.set_target(self.column_id, F::from_canonical_usize(data.column_id));
        pw.set_target(
            self.rel_byte_offset,
            F::from_canonical_usize(data.rel_byte_offset),
        );
        pw.set_target(self.len, F::from_canonical_usize(data.len));
    }
}

impl EventWires {
    /// Convert to an array  for metadata digest
    pub fn to_slice(&self) -> [Target; 70] {
        let topics_flat = self
            .topics
            .iter()
            .flat_map(|t| t.to_array())
            .collect::<Vec<Target>>();
        let data_flat = self
            .data
            .iter()
            .flat_map(|t| t.to_array())
            .collect::<Vec<Target>>();
        let mut out = [Target::default(); 70];
        out[0] = self.size;
        out.iter_mut()
            .skip(1)
            .take(20)
            .enumerate()
            .for_each(|(i, entry)| *entry = self.address.arr[i]);
        out[21] = self.add_rel_offset;
        out.iter_mut()
            .skip(22)
            .take(32)
            .enumerate()
            .for_each(|(i, entry)| *entry = self.event_signature.arr[i]);
        out[54] = self.sig_rel_offset;
        out.iter_mut()
            .skip(55)
            .take(9)
            .enumerate()
            .for_each(|(i, entry)| *entry = topics_flat[i]);
        out.iter_mut()
            .skip(64)
            .take(6)
            .enumerate()
            .for_each(|(i, entry)| *entry = data_flat[i]);
        out
    }

    pub fn verify_logs_and_extract_values(
        &self,
        b: &mut CBuilder,
        value: &Array<Target, MAX_RECEIPT_LEAF_VALUE_LEN>,
        status_offset: Target,
        relevant_logs_offsets: &VectorWire<Target, MAX_LOGS_PER_TX>,
    ) -> CurveTarget {
        let t = b._true();
        let zero = b.zero();
        let curve_zero = b.curve_zero();
        let mut value_digest = b.curve_zero();

        // Enforce status is true.
        let status = value.random_access_large_array(b, status_offset);
        b.connect(status, t.target);

        for log_offset in relevant_logs_offsets.arr.arr {
            // Extract the address bytes
            let address_start = b.add(log_offset, self.add_rel_offset);

            let address_bytes = value.extract_array_large::<_, _, 20>(b, address_start);

            let address_check = address_bytes.equals(b, &self.address);
            // Extract the signature bytes
            let sig_start = b.add(log_offset, self.sig_rel_offset);

            let sig_bytes = value.extract_array_large::<_, _, 32>(b, sig_start);

            let sig_check = sig_bytes.equals(b, &self.event_signature);

            // We check to see if the relevant log offset is zero (this indicates a dummy value)
            let dummy = b.is_equal(log_offset, zero);

            let address_to_enforce = b.select(dummy, t.target, address_check.target);
            let sig_to_enforce = b.select(dummy, t.target, sig_check.target);

            b.connect(t.target, address_to_enforce);
            b.connect(t.target, sig_to_enforce);

            for &log_column in self.topics.iter().chain(self.data.iter()) {
                let data_start = b.add(log_offset, log_column.rel_byte_offset);
                // The data is always 32 bytes long
                let data_bytes = value.extract_array_large::<_, _, 32>(b, data_start);

                // Pack the data and get the digest
                let packed_data = data_bytes.arr.pack(b, Endianness::Big);
                let data_digest = b.map_to_curve_point(
                    &std::iter::once(log_column.column_id)
                        .chain(packed_data)
                        .collect::<Vec<_>>(),
                );

                // For each column we use the `column_id` field to tell if its a dummy or not, zero indicates a dummy.
                let dummy_column = b.is_equal(log_column.column_id, zero);
                let selector = b.and(dummy_column, dummy);

                let selected_point = b.select_curve_point(selector, curve_zero, data_digest);
                value_digest = b.add_curve_point(&[selected_point, value_digest]);
            }
        }

        value_digest
    }
}

/// Circuit to prove the correct derivation of the MPT key from a simple slot
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReceiptLeafCircuit<const NODE_LEN: usize> {
    pub(crate) info: ReceiptProofInfo,
}

impl<const NODE_LEN: usize> ReceiptLeafCircuit<NODE_LEN>
where
    [(); PAD_LEN(NODE_LEN)]:,
{
    pub fn build_leaf_wires(b: &mut CBuilder) -> ReceiptLeafWires<NODE_LEN> {
        // Build the event wires
        let event_wires = Self::build_event_wires(b);

        // Add targets for the data specific to this receipt
        let index = b.add_virtual_target();
        let status_offset = b.add_virtual_target();
        let relevant_logs_offset = VectorWire::<Target, MAX_LOGS_PER_TX>::new(b);

        let mpt_key = ReceiptKeyWire::new(b);

        // Build the node wires.
        let wires = MPTLeafOrExtensionNodeGeneric::build_and_advance_key::<
            _,
            D,
            NODE_LEN,
            MAX_RECEIPT_LEAF_VALUE_LEN,
        >(b, &mpt_key);
        let node = wires.node;
        let root = wires.root;

        // For each relevant log in the transaction we have to verify it lines up with the event we are monitoring for
        let receipt_body = wires.value;
        let mut dv = event_wires.verify_logs_and_extract_values(
            b,
            &receipt_body,
            status_offset,
            &relevant_logs_offset,
        );
        let value_id = b.map_to_curve_point(&[index]);
        dv = b.add_curve_point(&[value_id, dv]);

        let dm = b.hash_n_to_hash_no_pad::<H>(event_wires.to_slice().to_vec());

        // Register the public inputs
        PublicInputArgs {
            h: &root.output_array,
            k: &wires.key,
            dv,
            dm,
        }
        .register_args(b);

        ReceiptLeafWires {
            event: event_wires,
            node,
            value: receipt_body,
            root,
            status_offset,
            relevant_logs_offset,
            mpt_key,
        }
    }

    fn build_event_wires(b: &mut CBuilder) -> EventWires {
        let size = b.add_virtual_target();

        // Packed address
        let arr = [b.add_virtual_target(); 20];
        let address = Array::from_array(arr);

        // relative offset of the address
        let add_rel_offset = b.add_virtual_target();

        // Event signature
        let arr = [b.add_virtual_target(); 32];
        let event_signature = Array::from_array(arr);

        // Signature relative offset
        let sig_rel_offset = b.add_virtual_target();

        // topics
        let topics = [Self::build_log_column(b); 3];

        // data
        let data = [Self::build_log_column(b); 2];

        EventWires {
            size,
            address,
            add_rel_offset,
            event_signature,
            sig_rel_offset,
            topics,
            data,
        }
    }

    fn build_log_column(b: &mut CBuilder) -> LogColumn {
        let column_id = b.add_virtual_target();
        let rel_byte_offset = b.add_virtual_target();
        let len = b.add_virtual_target();

        LogColumn {
            column_id,
            rel_byte_offset,
            len,
        }
    }

    pub fn assign(&self, pw: &mut PartialWitness<GFp>, wires: &ReceiptLeafWires<NODE_LEN>) {
        self.assign_event_wires(pw, &wires.event);

        let node = self
            .info
            .mpt_proof
            .last()
            .expect("Receipt MPT proof had no nodes");
        let pad_node =
            Vector::<u8, { PAD_LEN(NODE_LEN) }>::from_vec(node).expect("invalid node given");
        wires.node.assign(pw, &pad_node);
        KeccakCircuit::<{ PAD_LEN(NODE_LEN) }>::assign(
            pw,
            &wires.root,
            &InputData::Assigned(&pad_node),
        );

        pw.set_target(
            wires.status_offset,
            GFp::from_canonical_usize(self.info.status_offset),
        );

        let relevant_logs_vector =
            Vector::<usize, MAX_LOGS_PER_TX>::from_vec(&self.info.relevant_logs_offset)
                .expect("Could not assign relevant logs offsets");
        wires.relevant_logs_offset.assign(pw, &relevant_logs_vector);

        let key_encoded = self.info.tx_index.rlp_bytes();
        let nibbles = key_encoded
            .iter()
            .flat_map(|byte| [byte / 16, byte % 16])
            .collect::<Vec<u8>>();

        let mut key_nibbles = [0u8; MAX_TX_KEY_NIBBLE_LEN];
        key_nibbles
            .iter_mut()
            .enumerate()
            .for_each(|(index, nibble)| {
                if index < nibbles.len() {
                    *nibble = nibbles[index]
                }
            });

        wires.mpt_key.assign(pw, &key_nibbles, self.info.index_size);
    }

    pub fn assign_event_wires(&self, pw: &mut PartialWitness<GFp>, wires: &EventWires) {
        let EventLogInfo {
            size,
            address,
            add_rel_offset,
            event_signature,
            sig_rel_offset,
            topics,
            data,
        } = self.info.event_log_info;

        pw.set_target(wires.size, F::from_canonical_usize(size));

        wires
            .address
            .assign(pw, &address.0.map(|byte| GFp::from_canonical_u8(byte)));

        pw.set_target(
            wires.add_rel_offset,
            F::from_canonical_usize(add_rel_offset),
        );

        wires.event_signature.assign(
            pw,
            &event_signature.map(|byte| GFp::from_canonical_u8(byte)),
        );

        pw.set_target(
            wires.sig_rel_offset,
            F::from_canonical_usize(sig_rel_offset),
        );

        wires
            .topics
            .iter()
            .zip(topics.into_iter())
            .for_each(|(topic_wire, topic)| topic_wire.assign(pw, topic));
        wires
            .data
            .iter()
            .zip(data.into_iter())
            .for_each(|(data_wire, data)| data_wire.assign(pw, data));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[derive(Clone, Debug)]
    struct TestReceiptLeafCircuit<const NODE_LEN: usize> {
        c: ReceiptLeafCircuit<NODE_LEN>,
        exp_value: Vec<u8>,
    }

    impl<const NODE_LEN: usize> UserCircuit<F, D> for TestReceiptLeafCircuit<NODE_LEN>
    where
        [(); PAD_LEN(NODE_LEN)]:,
    {
        // Leaf wires + expected extracted value
        type Wires = (
            ReceiptLeafWires<NODE_LEN>,
            Array<Target, MAPPING_LEAF_VALUE_LEN>,
        );

        fn build(b: &mut CircuitBuilder<F, D>) -> Self::Wires {
            let exp_value = Array::<Target, MAPPING_LEAF_VALUE_LEN>::new(b);

            let leaf_wires = ReceiptLeafCircuit::<NODE_LEN>::build(b);
            leaf_wires.value.enforce_equal(b, &exp_value);

            (leaf_wires, exp_value)
        }

        fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
            self.c.assign(pw, &wires.0);
            wires
                .1
                .assign_bytes(pw, &self.exp_value.clone().try_into().unwrap());
        }
    }
    #[test]
    fn test_leaf_circuit() {
        const NODE_LEN: usize = 80;

        let simple_slot = 2_u8;
        let slot = StorageSlot::Simple(simple_slot as usize);
        let contract_address = Address::from_str(TEST_CONTRACT_ADDRESS).unwrap();
        let chain_id = 10;
        let id = identifier_single_var_column(simple_slot, &contract_address, chain_id, vec![]);

        let (mut trie, _) = generate_random_storage_mpt::<3, MAPPING_LEAF_VALUE_LEN>();
        let value = random_vector(MAPPING_LEAF_VALUE_LEN);
        let encoded_value: Vec<u8> = rlp::encode(&value).to_vec();
        // assert we added one byte of RLP header
        assert_eq!(encoded_value.len(), MAPPING_LEAF_VALUE_LEN + 1);
        println!("encoded value {:?}", encoded_value);
        trie.insert(&slot.mpt_key(), &encoded_value).unwrap();
        trie.root_hash().unwrap();

        let proof = trie.get_proof(&slot.mpt_key_vec()).unwrap();
        let node = proof.last().unwrap().clone();

        let c = LeafSingleCircuit::<NODE_LEN> {
            node: node.clone(),
            slot: SimpleSlot::new(simple_slot),
            id,
        };
        let test_circuit = TestLeafSingleCircuit {
            c,
            exp_value: value.clone(),
        };

        let proof = run_circuit::<F, D, C, _>(test_circuit);
        let pi = PublicInputs::new(&proof.public_inputs);

        {
            let exp_hash = keccak256(&node).pack(Endianness::Little);
            assert_eq!(pi.root_hash(), exp_hash);
        }
        {
            let (key, ptr) = pi.mpt_key_info();

            let exp_key = slot.mpt_key_vec();
            let exp_key: Vec<_> = bytes_to_nibbles(&exp_key)
                .into_iter()
                .map(F::from_canonical_u8)
                .collect();
            assert_eq!(key, exp_key);

            let leaf_key: Vec<Vec<u8>> = rlp::decode_list(&node);
            let nib = Nibbles::from_compact(&leaf_key[0]);
            let exp_ptr = F::from_canonical_usize(MAX_KEY_NIBBLE_LEN - 1 - nib.nibbles().len());
            assert_eq!(exp_ptr, ptr);
        }
        // Check values digest
        {
            let exp_digest = compute_leaf_single_values_digest(id, &value);
            assert_eq!(pi.values_digest(), exp_digest.to_weierstrass());
        }
        // Check metadata digest
        {
            let exp_digest = compute_leaf_single_metadata_digest(id, simple_slot);
            assert_eq!(pi.metadata_digest(), exp_digest.to_weierstrass());
        }
        assert_eq!(pi.n(), F::ONE);
    }
}