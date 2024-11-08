//! Module handling the leaf node inside a Receipt Trie

use crate::MAX_RECEIPT_LEAF_NODE_LEN;

use super::public_inputs::{PublicInputArgs, PublicInputs};

use mp2_common::{
    array::{Array, Vector, VectorWire},
    eth::{EventLogInfo, LogDataInfo, ReceiptProofInfo},
    group_hashing::CircuitBuilderGroupHashing,
    keccak::{InputData, KeccakCircuit, KeccakWires},
    mpt_sequential::{MPTReceiptLeafNode, ReceiptKeyWire, MAX_TX_KEY_NIBBLE_LEN, PAD_LEN},
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
    plonk::circuit_builder::CircuitBuilder,
};

use plonky2_ecgfp5::gadgets::curve::{CircuitBuilderEcGFp5, CurveTarget};

use recursion_framework::circuit_builder::CircuitLogicWires;
use rlp::Encodable;
use serde::{Deserialize, Serialize};
use std::array::from_fn;
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
    /// the hash of the node bytes
    pub root: KeccakWires<{ PAD_LEN(NODE_LEN) }>,
    /// The index of this receipt in the block
    pub index: Target,
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
    pub fn to_vec(&self) -> Vec<Target> {
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
        let mut out = Vec::new();
        out.push(self.size);
        out.extend_from_slice(&self.address.arr);
        out.push(self.add_rel_offset);
        out.extend_from_slice(&self.event_signature.arr);
        out.push(self.sig_rel_offset);
        out.extend_from_slice(&topics_flat);
        out.extend_from_slice(&data_flat);

        out
    }

    pub fn verify_logs_and_extract_values<const NODE_LEN: usize>(
        &self,
        b: &mut CBuilder,
        value: &VectorWire<Target, { PAD_LEN(NODE_LEN) }>,
        status_offset: Target,
        relevant_logs_offsets: &VectorWire<Target, MAX_LOGS_PER_TX>,
    ) -> CurveTarget {
        let t = b._true();
        let zero = b.zero();
        let curve_zero = b.curve_zero();
        let mut points = Vec::new();

        // Enforce status is true.
        let status = value.arr.random_access_large_array(b, status_offset);
        b.connect(status, t.target);

        for log_offset in relevant_logs_offsets.arr.arr {
            // Extract the address bytes
            let address_start = b.add(log_offset, self.add_rel_offset);

            let address_bytes = value.arr.extract_array_large::<_, _, 20>(b, address_start);

            let address_check = address_bytes.equals(b, &self.address);
            // Extract the signature bytes
            let sig_start = b.add(log_offset, self.sig_rel_offset);

            let sig_bytes = value.arr.extract_array_large::<_, _, 32>(b, sig_start);

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
                let data_bytes = value.arr.extract_array_large::<_, _, 32>(b, data_start);

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
                points.push(selected_point);
            }
        }

        b.add_curve_point(&points)
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
    pub fn build(b: &mut CBuilder) -> ReceiptLeafWires<NODE_LEN> {
        // Build the event wires
        let event_wires = Self::build_event_wires(b);

        // Add targets for the data specific to this receipt
        let index = b.add_virtual_target();
        let status_offset = b.add_virtual_target();
        let relevant_logs_offset = VectorWire::<Target, MAX_LOGS_PER_TX>::new(b);

        let mpt_key = ReceiptKeyWire::new(b);

        // Build the node wires.
        let wires = MPTReceiptLeafNode::build_and_advance_key::<_, D, NODE_LEN>(b, &mpt_key);

        let node = wires.node;
        let root = wires.root;

        // For each relevant log in the transaction we have to verify it lines up with the event we are monitoring for
        let mut dv = event_wires.verify_logs_and_extract_values::<NODE_LEN>(
            b,
            &node,
            status_offset,
            &relevant_logs_offset,
        );

        let value_id = b.map_to_curve_point(&[index]);

        dv = b.add_curve_point(&[value_id, dv]);

        let dm = b.map_to_curve_point(&event_wires.to_vec());

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
            root,
            index,
            status_offset,
            relevant_logs_offset,
            mpt_key,
        }
    }

    fn build_event_wires(b: &mut CBuilder) -> EventWires {
        let size = b.add_virtual_target();

        // Packed address
        let address = Array::<Target, 20>::new(b);

        // relative offset of the address
        let add_rel_offset = b.add_virtual_target();

        // Event signature
        let event_signature = Array::<Target, 32>::new(b);

        // Signature relative offset
        let sig_rel_offset = b.add_virtual_target();

        // topics
        let topics: [LogColumn; 3] = from_fn(|_| Self::build_log_column(b));

        // data
        let data: [LogColumn; 2] = from_fn(|_| Self::build_log_column(b));

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
        pw.set_target(wires.index, GFp::from_canonical_u64(self.info.tx_index));
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

/// Num of children = 0
impl CircuitLogicWires<GFp, D, 0> for ReceiptLeafWires<MAX_RECEIPT_LEAF_NODE_LEN> {
    type CircuitBuilderParams = ();

    type Inputs = ReceiptLeafCircuit<MAX_RECEIPT_LEAF_NODE_LEN>;

    const NUM_PUBLIC_INPUTS: usize = PublicInputs::<GFp>::TOTAL_LEN;

    fn circuit_logic(
        builder: &mut CircuitBuilder<GFp, D>,
        _verified_proofs: [&plonky2::plonk::proof::ProofWithPublicInputsTarget<D>; 0],
        _builder_parameters: Self::CircuitBuilderParams,
    ) -> Self {
        ReceiptLeafCircuit::build(builder)
    }

    fn assign_input(
        &self,
        inputs: Self::Inputs,
        pw: &mut PartialWitness<GFp>,
    ) -> anyhow::Result<()> {
        inputs.assign(pw, self);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::receipt_extraction::compute_receipt_leaf_metadata_digest;
    use mp2_common::{
        utils::{keccak256, Packer},
        C,
    };
    use mp2_test::{
        circuit::{run_circuit, UserCircuit},
        mpt_sequential::generate_receipt_proofs,
    };
    #[derive(Clone, Debug)]
    struct TestReceiptLeafCircuit<const NODE_LEN: usize> {
        c: ReceiptLeafCircuit<NODE_LEN>,
    }

    impl<const NODE_LEN: usize> UserCircuit<F, D> for TestReceiptLeafCircuit<NODE_LEN>
    where
        [(); PAD_LEN(NODE_LEN)]:,
    {
        // Leaf wires + expected extracted value
        type Wires = ReceiptLeafWires<NODE_LEN>;

        fn build(b: &mut CircuitBuilder<F, D>) -> Self::Wires {
            ReceiptLeafCircuit::<NODE_LEN>::build(b)
        }

        fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
            self.c.assign(pw, &wires);
        }
    }
    #[test]
    fn test_leaf_circuit() {
        const NODE_LEN: usize = 512;

        let receipt_proof_infos = generate_receipt_proofs();
        let info = receipt_proof_infos.first().unwrap().clone();
        let c = ReceiptLeafCircuit::<NODE_LEN> { info: info.clone() };
        let test_circuit = TestReceiptLeafCircuit { c };

        let proof = run_circuit::<F, D, C, _>(test_circuit);
        let pi = PublicInputs::new(&proof.public_inputs);
        let node = info.mpt_proof.last().unwrap().clone();
        // Check the output hash
        {
            let exp_hash = keccak256(&node).pack(Endianness::Little);
            assert_eq!(pi.root_hash(), exp_hash);
        }

        // Check metadata digest
        {
            let exp_digest = compute_receipt_leaf_metadata_digest(&info.event_log_info);
            assert_eq!(pi.metadata_digest(), exp_digest.to_weierstrass());
        }
    }
}
