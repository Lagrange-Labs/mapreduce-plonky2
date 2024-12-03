//! Module handling the leaf node inside a Receipt Trie

use crate::MAX_RECEIPT_LEAF_NODE_LEN;

use super::public_inputs::{PublicInputs, PublicInputsArgs};

use mp2_common::{
    array::{Array, Vector, VectorWire},
    eth::{EventLogInfo, LogDataInfo, ReceiptProofInfo},
    group_hashing::CircuitBuilderGroupHashing,
    keccak::{InputData, KeccakCircuit, KeccakWires},
    mpt_sequential::{MPTKeyWire, MPTReceiptLeafNode, PAD_LEN},
    public_inputs::PublicInputCommon,
    rlp::MAX_KEY_NIBBLE_LEN,
    types::{CBuilder, GFp},
    utils::{less_than, less_than_or_equal_to, Endianness, PackerTarget},
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
use std::{array::from_fn, iter};
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
    pub mpt_key: MPTKeyWire,
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
    pub fn to_array(self) -> [Target; 3] {
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
        relevant_logs_offsets: &VectorWire<Target, MAX_LOGS_PER_TX>,
    ) -> (Target, CurveTarget) {
        let t = b._true();
        let one = b.one();
        let two = b.two();
        let zero = b.zero();
        let curve_zero = b.curve_zero();
        let mut points = Vec::new();

        // Extract the gas used in the transaction, since the position of this can vary because it is after the key
        // we have to prove we extracted from the correct location.
        let header_len_len = b.add_const(
            value.arr[0],
            F::from_canonical_u64(1) - F::from_canonical_u64(247),
        );
        let key_header = value.arr.random_access_large_array(b, header_len_len);
        let less_than_val = b.constant(F::from_canonical_u8(128));
        let single_value = less_than(b, key_header, less_than_val, 8);
        let key_len_maybe = b.add_const(key_header, F::ONE - F::from_canonical_u64(128));
        let key_len = b.select(single_value, one, key_len_maybe);

        // This is the start of the string that is the rlp encoded receipt (a string since the first element is transaction type).
        // From here we subtract 183 to get the length of the length, then the encoded gas used is at length of length + 1 (for tx type) + (1 + list length)
        // + 1 (for status) + 1 to get the header for the gas used string.
        let string_offset = b.add(key_len, header_len_len);
        let string_header = value.arr.random_access_large_array(b, string_offset);
        let string_len_len = b.add_const(string_header, -F::from_canonical_u64(183));

        let list_offset = b.add_many([string_offset, string_len_len, two]);
        let list_header = value.arr.random_access_large_array(b, list_offset);

        let gas_used_offset_lo = b.add_const(
            list_header,
            F::from_canonical_u64(2) - F::from_canonical_u64(247),
        );
        let gas_used_offset = b.add(gas_used_offset_lo, list_offset);

        let gas_used_header = value.arr.random_access_large_array(b, gas_used_offset);
        let gas_used_len = b.add_const(gas_used_header, -F::from_canonical_u64(128));

        let initial_gas_index = b.add(gas_used_offset, one);
        let final_gas_index = b.add(gas_used_offset, gas_used_len);

        let combiner = b.constant(F::from_canonical_u64(1 << 8));

        let gas_used = (0..3u64).fold(zero, |acc, i| {
            let access_index = b.add_const(initial_gas_index, F::from_canonical_u64(i));
            let array_value = value.arr.random_access_large_array(b, access_index);

            // If we have extracted a value from an index in the desired range (so lte final_gas_index) we want to add it.
            // If access_index was strictly less than final_gas_index we need to multiply by 1 << 8 after (since the encoding is big endian)
            let valid = less_than_or_equal_to(b, access_index, final_gas_index, 12);
            let need_scalar = less_than(b, access_index, final_gas_index, 12);

            let to_add = b.select(valid, array_value, zero);

            let scalar = b.select(need_scalar, combiner, one);
            let tmp = b.add(acc, to_add);
            b.mul(tmp, scalar)
        });

        // Map the gas used to a curve point for the value digest, gas used is the first column so use one as its column id.
        let gas_digest = b.map_to_curve_point(&[zero, gas_used]);

        // We also keep track of the number of real logs we process as each log forms a row in our table
        let mut n = zero;
        for (index, log_offset) in relevant_logs_offsets.arr.arr.into_iter().enumerate() {
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

                let selected_point = b.select_curve_point(dummy_column, curve_zero, data_digest);
                let selected_point = b.select_curve_point(dummy, curve_zero, selected_point);

                points.push(selected_point);
            }
            // If this is a real row we record the gas used in the transaction
            let gas_select = b.select_curve_point(dummy, curve_zero, gas_digest);
            points.push(gas_select);

            // We also keep track of which log this is in the receipt to avoid having identical rows in the table in the case
            // that the event we are tracking can be emitted multiple times in the same transaction but has no topics or data.
            let log_number = b.constant(F::from_canonical_usize(index + 1));
            let log_no_digest = b.map_to_curve_point(&[one, log_number]);
            let log_no_select = b.select_curve_point(dummy, curve_zero, log_no_digest);
            points.push(log_no_select);

            let increment = b.select(dummy, zero, one);
            n = b.add(n, increment);
        }

        (n, b.add_curve_point(&points))
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

        let mpt_key = MPTKeyWire::new(b);

        // Build the node wires.
        let wires = MPTReceiptLeafNode::build_and_advance_key::<_, D, NODE_LEN>(b, &mpt_key);

        let node = wires.node;
        let root = wires.root;

        // For each relevant log in the transaction we have to verify it lines up with the event we are monitoring for
        let (n, mut dv) =
            event_wires.verify_logs_and_extract_values::<NODE_LEN>(b, &node, &relevant_logs_offset);

        let value_id = b.map_to_curve_point(&[index]);

        dv = b.add_curve_point(&[value_id, dv]);

        let dm = b.map_to_curve_point(&event_wires.to_vec());

        // Register the public inputs
        PublicInputsArgs {
            h: &root.output_array,
            k: &wires.key,
            dv,
            dm,
            n,
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
        let key_nibbles: [u8; MAX_KEY_NIBBLE_LEN] = key_encoded
            .iter()
            .flat_map(|byte| [byte / 16, byte % 16])
            .chain(iter::repeat(0u8))
            .take(64)
            .collect::<Vec<u8>>()
            .try_into()
            .expect("Couldn't create mpt key with correct length");

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
            .assign(pw, &address.0.map(GFp::from_canonical_u8));

        pw.set_target(
            wires.add_rel_offset,
            F::from_canonical_usize(add_rel_offset),
        );

        wires
            .event_signature
            .assign(pw, &event_signature.map(GFp::from_canonical_u8));

        pw.set_target(
            wires.sig_rel_offset,
            F::from_canonical_usize(sig_rel_offset),
        );

        wires
            .topics
            .iter()
            .zip(topics)
            .for_each(|(topic_wire, topic)| topic_wire.assign(pw, topic));
        wires
            .data
            .iter()
            .zip(data)
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
    use super::{
        super::{compute_receipt_leaf_metadata_digest, compute_receipt_leaf_value_digest},
        *,
    };

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
            self.c.assign(pw, wires);
        }
    }
    #[test]
    fn test_leaf_circuit() {
        const NODE_LEN: usize = 512;

        let receipt_proof_infos = generate_receipt_proofs();
        let info = receipt_proof_infos.first().unwrap().clone();

        let c = ReceiptLeafCircuit::<NODE_LEN> { info: info.clone() };
        let test_circuit = TestReceiptLeafCircuit { c };

        let node = info.mpt_proof.last().unwrap().clone();

        let proof = run_circuit::<F, D, C, _>(test_circuit);
        let pi = PublicInputs::new(&proof.public_inputs);

        // Check the output hash
        {
            let exp_hash = keccak256(&node).pack(Endianness::Little);
            assert_eq!(pi.root_hash(), exp_hash);
        }

        // Check value digest
        {
            let exp_digest = compute_receipt_leaf_value_digest(&info);
            assert_eq!(pi.values_digest(), exp_digest.to_weierstrass());
        }

        // Check metadata digest
        {
            let exp_digest = compute_receipt_leaf_metadata_digest(&info.event_log_info);
            assert_eq!(pi.metadata_digest(), exp_digest.to_weierstrass());
        }
    }
}
