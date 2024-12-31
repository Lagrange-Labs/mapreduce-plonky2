//! Module handling the leaf node inside a Receipt Trie

use super::{
    gadgets::metadata_gadget::{TableMetadata, TableMetadataGadget, TableMetadataTarget},
    public_inputs::{PublicInputs, PublicInputsArgs},
};

use alloy::{
    primitives::{Address, Log, B256},
    rlp::Decodable,
};
use anyhow::Result;
use mp2_common::{
    array::{Array, Targetable, Vector, VectorWire},
    eth::EventLogInfo,
    group_hashing::CircuitBuilderGroupHashing,
    keccak::{InputData, KeccakCircuit, KeccakWires, HASH_LEN},
    mpt_sequential::{MPTKeyWire, MPTReceiptLeafNode, PAD_LEN},
    poseidon::{hash_to_int_target, H},
    public_inputs::PublicInputCommon,
    rlp::MAX_KEY_NIBBLE_LEN,
    types::{CBuilder, GFp},
    utils::{less_than, less_than_or_equal_to_unsafe, Endianness, ToTargets},
    CHasher, D, F,
};
use plonky2::{
    field::types::Field,
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{circuit_builder::CircuitBuilder, config::Hasher},
};

use plonky2_crypto::u32::arithmetic_u32::{CircuitBuilderU32, U32Target};
use plonky2_ecdsa::gadgets::nonnative::CircuitBuilderNonNative;
use plonky2_ecgfp5::gadgets::curve::CircuitBuilderEcGFp5;

use recursion_framework::circuit_builder::CircuitLogicWires;
use rlp::Encodable;
use serde::{Deserialize, Serialize};
use std::iter;

/// The number of bytes that `gas_used` could take up in the receipt.
/// We set a max of 3 here because this would be over half the gas in the block for Ethereum.
const MAX_GAS_SIZE: u64 = 3;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ReceiptLeafWires<const NODE_LEN: usize, const MAX_COLUMNS: usize>
where
    [(); PAD_LEN(NODE_LEN)]:,
    [(); MAX_COLUMNS - 2]:,
{
    /// The event we are monitoring for
    pub event: EventWires,
    /// The node bytes
    pub node: VectorWire<Target, { PAD_LEN(NODE_LEN) }>,
    /// the hash of the node bytes
    pub root: KeccakWires<{ PAD_LEN(NODE_LEN) }>,
    /// The index of this receipt in the block
    pub index: Target,
    /// The offsets of the relevant logs inside the node
    pub relevant_log_offset: Target,
    /// The key in the MPT Trie
    pub mpt_key: MPTKeyWire,
    /// The table metadata
    pub(crate) metadata: TableMetadataTarget<MAX_COLUMNS, 2>,
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
    event_signature: Array<Target, HASH_LEN>,
    /// Byte offset from the start of the log to event signature
    sig_rel_offset: Target,
}

/// Circuit to prove a transaction receipt contains logs relating to a specific event.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReceiptLeafCircuit<const NODE_LEN: usize, const MAX_COLUMNS: usize>
where
    [(); MAX_COLUMNS - 2]:,
{
    /// This is the RLP encoded leaf node in the Receipt Trie.
    pub node: Vec<u8>,
    /// The transaction index, telling us where the receipt is in the block. The RLP encoding of the index
    /// is also the key used in the Receipt Trie.
    pub tx_index: u64,
    /// The size of the node in bytes
    pub size: usize,
    /// The address of the contract that emits the log
    pub address: Address,
    /// The offset of the address in the rlp encoded log
    pub rel_add_offset: usize,
    /// The event signature hash
    pub event_signature: [u8; HASH_LEN],
    /// The offset of the event signature in the rlp encoded log
    pub sig_rel_offset: usize,
    /// This is the offset in the node to the start of the log that relates to `event_info`
    pub relevant_log_offset: usize,
    /// The table metadata
    pub metadata: TableMetadata<MAX_COLUMNS, 2>,
}

/// Contains all the information for data contained in an [`Event`]
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct LogDataInfo {
    /// The column id of this piece of info
    pub column_id: GFp,
    /// The byte offset from the beggining of the log to this target
    pub rel_byte_offset: usize,
    /// The length of this piece of data
    pub len: usize,
}

impl<const NODE_LEN: usize, const MAX_COLUMNS: usize> ReceiptLeafCircuit<NODE_LEN, MAX_COLUMNS>
where
    [(); PAD_LEN(NODE_LEN)]:,
    [(); MAX_COLUMNS - 2]:,
{
    /// Create a new [`ReceiptLeafCircuit`] from a [`ReceiptProofInfo`] and a [`EventLogInfo`]
    pub fn new<const NO_TOPICS: usize, const MAX_DATA: usize>(
        last_node: &[u8],
        tx_index: u64,
        event: &EventLogInfo<NO_TOPICS, MAX_DATA>,
    ) -> Result<Self>
    where
        [(); MAX_COLUMNS - 2 - NO_TOPICS - MAX_DATA]:,
    {
        // Convert to Rlp form so we can use provided methods.
        let node_rlp = rlp::Rlp::new(last_node);

        // The actual receipt data is item 1 in the list
        let (receipt_rlp, receipt_off) = node_rlp.at_with_offset(1)?;
        // The rlp encoded Receipt is not a list but a string that is formed of the `tx_type` followed by the remaining receipt
        // data rlp encoded as a list. We retrieve the payload info so that we can work out relevant offsets later.
        let receipt_str_payload = receipt_rlp.payload_info()?;

        // We make a new `Rlp` struct that should be the encoding of the inner list representing the `ReceiptEnvelope`
        let receipt_list = rlp::Rlp::new(&receipt_rlp.data()?[1..]);

        // The logs themselves start are the item at index 3 in this list
        let (logs_rlp, logs_off) = receipt_list.at_with_offset(3)?;

        // We calculate the offset the that the logs are at from the start of the node
        let logs_offset = receipt_off + receipt_str_payload.header_len + 1 + logs_off;

        // Now we produce an iterator over the logs with each logs offset.
        let relevant_log_offset = iter::successors(Some(0usize), |i| Some(i + 1))
            .map_while(|i| logs_rlp.at_with_offset(i).ok())
            .find_map(|(log_rlp, log_off)| {
                let mut bytes = log_rlp.as_raw();
                let log = Log::decode(&mut bytes).ok()?;

                if log.address == event.address
                    && log
                        .data
                        .topics()
                        .contains(&B256::from(event.event_signature))
                {
                    Some(logs_offset + log_off)
                } else {
                    Some(0usize)
                }
            })
            .ok_or(anyhow!("There were no relevant logs in this transaction"))?;

        let EventLogInfo::<NO_TOPICS, MAX_DATA> {
            size,
            address,
            add_rel_offset,
            event_signature,
            sig_rel_offset,
            ..
        } = *event;

        // Construct the table metadata from the event
        let metadata = TableMetadata::<MAX_COLUMNS, 2>::from(*event);

        Ok(Self {
            node: last_node.to_vec(),
            tx_index,
            size,
            address,
            rel_add_offset: add_rel_offset,
            event_signature,
            sig_rel_offset,
            relevant_log_offset,
            metadata,
        })
    }

    pub fn build(b: &mut CBuilder) -> ReceiptLeafWires<NODE_LEN, MAX_COLUMNS> {
        // Build the event wires
        let event_wires = Self::build_event_wires(b);
        // Build the metadata
        let metadata = TableMetadataGadget::build(b);
        let zero = b.zero();

        let one = b.one();
        let two = b.two();
        let t = b._true();
        // Add targets for the data specific to this receipt
        let index = b.add_virtual_target();

        let relevant_log_offset = b.add_virtual_target();

        let mpt_key = MPTKeyWire::new(b);

        // Build the node wires.
        let wires = MPTReceiptLeafNode::build_and_advance_key::<_, D, NODE_LEN>(b, &mpt_key);

        let node = wires.node;
        let root = wires.root;

        // Extract the gas used in the transaction, since the position of this can vary because it is after the key
        // we have to prove we extracted from the correct location.
        let header_len_len = b.add_const(
            node.arr.arr[0],
            F::from_canonical_u64(1) - F::from_canonical_u64(247),
        );
        let key_header = node.arr.random_access_large_array(b, header_len_len);
        let less_than_val = b.constant(F::from_canonical_u8(128));
        let single_value = less_than(b, key_header, less_than_val, 8);
        let key_len_maybe = b.add_const(key_header, F::ONE - F::from_canonical_u64(128));
        let key_len = b.select(single_value, one, key_len_maybe);

        // This is the start of the string that is the rlp encoded receipt (a string since the first element is transaction type).
        // From here we subtract 183 to get the length of the length, then the encoded gas used is at length of length + 1 (for tx type) + (1 + list length)
        // + 1 (for status) + 1 to get the header for the gas used string.
        let string_offset = b.add(key_len, header_len_len);
        let string_header = node.arr.random_access_large_array(b, string_offset);
        let string_len_len = b.add_const(string_header, -F::from_canonical_u64(183));

        let list_offset = b.add_many([string_offset, string_len_len, two]);
        let list_header = node.arr.random_access_large_array(b, list_offset);

        let gas_used_offset_lo = b.add_const(
            list_header,
            F::from_canonical_u64(2) - F::from_canonical_u64(247),
        );
        let gas_used_offset = b.add(gas_used_offset_lo, list_offset);

        let gas_used_header = node.arr.random_access_large_array(b, gas_used_offset);
        let gas_used_len = b.add_const(gas_used_header, -F::from_canonical_u64(128));

        let initial_gas_index = b.add(gas_used_offset, one);
        let final_gas_index = b.add(gas_used_offset, gas_used_len);

        let combiner = b.constant(F::from_canonical_u64(1 << 8));

        let gas_used = (0..MAX_GAS_SIZE).fold(zero, |acc, i| {
            let access_index = b.add_const(initial_gas_index, F::from_canonical_u64(i));
            let array_value = node.arr.random_access_large_array(b, access_index);

            // If we have extracted a value from an index in the desired range (so lte final_gas_index) we want to add it.
            // If access_index was strictly less than final_gas_index we need to multiply by 1 << 8 after (since the encoding is big endian)
            let valid = less_than_or_equal_to_unsafe(b, access_index, final_gas_index, 12);
            let need_scalar = less_than(b, access_index, final_gas_index, 12);

            let to_add = b.select(valid, array_value, zero);

            let scalar = b.select(need_scalar, combiner, one);
            let tmp = b.add(acc, to_add);
            b.mul(tmp, scalar)
        });

        let zero_u32 = b.zero_u32();
        let tx_index_input = Array::<U32Target, 8>::from_array([
            zero_u32,
            zero_u32,
            zero_u32,
            zero_u32,
            zero_u32,
            zero_u32,
            zero_u32,
            U32Target::from_target(index),
        ]);
        let gas_used_input = Array::<U32Target, 8>::from_array([
            zero_u32,
            zero_u32,
            zero_u32,
            zero_u32,
            zero_u32,
            zero_u32,
            zero_u32,
            U32Target::from_target(gas_used),
        ]);

        // Extract input values
        let (input_metadata_digest, input_value_digest) =
            metadata.inputs_digests(b, &[tx_index_input.clone(), gas_used_input.clone()]);
        // Now we verify extracted values
        let (address_extract, signature_extract, extracted_metadata_digest, extracted_value_digest) =
            metadata.extracted_receipt_digests(
                b,
                &node.arr,
                relevant_log_offset,
                event_wires.add_rel_offset,
                event_wires.sig_rel_offset,
            );

        let address_check = address_extract.equals(b, &event_wires.address);
        let sig_check = signature_extract.equals(b, &event_wires.event_signature);

        b.connect(t.target, address_check.target);
        b.connect(t.target, sig_check.target);

        let dm = b.add_curve_point(&[input_metadata_digest, extracted_metadata_digest]);

        let value_digest = b.add_curve_point(&[input_value_digest, extracted_value_digest]);

        // Compute the unique data to identify a row is the mapping key.
        // row_unique_data = H(tx_index || gas_used)
        let row_unique_data = b.hash_n_to_hash_no_pad::<CHasher>(
            tx_index_input
                .arr
                .iter()
                .map(|t| t.to_target())
                .chain(gas_used_input.arr.iter().map(|t| t.to_target()))
                .collect::<Vec<Target>>(),
        );
        // row_id = H2int(row_unique_data || num_actual_columns)
        let inputs = row_unique_data
            .to_targets()
            .into_iter()
            .chain(std::iter::once(metadata.num_actual_columns))
            .collect();
        let hash = b.hash_n_to_hash_no_pad::<CHasher>(inputs);
        let row_id = hash_to_int_target(b, hash);

        // values_digest = values_digest * row_id
        let row_id = b.biguint_to_nonnative(&row_id);
        let dv = b.curve_scalar_mul(value_digest, &row_id);

        // Register the public inputs
        PublicInputsArgs {
            h: &root.output_array,
            k: &wires.key,
            dv,
            dm,
            n: one,
        }
        .register_args(b);

        ReceiptLeafWires {
            event: event_wires,
            node,
            root,
            index,
            relevant_log_offset,
            mpt_key,
            metadata,
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

        EventWires {
            size,
            address,
            add_rel_offset,
            event_signature,
            sig_rel_offset,
        }
    }

    pub fn assign(
        &self,
        pw: &mut PartialWitness<GFp>,
        wires: &ReceiptLeafWires<NODE_LEN, MAX_COLUMNS>,
    ) {
        self.assign_event_wires(pw, &wires.event);

        let pad_node =
            Vector::<u8, { PAD_LEN(NODE_LEN) }>::from_vec(&self.node).expect("invalid node given");
        wires.node.assign(pw, &pad_node);
        KeccakCircuit::<{ PAD_LEN(NODE_LEN) }>::assign(
            pw,
            &wires.root,
            &InputData::Assigned(&pad_node),
        );
        pw.set_target(wires.index, GFp::from_canonical_u64(self.tx_index));

        pw.set_target(
            wires.relevant_log_offset,
            GFp::from_canonical_usize(self.relevant_log_offset),
        );
        let key_encoded = self.tx_index.rlp_bytes();
        let key_nibbles: [u8; MAX_KEY_NIBBLE_LEN] = key_encoded
            .iter()
            .flat_map(|byte| [byte / 16, byte % 16])
            .chain(iter::repeat(0u8))
            .take(MAX_KEY_NIBBLE_LEN)
            .collect::<Vec<u8>>()
            .try_into()
            .expect("Couldn't create mpt key with correct length");

        wires.mpt_key.assign(pw, &key_nibbles, key_encoded.len());

        TableMetadataGadget::<MAX_COLUMNS, 2>::assign(pw, &self.metadata, &wires.metadata);
    }

    pub fn assign_event_wires(&self, pw: &mut PartialWitness<GFp>, wires: &EventWires) {
        pw.set_target(wires.size, F::from_canonical_usize(self.size));

        wires
            .address
            .assign(pw, &self.address.0.map(GFp::from_canonical_u8));

        pw.set_target(
            wires.add_rel_offset,
            F::from_canonical_usize(self.rel_add_offset),
        );

        wires
            .event_signature
            .assign(pw, &self.event_signature.map(GFp::from_canonical_u8));

        pw.set_target(
            wires.sig_rel_offset,
            F::from_canonical_usize(self.sig_rel_offset),
        );
    }
}

/// Num of children = 0
impl<const NODE_LEN: usize, const MAX_COLUMNS: usize> CircuitLogicWires<GFp, D, 0>
    for ReceiptLeafWires<NODE_LEN, MAX_COLUMNS>
where
    [(); PAD_LEN(NODE_LEN)]:,
    [(); MAX_COLUMNS - 2]:,
{
    type CircuitBuilderParams = ();

    type Inputs = ReceiptLeafCircuit<NODE_LEN, MAX_COLUMNS>;

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

    use mp2_common::{
        eth::left_pad32,
        poseidon::hash_to_int_value,
        utils::{keccak256, Packer, ToFields},
        C,
    };
    use mp2_test::{
        circuit::{run_circuit, UserCircuit},
        mpt_sequential::generate_receipt_test_info,
    };
    use plonky2::hash::hash_types::HashOut;
    use plonky2_ecgfp5::curve::scalar_field::Scalar;
    #[derive(Clone, Debug)]
    struct TestReceiptLeafCircuit<const NODE_LEN: usize> {
        c: ReceiptLeafCircuit<NODE_LEN, 7>,
    }

    impl<const NODE_LEN: usize> UserCircuit<F, D> for TestReceiptLeafCircuit<NODE_LEN>
    where
        [(); PAD_LEN(NODE_LEN)]:,
    {
        // Leaf wires + expected extracted value
        type Wires = ReceiptLeafWires<NODE_LEN, 7>;

        fn build(b: &mut CircuitBuilder<F, D>) -> Self::Wires {
            ReceiptLeafCircuit::<NODE_LEN, 7>::build(b)
        }

        fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
            self.c.assign(pw, wires);
        }
    }
    #[test]
    fn test_leaf_circuit() {
        const NODE_LEN: usize = 512;
        test_leaf_circuit_helper::<1, 0, NODE_LEN>();
        test_leaf_circuit_helper::<2, 0, NODE_LEN>();
        test_leaf_circuit_helper::<3, 0, NODE_LEN>();
        test_leaf_circuit_helper::<3, 1, NODE_LEN>();
        test_leaf_circuit_helper::<3, 2, NODE_LEN>();
    }

    fn test_leaf_circuit_helper<
        const NO_TOPICS: usize,
        const MAX_DATA: usize,
        const NODE_LEN: usize,
    >()
    where
        [(); PAD_LEN(NODE_LEN)]:,
        [(); 7 - 2 - NO_TOPICS - MAX_DATA]:,
    {
        let receipt_proof_infos = generate_receipt_test_info::<NO_TOPICS, MAX_DATA>();
        let proofs = receipt_proof_infos.proofs();
        let info = proofs.first().unwrap();
        let query = receipt_proof_infos.query();

        let c = ReceiptLeafCircuit::<NODE_LEN, 7>::new::<NO_TOPICS, MAX_DATA>(
            info.mpt_proof.last().unwrap(),
            info.tx_index,
            &query.event,
        )
        .unwrap();
        let metadata = c.metadata.clone();

        let test_circuit = TestReceiptLeafCircuit { c };

        let node = info.mpt_proof.last().unwrap().clone();

        let mut tx_index_input = [0u8; 32];
        tx_index_input[31] = info.tx_index as u8;

        let node_rlp = rlp::Rlp::new(&node);
        // The actual receipt data is item 1 in the list
        let receipt_rlp = node_rlp.at(1).unwrap();

        // We make a new `Rlp` struct that should be the encoding of the inner list representing the `ReceiptEnvelope`
        let receipt_list = rlp::Rlp::new(&receipt_rlp.data().unwrap()[1..]);

        // The logs themselves start are the item at index 3 in this list
        let gas_used_rlp = receipt_list.at(1).unwrap();

        let gas_used_bytes = left_pad32(gas_used_rlp.data().unwrap());

        assert!(node.len() <= NODE_LEN);
        let proof = run_circuit::<F, D, C, _>(test_circuit);
        let pi = PublicInputs::new(&proof.public_inputs);

        // Check the output hash
        {
            let exp_hash = keccak256(&node).pack(Endianness::Little);
            assert_eq!(pi.root_hash(), exp_hash);
        }

        // Check value digest
        {
            let (input_d, row_unique_data) =
                metadata.input_value_digest(&[&tx_index_input, &gas_used_bytes]);
            let extracted_vd = metadata.extracted_receipt_value_digest(&node, &query.event);

            let total = input_d + extracted_vd;

            // row_id = H2int(row_unique_data || num_actual_columns)
            let inputs = HashOut::from(row_unique_data)
                .to_fields()
                .into_iter()
                .chain(std::iter::once(GFp::from_canonical_usize(
                    metadata.num_actual_columns,
                )))
                .collect::<Vec<GFp>>();
            let hash = H::hash_no_pad(&inputs);
            let row_id = hash_to_int_value(hash);

            // values_digest = values_digest * row_id
            let row_id = Scalar::from_noncanonical_biguint(row_id);

            let exp_digest = total * row_id;
            assert_eq!(pi.values_digest(), exp_digest.to_weierstrass());
        }

        // Check metadata digest
        {
            let exp_digest = metadata.digest();
            assert_eq!(pi.metadata_digest(), exp_digest.to_weierstrass());
        }
    }
}
