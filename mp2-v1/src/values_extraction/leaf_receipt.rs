//! Module handling the leaf node inside a Receipt Trie

use super::{
    gadgets::metadata_gadget::{TableMetadata, TableMetadataTarget},
    public_inputs::{PublicInputs, PublicInputsArgs},
    GAS_USED_PREFIX, TX_INDEX_PREFIX,
};

use alloy::primitives::Address;
use anyhow::Result;
use mp2_common::{
    array::{extract_value, Array, Targetable, Vector, VectorWire},
    eth::{left_pad32, EventLogInfo},
    group_hashing::CircuitBuilderGroupHashing,
    keccak::{InputData, KeccakCircuit, KeccakWires, HASH_LEN, PACKED_HASH_LEN},
    mpt_sequential::{utils::bytes_to_nibbles, MPTKeyWire, MPTReceiptLeafNode, PAD_LEN},
    poseidon::hash_to_int_target,
    public_inputs::PublicInputCommon,
    rlp::MAX_KEY_NIBBLE_LEN,
    types::{CBuilder, GFp},
    utils::{less_than_unsafe, Endianness, Packer, ToTargets},
    CHasher, D, F,
};
use plonky2::{
    field::types::Field,
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::circuit_builder::CircuitBuilder,
};

use plonky2_crypto::u32::arithmetic_u32::{CircuitBuilderU32, U32Target};
use plonky2_ecdsa::gadgets::nonnative::CircuitBuilderNonNative;
use plonky2_ecgfp5::gadgets::curve::CircuitBuilderEcGFp5;

use recursion_framework::circuit_builder::CircuitLogicWires;
use rlp::Encodable;
use serde::{Deserialize, Serialize};

/// The number of bytes that `gas_used` could take up in the receipt.
/// We set a max of 3 here because this would be over half the gas in the block for Ethereum.
const MAX_GAS_SIZE: u64 = 3;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct ReceiptLeafWires<const NODE_LEN: usize, const MAX_EXTRACTED_COLUMNS: usize>
where
    [(); PAD_LEN(NODE_LEN)]:,
{
    /// The event we are monitoring for
    pub(crate) event: EventWires,
    /// The node bytes
    pub(crate) node: VectorWire<Target, { PAD_LEN(NODE_LEN) }>,
    /// the hash of the node bytes
    pub(crate) root: KeccakWires<{ PAD_LEN(NODE_LEN) }>,
    /// The offsets of the relevant logs inside the node
    pub(crate) relevant_log_offset: Target,
    /// The key in the MPT Trie
    pub(crate) mpt_key: MPTKeyWire,
    /// The table metadata
    pub(crate) metadata: TableMetadataTarget<MAX_EXTRACTED_COLUMNS>,
}

/// Contains all the information for an [`Event`] in rlp form
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EventWires {
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
pub struct ReceiptLeafCircuit<const NODE_LEN: usize, const MAX_EXTRACTED_COLUMNS: usize> {
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
    pub metadata: TableMetadata,
}

impl<const NODE_LEN: usize, const MAX_EXTRACTED_COLUMNS: usize>
    ReceiptLeafCircuit<NODE_LEN, MAX_EXTRACTED_COLUMNS>
where
    [(); PAD_LEN(NODE_LEN)]:,
{
    /// Create a new [`ReceiptLeafCircuit`] from a [`ReceiptProofInfo`] and a [`EventLogInfo`]
    pub fn new<const NO_TOPICS: usize, const MAX_DATA_WORDS: usize>(
        last_node: &[u8],
        tx_index: u64,
        event: &EventLogInfo<NO_TOPICS, MAX_DATA_WORDS>,
    ) -> Result<Self> {
        // Get the relevant log offset
        let relevant_log_offset = event.get_log_offset(last_node)?;

        let EventLogInfo::<NO_TOPICS, MAX_DATA_WORDS> {
            size,
            address,
            add_rel_offset,
            event_signature,
            sig_rel_offset,
            ..
        } = *event;

        // Construct the table metadata from the event
        let metadata = TableMetadata::from(*event);

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

    pub(crate) fn build(b: &mut CBuilder) -> ReceiptLeafWires<NODE_LEN, MAX_EXTRACTED_COLUMNS> {
        // Build the event wires
        let event_wires = Self::build_event_wires(b);
        // Build the metadata
        let metadata = TableMetadata::build(b, 2);
        let zero = b.zero();

        let one = b.one();
        let two = b.two();

        // Add targets for the data specific to this receipt
        let relevant_log_offset = b.add_virtual_target();

        let mpt_key = MPTKeyWire::new(b);
        let index = mpt_key.fold_key(b);

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
        // Since header_len_len can be at most 8 bytes its safe for us to just take the first 64 elements of the array here as it will
        // always be in this range
        let key_header = extract_value(b, &node.arr.arr[..64], header_len_len);
        let less_than_val = b.constant(F::from_canonical_u8(128));
        let single_value = less_than_unsafe(b, key_header, less_than_val, 8);
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
        // This is the last index in the array (so inclusive) that contains data relating to gas used
        let final_gas_index = b.add(gas_used_offset, gas_used_len);

        let combiner = b.constant(F::from_canonical_u64(1 << 8));
        let mut last_byte_found = b._false();
        let gas_used = (0..MAX_GAS_SIZE).fold(zero, |acc, i| {
            let access_index = b.add_const(initial_gas_index, F::from_canonical_u64(i));
            let array_value = node.arr.random_access_large_array(b, access_index);

            // Check to see if we have reached the index where we stop summing
            let at_end = b.is_equal(access_index, final_gas_index);

            let tmp = b.mul_add(acc, combiner, array_value);
            let out = b.select(last_byte_found, acc, tmp);
            last_byte_found = b.or(at_end, last_byte_found);
            out
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
        // Add the key prefixes to the circuit as constants
        let tx_index_prefix: [Target; PACKED_HASH_LEN] = left_pad32(TX_INDEX_PREFIX)
            .pack(Endianness::Big)
            .iter()
            .map(|num| b.constant(F::from_canonical_u32(*num)))
            .collect::<Vec<Target>>()
            .try_into()
            .expect("This should never fail");
        let gas_used_prefix: [Target; PACKED_HASH_LEN] = left_pad32(GAS_USED_PREFIX)
            .pack(Endianness::Big)
            .iter()
            .map(|num| b.constant(F::from_canonical_u32(*num)))
            .collect::<Vec<Target>>()
            .try_into()
            .expect("This should never fail");

        // Now we verify extracted values
        let (extraction_id, extracted_metadata_digest, extracted_value_digest) = metadata
            .extracted_receipt_digests(
                b,
                &node.arr,
                relevant_log_offset,
                event_wires.add_rel_offset,
                event_wires.sig_rel_offset,
            );

        // Extract input values
        let (input_metadata_digest, input_value_digest) = metadata.inputs_digests(
            b,
            &[tx_index_input.clone(), gas_used_input.clone()],
            &[&tx_index_prefix, &gas_used_prefix],
            &extraction_id.arr,
        );

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
            relevant_log_offset,
            mpt_key,
            metadata,
        }
    }

    fn build_event_wires(b: &mut CBuilder) -> EventWires {
        // Packed address
        let address = Array::<Target, 20>::new(b);

        // relative offset of the address
        let add_rel_offset = b.add_virtual_target();

        // Event signature
        let event_signature = Array::<Target, 32>::new(b);

        // Signature relative offset
        let sig_rel_offset = b.add_virtual_target();

        EventWires {
            address,
            add_rel_offset,
            event_signature,
            sig_rel_offset,
        }
    }

    pub(crate) fn assign(
        &self,
        pw: &mut PartialWitness<GFp>,
        wires: &ReceiptLeafWires<NODE_LEN, MAX_EXTRACTED_COLUMNS>,
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

        pw.set_target(
            wires.relevant_log_offset,
            GFp::from_canonical_usize(self.relevant_log_offset),
        );
        let key_encoded = self.tx_index.rlp_bytes();
        let mut nibbles = bytes_to_nibbles(&key_encoded);
        let ptr = nibbles.len() - 1;
        nibbles.resize(MAX_KEY_NIBBLE_LEN, 0u8);

        let key_nibbles: [u8; MAX_KEY_NIBBLE_LEN] = nibbles
            .try_into()
            .expect("Couldn't create mpt key with correct length");

        wires.mpt_key.assign(pw, &key_nibbles, ptr);

        TableMetadata::assign(pw, &self.metadata, &wires.metadata);
    }

    pub fn assign_event_wires(&self, pw: &mut PartialWitness<GFp>, wires: &EventWires) {
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
impl<const NODE_LEN: usize, const MAX_EXTRACTED_COLUMNS: usize> CircuitLogicWires<GFp, D, 0>
    for ReceiptLeafWires<NODE_LEN, MAX_EXTRACTED_COLUMNS>
where
    [(); PAD_LEN(NODE_LEN)]:,
{
    type CircuitBuilderParams = ();

    type Inputs = ReceiptLeafCircuit<NODE_LEN, MAX_EXTRACTED_COLUMNS>;

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

    use crate::values_extraction::{
        compute_leaf_receipt_metadata_digest, compute_leaf_receipt_values_digest,
    };

    use super::*;

    use mp2_common::{
        utils::{keccak256, Endianness, Packer},
        C,
    };
    use mp2_test::{
        circuit::{run_circuit, UserCircuit},
        mpt_sequential::generate_receipt_test_info,
    };

    #[derive(Clone, Debug)]
    struct TestReceiptLeafCircuit<const NODE_LEN: usize> {
        c: ReceiptLeafCircuit<NODE_LEN, 5>,
    }

    impl<const NODE_LEN: usize> UserCircuit<F, D> for TestReceiptLeafCircuit<NODE_LEN>
    where
        [(); PAD_LEN(NODE_LEN)]:,
    {
        // Leaf wires + expected extracted value
        type Wires = ReceiptLeafWires<NODE_LEN, 5>;

        fn build(b: &mut CircuitBuilder<F, D>) -> Self::Wires {
            ReceiptLeafCircuit::<NODE_LEN, 5>::build(b)
        }

        fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
            self.c.assign(pw, wires);
        }
    }
    #[test]
    fn test_leaf_circuit() {
        const NODE_LEN: usize = 512;
        test_leaf_circuit_helper::<0, 0, NODE_LEN>();
        test_leaf_circuit_helper::<1, 0, NODE_LEN>();
        test_leaf_circuit_helper::<2, 0, NODE_LEN>();
        test_leaf_circuit_helper::<3, 0, NODE_LEN>();
        test_leaf_circuit_helper::<3, 1, NODE_LEN>();
        test_leaf_circuit_helper::<3, 2, NODE_LEN>();
    }

    fn test_leaf_circuit_helper<
        const NO_TOPICS: usize,
        const MAX_DATA_WORDS: usize,
        const NODE_LEN: usize,
    >()
    where
        [(); PAD_LEN(NODE_LEN)]:,
    {
        let receipt_proof_infos = generate_receipt_test_info::<NO_TOPICS, MAX_DATA_WORDS>();
        let proofs = receipt_proof_infos.proofs();
        let info = proofs.first().unwrap();
        let event = receipt_proof_infos.info();

        let c = ReceiptLeafCircuit::<NODE_LEN, 5>::new::<NO_TOPICS, MAX_DATA_WORDS>(
            info.mpt_proof.last().unwrap(),
            info.tx_index,
            event,
        )
        .unwrap();

        let test_circuit = TestReceiptLeafCircuit { c };

        let node = info.mpt_proof.last().unwrap().clone();

        let metadata_digest = compute_leaf_receipt_metadata_digest(event);
        let values_digest = compute_leaf_receipt_values_digest(event, &node, info.tx_index);

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
            assert_eq!(pi.values_digest(), values_digest.to_weierstrass());
        }

        // Check metadata digest
        {
            assert_eq!(pi.metadata_digest(), metadata_digest.to_weierstrass());
        }
    }
}
