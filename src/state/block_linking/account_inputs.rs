//! This is the account-inputs gadget. It builds the circuit to prove that the
//! sequential state MPT, and the hash of storage MPT root should be included in
//! the account node.

use crate::{
    keccak::{OutputByteHash, OutputHash},
    mpt_sequential::{
        Circuit as MPTCircuit, InputWires as MPTInputWires, OutputWires as MPTOutputWires, PAD_LEN,
    },
    utils::{find_index_subvector, keccak256, less_than},
};
use anyhow::Result;
use ethers::types::{H160, H256};
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::circuit_builder::CircuitBuilder,
};

/// The account input wires
pub struct AccountInputsWires<const DEPTH: usize, const NODE_LEN: usize>
where
    [(); PAD_LEN(NODE_LEN)]:,
    [(); DEPTH - 1]:,
{
    /// The offset of storage MPT root hash located in RLP encoded account node
    pub storage_root_offset: Target,
    /// Input wires of state MPT circuit
    pub state_mpt_input: MPTInputWires<DEPTH, NODE_LEN>,
    /// Output wires of state MPT circuit
    pub state_mpt_output: MPTOutputWires<DEPTH, NODE_LEN>,
}

/// The account input gadget
#[derive(Clone, Debug)]
pub struct AccountInputs<const DEPTH: usize, const NODE_LEN: usize> {
    /// The offset of storage root hash located in RLP encoded account node
    storage_root_offset: usize,
    /// MPT circuit used to verify the nodes of state Merkle Tree
    state_mpt_circuit: MPTCircuit<DEPTH, NODE_LEN>,
}

impl<const DEPTH: usize, const NODE_LEN: usize> AccountInputs<DEPTH, NODE_LEN>
where
    [(); PAD_LEN(NODE_LEN)]:,
    [(); DEPTH - 1]:,
{
    pub fn new(
        contract_address: H160,
        storage_root_hash: H256,
        state_mpt_nodes: Vec<Vec<u8>>,
    ) -> Self {
        // Find the storage root hash from account node.
        let storage_root_offset =
            find_index_subvector(&state_mpt_nodes[0], &storage_root_hash.0).unwrap();

        // Build the full MPT key as `keccak256(contract_address)` and convert
        // it to bytes.
        // Check with [ProofQuery::verify_state_proof] for details.
        let state_mpt_key = keccak256(&contract_address.0).try_into().unwrap();

        // Build the MPT circuit for state Merkle Tree.
        let state_mpt_circuit = MPTCircuit::new(state_mpt_key, state_mpt_nodes);

        Self {
            storage_root_offset,
            state_mpt_circuit,
        }
    }

    /// Build for circuit.
    pub fn build<F, const D: usize>(
        cb: &mut CircuitBuilder<F, D>,
    ) -> AccountInputsWires<DEPTH, NODE_LEN>
    where
        F: RichField + Extendable<D>,
    {
        let storage_root_offset = cb.add_virtual_target();

        // Generate the input and output wires of state MPT circuit.
        let state_mpt_input = MPTCircuit::create_input_wires(cb);
        let state_mpt_output = MPTCircuit::verify_mpt_proof(cb, &state_mpt_input);

        AccountInputsWires {
            storage_root_offset,
            state_mpt_input,
            state_mpt_output,
        }
    }

    /// Assign the wires.
    pub fn assign<F, const D: usize>(
        &self,
        pw: &mut PartialWitness<F>,
        wires: &AccountInputsWires<DEPTH, NODE_LEN>,
    ) -> Result<()>
    where
        F: RichField + Extendable<D>,
    {
        // Assign the offset of storage MPT root hash located in RLP encoded
        // account node.
        pw.set_target(
            wires.storage_root_offset,
            F::from_canonical_usize(self.storage_root_offset),
        );

        // Assign the input and output wires of state MPT circuit.
        self.state_mpt_circuit
            .assign_wires(pw, &wires.state_mpt_input, &wires.state_mpt_output)
    }

    /// Verify the account node includes the hash of storage MPT root.
    pub fn verify_storage_root_hash_inclusion<F, const D: usize>(
        cb: &mut CircuitBuilder<F, D>,
        wires: &AccountInputsWires<DEPTH, NODE_LEN>,
        storage_root_hash: &OutputHash,
    ) where
        F: RichField + Extendable<D>,
    {
        let tt = cb._true();
        let account_node = &wires.state_mpt_input.nodes[0];

        // Verify the offset of storage MPT root hash is within range. We use 8
        // bits for the range check since the account node is composed by
        // [nonce (U64), balance (U256), storage_hash (H256), code_hash (H256)]
        // and it has 104 bytes.
        let within_range = less_than(cb, wires.storage_root_offset, account_node.real_len, 8);
        cb.connect(within_range.target, tt.target);

        // Verify the account node includes the storage MPT root hash.
        let storage_root_hash = OutputByteHash::from_u32_array(cb, storage_root_hash);
        let is_included =
            account_node
                .arr
                .contains_array(cb, &storage_root_hash, wires.storage_root_offset);
        cb.connect(is_included.target, tt.target);
    }
}
