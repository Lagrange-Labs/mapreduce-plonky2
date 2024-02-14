//! Block-linking circuit implemention used to prove the pre-computed state root
//! proof is linked to the specific block header.

use super::{
    account_inputs::{AccountInputs, AccountInputsWires},
    block_inputs::{BlockInputs, BlockInputsWires},
    storage_proof::{StorageInputs, StorageInputsWires},
};
use crate::{mpt_sequential::PAD_LEN, rlp::MAX_KEY_NIBBLE_LEN};
use anyhow::Result;
use ethers::types::{Block, H256};
use plonky2::{
    field::extension::Extendable, hash::hash_types::RichField, iop::witness::PartialWitness,
    plonk::circuit_builder::CircuitBuilder,
};

/// Main block-linking wires
pub struct BlockLinkingWires<const DEPTH: usize, const NODE_LEN: usize, const BLOCK_LEN: usize>
where
    [(); PAD_LEN(NODE_LEN)]:,
    [(); DEPTH - 1]:,
{
    /// Account input data
    account_inputs: AccountInputsWires<DEPTH, NODE_LEN>,
    /// Block input data
    block_inputs: BlockInputsWires<BLOCK_LEN>,
    /// Previous storage proof
    storage_proof: StorageInputsWires,
}

impl<const DEPTH: usize, const NODE_LEN: usize, const BLOCK_LEN: usize>
    BlockLinkingWires<DEPTH, NODE_LEN, BLOCK_LEN>
where
    [(); PAD_LEN(NODE_LEN)]:,
    [(); DEPTH - 1]:,
{
    /// Register as public inputs.
    pub fn register_as_input<F, const D: usize>(&self, cb: &mut CircuitBuilder<F, D>)
    where
        F: RichField + Extendable<D>,
    {
        // We expose the public inputs as below:
        //
        // expose block.hash as H
        // expose block.mumber as N
        // expose block.parent_hash as PREV_H
        // expose storage_proof.public_input[A]
        // expose storage_proof.public_input[D]
        // expose storage_proof.public_input[M]
        // expose storage_proof.public_input[S]
        //
        // We only expose the equivalent storage tree root here, NOT the one
        // from blockchain, we can finally forget about it!
        // expose storage_proof.public_input[C2] as C

        self.block_inputs.hash.register_as_public_input(cb);
        cb.register_public_input(self.block_inputs.number);
        self.block_inputs.parent_hash.register_as_public_input(cb);
        cb.register_public_inputs(self.storage_proof.a_targets());
        cb.register_public_inputs(self.storage_proof.d_targets());
        cb.register_public_inputs(self.storage_proof.m_targets());
        cb.register_public_inputs(self.storage_proof.s_targets());
        cb.register_public_inputs(self.storage_proof.c2_targets());
    }
}

/// Block-linking circuit used to prove the pre-computed state root proof is
/// linked to the specific block header.
#[derive(Clone, Debug)]
pub struct BlockLinkingCircuit<F, const DEPTH: usize, const NODE_LEN: usize, const BLOCK_LEN: usize>
{
    /// Account input data
    account_inputs: AccountInputs<DEPTH, NODE_LEN>,
    /// Block input data
    block_inputs: BlockInputs,
    /// Previous storage proof
    storage_proof: StorageInputs<F>,
}

impl<F, const DEPTH: usize, const NODE_LEN: usize, const HEADER_LEN: usize>
    BlockLinkingCircuit<F, DEPTH, NODE_LEN, HEADER_LEN>
where
    [(); PAD_LEN(NODE_LEN)]:,
    [(); DEPTH - 1]:,
{
    pub fn new(
        storage_hash: H256,
        block: Block<H256>,
        storage_proof: StorageInputs<F>,
        // keccak(account_address)
        mpt_key: [u8; MAX_KEY_NIBBLE_LEN / 2],
        // account_proof
        mpt_nodes: Vec<Vec<u8>>,
    ) -> Self {
        // Nodes should be ordered from leaf to root.
        let state_mpt_root = mpt_nodes.last().unwrap();

        let block_inputs = BlockInputs::new(block, state_mpt_root);
        let account_inputs = AccountInputs::new(storage_hash, mpt_key, mpt_nodes);

        Self {
            account_inputs,
            block_inputs,
            storage_proof,
        }
    }

    /// Build the circuit.
    pub fn build_circuit<const D: usize>(
        cb: &mut CircuitBuilder<F, D>,
    ) -> BlockLinkingWires<DEPTH, NODE_LEN, HEADER_LEN>
    where
        F: RichField + Extendable<D>,
        [(); PAD_LEN(NODE_LEN)]:,
        [(); DEPTH - 1]:,
    {
        let account_inputs = AccountInputsWires::new(cb);
        let block_inputs = BlockInputsWires::new(cb);
        let storage_proof = StorageInputsWires::new(cb);

        // Verify the hash of storage MPT root equals to the one in previous
        // storage proof.
        let tt = cb._true();
        let is_storage_root_equal = account_inputs
            .storage_hash
            .equals(cb, &storage_proof.mpt_root_hash());
        cb.connect(is_storage_root_equal.target, tt.target);

        // Verify block header includes the hash of state MPT root.
        block_inputs.verify_root_hash_inclusion(cb, &account_inputs.mpt_output.root);

        BlockLinkingWires {
            account_inputs,
            block_inputs,
            storage_proof,
        }
    }

    /// Assign the wires.
    pub fn assign_wires<const D: usize>(
        &self,
        pw: &mut PartialWitness<F>,
        wires: &BlockLinkingWires<DEPTH, NODE_LEN, HEADER_LEN>,
    ) -> Result<()>
    where
        F: RichField + Extendable<D>,
    {
        wires.storage_proof.assign(pw, &self.storage_proof);
        wires.account_inputs.assign(pw, &self.account_inputs)?;
        wires.block_inputs.assign(pw, &self.block_inputs)
    }
}
