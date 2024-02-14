//! This is the account-inputs gadget. It builds the circuit to prove the
//! storage root hash and state Merkle tree (account proof) as data in
//! [EIP1186ProofResponse](https://github.com/gakonst/ethers-rs/blob/73e5de211c32a1f5777eb5194205bdb31f6a3502/ethers-core/src/types/proof.rs#L13).

use crate::{
    array::Array,
    keccak::PACKED_HASH_LEN,
    mpt_sequential::{Circuit, InputWires, OutputWires, PAD_LEN},
    rlp::MAX_KEY_NIBBLE_LEN,
    utils::convert_u8_slice_to_u32_fields,
};
use anyhow::Result;
use ethers::types::H256;
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::{target::Target, witness::PartialWitness},
    plonk::circuit_builder::CircuitBuilder,
};

/// The account input values
#[derive(Clone, Debug)]
pub struct AccountInputs<const DEPTH: usize, const NODE_LEN: usize> {
    /// Storage root hash
    storage_hash: H256,
    /// MPT circuit used to verify the state Merkle Tree of account proof
    mpt_circuit: Circuit<DEPTH, NODE_LEN>,
}

impl<const DEPTH: usize, const NODE_LEN: usize> AccountInputs<DEPTH, NODE_LEN>
where
    [(); PAD_LEN(NODE_LEN)]:,
    [(); DEPTH - 1]:,
{
    pub fn new(
        storage_hash: H256,
        // keccak(account_address)
        mpt_key: [u8; MAX_KEY_NIBBLE_LEN / 2],
        // account_proof
        mpt_nodes: Vec<Vec<u8>>,
    ) -> Self {
        Self {
            storage_hash,
            mpt_circuit: Circuit::new(mpt_key, mpt_nodes),
        }
    }
}

/// The account input wires
pub struct AccountInputsWires<const DEPTH: usize, const NODE_LEN: usize>
where
    [(); PAD_LEN(NODE_LEN)]:,
    [(); DEPTH - 1]:,
{
    /// Storage root hash
    pub storage_hash: Array<Target, PACKED_HASH_LEN>,
    /// Input wires of MPT circuit
    pub mpt_input: InputWires<DEPTH, NODE_LEN>,
    /// Output wires of MPT circuit
    pub mpt_output: OutputWires<DEPTH, NODE_LEN>,
}

impl<const DEPTH: usize, const NODE_LEN: usize> AccountInputsWires<DEPTH, NODE_LEN>
where
    [(); PAD_LEN(NODE_LEN)]:,
    [(); DEPTH - 1]:,
{
    pub fn new<F, const D: usize>(cb: &mut CircuitBuilder<F, D>) -> Self
    where
        F: RichField + Extendable<D>,
    {
        let storage_hash = Array::new(cb);

        // Generate MPT input and output wires, and verify MPT proof.
        let mpt_input = Circuit::create_input_wires(cb);
        let mpt_output = Circuit::verify_mpt_proof(cb, &mpt_input);

        Self {
            storage_hash,
            mpt_input,
            mpt_output,
        }
    }

    /// Assign the wires.
    pub fn assign<F, const D: usize>(
        &self,
        pw: &mut PartialWitness<F>,
        value: &AccountInputs<DEPTH, NODE_LEN>,
    ) -> Result<()>
    where
        F: RichField + Extendable<D>,
    {
        // Assign the storage root hash.
        self.storage_hash.assign(
            pw,
            &convert_u8_slice_to_u32_fields(&value.storage_hash.0)
                .try_into()
                .unwrap(),
        );

        // Assign MPT input and output wires.
        value
            .mpt_circuit
            .assign_wires(pw, &self.mpt_input, &self.mpt_output)
    }
}
