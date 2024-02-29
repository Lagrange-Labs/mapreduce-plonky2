//! This circuit is used to verify the length value extracted from storage trie.

use super::key::{SimpleSlot, SimpleSlotWires};
use crate::{
    keccak::{OutputHash, PACKED_HASH_LEN},
    mpt_sequential::{
        Circuit as MPTCircuit, InputWires as MPTInputWires, OutputWires as MPTOutputWires, PAD_LEN,
    },
    utils::{convert_u8_targets_to_u32, PackedAddressTarget, PACKED_ADDRESS_LEN},
};
use anyhow::Result;
use ethers::types::Address;
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::{target::Target, witness::PartialWitness},
    plonk::circuit_builder::CircuitBuilder,
};
use plonky2_crypto::u32::arithmetic_u32::U32Target;
use std::array;

/// This is a wrapper around an array of targets set as public inputs of any
/// proof generated in this module. They all share the same structure.
/// `C` MPT root hash
/// `A` Contract address
/// `S` storage slot of the variable holding the length
/// `V` Integer value stored at key `S` (can be given by prover)
#[derive(Clone, Debug)]
pub struct PublicInputs<'a, T: Clone> {
    pub(crate) proof_inputs: &'a [T],
}

impl<'a> PublicInputs<'a, Target> {
    pub fn register<F, const D: usize>(
        cb: &mut CircuitBuilder<F, D>,
        mpt_root_hash: &OutputHash,
        contract_address: &PackedAddressTarget,
        storage_slot: Target,
        length_value: Target,
    ) where
        F: RichField + Extendable<D>,
    {
        mpt_root_hash.register_as_input(cb);
        contract_address.register_as_input(cb);
        cb.register_public_input(storage_slot);
        cb.register_public_input(length_value);
    }

    pub fn root_hash(&self) -> OutputHash {
        let data = self.root_hash_data();
        OutputHash::from_array(array::from_fn(|i| U32Target(data[i])))
    }

    pub fn contract_address(&self) -> PackedAddressTarget {
        let data = self.contract_address_data();
        PackedAddressTarget::from_array(array::from_fn(|i| U32Target(data[i])))
    }
}

impl<'a, T: Copy> PublicInputs<'a, T> {
    pub(crate) const C_IDX: usize = 0;
    pub(crate) const A_IDX: usize = Self::C_IDX + PACKED_HASH_LEN;
    pub(crate) const S_IDX: usize = Self::A_IDX + PACKED_ADDRESS_LEN;
    pub(crate) const V_IDX: usize = Self::S_IDX + 1;
    pub(crate) const TOTAL_LEN: usize = Self::V_IDX + 1;

    pub fn from(arr: &'a [T]) -> Self {
        Self { proof_inputs: arr }
    }

    pub fn root_hash_data(&self) -> &[T] {
        &self.proof_inputs[Self::C_IDX..Self::A_IDX]
    }

    pub fn contract_address_data(&self) -> &[T] {
        &self.proof_inputs[Self::A_IDX..Self::S_IDX]
    }

    pub fn storage_slot(&self) -> T {
        self.proof_inputs[Self::S_IDX]
    }

    pub fn length_value(&self) -> T {
        self.proof_inputs[Self::V_IDX]
    }
}

pub struct LengthExtractWires<const DEPTH: usize, const NODE_LEN: usize>
where
    [(); PAD_LEN(NODE_LEN)]:,
    [(); DEPTH - 1]:,
{
    /// Simple slot wires
    slot: SimpleSlotWires,
    /// Input wires of MPT circuit
    mpt_input: MPTInputWires<DEPTH, NODE_LEN>,
    /// Output wires of MPT circuit
    mpt_output: MPTOutputWires<DEPTH, NODE_LEN>,
}

#[derive(Clone, Debug)]
struct LengthExtractCircuit<const DEPTH: usize, const NODE_LEN: usize> {
    /// Storage slot saved the length value
    slot: SimpleSlot,
    /// MPT circuit used to verify the nodes of storage Merkle Tree
    mpt_circuit: MPTCircuit<DEPTH, NODE_LEN>,
}

impl<const DEPTH: usize, const NODE_LEN: usize> LengthExtractCircuit<DEPTH, NODE_LEN>
where
    [(); PAD_LEN(NODE_LEN)]:,
    [(); DEPTH - 1]:,
{
    pub fn new(slot: u8, contract_address: Address, nodes: Vec<Vec<u8>>) -> Self {
        let slot = SimpleSlot::new(slot, contract_address);
        let mpt_circuit = MPTCircuit::new(slot.mpt_key(), nodes);

        Self { slot, mpt_circuit }
    }

    /// Build for circuit.
    pub fn build<F, const D: usize>(
        cb: &mut CircuitBuilder<F, D>,
    ) -> LengthExtractWires<DEPTH, NODE_LEN>
    where
        F: RichField + Extendable<D>,
    {
        let slot = SimpleSlot::build(cb);
        let packed_contract_address = slot.contract_address.convert_u8_to_u32(cb);

        // Generate the input and output wires of MPT circuit.
        let mpt_input = MPTCircuit::create_input_wires(cb);
        let mpt_output = MPTCircuit::verify_mpt_proof(cb, &mpt_input);

        // Range check to constrain only bytes for each node of state MPT input.
        mpt_input.nodes.iter().for_each(|n| n.assert_bytes(cb));

        // Constrain the MPT keys are equal.
        slot.mpt_key.key.enforce_equal(cb, &mpt_input.key.key);

        // TODO: could assume the length value is in U32?
        let length_value = convert_u8_targets_to_u32(cb, &mpt_output.leaf.arr);
        length_value[1..].iter().for_each(|v| cb.assert_zero(v.0));

        // Register the public inputs.
        PublicInputs::register(
            cb,
            &mpt_output.root,
            &packed_contract_address,
            slot.slot,
            length_value[0].0,
        );

        LengthExtractWires {
            slot,
            mpt_input,
            mpt_output,
        }
    }

    /// Assign the wires.
    pub fn assign<F, const D: usize>(
        &self,
        pw: &mut PartialWitness<F>,
        wires: &LengthExtractWires<DEPTH, NODE_LEN>,
    ) -> Result<()>
    where
        F: RichField + Extendable<D>,
    {
        // Assign the slot.
        self.slot.assign(pw, &wires.slot);

        // Assign the input and output wires of MPT circuit.
        self.mpt_circuit
            .assign_wires(pw, &wires.mpt_input, &wires.mpt_output)
    }
}
