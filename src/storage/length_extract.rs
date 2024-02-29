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
use ethers::types::H160;
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
    pub fn new(slot: u8, contract_address: H160, nodes: Vec<Vec<u8>>) -> Self {
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

        // The length value shouldn't exceed 4-bytes (U32).
        let length_value = convert_u8_targets_to_u32(cb, &mpt_output.leaf.arr);

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        benches::init_logging,
        circuit::{test::run_circuit, UserCircuit},
        utils::keccak256,
    };
    use eth_trie::{EthTrie, MemoryDB, Trie};
    use ethers::types::H160;
    use plonky2::{
        field::types::Field,
        iop::witness::{PartialWitness, WitnessWrite},
        plonk::config::{GenericConfig, PoseidonGoldilocksConfig},
    };
    use rand::{thread_rng, Rng};
    use std::sync::Arc;

    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    /// Test data
    struct TestData {
        /// Storage slot
        slot: u8,
        /// Contract address
        contract_address: H160,
        /// MPT nodes
        nodes: Vec<Vec<u8>>,
    }

    /// Test circuit
    #[derive(Clone, Debug)]
    struct TestCircuit<const DEPTH: usize, const NODE_LEN: usize>
    where
        [(); PAD_LEN(NODE_LEN)]:,
        [(); DEPTH - 1]:,
    {
        c: LengthExtractCircuit<DEPTH, NODE_LEN>,
    }

    impl<const DEPTH: usize, const NODE_LEN: usize> UserCircuit<F, D> for TestCircuit<DEPTH, NODE_LEN>
    where
        [(); PAD_LEN(NODE_LEN)]:,
        [(); DEPTH - 1]:,
    {
        type Wires = LengthExtractWires<DEPTH, NODE_LEN>;

        fn build(cb: &mut CircuitBuilder<F, D>) -> Self::Wires {
            LengthExtractCircuit::build(cb)
        }

        fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
            self.c.assign::<F, D>(pw, wires).unwrap();
        }
    }

    /// Test the length-match circuit with a generated random MPT.
    #[test]
    fn test_length_extract_circuit_with_random_mpt() {
        init_logging();

        const DEPTH: usize = 4;
        const NODE_LEN: usize = 500;

        let test_data = generate_test_data::<DEPTH>();
        let test_circuit = TestCircuit::<DEPTH, NODE_LEN> {
            c: LengthExtractCircuit::new(
                test_data.slot,
                test_data.contract_address,
                test_data.nodes,
            ),
        };
        run_circuit::<F, D, C, _>(test_circuit);
    }

    fn generate_test_data<const DEPTH: usize>() -> TestData {
        let mut elements = Vec::new();
        let memdb = Arc::new(MemoryDB::new(true));
        let mut trie = EthTrie::new(Arc::clone(&memdb));

        // Loop to insert random elements as long as a random selected proof is
        // not of the right length.
        let mut rng = thread_rng();
        let (slot, contract_address, mpt_key) = loop {
            println!(
                "[+] Random mpt: insertion of {} elements so far...",
                elements.len(),
            );

            // Generate a MPT key from the slot and contract address.
            let slot = rng.gen::<u8>();
            let contract_address = H160(rng.gen::<[u8; 20]>());
            let key = SimpleSlot::new(slot, contract_address).mpt_key();

            // Insert the key and value.
            let value = rng.gen::<u8>();
            trie.insert(&key, &[value]).unwrap();
            trie.root_hash().unwrap();

            // Save the slot, contract address and key temporarily.
            elements.push((slot, contract_address, key));

            // Check if any node has the DEPTH elements.
            if let Some((slot, contract_address, key)) = elements
                .iter()
                .find(|(_, _, key)| trie.get_proof(key).unwrap().len() == DEPTH)
            {
                break (*slot, *contract_address, key);
            }
        };

        let root_hash = trie.root_hash().unwrap();
        let mut nodes = trie.get_proof(mpt_key).unwrap();
        nodes.reverse();
        assert!(keccak256(nodes.last().unwrap()) == root_hash.to_fixed_bytes());

        TestData {
            slot,
            contract_address,
            nodes,
        }
    }
}
