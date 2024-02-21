//! Block-linking circuit implemention used to prove the pre-computed state root
//! proof is linked to the specific block header.

mod account_inputs;
mod block_inputs;
mod public_inputs;
mod storage_proof;

use crate::mpt_sequential::PAD_LEN;
use account_inputs::{AccountInputs, AccountInputsWires};
use anyhow::Result;
use block_inputs::{BlockInputs, BlockInputsWires};
use ethers::types::{Block, H256};
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::{target::Target, witness::PartialWitness},
    plonk::circuit_builder::CircuitBuilder,
};
use storage_proof::StorageInputs;

/// This is a wrapper around an array of targets set as public inputs of any
/// proof generated in this module. They all share the same structure.
/// `H` Block header hash
/// `N` Block number
/// `PREV_H` Header hash of the previous block (parent hash)
/// `A` Smart contract address
/// `D` Digest of the values
/// `M` Storage slot of the mapping
/// `S` Storage slot of the variable holding the length
/// `C` Merkle root of the storage database
pub struct PublicInputs<'a> {
    proof_inputs: &'a [Target],
}

impl<'a> PublicInputs<'a> {
    pub fn register<
        F,
        const D: usize,
        const DEPTH: usize,
        const NODE_LEN: usize,
        const BLOCK_LEN: usize,
    >(
        cb: &mut CircuitBuilder<F, D>,
        wires: &BlockLinkingWires<DEPTH, NODE_LEN, BLOCK_LEN>,
    ) where
        F: RichField + Extendable<D>,
        [(); PAD_LEN(NODE_LEN)]:,
        [(); DEPTH - 1]:,
    {
        wires.block_inputs.hash.register_as_public_input(cb);
        cb.register_public_input(wires.block_inputs.number);
        wires.block_inputs.parent_hash.register_as_public_input(cb);
        cb.register_public_inputs(wires.storage_proof.a());
        cb.register_public_inputs(wires.storage_proof.d());
        cb.register_public_inputs(wires.storage_proof.m());
        cb.register_public_inputs(wires.storage_proof.s());

        // Only expose the equivalent storage tree root here, NOT the one from
        // blockchain.
        cb.register_public_inputs(wires.storage_proof.merkle_root());
    }

    // TODO: add functions to get public inputs for next circuit.
}

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
    /// TODO : to replace with real proof once recursion framework done
    storage_proof: StorageInputs<Target>,
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

impl<F, const DEPTH: usize, const NODE_LEN: usize, const BLOCK_LEN: usize>
    BlockLinkingCircuit<F, DEPTH, NODE_LEN, BLOCK_LEN>
where
    F: RichField,
    [(); PAD_LEN(NODE_LEN)]:,
    [(); DEPTH - 1]:,
{
    pub fn new(
        block: Block<H256>,
        storage_proof: StorageInputs<F>,
        // Nodes of state MPT, it's ordered from leaf to root.
        state_mpt_nodes: Vec<Vec<u8>>,
    ) -> Self {
        // Get the hash of state MPT root and create the block inputs gadget.
        let state_mpt_root = state_mpt_nodes.last().unwrap();
        let block_inputs = BlockInputs::new(block, state_mpt_root);

        // Get the contract address and hash of storage MPT root, and create the
        // account inputs gadget.
        let contract_address = storage_proof.contract_address();
        let storage_mpt_root = storage_proof.mpt_root_value();
        let account_inputs =
            AccountInputs::new(contract_address, storage_mpt_root, state_mpt_nodes);

        Self {
            account_inputs,
            block_inputs,
            storage_proof,
        }
    }

    /// Build for circuit.
    pub fn build_circuit<const D: usize>(
        cb: &mut CircuitBuilder<F, D>,
    ) -> BlockLinkingWires<DEPTH, NODE_LEN, BLOCK_LEN>
    where
        F: RichField + Extendable<D>,
        [(); PAD_LEN(NODE_LEN)]:,
        [(); DEPTH - 1]:,
    {
        let account_inputs = AccountInputsWires::new(cb);
        let block_inputs = BlockInputsWires::new(cb);
        let storage_proof = StorageInputs::new(cb);

        // Verify the account node includes the hash of storage MPT root.
        account_inputs.verify_storage_root_hash_inclusion(cb, &storage_proof.mpt_root_target());

        // Verify the block header includes the hash of state MPT root.
        block_inputs.verify_state_root_hash_inclusion(cb, &account_inputs.state_mpt_output.root);

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
        wires: &BlockLinkingWires<DEPTH, NODE_LEN, BLOCK_LEN>,
    ) -> Result<()>
    where
        F: RichField + Extendable<D>,
    {
        wires.storage_proof.assign(pw, &self.storage_proof);
        wires.account_inputs.assign(pw, &self.account_inputs)?;
        wires.block_inputs.assign(pw, &self.block_inputs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::benches::init_logging;
    use crate::{
        circuit::{test::test_simple_circuit, UserCircuit},
        mpt_sequential::test::generate_random_mpt,
    };
    use anyhow::Result;
    use ethers::types::H160;
    use plonky2::plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::CircuitConfig,
        config::{GenericConfig, PoseidonGoldilocksConfig},
    };

    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    /// Test circuit
    #[derive(Clone, Debug)]
    struct TestCircuit<const DEPTH: usize, const NODE_LEN: usize, const BLOCK_LEN: usize> {
        c: BlockLinkingCircuit<F, DEPTH, NODE_LEN, BLOCK_LEN>,
    }

    impl<const DEPTH: usize, const NODE_LEN: usize, const BLOCK_LEN: usize> UserCircuit<F, D>
        for TestCircuit<DEPTH, NODE_LEN, BLOCK_LEN>
    where
        [(); PAD_LEN(NODE_LEN)]:,
        [(); DEPTH - 1]:,
    {
        type Wires = BlockLinkingWires<DEPTH, NODE_LEN, BLOCK_LEN>;

        fn build(cb: &mut CircuitBuilder<F, D>) -> Self::Wires {
            BlockLinkingCircuit::build_circuit(cb)
        }

        fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
            self.c.assign_wires::<D>(pw, wires).unwrap();
        }
    }

    /// Test the block-linking circuit.
    #[test]
    fn test_block_linking_circuit() {
        // Maximum depth of the trie
        const DEPTH: usize = 4;
        // Leave one for padding
        const ACTUAL_DEPTH: usize = DEPTH - 1;
        // Maximum length of a node
        const NODE_LEN: usize = 500;
        const VALUE_LEN: usize = 100;
        /* gupeng

        init_logging();

        let mpt_nodes = state_mpt_nodes();

        let test_circuit = TestCircuit::<DEPTH, NODE_LEN, BLOCK_LEN> {
            c: Circuit::new(block, storage_proof, mpt_nodes),
        };
        test_simple_circuit::<F, D, C, _>(test_circuit);
        */
    }

    /// Generate the test nodes of state MPT.
    fn state_mpt_nodes() -> (Vec<Vec<u8>>, u8) {
        todo!()
        /*
        let (trie, key) = generate_random_mpt::<ACTUAL_DEPTH, VALUE_LEN>();

                block: Block<H256>,
                storage_proof: StorageInputs<F>,
                // Nodes of state MPT, it's ordered from leaf to root.
                state_mpt_nodes: Vec<Vec<u8>>,
        */

        /*
                let (proof, key, root, value) = {

                    let root = trie.root_hash().unwrap();
                    // root is first so we reverse the order as in circuit we prove the opposite way
                    let mut proof = trie.get_proof(&key).unwrap();
                    proof.reverse();
                    assert!(proof.len() == ACTUAL_DEPTH);
                    assert!(proof.len() <= DEPTH);
                    assert!(keccak256(proof.last().unwrap()) == root.to_fixed_bytes());
                    let value = trie.get(&key).unwrap().unwrap();
                    (proof, key, root.to_fixed_bytes(), value)
                };
        */
    }

    /// Generate the test block header.
    fn block(state_root_hash: H256) -> Block<H256> {
        todo!()
    }

    /// Generate the test storage proof.
    fn storage_proof<F>(contract_address: H160, storage_root_hash: H256) -> StorageInputs<F> {
        todo!()
    }
}
