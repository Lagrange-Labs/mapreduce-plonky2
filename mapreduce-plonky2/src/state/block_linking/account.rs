//! This is the account-inputs gadget. It builds the circuit to prove that the
//! sequential state MPT, and the hash of storage MPT root should be included in
//! the account node.

use crate::{
    array::{Array, Vector, VectorWire},
    keccak::{InputData, KeccakCircuit, KeccakWires, OutputByteHash, OutputHash},
    mpt_sequential::{
        Circuit as MPTCircuit, InputWires as MPTInputWires, MPTKeyWire,
        OutputWires as MPTOutputWires, PAD_LEN,
    },
    storage::PublicInputs as StorageInputs,
    types::{AddressTarget, PackedAddressTarget, ADDRESS_LEN},
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
use serde::{Deserialize, Serialize};

/// Keccak input padded length for address
const INPUT_PADDED_ADDRESS_LEN: usize = PAD_LEN(ADDRESS_LEN);

#[derive(Serialize, Deserialize)]
/// The account input wires
pub struct AccountInputsWires<const DEPTH: usize, const NODE_LEN: usize>
where
    [(); PAD_LEN(NODE_LEN)]:,
    [(); DEPTH - 1]:,
{
    /// The contract address
    pub(super) contract_address: AddressTarget,
    /// The keccak wires computed from contract address, which is set to the
    /// state MPT root hash
    keccak_contract_address: KeccakWires<INPUT_PADDED_ADDRESS_LEN>,
    /// The offset of storage MPT root hash located in RLP encoded account node
    pub(crate) storage_root_offset: Target,
    /// Input wires of state MPT circuit
    pub(crate) state_mpt_input: MPTInputWires<DEPTH, NODE_LEN>,
    /// Output wires of state MPT circuit
    pub(crate) state_mpt_output: MPTOutputWires<DEPTH, NODE_LEN>,
}

/// The account input gadget
#[derive(Clone, Debug)]
pub struct Account<const DEPTH: usize, const NODE_LEN: usize> {
    /// The contract address
    contract_address: H160,
    /// The offset of storage root hash located in RLP encoded account node
    storage_root_offset: usize,
    /// MPT circuit used to verify the nodes of state Merkle Tree
    state_mpt_circuit: MPTCircuit<DEPTH, NODE_LEN>,
}

impl<const DEPTH: usize, const NODE_LEN: usize> Account<DEPTH, NODE_LEN>
where
    [(); PAD_LEN(NODE_LEN)]:,
    [(); DEPTH - 1]:,
{
    pub fn new(
        contract_address: H160,
        storage_root_bytes: H256,
        state_mpt_nodes: Vec<Vec<u8>>,
    ) -> Self {
        // Find the storage root hash from account node.
        let storage_root_offset =
            find_index_subvector(&state_mpt_nodes[0], &storage_root_bytes.0).unwrap();

        // Build the full MPT key as `keccak256(contract_address)` and convert
        // it to bytes.
        // Check with [ProofQuery::verify_state_proof] for details.
        let state_mpt_key = keccak256(&contract_address.0).try_into().unwrap();

        // Build the MPT circuit for state Merkle Tree.
        let state_mpt_circuit = MPTCircuit::new(state_mpt_key, state_mpt_nodes);

        Self {
            contract_address,
            storage_root_offset,
            state_mpt_circuit,
        }
    }

    /// Build for circuit.
    pub fn build<F, const D: usize>(
        cb: &mut CircuitBuilder<F, D>,
        storage_pi: &[Target],
    ) -> AccountInputsWires<DEPTH, NODE_LEN>
    where
        F: RichField + Extendable<D>,
    {
        let contract_address = Array::new(cb);
        let storage_pi = StorageInputs::from(storage_pi);

        let storage_root_offset = cb.add_virtual_target();

        // Calculate the keccak hash of contract address, and use it as the
        // state MPT root hash.
        let mut arr = [cb.zero(); INPUT_PADDED_ADDRESS_LEN];
        arr[..ADDRESS_LEN].copy_from_slice(&contract_address.arr);
        let bytes_to_keccak = &VectorWire::<Target, INPUT_PADDED_ADDRESS_LEN> {
            real_len: cb.constant(F::from_canonical_usize(ADDRESS_LEN)),
            arr: Array { arr },
        };
        let keccak_contract_address = KeccakCircuit::hash_vector(cb, bytes_to_keccak);
        let expected_mpt_key =
            MPTKeyWire::init_from_u32_targets(cb, &keccak_contract_address.output_array);

        // Generate the input and output wires of state MPT circuit.
        let state_mpt_input = MPTCircuit::create_input_wires(cb, Some(expected_mpt_key));
        let state_mpt_output = MPTCircuit::verify_mpt_proof(cb, &state_mpt_input);

        // Range check to constrain only bytes for each node of state MPT input.
        state_mpt_input
            .nodes
            .iter()
            .for_each(|n| n.assert_bytes(cb));

        AccountInputsWires {
            contract_address,
            keccak_contract_address,
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
        // Assign the contract address.
        wires
            .contract_address
            .assign(pw, &self.contract_address.0.map(F::from_canonical_u8));

        // Assign the keccak value of contract address.
        KeccakCircuit::<{ PAD_LEN(ADDRESS_LEN) }>::assign(
            pw,
            &wires.keccak_contract_address,
            &InputData::Assigned(
                &Vector::from_vec(&self.contract_address.0)
                    .expect("Cannot create vector input for keccak contract address"),
            ),
        );

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

        // Verify the offset of storage MPT root hash is within range. We use 7
        // bits for the range check since the account node is composed by
        // [nonce (U64), balance (U256), storage_hash (H256), code_hash (H256)]
        // and it has 104 bytes.
        let within_range = less_than(cb, wires.storage_root_offset, account_node.real_len, 7);
        cb.connect(within_range.target, tt.target);

        // Verify the account node includes the storage MPT root hash.
        let expected_storage_root: OutputByteHash = account_node
            .arr
            .extract_array(cb, wires.storage_root_offset);
        expected_storage_root
            .convert_u8_to_u32(cb)
            .enforce_equal(cb, storage_root_hash);
    }
}

#[cfg(test)]
mod test {
    use std::{str::FromStr, sync::Arc};

    use eth_trie::{EthTrie, MemoryDB, Trie};
    use ethers::{
        providers::{Http, Middleware, Provider},
        types::{Address, BlockId, BlockNumber, H160, H256, U64},
    };
    use plonky2::{
        field::{
            extension::Extendable,
            types::{Field, Sample},
        },
        hash::hash_types::RichField,
        iop::{
            target::Target,
            witness::{PartialWitness, WitnessWrite},
        },
        plonk::{
            circuit_builder::CircuitBuilder,
            config::{GenericConfig, PoseidonGoldilocksConfig},
        },
    };
    use serial_test::serial;

    use crate::{
        benches::init_logging,
        circuit::{test::run_circuit, UserCircuit},
        eth::{BlockData, ProofQuery},
        mpt_sequential::{Circuit as MPTCircuit, PAD_LEN},
        state::block_linking::block::SEPOLIA_NUMBER_LEN,
        storage::PublicInputs as StorageInputs,
        utils::{
            convert_u8_slice_to_u32_fields, find_index_subvector, keccak256, test::random_vector,
        },
    };

    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;
    use super::{Account, AccountInputsWires};
    #[derive(Clone, Debug)]
    struct TestAccountInputs<const DEPTH: usize, const NODE_LEN: usize> {
        a: Account<DEPTH, NODE_LEN>,
        storage_pi: Vec<F>,
    }

    impl<const DEPTH: usize, const NODE_LEN: usize> UserCircuit<F, D>
        for TestAccountInputs<DEPTH, NODE_LEN>
    where
        [(); DEPTH - 1]:,
        [(); PAD_LEN(NODE_LEN)]:,
    {
        type Wires = (AccountInputsWires<DEPTH, NODE_LEN>, Vec<Target>);

        fn build(c: &mut CircuitBuilder<F, D>) -> Self::Wires {
            let storage_pi = c.add_virtual_targets(StorageInputs::<Target>::TOTAL_LEN);
            let wires = Account::build(c, &storage_pi);
            (wires, storage_pi)
        }

        fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
            self.a.assign::<F, D>(pw, &wires.0).unwrap();
            pw.set_target_arr(&wires.1, &self.storage_pi);
        }
    }
    use anyhow::Result;

    #[tokio::test]
    #[serial]
    async fn test_account_inputs_on_sepolia() -> Result<()> {
        #[cfg(feature = "ci")]
        let url = env::var("CI_SEPOLIA").expect("CI_SEPOLIA env var not set");
        #[cfg(not(feature = "ci"))]
        let url = "https://ethereum-sepolia-rpc.publicnode.com";

        let contract_address = "0xd6a2bFb7f76cAa64Dad0d13Ed8A9EFB73398F39E";

        // Written as constants from the result.
        const DEPTH: usize = 8;
        const NODE_LEN: usize = 532;
        const BLOCK_LEN: usize = 620;

        test_account_inputs::<DEPTH, NODE_LEN, BLOCK_LEN, SEPOLIA_NUMBER_LEN>(url, contract_address)
            .await
    }

    #[tokio::test]
    #[serial]
    async fn test_account_inputs_on_mainnet() -> Result<()> {
        #[cfg(feature = "ci")]
        let url = env::var("CI_ETH").expect("CI_ETH env var not set");
        #[cfg(not(feature = "ci"))]
        let url = "https://eth.llamarpc.com";
        // TODO: this Mainnet contract address only works with state proof
        let contract_address = "0x105dD0eF26b92a3698FD5AaaF688577B9Cafd970";

        // Written as constants from the result.
        const DEPTH: usize = 8;
        const NODE_LEN: usize = 532;
        const BLOCK_LEN: usize = 620;

        test_account_inputs::<DEPTH, NODE_LEN, BLOCK_LEN, SEPOLIA_NUMBER_LEN>(url, contract_address)
            .await
    }

    async fn test_account_inputs<
        const DEPTH: usize,
        const NODE_LEN: usize,
        const BLOCK_LEN: usize,
        const NUMBER_LEN: usize,
    >(
        url: &str,
        contract_address: &str,
    ) -> Result<()>
    where
        [(); PAD_LEN(NODE_LEN)]:,
        [(); PAD_LEN(BLOCK_LEN)]:,
        [(); DEPTH - 1]:,
    {
        init_logging();

        let contract_address = Address::from_str(contract_address)?;

        let provider =
            Provider::<Http>::try_from(url).expect("could not instantiate HTTP Provider");

        let block_number = provider.get_block_number().await?;
        // Simple storage test
        let query = ProofQuery::new_simple_slot(contract_address, 0);
        let block = provider
            .get_block_with_txs(BlockId::Number(BlockNumber::Number(block_number)))
            .await?
            .expect("should have been a block");
        let res = query
            .query_mpt_proof(
                &provider,
                Some(BlockId::Number(BlockNumber::Number(block_number))),
            )
            .await?;
        let account_proof = res
            .account_proof
            .iter()
            .rev()
            .map(|b| b.to_vec())
            .collect::<Vec<Vec<u8>>>();
        let state_root = keccak256(&account_proof.last().unwrap());
        let key = keccak256(&contract_address.as_bytes());
        let db = MemoryDB::new(true);
        let trie = EthTrie::new(Arc::new(db));
        let is_proof_valid = trie
            .verify_proof(H256::from_slice(&state_root), &key, account_proof.clone())
            .expect("proof should be valid");
        assert!(is_proof_valid.is_some());
        let storage_root = keccak256(&res.storage_proof[0].proof[0].clone());
        let state_account = account_proof[0].clone();
        let storage_root_offset =
            find_index_subvector(&state_account, &storage_root).expect("no subvector");
        let acc = Account::<DEPTH, NODE_LEN> {
            contract_address,
            storage_root_offset,
            state_mpt_circuit: MPTCircuit::new(key.try_into().unwrap(), account_proof),
        };
        // manually construct random proofs inputs with specific contract address and storage root
        // as these are the two informations are used from the proof inside this circuit
        let mut storage_pi: Vec<_> = random_vector::<u32>(StorageInputs::<F>::TOTAL_LEN)
            .into_iter()
            .map(F::from_canonical_u32)
            .collect();
        storage_pi[StorageInputs::<F>::C1_IDX..StorageInputs::<F>::C2_IDX]
            .copy_from_slice(&convert_u8_slice_to_u32_fields(&storage_root));
        run_circuit::<F, D, C, _>(TestAccountInputs { a: acc, storage_pi });
        Ok(())
    }
}
