//! Test case for local Simple contract
//! Reference `test-contracts/src/Simple.sol` for the details of Simple contract.

use anyhow::Result;
use log::{debug, info};
use mp2_test::cells_tree::TestCell as Cell;
use mp2_v1::values_extraction::compute_leaf_single_id;
use plonky2::field::{goldilocks_field::GoldilocksField, types::Field};

use crate::common::{
    bindings::simple::Simple,
    proof_storage::{BlockPrimaryIndex, ProofKey, ProofStorage},
    TestContext,
};

use super::{
    super::bindings::simple::Simple::SimpleInstance, ContractExtractionArgs, LengthExtractionArgs,
    MappingKey, MappingValuesExtractionArgs, SingleValuesExtractionArgs, TableSourceSlot, TestCase,
};
use alloy::{
    contract::private::{Network, Provider, Transport},
    eips::BlockNumberOrTag,
    primitives::{Address, U256},
    providers::ProviderBuilder,
};
use mp2_common::eth::{ProofQuery, StorageSlot};
use rand::{thread_rng, Rng};
use std::str::FromStr;

/// Test slots for single values extraction
const SINGLE_SLOTS: [u8; 4] = [0, 1, 2, 3];

/// Test slot for mapping values extraction
const MAPPING_SLOT: u8 = 4;

/// Test mapping addresses (keys) for mapping values extraction
const MAPPING_ADDRESSES: [&str; LENGTH_VALUE as usize] = [
    "0x3bf5733f695b2527acc7bd4c5350e57acfd9fbb5",
    "0x6cac7190535f4908d0524e7d55b3750376ea1ef7",
];

/// Test slot for length extraction
const LENGTH_SLOT: u8 = 1;

/// Test length value for length extraction
const LENGTH_VALUE: u8 = 2;

/// Test slot for contract extraction
const CONTRACT_SLOT: usize = 1;
impl TestCase {
    /// Deploy a simple contract, and insert some dummy values at first
    pub(crate) async fn new_local_simple_contract<P: ProofStorage>(
        ctx: &TestContext<P>,
    ) -> Result<Vec<Self>> {
        // Create a provider with the wallet for contract deployment and interaction.
        let provider = ProviderBuilder::new()
            .with_recommended_fillers()
            .wallet(ctx.wallet())
            .on_http(ctx.rpc_url.parse().unwrap());

        let contract = Simple::deploy(&provider).await.unwrap();
        info!(
            "Deployed Simple contract at address: {}",
            contract.address()
        );
        let contract_address = contract.address().clone();
        // Call the contract function to set the test data.
        set_contract_data(contract).await;

        let single = Self {
            source: TableSourceSlot::SingleValues(SingleValuesExtractionArgs {
                slots: SINGLE_SLOTS.to_vec(),
            }),
            contract_address: contract_address.clone(),
            contract_extraction: ContractExtractionArgs {
                slot: StorageSlot::Simple(CONTRACT_SLOT),
            },
        };
        let mapping = Self {
            contract_extraction: ContractExtractionArgs {
                slot: StorageSlot::Simple(CONTRACT_SLOT),
            },
            contract_address: contract_address.clone(),
            source: TableSourceSlot::Mapping((
                MappingValuesExtractionArgs {
                    slot: MAPPING_SLOT,
                    mapping_keys: test_mapping_keys(),
                },
                Some(LengthExtractionArgs {
                    slot: LENGTH_SLOT,
                    value: LENGTH_VALUE,
                }),
            )),
        };
        // Right now only single values. Moving to values in subsequent PR
        //Ok(vec![single, mapping])
        Ok(vec![single])
    }

    pub async fn run<P: ProofStorage>(&self, ctx: &mut TestContext<P>) -> Result<()> {
        self.run_mpt_preprocessing(ctx).await?;
        self.run_lagrange_preprocessing(ctx).await?;
        Ok(())
    }

    // separate function only dealing with preprocesisng MPT proofs
    // This function is "generic" as it can table a table description
    async fn run_lagrange_preprocessing<P: ProofStorage>(
        &self,
        ctx: &mut TestContext<P>,
    ) -> Result<()> {
        let cells = self.build_cells(ctx).await;
        let row = ctx.prove_cells_tree(&self.table_id(), cells).await;
        info!("Generated final CELLs tree proofs for single variables");
        // In the case of the scalars slots, there is a single node in the row tree.
        let rows = vec![row];
        let row_tree_proof_key = ctx.build_and_prove_rowtree(&self.table_id(), &rows).await;
        info!("Generated final ROWs tree proofs for single variables");
        let _ = ctx
            .build_and_prove_index_tree(&self.table_id(), &row_tree_proof_key)
            .await;
        info!("Generated final BLOCK tree proofs for single variables");

        Ok(())
    }

    // separate function only dealing with preprocessing MPT proofs
    async fn run_mpt_preprocessing<P: ProofStorage>(&self, ctx: &mut TestContext<P>) -> Result<()> {
        let bn = ctx.block_number().await;
        let contract_proof_key =
            ProofKey::Contract((self.contract_address, bn as BlockPrimaryIndex));
        let contract_proof = match ctx.storage.get_proof(&contract_proof_key) {
            Ok(proof) => {
                info!(
                    "Loaded Contract Extraction (C.3) proof for block number {}",
                    bn
                );
                proof
            }
            Err(_) => {
                let contract_proof = ctx
                    .prove_contract_extraction(
                        &self.contract_address,
                        self.contract_extraction.slot.clone(),
                        bn,
                    )
                    .await;
                ctx.storage
                    .store_proof(contract_proof_key, contract_proof.clone())?;
                info!(
                    "Generated Contract Extraction (C.3) proof for block number {}",
                    bn
                );
                contract_proof
            }
        };

        // We look if block proof has already been generated for this block
        // since it is the same between proofs
        let block_proof_key = ProofKey::Block(bn as BlockPrimaryIndex);
        let block_proof = match ctx.storage.get_proof(&block_proof_key) {
            Ok(proof) => {
                info!(
                    "Loaded Block Extraction (C.4) proof for block number {}",
                    bn
                );
                proof
            }
            Err(_) => {
                let proof = ctx.prove_block_extraction().await.unwrap();
                ctx.storage.store_proof(block_proof_key, proof.clone())?;
                info!(
                    "Generated Block Extraction (C.4) proof for block number {}",
                    bn
                );
                proof
            }
        };

        let table_id = self.table_id();
        match self.source {
            TableSourceSlot::Mapping(_) => panic!("not yet implemented"),
            TableSourceSlot::SingleValues(ref args) => {
                let proof_key =
                    ProofKey::ValueExtraction((table_id.clone(), bn as BlockPrimaryIndex));
                let single_value_proof = match ctx.storage.get_proof(&proof_key) {
                    Ok(p) => p,
                    Err(_) => {
                        let single_values_proof = ctx
                            .prove_single_values_extraction(&self.contract_address, &args.slots)
                            .await;
                        ctx.storage
                            .store_proof(proof_key, single_values_proof.clone())?;
                        info!("Generated Values Extraction (C.1) proof for single variables");
                        single_values_proof
                    }
                };
                // final extraction for single variables combining the different proofs generated before
                let final_key = ProofKey::Extraction((table_id.clone(), bn as BlockPrimaryIndex));
                match ctx.storage.get_proof(&final_key) {
                    Ok(proof) => proof,
                    Err(_) => {
                        let proof = ctx
                            .prove_final_extraction(
                                contract_proof,
                                single_value_proof,
                                block_proof,
                                false,
                                None,
                            )
                            .await
                            .unwrap();
                        ctx.storage.store_proof(final_key, proof.clone())?;
                        debug!("SAVING final extraction key from {table_id:?} and {bn}");
                        info!("Generated Final Extraction (C.5.1) proof for single variables");
                        proof
                    }
                }
            }
        };

        info!("Generated Single Variables MPT preprocessing proofs");

        Ok(())
    }

    /// Fetch the values and build the identifiers from a list of slots to
    /// generate [`Cell`]s that will then be encoded as a [`MerkleCellTree`].
    pub async fn build_cells<P: ProofStorage>(&self, ctx: &TestContext<P>) -> Vec<Cell> {
        let mut cells = Vec::new();
        match self.source {
            TableSourceSlot::Mapping(_) => unimplemented!("to come"),
            TableSourceSlot::SingleValues(ref args) => {
                for slot in args.slots.iter() {
                    let query =
                        ProofQuery::new_simple_slot(self.contract_address.clone(), *slot as usize);
                    let id = GoldilocksField::from_canonical_u64(compute_leaf_single_id(
                        *slot,
                        &self.contract_address,
                    ));
                    let value = ctx
                        .query_mpt_proof(&query, BlockNumberOrTag::Number(ctx.block_number().await))
                        .await
                        .storage_proof[0]
                        .value;
                    cells.push(Cell {
                        id,
                        value,
                        // we don't know yet its hash because the tree is not constructed
                        // this will be done by the Aggregate trait
                        hash: Default::default(),
                    });
                }
                cells
            }
        }
    }
}

/// Call the contract function to set the test data.
async fn set_contract_data<T: Transport + Clone, P: Provider<T, N>, N: Network>(
    contract: SimpleInstance<T, P, N>,
) {
    // setSimples(bool newS1, uint256 newS2, string memory newS3, address newS4)
    let b = contract.setSimples(
        true,
        U256::from(LENGTH_VALUE), // use this variable as the length slot for the mapping
        "test".to_string(),
        Address::from_str("0xb90ed61bffed1df72f2ceebd965198ad57adfcbd").unwrap(),
    );
    b.send().await.unwrap().watch().await.unwrap();

    // setMapping(address key, uint256 value)
    let mut rng = thread_rng();
    for addr in MAPPING_ADDRESSES {
        let b = contract.setMapping(
            Address::from_str(addr).unwrap(),
            U256::from(rng.gen::<u64>()),
        );
        b.send().await.unwrap().watch().await.unwrap();
    }

    // addToArray(uint256 value)
    for _ in 0..=LENGTH_VALUE {
        let b = contract.addToArray(U256::from(rng.gen::<u64>()));
        b.send().await.unwrap().watch().await.unwrap();
    }
}

/// Convert the test mapping addresses to mapping keys.
fn test_mapping_keys() -> Vec<MappingKey> {
    MAPPING_ADDRESSES
        .iter()
        .map(|address| {
            let address = Address::from_str(address).unwrap();
            address.into_word().to_vec()
        })
        .collect()
}
