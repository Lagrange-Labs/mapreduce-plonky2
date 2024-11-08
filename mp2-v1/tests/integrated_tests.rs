//! Database creation integration test
// Used to fix the error: failed to evaluate generic const expression `PAD_LEN(NODE_LEN)`.
#![feature(generic_const_exprs)]
#![feature(let_chains)]
#![feature(async_closure)]
#![feature(assert_matches)]
#![feature(associated_type_defaults)]

use std::{
    fs::File,
    io::{BufReader, BufWriter},
    path::PathBuf,
};

use alloy::primitives::U256;
use anyhow::{Context, Result};

use common::{
    cases::{
        indexing::{ChangeType, UpdateType},
        query::{
            test_query, GlobalCircuitInput, RevelationCircuitInput, MAX_NUM_COLUMNS,
            MAX_NUM_ITEMS_PER_OUTPUT, MAX_NUM_OUTPUTS, MAX_NUM_PLACEHOLDERS, MAX_NUM_PREDICATE_OPS,
            MAX_NUM_RESULT_OPS,
        },
        TableIndexing,
    },
    context::{self, ParamsType, TestContextConfig},
    proof_storage::{ProofKV, DEFAULT_PROOF_STORE_FOLDER},
    table::Table,
    TableInfo,
};
use envconfig::Envconfig;
use log::info;
use parsil::{
    assembler::DynamicCircuitPis,
    parse_and_validate,
    symbols::{ContextProvider, ZkTable},
    utils::ParsilSettingsBuilder,
    PlaceholderSettings,
};
use test_log::test;
use verifiable_db::query::universal_circuit::universal_circuit_inputs::Placeholders;

pub(crate) mod common;

//) {
//    let length_proof = ctx
//        .prove_length_extraction(
//            &t.contract_address,
//            t.length_extraction.slot,
//            t.length_extraction.value,
//        )
//        .await;
//    info!("Generated Length Extraction (C.2) proof");
//
//    let _ = ctx.prove_final_extraction(
//        contract_proof.serialize().unwrap(),
//        mapping_values_proof.serialize().unwrap(),
//        block_proof.to_vec(),
//        true,
//        Some(length_proof.serialize().unwrap()),
//    );
//    info!("Generated Final Extraction (C.5.1) proof for mapping (with length slot check)");
//}
//

const PROOF_STORE_FILE: &str = "test_proofs.store";
const MAPPING_TABLE_INFO_FILE: &str = "mapping_column_info.json";
const MERGE_TABLE_INFO_FILE: &str = "merge_column_info.json";

#[test(tokio::test)]
#[ignore]
async fn integrated_indexing() -> Result<()> {
    // Create the test context for mainnet.
    // let ctx = &mut TestContext::new_mainet();
    let _ = env_logger::try_init();
    info!("Running INDEXING test");
    let storage = ProofKV::new_from_env(PROOF_STORE_FILE)?;
    info!("Loading Anvil and contract");
    let mut ctx = context::new_local_chain(storage).await;
    info!("Initial Anvil block: {}", ctx.block_number().await);
    info!("Building indexing params");
    ctx.build_params(ParamsType::Indexing).unwrap();

    info!("Params built");
    // NOTE: to comment to avoid very long tests...

    let (mut single, genesis) = TableIndexing::single_value_test_case(&mut ctx).await?;
    let changes = vec![
        ChangeType::Update(UpdateType::Rest),
        ChangeType::Silent,
        ChangeType::Update(UpdateType::SecondaryIndex),
    ];
    single.run(&mut ctx, genesis, changes.clone()).await?;

    let (mut single_struct, genesis) = TableIndexing::single_struct_test_case(&mut ctx).await?;
    let changes = vec![
        ChangeType::Update(UpdateType::Rest),
        ChangeType::Silent,
        ChangeType::Update(UpdateType::SecondaryIndex),
    ];
    single_struct
        .run(&mut ctx, genesis, changes.clone())
        .await?;

    let (mut mapping, genesis) = TableIndexing::mapping_test_case(&mut ctx).await?;
    let changes = vec![
        ChangeType::Insertion,
        ChangeType::Update(UpdateType::Rest),
        ChangeType::Silent,
        ChangeType::Update(UpdateType::SecondaryIndex),
        ChangeType::Deletion,
    ];
    mapping.run(&mut ctx, genesis, changes).await?;

    let (mut mapping_struct, genesis) = TableIndexing::mapping_struct_test_case(&mut ctx).await?;
    let changes = vec![
        ChangeType::Insertion,
        ChangeType::Update(UpdateType::Rest),
        ChangeType::Silent,
        ChangeType::Update(UpdateType::SecondaryIndex),
        ChangeType::Deletion,
    ];
    mapping_struct.run(&mut ctx, genesis, changes).await?;

    let (mut merged, genesis) = TableIndexing::merge_table_test_case(&mut ctx).await?;
    let changes = vec![
        ChangeType::Insertion,
        ChangeType::Update(UpdateType::Rest),
        ChangeType::Update(UpdateType::Rest),
        ChangeType::Silent,
        ChangeType::Deletion,
    ];
    merged.run(&mut ctx, genesis, changes).await?;

    // save columns information and table information in JSON so querying test can pick up
    write_table_info(MAPPING_TABLE_INFO_FILE, mapping.table_info())?;
    write_table_info(MERGE_TABLE_INFO_FILE, merged.table_info())?;

    Ok(())
}

async fn integrated_querying(table_info: TableInfo) -> Result<()> {
    let storage = ProofKV::new_from_env(PROOF_STORE_FILE)?;
    info!("Loading Anvil and contract");
    let mut ctx = context::new_local_chain(storage).await;
    info!("Building querying params");
    ctx.build_params(ParamsType::Query).unwrap();
    info!("Params built");
    let table = Table::load(
        table_info.public_name.clone(),
        table_info.columns.clone(),
        table_info.row_unique_id.clone(),
    )
    .await?;
    dbg!(&table.public_name);
    test_query(&mut ctx, table, table_info).await?;
    Ok(())
}

#[test(tokio::test)]
#[ignore]
async fn integrated_querying_mapping_table() -> Result<()> {
    let _ = env_logger::try_init();
    info!("Running QUERY test for mapping table");
    let table_info = read_table_info(MAPPING_TABLE_INFO_FILE)?;
    integrated_querying(table_info).await
}

#[test(tokio::test)]
#[ignore]
async fn integrated_querying_merged_table() -> Result<()> {
    let _ = env_logger::try_init();
    info!("Running QUERY test for merged table");
    let table_info = read_table_info(MERGE_TABLE_INFO_FILE)?;
    integrated_querying(table_info).await
}

fn table_info_path(f: &str) -> PathBuf {
    let cfg = TestContextConfig::init_from_env()
        .context("while parsing configuration")
        .unwrap();
    let path = cfg
        .params_dir
        .unwrap_or(DEFAULT_PROOF_STORE_FOLDER.to_string());
    let mut path = PathBuf::from(path);
    path.push(f);
    path
}

fn write_table_info(f: &str, info: TableInfo) -> Result<()> {
    let full_path = table_info_path(f);
    let file = File::create(full_path)?;
    let writer = BufWriter::new(file);
    serde_json::to_writer(writer, &info)?;
    Ok(())
}

fn read_table_info(f: &str) -> Result<TableInfo> {
    let full_path = table_info_path(f);
    let file = File::open(full_path)?;
    let reader = BufReader::new(file);
    let info = serde_json::from_reader(reader)?;
    Ok(info)
}

struct T(ZkTable);
impl ContextProvider for T {
    fn fetch_table(&self, table_name: &str) -> Result<ZkTable> {
        Ok(self.0.clone())
    }

    const MAX_NUM_COLUMNS: usize = MAX_NUM_COLUMNS;

    const MAX_NUM_PREDICATE_OPS: usize = MAX_NUM_PREDICATE_OPS;

    const MAX_NUM_RESULT_OPS: usize = MAX_NUM_RESULT_OPS;

    const MAX_NUM_ITEMS_PER_OUTPUT: usize = MAX_NUM_ITEMS_PER_OUTPUT;

    const MAX_NUM_OUTPUTS: usize = MAX_NUM_OUTPUTS;
}

#[tokio::test]
#[ignore]
async fn test_andrus_query() -> Result<()> {
    let _ = env_logger::try_init();
    let storage = ProofKV::new_from_env(PROOF_STORE_FILE)?;
    let cfg = TestContextConfig::init_from_env().context("while parsing configuration")?;
    let folder = cfg
        .params_dir
        .unwrap_or(DEFAULT_PROOF_STORE_FOLDER.to_string());
    let ivc_proof_name = format!("{folder}/{}", "ivc.proof");
    let root_query_proof_name = format!("{folder}/{}", "root.proof");
    let pis_name = format!("{folder}/{}", "pis.json");
    let ivc_proof = tokio::fs::read(ivc_proof_name).await?;
    let root_query_proof = tokio::fs::read(root_query_proof_name).await?;

    let ph = Placeholders::new_empty(U256::from(2228671), U256::from(2228671));
    let query = "select AVG(field1) from primitive1_rows WHERE block_number >= $MIN_BLOCK and block_number <= $MAX_BLOCK";
    let zktable_str = r#"{"user_name":"primitive1","name":"primitive1_rows","columns":[{"name":"block_number","kind":"PrimaryIndex","id":15542555334667826467},{"name":"field1","kind":"SecondaryIndex","id":10143644063834010325},{"name":"field2","kind":"Standard","id":14738928498191419754},{"name":"field3","kind":"Standard","id":2724380514203373020},{"name":"field4","kind":"Standard","id":1084192582840933701}]}"#;
    let table: ZkTable = serde_json::from_str(zktable_str)?;
    let settings = ParsilSettingsBuilder::default()
        .context(T(table))
        .placeholders(PlaceholderSettings::with_freestanding(
            MAX_NUM_PLACEHOLDERS - 2,
        ))
        .build()
        .unwrap();

    let parsed = parse_and_validate(query, &settings)?;
    let computed_pis = parsil::assembler::assemble_dynamic(&parsed, &settings, &ph)?;

    let expected_pis: DynamicCircuitPis =
        serde_json::from_slice(&tokio::fs::read(pis_name).await?)?;
    assert_eq!(expected_pis, computed_pis);

    info!("Loading Anvil and contract");
    let mut ctx = context::new_local_chain(storage).await;
    info!("Building querying params");
    ctx.build_params(ParamsType::Query).unwrap();

    let input = RevelationCircuitInput::new_revelation_aggregated(
        root_query_proof,
        ivc_proof,
        &computed_pis.bounds,
        &ph,
        &computed_pis.predication_operations,
        &computed_pis.result,
    )?;
    info!("Generating the revelation proof");
    let proof = ctx.run_query_proof("revelation", GlobalCircuitInput::Revelation(input))?;
    info!("all good");
    Ok(())
}
