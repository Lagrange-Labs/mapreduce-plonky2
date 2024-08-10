//! Database creation integration test
// Used to fix the error: failed to evaluate generic const expression `PAD_LEN(NODE_LEN)`.
#![feature(generic_const_exprs)]
#![feature(assert_matches)]

use std::{
    fs::File,
    io::{BufReader, BufWriter},
    path::PathBuf,
};

use anyhow::{Context, Result};

use common::{
    cases::{
        indexing::{ChangeType, TreeFactory, UpdateType},
        query::{test_query, TableType},
    },
    context::{self, ParamsType, TestContextConfig},
    proof_storage::{ProofKV, ProofStorage, DEFAULT_PROOF_STORE_FOLDER},
    table::{Table, TableInfo},
    TestCase, TestContext,
};
use envconfig::Envconfig;
use log::info;
use parsil::symbols::ContextProvider;
use test_log::test;

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

#[test(tokio::test)]
async fn integrated_indexing() -> Result<()> {
    let _ = env_logger::try_init();
    info!("Running INDEXING test");
    let storage = ProofKV::new_from_env(PROOF_STORE_FILE)?;
    info!("Loading Anvil and contract");
    let mut ctx = context::new_local_chain(storage).await;
    info!("Initial Anvil block: {}", ctx.block_number().await);
    info!("Building indexing params");
    ctx.build_params(ParamsType::Indexing).unwrap();

    info!("Params built");
    let mut single = TestCase::single_value_test_case(&ctx, TreeFactory::New).await?;
    let changes = vec![
        ChangeType::Update(UpdateType::Rest),
        ChangeType::Update(UpdateType::SecondaryIndex),
    ];
    single.run(&mut ctx, changes.clone()).await?;
    let mut mapping = TestCase::mapping_test_case(&ctx, TreeFactory::New).await?;
    let changes = vec![
        ChangeType::Insertion,
        ChangeType::Update(UpdateType::Rest),
        ChangeType::Insertion,
        ChangeType::Update(UpdateType::SecondaryIndex),
        ChangeType::Deletion,
    ];
    mapping.run(&mut ctx, changes).await?;
    // save columns information and table information in JSON so querying test can pick up
    write_table_info(MAPPING_TABLE_INFO_FILE, mapping.table.table_info())?;
    Ok(())
}

#[test(tokio::test)]
async fn integrated_querying() -> Result<()> {
    let _ = env_logger::try_init();
    info!("Running QUERY test");
    let table_info = read_table_info(MAPPING_TABLE_INFO_FILE)?;
    let storage = ProofKV::new_from_env(PROOF_STORE_FILE)?;
    info!("Loading Anvil and contract");
    let mut ctx = context::new_local_chain(storage).await;
    info!("Building querying params");
    ctx.build_params(ParamsType::Query).unwrap();
    info!("Params built");
    let table = Table::load(table_info.table_name, table_info.columns).await?;
    test_query(&mut ctx, table, TableType::Mapping).await?;
    Ok(())
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
    let file = File::create(f)?;
    let writer = BufWriter::new(file);
    serde_json::to_writer(writer, &info)?;
    Ok(())
}

fn read_table_info(f: &str) -> Result<TableInfo> {
    let file = File::open(f)?;
    let reader = BufReader::new(file);
    let info = serde_json::from_reader(reader)?;
    Ok(info)
}

//#[test]
//fn ryhope_scapegoat2() -> Result<()> {
//    let mut row_tree = MerkleRowTree::new(
//        InitSettings::Reset(scapegoat::Tree::empty(Alpha::new(0.8))),
//        (),
//    )
//    .unwrap();
//    let cell = Cell {
//        id: 10,
//        value: U256::from(10),
//    };
//    let payload = RowPayload {
//        cells: CellCollection(vec![cell.clone(), cell.clone(), cell.clone()]),
//        ..Default::default()
//    };
//    // RowTreeKey { value: VectorU256(1056494154592187365319695072752373049978398833853), rest: [10] }/None (3)
//    //   |RowTreeKey { value: VectorU256(1056494154592187365319695072752373049978398833853), rest: [11] }/RowTreeKey { value: , rest: [10] } (2)
//    //   |  |RowTreeKey { value: VectorU256(1056494154592187365319695072752373049978398834414), rest: [12] }/RowTreeKey { value: , rest: [11] } (1)
//    let r10 = RowTreeKey {
//        value: U256::from_str_radix("1056494154592187365319695072752373049978398833853", 10)
//            .unwrap()
//            .into(),
//        rest: vec![10],
//    };
//    let r11 = RowTreeKey {
//        value: U256::from_str_radix("1056494154592187365319695072752373049978398833853", 10)
//            .unwrap()
//            .into(),
//        rest: vec![11],
//    };
//    let r12 = RowTreeKey {
//        value: U256::from_str_radix("1056494154592187365319695072752373049978398834414", 10)
//            .unwrap()
//            .into(),
//        rest: vec![12],
//    };
//    enum Update {
//        Insert(RowTreeKey),
//        Deletion(RowTreeKey),
//    }
//    let mut apply_update =
//        |tree: &mut MerkleRowTree, updates: Vec<Update>| -> Result<UpdateTree<RowTreeKey>> {
//            tree.in_transaction(|t| {
//                for u in updates {
//                    match u {
//                        Update::Insert(k) => {
//                            t.store(k, payload.clone())?;
//                        }
//                        Update::Deletion(k) => {
//                            t.remove(k)?;
//                        }
//                    }
//                }
//                Ok(())
//            })
//        };
//    println!("block 2");
//    apply_update(
//        &mut row_tree,
//        vec![
//            Update::Insert(r10.clone()),
//            Update::Insert(r11.clone()),
//            Update::Insert(r12),
//        ],
//    )?;
//
//    println!("block 3");
//    // Insertion(Row { k: RowTreeKey { value: VectorU256(131889689160155728452442635557830924454313873897), rest: [13] },
//    let r13 = RowTreeKey {
//        value: U256::from_str_radix("131889689160155728452442635557830924454313873897", 10)
//            .unwrap()
//            .into(),
//        rest: vec![13],
//    };
//    apply_update(&mut row_tree, vec![Update::Insert(r13)])?;
//
//    // Insertion(Row { k: RowTreeKey { value: VectorU256(760593967277233584130757083408460933562276361544), rest: [14] }, :
//    println!("block 4");
//    let r14 = RowTreeKey {
//        value: U256::from_str_radix("760593967277233584130757083408460933562276361544", 10)
//            .unwrap()
//            .into(),
//        rest: vec![14],
//    };
//    apply_update(&mut row_tree, vec![Update::Insert(r14)])?;
//    // Deletion(RowTreeKey { value: VectorU256(1056494154592187365319695072752373049978398833853), rest: [10] })
//    // Insertion(Row { k: RowTreeKey { value: VectorU256(1056494154592187365319695072752373049978398833853), rest: [15]
//    println!("block 5");
//    let r15 = RowTreeKey {
//        value: U256::from_str_radix("1056494154592187365319695072752373049978398833853", 10)
//            .unwrap()
//            .into(),
//        rest: vec![15],
//    };
//    apply_update(
//        &mut row_tree,
//        vec![Update::Deletion(r10), Update::Insert(r15)],
//    )?;
//
//    //  Deletion(RowTreeKey { value: VectorU256(1056494154592187365319695072752373049978398833853), rest: [11] })
//    // Insertion(Row { k: RowTreeKey { value: VectorU256(252811549864805747143179347346470204140167719177), rest: [11] },
//    println!("block 6");
//    let r11_bis = RowTreeKey {
//        value: U256::from_str_radix("252811549864805747143179347346470204140167719177", 10)
//            .unwrap()
//            .into(),
//        rest: vec![11],
//    };
//
//    apply_update(
//        &mut row_tree,
//        vec![Update::Deletion(r11), Update::Insert(r11_bis.clone())],
//    )?;
//    // Deletion(RowTreeKey { value: VectorU256(252811549864805747143179347346470204140167719177), rest: [11] }
//    println!("block 7");
//    println!("BEFORE");
//    row_tree.print_tree();
//    let ut = apply_update(&mut row_tree, vec![Update::Deletion(r11_bis)])?;
//
//    println!("AFTER");
//    row_tree.print_tree();
//    println!("UT: ------------------------");
//    ut.print();
//    println!("----------------------------");
//    Ok(())
//}
