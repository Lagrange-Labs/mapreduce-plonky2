//! Database creation integration test
// Used to fix the error: failed to evaluate generic const expression `PAD_LEN(NODE_LEN)`.
#![feature(generic_const_exprs)]
#![feature(assert_matches)]
use std::future::Future;

use alloy::primitives::U256;
use anyhow::Result;

use common::{
    cases::local_simple::{ChangeType, UpdateType},
    celltree::Cell,
    context,
    proof_storage::{KeyValueDB, MemoryProofStorage, ProofKey},
    rowtree::{CellCollection, MerkleRowTree, Row, RowPayload, RowTreeKey},
    TestCase, TestContext,
};
use log::info;
use ryhope::{
    storage::{EpochKvStorage, RoEpochKvStorage, TreeTransactionalStorage},
    tree::scapegoat::{self, Alpha},
    InitSettings,
};
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

#[test(tokio::test)]
async fn db_creation_integrated_tests() -> Result<()> {
    // Create the test context for mainnet.
    // let ctx = &mut TestContext::new_mainet();
    let _ = env_logger::try_init();
    // Create the test context for the local node.
    //let storage = MemoryProofStorage::default();
    info!("Loading proof storage");
    let storage = KeyValueDB::new_from_env("test_proofs.store")?;
    info!("Loading Anvil and contract");
    let mut ctx = context::new_local_chain(storage).await;
    info!("Initial Anvil block: {}", ctx.block_number().await);
    info!("Building params");
    // Build the parameters.
    ctx.build_params().unwrap();

    info!("Params built");
    let mut single = TestCase::single_value_test_case(&ctx).await?;
    let changes = vec![
        ChangeType::Update(UpdateType::Rest),
        ChangeType::Update(UpdateType::SecondaryIndex),
    ];
    single.run(&mut ctx, changes.clone()).await?;
    let mut mapping = TestCase::mapping_test_case(&ctx).await?;
    let changes = vec![
        ChangeType::Insertion,
        ChangeType::Insertion,
        ChangeType::Update(UpdateType::Rest),
        ChangeType::Deletion,
        ChangeType::Update(UpdateType::SecondaryIndex),
    ];
    mapping.run(&mut ctx, changes).await?;
    Ok(())
}

#[test]
fn ryhope_scapegoat() -> Result<()> {
    let mut row_tree = MerkleRowTree::new(
        InitSettings::Reset(scapegoat::Tree::empty(Alpha::new(0.8))),
        (),
    )
    .unwrap();
    let cell = Cell {
        id: 10,
        value: U256::from(10),
    };
    let payload = RowPayload {
        cells: CellCollection(vec![cell.clone(), cell.clone(), cell.clone()]),
        ..Default::default()
    };
    //  |  |RowTreeKey { value: VectorU256(50753836057528776923099068107172127467069229311), rest: [14] }/RowTreeKey { value: (..), rest: [13] } (1)
    //  |RowTreeKey { value: VectorU256(974563147394964930332893888102456177088745185481), rest: [13] }/RowTreeKey { value: ..), rest: [11] } (2)
    //RowTreeKey { value: VectorU256(1056494154592187365319695072752373049978398833853), rest: [11] }/None (5)
    //  |  |RowTreeKey { value: VectorU256(1056494154592187365319695072752373049978398833853), rest: [15] }/RowTreeKey { value: ..), rest: [12] } (1)
    //  |RowTreeKey { value: VectorU256(1056494154592187365319695072752373049978398834414), rest: [12] }/RowTreeKey { value: ..), rest: [11] } (2)
    //
    let r11 = RowTreeKey {
        value: U256::from_str_radix("1056494154592187365319695072752373049978398833853", 10)
            .unwrap()
            .into(),
        rest: vec![11],
    };
    let r13 = RowTreeKey {
        value: U256::from_str_radix("974563147394964930332893888102456177088745185481", 10)
            .unwrap()
            .into(),
        rest: vec![13],
    };
    let r12 = RowTreeKey {
        value: U256::from_str_radix("1056494154592187365319695072752373049978398834414", 10)
            .unwrap()
            .into(),
        rest: vec![12],
    };
    let r15 = RowTreeKey {
        value: U256::from_str_radix("1056494154592187365319695072752373049978398833853", 10)
            .unwrap()
            .into(),
        rest: vec![15],
    };
    let r14 = RowTreeKey {
        value: U256::from_str_radix("50753836057528776923099068107172127467069229311", 10)
            .unwrap()
            .into(),
        rest: vec![14],
    };
    row_tree.in_transaction(|t| {
        t.store(r11.clone(), payload.clone())?;
        t.store(r12, payload.clone())?;
        t.store(r13, payload.clone())?;
        t.store(r14, payload.clone())?;
        t.store(r15, payload.clone())?;
        Ok(())
    })?;
    println!("BEFORE");
    row_tree.print_tree();
    // Deletion RowTreeKey { value: VectorU256(1056494154592187365319695072752373049978398833853), rest: [11] }
    // Insertion(Row { k: RowTreeKey { value: VectorU256(97094728283605215696305910369622631687767667916), rest: [11] }
    let r11bis = RowTreeKey {
        value: U256::from_str_radix("97094728283605215696305910369622631687767667916", 10)
            .unwrap()
            .into(),
        rest: vec![11],
    };
    let ut = row_tree.in_transaction(|t| {
        t.remove(r11)?;
        t.store(r11bis, payload.clone())?;
        Ok(())
    })?;
    println!("AFTER");
    row_tree.print_tree();
    println!("UT: ------------------------");
    ut.print();
    println!("----------------------------");
    Ok(())
}
