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
    enum Op {
        Insertion,
        Deletion,
        Update,
    }
    let ops = vec![vec![Op::Insertion, Op::Insertion, Op::Insertion]];
    let rows = (0..5)
        .map(|i| Row {
            k: RowTreeKey {
                value: U256::from(i).into(),
                ..Default::default()
            },
            payload: RowPayload {
                cells: CellCollection(vec![Cell {
                    id: i,
                    value: U256::from(i),
                }]),
                ..Default::default()
            },
        })
        .collect::<Vec<_>>();
    let mut row_tree = MerkleRowTree::new(
        InitSettings::Reset(scapegoat::Tree::empty(Alpha::new(0.8))),
        (),
    )
    .unwrap();
    row_tree.in_transaction(|t| {
        for i in 0..3 {
            t.store(rows[i].k.clone(), rows[i].payload.clone())?;
        }
        Ok(())
    })?;
    row_tree.in_transaction(|t| {
        t.store(rows[3].k.clone(), rows[3].payload.clone())?;
        t.store(rows[4].k.clone(), rows[4].payload.clone())?;
        Ok(())
    })?;
    row_tree.in_transaction(|t| {
        t.remove(rows[4].k.clone())?;
        Ok(())
    })?;
    row_tree.try_fetch(&rows[0].k).expect("should be there");
    row_tree.try_fetch(&rows[1].k).expect("should be there");
    row_tree.try_fetch(&rows[2].k).expect("should be there");
    row_tree.try_fetch(&rows[3].k).expect("should be there");
    assert!(row_tree.try_fetch(&rows[4].k).is_none());
    Ok(())
}
