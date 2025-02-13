use plonky2::{
    field::types::PrimeField64, hash::hash_types::HashOut, plonk::config::GenericHashOut,
};
use std::{cmp::max, collections::HashMap};

use crate::common::{
    cases::{
        indexing::BLOCK_COLUMN_NAME,
        query::{QueryCooking, SqlReturn, SqlType, NUM_CHUNKS, NUM_ROWS},
        table_source::BASE_VALUE,
    },
    proof_storage::{ProofKey, ProofStorage},
    table::Table,
    TableInfo,
};

use crate::context::TestContext;
use alloy::primitives::U256;
use anyhow::Result;
use futures::{stream, FutureExt, StreamExt};

use itertools::Itertools;
use log::*;
use mp2_common::{
    poseidon::empty_poseidon_hash,
    proof::{deserialize_proof, ProofWithVK},
    types::HashOutput,
    C, D, F,
};
use mp2_v1::{
    api::MetadataHash,
    indexing::{
        self,
        block::BlockPrimaryIndex,
        cell::MerkleCell,
        row::{MerkleRowTree, Row, RowPayload, RowTreeKey},
    },
    query::{
        batching_planner::{generate_chunks_and_update_tree, UTForChunkProofs, UTKey},
        planner::{execute_row_query, NonExistenceInputIndex, NonExistenceInputRow, TreeFetcher},
    },
};
use parsil::{
    assembler::{DynamicCircuitPis, StaticCircuitPis},
    queries::{core_keys_for_index_tree, core_keys_for_row_tree},
    DEFAULT_MAX_BLOCK_PLACEHOLDER, DEFAULT_MIN_BLOCK_PLACEHOLDER,
};
use ryhope::{
    storage::{
        updatetree::{Next, WorkplanItem},
        EpochKvStorage, RoEpochKvStorage, TreeTransactionalStorage,
    },
    UserEpoch,
};
use sqlparser::ast::Query;
use tokio_postgres::Row as PsqlRow;
use verifiable_db::{
    ivc::PublicInputs as IndexingPIS,
    query::{
        computational_hash_ids::{ColumnIDs, Identifiers, PlaceholderIdentifier},
        universal_circuit::universal_circuit_inputs::{ColumnCell, Placeholders},
    },
    revelation::PublicInputs,
};

use super::{
    GlobalCircuitInput, QueryCircuitInput, QueryPlanner, RevelationCircuitInput,
    MAX_NUM_ITEMS_PER_OUTPUT, MAX_NUM_OUTPUTS, MAX_NUM_PLACEHOLDERS,
};

pub type RevelationPublicInputs<'a> =
    PublicInputs<'a, F, MAX_NUM_OUTPUTS, MAX_NUM_ITEMS_PER_OUTPUT, MAX_NUM_PLACEHOLDERS>;

/// Execute a query to know all the touched rows, and then call the universal circuit on all rows
pub(crate) async fn prove_query(
    mut parsed: Query,
    res: Vec<PsqlRow>,
    metadata: MetadataHash,
    planner: &mut QueryPlanner<'_>,
) -> Result<()> {
    let current_epoch = planner.table.index.current_epoch().await? as BlockPrimaryIndex;
    let index_query = core_keys_for_index_tree(
        current_epoch as UserEpoch,
        (planner.query.min_block, planner.query.max_block),
        &planner.table.index_table_name(),
    )?;
    let big_index_cache = planner
        .table
        .index
        // The bounds here means between which versions of the tree should we look. For index tree,
        // we only look at _one_ version of the tree.
        .wide_lineage_between(
            current_epoch as UserEpoch,
            &index_query,
            (current_epoch as UserEpoch, current_epoch as UserEpoch),
        )
        .await?;
    // prove the index tree, on a single version. Both path can be taken depending if we do have
    // some nodes or not
    let initial_epoch = planner.table.genesis_block;
    let block_range =
        planner.query.min_block.max(initial_epoch)..=planner.query.max_block.min(current_epoch);
    let num_blocks_in_range = big_index_cache.num_touched_rows();
    info!(
        "found {} blocks in range: {:?}",
        num_blocks_in_range, block_range
    );
    let column_ids = ColumnIDs::from(&planner.table.columns);
    let query_proof_id = if num_blocks_in_range == 0 {
        info!("Running INDEX TREE proving for EMPTY query");
        let to_be_proven_node = NonExistenceInputIndex::new(
            &planner.table.index,
            planner.table.index_table_name().to_string(),
            &planner.table.db_pool,
            planner.settings,
            &planner.pis.bounds,
        )
        .find_node_for_non_existence(current_epoch as BlockPrimaryIndex)
        .await
        .unwrap_or_else(|e| {
            panic!(
                "Empty block range to be proven for query bounds {}, {}, but no node
                    to be proven with non-existence circuit was found: {e:?}",
                planner.query.min_block, planner.query.max_block
            )
        });
        let index_path = planner
            .table
            .index
            .compute_path(&to_be_proven_node, current_epoch as UserEpoch)
            .await
            .unwrap_or_else(|| {
                panic!("Compute path for index node with key {to_be_proven_node} failed")
            });
        let input = QueryCircuitInput::new_non_existence_input(
            index_path,
            &column_ids,
            &planner.pis.predication_operations,
            &planner.pis.result,
            &planner.query.placeholders,
            &planner.pis.bounds,
        )?;
        let query_proof = planner
            .ctx
            .run_query_proof("batching::non_existence", GlobalCircuitInput::Query(input))?;
        let proof_key = ProofKey::QueryAggregate((
            planner.query.query.clone(),
            planner.query.placeholders.placeholder_values(),
            UTKey::default(),
        ));
        planner
            .ctx
            .storage
            .store_proof(proof_key.clone(), query_proof)?;
        proof_key
    } else {
        info!(
            "Row cache query: {}",
            &core_keys_for_row_tree(
                &planner.query.query,
                planner.settings,
                &planner.pis.bounds,
                &planner.query.placeholders,
            )?
        );
        let row_cache = planner
            .table
            .row
            .wide_lineage_between(
                planner.table.row.current_epoch().await?,
                &core_keys_for_row_tree(
                    &planner.query.query,
                    planner.settings,
                    &planner.pis.bounds,
                    &planner.query.placeholders,
                )?,
                (
                    planner.query.min_block as UserEpoch,
                    planner.query.max_block as UserEpoch,
                ),
            )
            .await?;
        info!("Running INDEX tree proving from cache");
        let (proven_chunks, update_tree) =
            generate_chunks_and_update_tree::<NUM_ROWS, NUM_CHUNKS, _>(
                row_cache,
                big_index_cache,
                &column_ids,
                NonExistenceInputRow::new(
                    &planner.table.row,
                    planner.table.public_name.clone(),
                    &planner.table.db_pool,
                    planner.settings,
                    &planner.pis.bounds,
                ),
                current_epoch as UserEpoch,
            )
            .await?;
        info!("Root of update tree is {:?}", update_tree.root());
        let mut workplan = update_tree.into_workplan();
        let mut proof_id = None;
        while let Some(Next::Ready(wk)) = workplan.next() {
            let (k, is_path_end) = if let WorkplanItem::Node { k, is_path_end } = &wk {
                (k, *is_path_end)
            } else {
                unreachable!("this update tree has been created with a batch size of 1")
            };
            let proof = if is_path_end {
                // this is a row chunk to be proven
                let to_be_proven_chunk = proven_chunks
                    .get(k)
                    .unwrap_or_else(|| panic!("chunk for key {:?} not found", k));
                let input = QueryCircuitInput::new_row_chunks_input(
                    to_be_proven_chunk,
                    &planner.pis.predication_operations,
                    &planner.query.placeholders,
                    &planner.pis.bounds,
                    &planner.pis.result,
                )?;
                info!("Proving chunk {:?}", k);
                planner.ctx.run_query_proof(
                    "batching::chunk_processing",
                    GlobalCircuitInput::Query(input),
                )
            } else {
                let children_keys = workplan.tree().get_children_keys(k);
                info!("children keys: {:?}", children_keys);
                // fetch the proof for each child from the storage
                let child_proofs = children_keys
                    .into_iter()
                    .map(|child_key| {
                        let proof_key = ProofKey::QueryAggregate((
                            planner.query.query.clone(),
                            planner.query.placeholders.placeholder_values(),
                            child_key,
                        ));
                        planner.ctx.storage.get_proof_exact(&proof_key)
                    })
                    .collect::<Result<Vec<_>>>()?;
                let input = QueryCircuitInput::new_chunk_aggregation_input(&child_proofs)?;
                info!("Aggregating chunk {:?}", k);
                planner.ctx.run_query_proof(
                    "batching::chunk_aggregation",
                    GlobalCircuitInput::Query(input),
                )
            }?;
            let proof_key = ProofKey::QueryAggregate((
                planner.query.query.clone(),
                planner.query.placeholders.placeholder_values(),
                *k,
            ));
            planner.ctx.storage.store_proof(proof_key.clone(), proof)?;
            proof_id = Some(proof_key);
            workplan.done(&wk)?;
        }
        proof_id.unwrap()
    };

    info!("proving revelation");

    let proof = prove_revelation(
        planner.ctx,
        &planner.query,
        planner.pis,
        planner.table.index.current_epoch().await?,
        &query_proof_id,
    )
    .await?;
    info!("Revelation proof done! Checking public inputs...");

    // get `StaticPublicInputs`, i.e., the data about the query available only at query registration time,
    // to check the public inputs
    let pis = parsil::assembler::assemble_static(&parsed, planner.settings)?;
    // get number of matching rows
    let mut exec_query = parsil::executor::generate_query_keys(&mut parsed, planner.settings)?;
    let query_params = exec_query.convert_placeholders(&planner.query.placeholders);
    let num_touched_rows = execute_row_query(
        &planner.table.db_pool,
        &exec_query
            .normalize_placeholder_names()
            .to_pgsql_string_with_placeholder(),
        &query_params,
    )
    .await?
    .len();

    check_final_outputs(
        proof,
        planner.ctx,
        planner.table,
        &planner.query,
        &pis,
        planner.table.index.current_epoch().await?,
        num_touched_rows,
        res,
        metadata,
    )?;
    info!("Revelation done!");
    Ok(())
}

async fn prove_revelation(
    ctx: &TestContext,
    query: &QueryCooking,
    pis: &DynamicCircuitPis,
    tree_epoch: UserEpoch,
    query_proof_id: &ProofKey,
) -> Result<Vec<u8>> {
    // load the query proof, which is at the root of the tree
    let query_proof = ctx.storage.get_proof_exact(query_proof_id)?;
    // load the preprocessing proof at the same epoch
    let indexing_proof = {
        let pk = ProofKey::IVC(tree_epoch as BlockPrimaryIndex);
        ctx.storage.get_proof_exact(&pk)?
    };
    let input = RevelationCircuitInput::new_revelation_aggregated(
        query_proof,
        indexing_proof,
        &pis.bounds,
        &query.placeholders,
        &pis.predication_operations,
        &pis.result,
    )?;
    let proof = ctx.run_query_proof(
        "querying::revelation",
        GlobalCircuitInput::Revelation(input),
    )?;
    Ok(proof)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn check_final_outputs(
    revelation_proof: Vec<u8>,
    ctx: &TestContext,
    table: &Table,
    query: &QueryCooking,
    pis: &StaticCircuitPis,
    tree_epoch: UserEpoch,
    num_touched_rows: usize,
    res: Vec<PsqlRow>,
    offcircuit_md: MetadataHash,
) -> Result<()> {
    // fetch indexing proof, whose public inputs are needed to check correctness of revelation proof outputs
    let indexing_proof = {
        let pk = ProofKey::IVC(tree_epoch as BlockPrimaryIndex);
        ctx.storage.get_proof_exact(&pk)?
    };
    let deserialized_indexing_proof = ProofWithVK::deserialize(&indexing_proof)?;
    let indexing_pis = IndexingPIS::from_slice(&deserialized_indexing_proof.proof().public_inputs);

    let deserialized_proof = deserialize_proof::<F, C, D>(&revelation_proof)?;
    let revelation_pis = RevelationPublicInputs::from_slice(&deserialized_proof.public_inputs);
    // check original blockchain hash. ToDo: access it from Anvil
    assert_eq!(
        indexing_pis.block_hash_fields(),
        revelation_pis.original_block_hash(),
    );
    // check computational hash
    let metadata_hash = HashOutput::try_from(
        HashOut::<F>::from_vec(indexing_pis.metadata_hash().to_vec()).to_bytes(),
    )?;
    assert_eq!(
        offcircuit_md, metadata_hash,
        "metadata hash computed by circuit and offcircuit is not the same"
    );

    let column_ids = ColumnIDs::from(&table.columns);
    let expected_computational_hash = Identifiers::computational_hash(
        &column_ids,
        &pis.predication_operations,
        &pis.result,
        &metadata_hash,
        pis.bounds.min_query_secondary.clone(),
        pis.bounds.max_query_secondary.clone(),
    )?;
    assert_eq!(
        HashOutput::try_from(
            revelation_pis
                .flat_computational_hash()
                .iter()
                .flat_map(|f| u32::try_from(f.to_canonical_u64()).unwrap().to_be_bytes())
                .collect_vec()
        )?,
        expected_computational_hash,
    );
    // check num placeholders
    let expected_num_placeholders = query.placeholders.len();
    assert_eq!(
        expected_num_placeholders as u64,
        revelation_pis.num_placeholders().to_canonical_u64(),
    );
    // check placeholder values
    let expected_placeholder_values = query.placeholders.placeholder_values();
    assert_eq!(
        expected_placeholder_values,
        revelation_pis.placeholder_values()[..expected_num_placeholders], // consider only the valid placeholders
    );
    // check entry count
    assert_eq!(
        num_touched_rows as u64,
        revelation_pis.entry_count().to_canonical_u64(),
    );
    // check there were no overflow errors
    assert!(!revelation_pis.overflow_flag());
    // check number of results
    assert_eq!(
        res.len() as u64,
        revelation_pis.num_results().to_canonical_u64(),
    );
    // check results: we check that each result in res appears in set
    // of results exposed by the proof, and vice versa:
    // - first, we accumulate each result in `res` to a `HashMap`,
    //   and we do the same for the set of results exposed by the proof
    // - then, we check that the 2 `HashMap`s are the same
    let mut expected_res_accumulator: HashMap<Vec<U256>, usize> = HashMap::new();
    let mut proof_res_accumulator: HashMap<Vec<U256>, usize> = HashMap::new();
    res.into_iter()
        .zip(revelation_pis.result_values())
        .for_each(|(row, res)| {
            let (expected_res, proof_res): (Vec<_>, Vec<_>) = (0..row.len())
                .map(|i| {
                    let SqlReturn::Numeric(expected_res) =
                        SqlType::Numeric.extract(&row, i).unwrap();
                    (expected_res, res[i])
                })
                .unzip();
            *expected_res_accumulator.entry(expected_res).or_default() += 1;
            *proof_res_accumulator.entry(proof_res).or_default() += 1;
        });
    assert_eq!(expected_res_accumulator, proof_res_accumulator,);

    Ok(())
}

type BlockRange = (BlockPrimaryIndex, BlockPrimaryIndex);

pub(crate) async fn cook_query_between_blocks(
    table: &Table,
    info: &TableInfo,
) -> Result<QueryCooking> {
    let max = table.row.current_epoch().await?;
    let min = max - 1;

    let value_column = &info.value_column;
    let table_name = &table.public_name;
    let placeholders = Placeholders::new_empty(U256::from(min), U256::from(max));

    let query_str = format!(
        "SELECT AVG({value_column})
                FROM {table_name}
                WHERE {BLOCK_COLUMN_NAME} >= {DEFAULT_MIN_BLOCK_PLACEHOLDER}
                AND {BLOCK_COLUMN_NAME} <= {DEFAULT_MAX_BLOCK_PLACEHOLDER};"
    );
    Ok(QueryCooking {
        min_block: min as BlockPrimaryIndex,
        max_block: max as BlockPrimaryIndex,
        query: query_str,
        placeholders,
        limit: None,
        offset: None,
    })
}

pub(crate) async fn cook_query_secondary_index_nonexisting_placeholder(
    table: &Table,
    info: &TableInfo,
) -> Result<QueryCooking> {
    let (longest_key, (min_block, max_block)) = find_longest_lived_key(table, false).await?;
    let key_value = hex::encode(longest_key.value.to_be_bytes_trimmed_vec());
    info!(
        "Longest sequence is for key {longest_key:?} -> from block {:?} to  {:?}, hex -> {}",
        min_block, max_block, key_value
    );
    // now we can fetch the key that we want
    let key_column = table.columns.secondary.name.clone();
    // Assuming this is mapping with only two columns !
    let value_column = &info.value_column;
    let table_name = &table.public_name;

    let filtering_value = *BASE_VALUE + U256::from(5);

    let random_value = U256::from(1234567890);
    let placeholders = Placeholders::from((
        vec![
            (PlaceholderIdentifier::Generic(1), random_value),
            (PlaceholderIdentifier::Generic(2), filtering_value),
        ],
        U256::from(min_block),
        U256::from(max_block),
    ));

    let query_str = format!(
        "SELECT AVG({value_column})
                FROM {table_name}
                WHERE {BLOCK_COLUMN_NAME} >= {DEFAULT_MIN_BLOCK_PLACEHOLDER}
                AND {BLOCK_COLUMN_NAME} <= {DEFAULT_MAX_BLOCK_PLACEHOLDER}
                AND {key_column} = $1 AND {value_column} >= $2;"
    );
    Ok(QueryCooking {
        min_block: min_block as BlockPrimaryIndex,
        max_block: max_block as BlockPrimaryIndex,
        query: query_str,
        placeholders,
        limit: None,
        offset: None,
    })
}

// cook up a SQL query on the secondary index and with a predicate on the non-indexed column.
// we just iterate on mapping keys and take the one that exist for most blocks. We also choose
// a value to filter over the non-indexed column
pub(crate) async fn cook_query_secondary_index_placeholder(
    table: &Table,
    info: &TableInfo,
) -> Result<QueryCooking> {
    let (longest_key, (min_block, max_block)) = find_longest_lived_key(table, false).await?;
    let key_value = hex::encode(longest_key.value.to_be_bytes_trimmed_vec());
    info!(
        "Longest sequence is for key {longest_key:?} -> from block {:?} to  {:?}, hex -> {}",
        min_block, max_block, key_value
    );
    // now we can fetch the key that we want
    let key_column = table.columns.secondary.name.clone();
    let value_column = &info.value_column;
    let table_name = &table.public_name;

    let filtering_value = *BASE_VALUE + U256::from(5);

    let placeholders = Placeholders::from((
        vec![
            (PlaceholderIdentifier::Generic(1), longest_key.value),
            (PlaceholderIdentifier::Generic(2), filtering_value),
        ],
        U256::from(min_block),
        U256::from(max_block),
    ));

    let query_str = format!(
        "SELECT AVG({value_column})
                FROM {table_name}
                WHERE {BLOCK_COLUMN_NAME} >= {DEFAULT_MIN_BLOCK_PLACEHOLDER}
                AND {BLOCK_COLUMN_NAME} <= {DEFAULT_MAX_BLOCK_PLACEHOLDER}
                AND {key_column} = $1 AND {value_column} >= $2;"
    );
    Ok(QueryCooking {
        min_block: min_block as BlockPrimaryIndex,
        max_block: max_block as BlockPrimaryIndex,
        query: query_str,
        placeholders,
        limit: None,
        offset: None,
    })
}

// cook up a SQL query on the secondary index. For that we just iterate on mapping keys and
// take the one that exist for most blocks
pub(crate) async fn cook_query_unique_secondary_index(
    table: &Table,
    info: &TableInfo,
) -> Result<QueryCooking> {
    let (longest_key, (min_block, max_block)) = find_longest_lived_key(table, false).await?;
    let key_value = hex::encode(longest_key.value.to_be_bytes_trimmed_vec());
    info!(
        "Longest sequence is for key {longest_key:?} -> from block {:?} to  {:?}, hex -> {}",
        min_block, max_block, key_value
    );
    // now we can fetch the key that we want
    let key_column = table.columns.secondary.name.clone();
    let value_column = &info.value_column;
    let table_name = &table.public_name;
    let max_block = min_block + 1;
    // primary_min_placeholder = ".."
    // primary_max_placeholder = ".."
    // Address == $3 --> placeholders.hashmap empty, put in query bounds secondary_min = secondary_max = "$3""
    // adddress IN ($3,$4,$5) -> min "$3" max "$5", put in query bounds
    // secondary_min = $3, and secondary_max = "$5", placeholders.put(generic, "$4")
    // placeholders.generic(("generic", $3)),(generic,$4), (generic,$5))
    // WHERE price > $3 AND price < $4 <--
    // placeholders _values = [min_block,max_block,sec_address];
    // "$3" = secondary min placeholder
    // "$4" = secondary max placeholder
    // "secondary_column < $3 || secondary_column > $3 || secondary_column == $3" <-- then it can
    // Ok iv'e seen < for $3,
    //  * if i see > $4 it's ok,
    //  * if i see sec_index < $4 , then it's worng because i already have seen an < for sec. index
    // go to QueryBounds, so we need to know that $3 is being used for secondary index
    // "secondary_column + price < $3 * 9" <--- it NEVER goes into range stuff not QUeryBounds
    // * secondary_column < $3 AND secondary_column + price < $3 * 9 AND secondary_column > $4" -->
    //     secondary placeholder usage = min = $3, max = $4
    //     basic operations = secondary_column + Price < $3 * 9
    //  * secondary_column < $3 AND secondary_column < $4
    // secondary_index In [1,2,4,5] -> sec >= 1 AND sec <= 5 AND (sec=1 OR sec = 2 OR sec = 4 OR sec=5)
    // WHERE something() OR sec_index > $4 <-- we dont use range, it's expensive
    // WHERE something() AND sec_index OP [$1] <-- we use range
    // WHERE something() AND sec_index >= [$1] AND sec_index + price < 3*quantity <-- not optimized
    // (AND (< sec_ind $4) (OR (something) (< sec_ind (+ price 3)))
    // something1 AND (sec_indx < $4 AND (something OR $4 < price  + 3)) <-- al right stuff goes into basic
    // operation --> transformation to ?
    // something1 AND (1 AND (something OR sec_ind < price  + 3)) <-- al right stuff goes into basic
    // parseil needs to take as input
    // * placeholder namings for ranges
    //      "$1" => primary_index_min, "$2" => primary_index_max
    //      max number of placeholders supported
    //  * parsil needs to output as well
    //      * Option<"$3"=> secondary_index_min >
    //      * Option<"$4"=> secondary_index_max >
    //  * parsil restrictions
    //      * block number will always be "block >= $1 AND block =< $2"
    //      * secondary_index to be used in optimuzed query needs to be of form "sec_index OP $3"
    //      with only AND with similar formats (range format)
    //          * we can't have "sec_index < $3" OR "sec_index > $4"
    //          * but we can have "sec_index < $3 AND (price < $3 -10 OR sec_index * price < $4 + 20")
    //              * only the first predicate is used in range query
    let placeholders = Placeholders::new_empty(U256::from(min_block), U256::from(max_block));

    let query_str = format!(
        "SELECT AVG({value_column})
                FROM {table_name}
                WHERE {BLOCK_COLUMN_NAME} >= {DEFAULT_MIN_BLOCK_PLACEHOLDER}
                AND {BLOCK_COLUMN_NAME} <= {DEFAULT_MAX_BLOCK_PLACEHOLDER}
                AND {key_column} = '0x{key_value}';"
    );
    Ok(QueryCooking {
        min_block: min_block as BlockPrimaryIndex,
        max_block,
        query: query_str,
        placeholders,
        limit: None,
        offset: None,
    })
}

pub(crate) async fn cook_query_partial_block_range(
    table: &Table,
    info: &TableInfo,
) -> Result<QueryCooking> {
    let (longest_key, (min_block, max_block)) = find_longest_lived_key(table, false).await?;
    let key_value = hex::encode(longest_key.value.to_be_bytes_trimmed_vec());
    info!(
        "Longest sequence is for key {longest_key:?} -> from block {:?} to  {:?}, hex -> {}",
        min_block, max_block, key_value
    );
    // now we can fetch the key that we want
    let key_column = table.columns.secondary.name.clone();
    let value_column = info.value_column.clone();
    let table_name = &table.public_name;
    let initial_epoch = table.row.initial_epoch().await;
    // choose a min query bound smaller than initial epoch
    let min_block = initial_epoch - 1;
    let placeholders = Placeholders::new_empty(U256::from(min_block), U256::from(max_block));

    let query_str = format!(
        "SELECT AVG({value_column})
                FROM {table_name}
                WHERE {BLOCK_COLUMN_NAME} >= {DEFAULT_MIN_BLOCK_PLACEHOLDER}
                AND {BLOCK_COLUMN_NAME} <= {DEFAULT_MAX_BLOCK_PLACEHOLDER}
                AND {key_column} = '0x{key_value}';"
    );
    Ok(QueryCooking {
        min_block: min_block as BlockPrimaryIndex,
        max_block: max_block as BlockPrimaryIndex,
        query: query_str,
        placeholders,
        limit: None,
        offset: None,
    })
}

pub(crate) async fn cook_query_no_matching_entries(
    table: &Table,
    info: &TableInfo,
) -> Result<QueryCooking> {
    let initial_epoch = table.row.initial_epoch().await;
    // choose query bounds outside of the range [initial_epoch, last_epoch]
    let min_block = max(0, initial_epoch - 2) as usize;
    let max_block = initial_epoch - 1;
    // now we can fetch the key that we want
    let value_column = &info.value_column;
    let table_name = &table.public_name;
    let placeholders = Placeholders::new_empty(U256::from(min_block), U256::from(max_block));

    let query_str = format!(
        "SELECT SUM({value_column})
                FROM {table_name}
                WHERE {BLOCK_COLUMN_NAME} >= {DEFAULT_MIN_BLOCK_PLACEHOLDER}
                AND {BLOCK_COLUMN_NAME} <= {DEFAULT_MAX_BLOCK_PLACEHOLDER};"
    );

    Ok(QueryCooking {
        query: query_str,
        placeholders,
        min_block,
        max_block: max_block as usize,
        limit: None,
        offset: None,
    })
}

/// Cook a query where there are no entries satisying the secondary query bounds only for some
/// blocks of the primary index bounds (not for all the blocks)
pub(crate) async fn cook_query_non_matching_entries_some_blocks(
    table: &Table,
    info: &TableInfo,
) -> Result<QueryCooking> {
    let (longest_key, (min_block, max_block)) = find_longest_lived_key(table, true).await?;
    let key_value = hex::encode(longest_key.value.to_be_bytes_trimmed_vec());
    info!(
        "Longest sequence is for key {longest_key:?} -> from block {:?} to  {:?}, hex -> {}",
        min_block, max_block, key_value
    );
    // now we can fetch the key that we want
    let key_column = &table.columns.secondary.name;
    let value_column = &info.value_column;
    let table_name = &table.public_name;
    // in this query we set query bounds on block numbers to the widest range, so that we
    // are sure that there are blocks where the chosen key is not alive
    let min_block = table.genesis_block;
    let max_block = table.row.current_epoch().await?;
    let placeholders = Placeholders::new_empty(U256::from(min_block), U256::from(max_block));

    let query_str = format!(
        "SELECT AVG({value_column})
                FROM {table_name}
                WHERE {BLOCK_COLUMN_NAME} >= {DEFAULT_MIN_BLOCK_PLACEHOLDER}
                AND {BLOCK_COLUMN_NAME} <= {DEFAULT_MAX_BLOCK_PLACEHOLDER}
                AND {key_column} = '0x{key_value}';"
    );
    Ok(QueryCooking {
        min_block: min_block as BlockPrimaryIndex,
        max_block: max_block as BlockPrimaryIndex,
        query: query_str,
        placeholders,
        limit: None,
        offset: None,
    })
}

/// Cook a query with a block range that doesn't match any primary index value in
/// the table. Differently from `cook_query_no_matching_entries`, this query uses
/// a block range that is entirely between 2 subsequent epochs in the index tree,
/// therefore it is meaningful only in tables where epochs may be non-consecutive.
/// The method returns None if there are no non-consecutive epochs in the index tree.
pub(crate) async fn cook_query_no_matching_block_range(
    table: &Table,
    info: &TableInfo,
) -> Result<Option<QueryCooking>> {
    let subsequent_epochs = subsequent_epochs(table).await?;
    // find if there are 2 subsequent epochs in the index tree which are not consecutive
    Ok(subsequent_epochs
        .into_iter()
        .find(|(e0, e1)| *e1 > *e0 + 1)
        .map(|non_consecutive_epochs| {
            // now choose min and max block between the identifier non-consecutive epochs
            let min_block = non_consecutive_epochs.0 as BlockPrimaryIndex + 1;
            let max_block = non_consecutive_epochs.1 as BlockPrimaryIndex - 1;

            let value_column = &info.value_column;
            let table_name = &table.public_name;
            let placeholders =
                Placeholders::new_empty(U256::from(min_block), U256::from(max_block));

            let query_str = format!(
                "SELECT AVG({value_column})
                        FROM {table_name}
                        WHERE {BLOCK_COLUMN_NAME} >= {DEFAULT_MIN_BLOCK_PLACEHOLDER}
                        AND {BLOCK_COLUMN_NAME} <= {DEFAULT_MAX_BLOCK_PLACEHOLDER};"
            );
            QueryCooking {
                query: query_str,
                placeholders,
                min_block,
                max_block,
                limit: None,
                offset: None,
            }
        }))
}

/// Utility function to associated to each row in the tree, the blocks where the row
/// was valid
async fn extract_row_liveness(table: &Table) -> Result<HashMap<RowTreeKey, Vec<UserEpoch>>> {
    let mut all_table = HashMap::new();
    let current_epoch = table.index.current_epoch().await?;
    let epochs = table.index.keys_at(current_epoch).await;
    for block in epochs {
        println!("Querying for block {block}");
        let rows = collect_all_at(&table.row, block as UserEpoch).await?;
        debug!(
            "Collecting {} rows at epoch {} (rows_keys {:?})",
            rows.len(),
            block,
            rows.iter().map(|r| r.k.value).collect::<Vec<_>>()
        );
        for row in rows {
            let blocks = all_table.entry(row.k.clone()).or_insert(Vec::new());
            blocks.push(block as UserEpoch);
        }
    }
    // sort the epochs
    all_table
        .iter_mut()
        .for_each(|(_, epochs)| epochs.sort_unstable());
    Ok(all_table)
}

/// Associate to each epoch found in the index tree of `table` the subsequent
/// epoch in the tree
async fn subsequent_epochs(table: &Table) -> Result<HashMap<UserEpoch, UserEpoch>> {
    let last_epoch = table.index.current_epoch().await?;
    let mut epochs = table.index.keys_at(last_epoch).await;
    epochs.sort_unstable();
    Ok(epochs
        .windows(2)
        .map(|w| (w[0] as i64, w[1] as i64))
        .collect())
}

/// Find the the key of the node that lives the longest across all the blocks. If the
/// `must_not_be_alive_in_some_blocks` flag is true, then the method considers only nodes
/// that aren't live for all the blocks
pub(crate) async fn find_longest_lived_key(
    table: &Table,
    must_not_be_alive_in_some_blocks: bool,
) -> Result<(RowTreeKey, BlockRange)> {
    let initial_epoch = table.genesis_block as UserEpoch;
    let last_epoch = table.row.current_epoch().await?;
    let all_table = extract_row_liveness(table).await?;
    let subsequent_epochs = subsequent_epochs(table).await?;
    // find the longest running row
    let (longest_key, _, starting, ending) = all_table
        .iter()
        .filter_map(|(k, epochs)| {
            // simplification here to start at first epoch where this row was. Otherwise need to do
            // longest consecutive sequence etc...
            let (l, start, end) = find_longest_consecutive_sequence(epochs, &subsequent_epochs);
            debug!("finding sequence of {l} blocks for key {k:?} (epochs {epochs:?}");
            if must_not_be_alive_in_some_blocks {
                if start > initial_epoch || end < last_epoch {
                    Some((k, l, start, end))
                } else {
                    None // it's live for all blocks, so we drop this row
                }
            } else {
                Some((k, l, start, end))
            }
        })
        .max_by_key(|(_k, l, _start, _end)| *l)
        .unwrap_or_else(|| {
            panic!(
                "unable to find longest row? -> length all _table {}, max {}",
                all_table.len(),
                last_epoch,
            )
        });
    // we set the block bounds
    let min_block = starting as BlockPrimaryIndex;
    let max_block = ending as BlockPrimaryIndex;
    Ok((longest_key.clone(), (min_block, max_block)))
}

async fn collect_all_at(
    tree: &MerkleRowTree,
    at: UserEpoch,
) -> Result<Vec<Row<BlockPrimaryIndex>>> {
    let root_key = tree.root_at(at).await?.unwrap();
    let (ctx, payload) = tree
        .try_fetch_with_context_at(&root_key, at)
        .await?
        .unwrap();
    let root_row = Row {
        k: root_key,
        payload,
    };
    let mut all_rows = vec![root_row];
    let mut to_inspect = vec![ctx];
    while !to_inspect.is_empty() {
        let local = to_inspect.clone();
        let (local_rows, local_ctx): (Vec<_>, Vec<_>) = stream::iter(local.iter())
            .then(|ctx| async {
                let lctx = ctx.clone();
                let mut local_rows = Vec::new();
                let mut local_ctx = Vec::new();
                for child_k in lctx.iter_children().flatten() {
                    let (child_ctx, child_payload) = tree
                        .try_fetch_with_context_at(child_k, at)
                        .await
                        .unwrap()
                        .unwrap();
                    local_rows.push(Row {
                        k: child_k.clone(),
                        payload: child_payload,
                    });
                    local_ctx.push(child_ctx.clone())
                }
                (local_rows, local_ctx)
            })
            .unzip()
            .await;
        all_rows.extend(local_rows.into_iter().flatten().collect::<Vec<_>>());
        to_inspect = local_ctx.into_iter().flatten().collect::<Vec<_>>();
    }
    Ok(all_rows)
}

fn find_longest_consecutive_sequence(
    v: &[i64],
    subsequent_epochs: &HashMap<i64, i64>,
) -> (usize, i64, i64) {
    let mut current = 0;
    let mut starting_idx = 0;
    let mut longest = (0, 0);
    let mut update_longest = |current, idx| {
        if current > (longest.1 - longest.0) {
            longest = (starting_idx, idx)
        }
        starting_idx = idx + 1;
    };
    for i in 0..v.len() - 1 {
        if *subsequent_epochs.get(&v[i]).unwrap() == v[i + 1] {
            current += 1;
        } else {
            update_longest(current, i);
            current = 0;
        }
    }
    update_longest(current, v.len() - 1);
    (longest.1 - longest.0, v[longest.0], v[longest.1])
}

#[allow(dead_code)]
async fn check_correct_cells_tree(
    all_cells: &[ColumnCell],
    payload: &RowPayload<BlockPrimaryIndex>,
) -> Result<()> {
    let local_cells = all_cells.to_vec();
    let expected_cells_root = payload
        .cell_root_hash
        .unwrap_or(HashOutput::from(*empty_poseidon_hash()));
    let mut tree = indexing::cell::new_tree().await;
    tree.in_transaction(|t| {
        async move {
            for (i, cell) in local_cells[2..].iter().enumerate() {
                // putting 0 for primary index as it doesn't matter in the hash computation
                t.store(
                    i + 1,
                    MerkleCell::new(cell.id.to_canonical_u64(), cell.value, 0),
                )
                .await?;
            }
            Ok(())
        }
        .boxed()
    })
    .await
    .expect("can't update cell tree");
    let found_hash = tree.root_data().await?.unwrap().hash;
    assert_eq!(
        expected_cells_root, found_hash,
        "cells root hash not the same when given to circuit"
    );
    Ok(())
}
