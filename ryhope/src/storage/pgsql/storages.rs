use crate::{
    error::{ensure, RyhopeError},
    mapper_table_name,
    storage::{
        memory::InMemoryEpochMapper, CurrenEpochUndefined, EpochKvStorage, EpochMapper,
        EpochStorage, RoEpochKvStorage, RoSharedEpochMapper, SqlTransactionStorage,
        TransactionalStorage, TreeStorage, WideLineage,
    },
    tree::{
        sbbst::{self, NodeIdx},
        scapegoat, NodeContext, TreeTopology,
    },
    IncrementalEpoch, UserEpoch, EPOCH, INCREMENTAL_EPOCH, KEY, PAYLOAD, USER_EPOCH, VALID_FROM,
    VALID_UNTIL,
};
use bb8::Pool;
use bb8_postgres::PostgresConnectionManager;
use itertools::Itertools;
use postgres_types::Json;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeSet, HashMap, HashSet},
    fmt::Debug,
    future::Future,
    marker::PhantomData,
    sync::Arc,
};
use tokio::sync::RwLock;
use tokio_postgres::{self, NoTls, Row, Transaction};
use tracing::*;

use super::{CachedValue, PayloadInDb, ToFromBytea, MAX_PGSQL_BIGINT};

pub type DBPool = Pool<PostgresConnectionManager<NoTls>>;

const PARENT: &str = "__parent";
const LEFT_CHILD: &str = "__left_child";
const RIGHT_CHILD: &str = "__right_child";
const SUBTREE_SIZE: &str = "__subtree_size";

/// Type implementing this trait define the behavior of a storage tree
/// components regarding their persistence in DB.
pub trait DbConnector<V>: TreeTopology
where
    Self::Key: ToFromBytea,
    V: Serialize + for<'a> Deserialize<'a> + Clone + Send + Sync + Debug,
{
    /// Return a list of pairs column name, SQL type required by the connector.
    fn columns() -> Vec<(&'static str, &'static str)> {
        Self::node_columns()
            .iter()
            .cloned()
            .chain(Self::payload_columns().iter().cloned())
            .collect()
    }

    /// Return a list of pairs of column names and SQL types required by the
    /// connector to store node-related information.
    fn node_columns() -> &'static [(&'static str, &'static str)];

    /// Return a list of pairs of column names and SQL types required by the
    /// connector to store payload-related information.
    fn payload_columns() -> &'static [(&'static str, &'static str)] {
        &[(PAYLOAD, "JSONB")]
    }

    /// Within a PgSQL transaction, insert the given value at the given epoch.
    fn create_node_in_tx(
        db_tx: &tokio_postgres::Transaction<'_>,
        table: &str,
        k: &Self::Key,
        birth_epoch: IncrementalEpoch,
        v: &Self::Node,
    ) -> impl Future<Output = Result<(), RyhopeError>>;

    /// Within a PgSQL transaction, update the value associated at the given
    /// epoch to the given key.
    fn set_at_in_tx(
        db_tx: &tokio_postgres::Transaction<'_>,
        table: &str,
        k: &Self::Key,
        epoch: IncrementalEpoch,
        v: V,
    ) -> impl Future<Output = Result<(), RyhopeError>> {
        async move {
            db_tx
            .execute(
                &format!(
                    "UPDATE {} SET {PAYLOAD}=$3 WHERE {KEY}=$1 AND {VALID_FROM}<=$2 AND $2<={VALID_UNTIL}",
                    table
                ),
                &[&k.to_bytea(), &epoch, &Json(v)],
            )
            .await
                .map(|_| ())
                .map_err(|err| RyhopeError::from_db("while updating payload", err))
        }
    }

    /// Return the value associated to the given key at the given epoch.
    fn fetch_node_at(
        db: DBPool,
        table: &str,
        k: &Self::Key,
        epoch: IncrementalEpoch,
    ) -> impl Future<Output = Result<Option<Self::Node>, RyhopeError>> + Send;

    fn fetch_all_keys(
        db: DBPool,
        table: &str,
        epoch: IncrementalEpoch,
    ) -> impl Future<Output = Result<Vec<Self::Key>, RyhopeError>> + Send {
        async move {
            let connection = db.get().await.unwrap();
            Ok(connection
                .query(
                    &format!(
                        "SELECT {KEY} FROM {} WHERE {VALID_FROM} <= $1 AND $1 <= {VALID_UNTIL}",
                        table
                    ),
                    &[&epoch],
                )
                .await
                .map_err(|err| RyhopeError::from_db("while fetching all keys from database", err))?
                .iter()
                .map(|row| Self::Key::from_bytea(row.get::<_, Vec<u8>>(0)))
                .collect())
        }
    }

    /// Return, if a any, a key alive at the give epoch
    fn fetch_a_key(
        db: DBPool,
        table: &str,
        epoch: IncrementalEpoch,    
    ) -> impl Future<Output = Result<Option<Self::Key>, RyhopeError>> + Send {
        async move {
            let connection = db.get().await.unwrap();
            Ok(connection
                .query(
                    &format!(
                        "SELECT {KEY} FROM {} WHERE {VALID_FROM} <= $1 AND $1 <= {VALID_UNTIL} LIMIT 1",
                        table
                    ),
                    &[&epoch],
                )
                .await
                .map_err(|err| RyhopeError::from_db("while fetching all keys from DB", err))?
                .iter()
                .map(|row| Self::Key::from_bytea(row.get::<_, Vec<u8>>(0)))
                .collect::<Vec<_>>().into_iter().next())
        }
    }

    /// Retrieve all the (key, payload) pairs valid at a given epoch
    fn fetch_all_pairs(
        db: DBPool,
        table: &str,
        epoch: IncrementalEpoch,
    ) -> impl Future<Output = Result<HashMap<Self::Key, V>, RyhopeError>> + std::marker::Send {
        async move {
            let connection = db.get().await.unwrap();
            Ok(connection
                .query(
                    &format!(
                        "SELECT {KEY}, {PAYLOAD} FROM {} WHERE {VALID_FROM} <= $1 AND $1 <= {VALID_UNTIL}",
                        table
                    ),
                    &[&epoch],
                )
                .await
                .map_err(|err| RyhopeError::from_db("while fetching all pairs from database", err))?
                .iter()
                .map(|row| (Self::Key::from_bytea(row.get::<_, Vec<u8>>(0)), row.get::<_, Json<V>>(1).0))
                .collect())
        }
    }

    /// Return the value associated to the given key at the given epoch.
    fn fetch_payload_at(
        db: DBPool,
        table: &str,
        k: &Self::Key,
        epoch: IncrementalEpoch,
    ) -> impl std::future::Future<Output = Result<Option<V>, RyhopeError>> + std::marker::Send {
        async move {
            let connection = db.get().await.unwrap();
            connection
            .query(
                &format!(
                    "SELECT {PAYLOAD} FROM {} WHERE {KEY}=$1 AND {VALID_FROM} <= $2 AND $2 <= {VALID_UNTIL}",
                    table
                ),
                &[&(k.to_bytea()), &epoch],
            )
                .await
                .map_err(|err| RyhopeError::from_db("fetching payload from DB", err))
            .and_then(|rows| match rows.len() {
                0 => Ok(None),
                1 => Ok(Some(rows[0].get::<_, Json<V>>(0).0)),
                _ => Err(RyhopeError::internal(format!("internal coherency error: {:?}", rows))),
            })
        }
    }

    /// Given a PgSQL row, extract a value from it.
    fn payload_from_row(row: &Row) -> Result<V, RyhopeError> {
        row.try_get::<_, Json<V>>(PAYLOAD)
            .map(|x| x.0)
            .map_err(|err| {
                RyhopeError::invalid_format(format!("parsing payload from {row:?}"), err)
            })
    }

    fn node_from_row(row: &Row) -> Self::Node;

    fn wide_lineage_between<S: TreeStorage<Self>>(
        &self,
        s: &S,
        db: DBPool,
        table: &str,
        keys_query: &str,
        bounds: (UserEpoch, UserEpoch), // we keep `UserEpoch` here because we need to do ranges
         // over epochs in this operation
    ) -> impl Future<Output = Result<WideLineage<Self::Key, V>, RyhopeError>>;

    /// Return the value associated to the given key at the given epoch.
    #[allow(clippy::type_complexity)]
    fn fetch_many_at<
        S: TreeStorage<Self>,
        I: IntoIterator<Item = (IncrementalEpoch, Self::Key)> + Send,
        T: EpochMapper,
    >(
        &self,
        s: &S,
        db: DBPool,
        table: &str,
        data: I,
        epoch_mapper: &RoSharedEpochMapper<T>,
    ) -> impl Future<Output = Result<Vec<(UserEpoch, NodeContext<Self::Key>, V)>, RyhopeError>> + Send;
}

/// Implementation of a [`DbConnector`] for a tree over `K` with empty nodes.
/// Only applies to the SBBST for now.
impl<const IS_EPOCH_TREE: bool, V> DbConnector<V> for sbbst::Tree<IS_EPOCH_TREE>
where
    V: Debug + Clone + Send + Sync + Serialize + for<'a> Deserialize<'a>,
{
    fn node_columns() -> &'static [(&'static str, &'static str)] {
        &[]
    }

    async fn fetch_node_at(
        db: DBPool,
        table: &str,
        k: &NodeIdx,
        epoch: IncrementalEpoch,
    ) -> Result<Option<()>, RyhopeError> {
        let connection = db.get().await.unwrap();
        connection
            .query(
                &format!(
                    "SELECT * FROM {} WHERE {KEY}=$1 AND {VALID_FROM}<=$2 AND $2<={VALID_UNTIL}",
                    table
                ),
                &[&k.to_bytea(), &epoch],
            )
            .await
            .map_err(|e| RyhopeError::from_db("while fetching node", e))
            .and_then(|rows| match rows.len() {
                0 => Ok(None),
                1 => Ok(Some(())),
                _ => Err(RyhopeError::internal("internal coherency error")),
            })
    }

    fn node_from_row(_r: &Row) {}

    async fn create_node_in_tx(
        db_tx: &tokio_postgres::Transaction<'_>,
        table: &str,
        k: &NodeIdx,
        birth_epoch: IncrementalEpoch,
        _n: &(),
    ) -> Result<(), RyhopeError> {
        db_tx
            .execute(
                &format!(
                    "INSERT INTO
                     {} ({KEY}, {VALID_FROM}, {VALID_UNTIL})
                     VALUES ($1, $2, $3)",
                    table
                ),
                &[&k.to_bytea(), &birth_epoch, &MAX_PGSQL_BIGINT],
            )
            .await
            .map_err(|err| RyhopeError::from_db("inserting new node row", err))
            .map(|_| ())
    }

    async fn wide_lineage_between<S: TreeStorage<Self>>(
        &self,
        s: &S,
        db: DBPool,
        table: &str,
        keys_query: &str,
        bounds: (UserEpoch, UserEpoch),
    ) -> Result<WideLineage<NodeIdx, V>, RyhopeError> {
        // Execute `keys_query` to retrieve the core keys from the DB
        let core_keys = db
            .get()
            .await
            .map_err(|err| RyhopeError::from_bb8("getting a connection", err))?
            .query(&keys_query.to_string(), &[])
            .await
            .map_err(|err| {
                RyhopeError::from_db(
                    format!("failed to execute `{}` on `{}`", keys_query, table),
                    err,
                )
            })?
            .iter()
            .map(|row| (row.get::<_, i64>(EPOCH), row.get::<_, i64>(KEY) as NodeIdx))
            .collect::<Vec<_>>();

        // The SBBST can compute all the wide lineage in closed form
        let ascendances = self
            .ascendance(core_keys.iter().map(|(_epoch, key)| key).cloned(), s)
            .await?;
        let mut touched_keys = HashSet::new();
        for n in ascendances.into_iter() {
            touched_keys.extend(self.descendance(s, &n, 2).await?);
        }

        // Fetch all the payloads for the wide lineage in one fell swoop
        let mapper_table_name = mapper_table_name(table);
        let payload_query = format!("
            SELECT 
                {KEY}, 
                generate_series(GREATEST({VALID_FROM}, min_epoch), LEAST({VALID_UNTIL}, max_epoch)) AS epoch,
                {PAYLOAD} 
            FROM {table} CROSS JOIN 
                (SELECT MIN({INCREMENTAL_EPOCH}) as min_epoch, MAX({INCREMENTAL_EPOCH}) as max_epoch 
                FROM {mapper_table_name} 
                WHERE {USER_EPOCH} >= $1 AND {USER_EPOCH} <= $2) as mapper_range 
            WHERE {VALID_FROM} <= mapper_range.max_epoch AND {VALID_UNTIL} >= mapper_range.min_epoch 
            AND {KEY} = ANY($3)
            ;
        ");
        let rows = db
            .get()
            .await
            .map_err(|err| RyhopeError::from_bb8("getting a connection", err))?
            .query(
                &payload_query,
                &[
                    &bounds.0,
                    &bounds.1,
                    &touched_keys
                        .into_iter()
                        .map(|x| x.to_bytea())
                        .collect::<Vec<_>>(),
                ],
            )
            .await
            .map_err(|err| RyhopeError::from_db("fetching payload for touched keys", err))?;

        // Assemble the final result
        #[allow(clippy::type_complexity)]
        let mut epoch_lineages: HashMap<
            UserEpoch,
            (HashMap<NodeIdx, NodeContext<NodeIdx>>, HashMap<NodeIdx, V>),
        > = HashMap::new();
        for row in &rows {
            let epoch = row.get::<_, i64>("epoch");
            // convert incremental epoch to user epoch
            let epoch = s
                .epoch_mapper()
                .try_to_user_epoch(epoch as IncrementalEpoch)
                .await
                .ok_or(anyhow!("Epoch correspong to inner epoch {epoch} not found"))?;
            let key = NodeIdx::from_bytea(row.get::<_, Vec<u8>>(KEY));

            let payload = Self::payload_from_row(row)?;
            let context = self.node_context(&key, s).await?.unwrap();

            let h_epoch = epoch_lineages.entry(epoch).or_default();
            h_epoch.0.insert(key, context);
            h_epoch.1.insert(key, payload);
        }

        Ok(WideLineage {
            core_keys,
            epoch_lineages,
        })
    }

    async fn fetch_many_at<
        S: TreeStorage<Self>,
        I: IntoIterator<Item = (IncrementalEpoch, Self::Key)> + Send,
        T: EpochMapper,
    >(
        &self,
        s: &S,
        db: DBPool,
        table: &str,
        data: I,
        epoch_mapper: &RoSharedEpochMapper<T>,
    ) -> Result<Vec<(UserEpoch, NodeContext<Self::Key>, V)>, RyhopeError> 
    {
        let connection = db.get().await.unwrap();
        let immediate_table = data
            .into_iter()
            .map(|(epoch, key)| {
                format!(
                    "({epoch}::BIGINT, '\\x{}'::BYTEA)",
                    hex::encode(key.to_bytea())
                )
            })
            .join(", ");

        let mut r = Vec::new();
        for row in connection
        .query(
            &dbg!(format!(
               "SELECT batch.key, batch.epoch, {table}.{PAYLOAD} FROM
                 (VALUES {}) AS batch (epoch, key)
                 LEFT JOIN {table} ON
                 batch.key = {table}.{KEY} AND {table}.{VALID_FROM} <= batch.epoch AND batch.epoch <= {table}.{VALID_UNTIL}",
               immediate_table
           )),
            &[],
        )
            .await
            .map_err(|err| RyhopeError::from_db("fetching payload from DB", err))?
            .iter() {
               let k = Self::Key::from_bytea(row.get::<_, Vec<u8>>(0));
               let epoch = row.get::<_, UserEpoch>(1);
               // convert internal incremental epoch to an arbitrary epoch
               let epoch = epoch_mapper.try_to_user_epoch(epoch as IncrementalEpoch)
                .await.ok_or(anyhow!("Epoch correspong to inner epoch {epoch} not found"))?;
                let v = row.get::<_, Option<Json<V>>>(2).map(|x| x.0);
                if let Some(v) = v {
                    r.push((epoch, self.node_context(&k, s).await?.unwrap() , v));
                }
            }
        Ok(r)
    }
}

/// Implementation of [`DbConnector`] for any valid key and a scapegoat tree
/// built upon it.
impl<K, V> DbConnector<V> for scapegoat::Tree<K>
where
    K: ToFromBytea
        + Send
        + Sync
        + Serialize
        + for<'a> Deserialize<'a>
        + Ord
        + std::hash::Hash
        + Debug,
    V: Serialize + for<'a> Deserialize<'a> + Clone + Send + Sync + Debug,
{
    fn node_columns() -> &'static [(&'static str, &'static str)] {
        &[
            (PARENT, "BYTEA"),
            (LEFT_CHILD, "BYTEA"),
            (RIGHT_CHILD, "BYTEA"),
            (SUBTREE_SIZE, "BIGINT"),
        ]
    }

    async fn fetch_node_at(
        db: DBPool,
        table: &str,
        k: &K,
        epoch: IncrementalEpoch,
    ) -> Result<Option<Self::Node>, RyhopeError> {
        let connection = db.get().await.unwrap();
        connection
            .query(
                &format!(
                    "SELECT {PARENT}, {LEFT_CHILD}, {RIGHT_CHILD}, {SUBTREE_SIZE} FROM {}
                       WHERE {KEY}=$1 AND {VALID_FROM} <= $2 AND $2 <= {VALID_UNTIL}",
                    table
                ),
                &[&k.to_bytea(), &epoch],
            )
            .await
            .map_err(|err| RyhopeError::from_db("fetching node", err))
            .and_then(|rows| match rows.len() {
                0 => Ok(None),
                1 => {
                    let r = &rows[0];
                    Ok(Some(scapegoat::Node {
                        k: k.to_owned(),
                        parent: r.get::<_, Option<Vec<u8>>>(0).map(|p| K::from_bytea(p)),
                        left: r.get::<_, Option<Vec<u8>>>(1).map(|p| K::from_bytea(p)),
                        right: r.get::<_, Option<Vec<u8>>>(2).map(|p| K::from_bytea(p)),
                        subtree_size: r.get::<_, i64>(3) as usize,
                    }))
                }
                _ => Err(RyhopeError::fatal("internal coherency error")),
            })
    }

    fn node_from_row(row: &Row) -> Self::Node {
        Self::Node {
            k: K::from_bytea(row.get::<_, Vec<u8>>(KEY)),
            subtree_size: row.get::<_, i64>(SUBTREE_SIZE).try_into().unwrap(),
            parent: row.get::<_, Option<Vec<u8>>>(PARENT).map(K::from_bytea),
            left: row.get::<_, Option<Vec<u8>>>(LEFT_CHILD).map(K::from_bytea),
            right: row
                .get::<_, Option<Vec<u8>>>(RIGHT_CHILD)
                .map(K::from_bytea),
        }
    }

    async fn create_node_in_tx(
        db_tx: &tokio_postgres::Transaction<'_>,
        table: &str,
        k: &K,
        birth_epoch: IncrementalEpoch,
        n: &Self::Node,
    ) -> Result<(), RyhopeError> {
        db_tx
            .execute(
                &format!(
                    "INSERT INTO
                     {} ({KEY}, {VALID_FROM}, {VALID_UNTIL}, {SUBTREE_SIZE}, {PARENT}, {LEFT_CHILD}, {RIGHT_CHILD})
                     VALUES ($1, $2, $3, $4, $5, $6, $7)",
                    table
                ),
                &[
                    &k.to_bytea(),
                    &birth_epoch,
                    &MAX_PGSQL_BIGINT,
                    &(n.subtree_size as i64),
                    &n.parent.as_ref().map(ToFromBytea::to_bytea),
                    &n.left.as_ref().map(ToFromBytea::to_bytea),
                    &n.right.as_ref().map(ToFromBytea::to_bytea),
                ],
            )
            .await
            .map_err(|err| RyhopeError::from_db("inserting new node row", err))
            .map(|_| ())
    }

    async fn wide_lineage_between<S: TreeStorage<Self>>(
        &self,
        s: &S,
        db: DBPool,
        table: &str,
        keys_query: &str,
        bounds: (UserEpoch, UserEpoch),
    ) -> Result<WideLineage<K, V>, RyhopeError> {
        ensure(
            !keys_query.contains('$'),
            "unexpected placeholder found in keys_query",
        )?;

        // Call the mega-query doing everything
        let query = format!(
            include_str!("wide_lineage.sql"),
            KEY = KEY,
            EPOCH = EPOCH,
            PAYLOAD = PAYLOAD,
            VALID_FROM = VALID_FROM,
            VALID_UNTIL = VALID_UNTIL,
            PARENT = PARENT,
            LEFT_CHILD = LEFT_CHILD,
            RIGHT_CHILD = RIGHT_CHILD,
            SUBTREE_SIZE = SUBTREE_SIZE,
            INCREMENTAL_EPOCH = INCREMENTAL_EPOCH,
            USER_EPOCH = USER_EPOCH,
            max_depth = 2,
            zk_table = table,
            mapper_table_name = mapper_table_name(table),
            core_keys_query = keys_query,
        );
        let connection = db.get().await.unwrap();
        let rows = connection
            .query(&query, &[&bounds.0, &bounds.1])
            .await
            .map_err(|err| {
                RyhopeError::from_db(
                    format!(
                        "while fetching wide lineage for {table} [[{}, {}]] with: {query}",
                        bounds.0, bounds.1
                    ),
                    err,
                )
            })?;

        // Assemble the final result
        let mut core_keys = Vec::new();
        #[allow(clippy::type_complexity)]
        let mut epoch_lineages: HashMap<
            UserEpoch,
            (HashMap<K, NodeContext<K>>, HashMap<K, V>),
        > = HashMap::new();

        for row in &rows {
            let is_core = row.try_get::<_, i32>("is_core").map_err(|err| {
                RyhopeError::invalid_format(format!("fetching `is_core` flag from {row:?}"), err)
            })? > 0;
            let epoch = row.try_get::<_, i64>(EPOCH).map_err(|err| {
                RyhopeError::invalid_format(format!("fetching `epoch` from {row:?}"), err)
            })?;
            // convert incremental epoch to user epoch
            let epoch = s
                .epoch_mapper()
                .try_to_user_epoch(epoch as IncrementalEpoch)
                .await
                .ok_or(anyhow!("Epoch correspong to inner epoch {epoch} not found"))?;
            let node = <Self as DbConnector<V>>::node_from_row(row);
            let payload = Self::payload_from_row(row)?;
            if is_core {
                core_keys.push((epoch, node.k.clone()));
            }

            let h_epoch = epoch_lineages.entry(epoch).or_default();
            h_epoch.0.insert(
                node.k.clone(),
                NodeContext {
                    node_id: node.k.clone(),
                    parent: node.parent.clone(),
                    left: node.left.clone(),
                    right: node.right.clone(),
                },
            );
            h_epoch.1.insert(node.k, payload);
        }

        Ok(WideLineage {
            core_keys,
            epoch_lineages,
        })
    }

    async fn fetch_many_at<
        S: TreeStorage<Self>,
        I: IntoIterator<Item = (IncrementalEpoch, Self::Key)> + Send,
        T: EpochMapper,
    >(
        &self,
        _s: &S,
        db: DBPool,
        table: &str,
        data: I,
        epoch_mapper: &RoSharedEpochMapper<T>,
    ) -> Result<Vec<(UserEpoch, NodeContext<Self::Key>, V)>, RyhopeError> 
    {
        let connection = db.get().await.unwrap();
        let immediate_table = data
            .into_iter()
            .map(|(epoch, key)| {
                format!(
                    "({epoch}::BIGINT, '\\x{}'::BYTEA)",
                    hex::encode(key.to_bytea())
                )
            })
            .join(", ");

        let mut r = Vec::new();
        for row in connection
            .query(
                 &format!(
                     "SELECT
                        batch.key, batch.epoch, {table}.{PAYLOAD},
                        {table}.{PARENT}, {table}.{LEFT_CHILD}, {table}.{RIGHT_CHILD}
                      FROM
                        (VALUES {}) AS batch (epoch, key)
                      LEFT JOIN {table} ON
                        batch.key = {table}.{KEY} AND {table}.{VALID_FROM} <= batch.epoch AND batch.epoch <= {table}.{VALID_UNTIL}",
                    immediate_table
                ),
                &[],
            )
            .await
            .map_err(|err| RyhopeError::from_db("fetching payload from DB", err))?
            .iter()
        {
            let k = Self::Key::from_bytea(row.get::<_, Vec<u8>>(0));
            let epoch = row.get::<_, UserEpoch>(1);
            // convert internal incremental epoch to a user epoch
            let epoch = epoch_mapper.try_to_user_epoch(epoch as IncrementalEpoch)
                .await.ok_or(anyhow!("Epoch correspong to inner epoch {epoch} not found"))?; 
            let v = row.get::<_, Option<Json<V>>>(2).map(|x| x.0);
            if let Some(v) = v {
                r.push((
                    epoch,
                    NodeContext {
                        node_id: k,
                        parent: row.get::<_, Option<Vec<u8>>>(3).map(K::from_bytea),
                        left: row.get::<_, Option<Vec<u8>>>(4).map(K::from_bytea),
                        right: row.get::<_, Option<Vec<u8>>>(5).map(K::from_bytea),
                    },
                    v,
                ));
            }
        }
        Ok(r)
    }
}

/// Stores the chronological evolution of a single value in a CoW manner.
pub struct CachedDbStore<V: Debug + Clone + Send + Sync + Serialize + for<'a> Deserialize<'a>> {
    /// A pointer to the DB client
    db: DBPool,
    /// Whether a transaction is in process
    in_tx: bool,
    /// True if the wrapped state has been modified
    dirty: bool,
    /// The current epoch
    epoch: IncrementalEpoch,
    /// The table in which the data must be persisted
    table: String,
    // epoch mapper
    epoch_mapper: RoSharedEpochMapper<EpochMapperStorage>,
    pub(super) cache: RwLock<Option<V>>,
}
impl<T: Debug + Clone + Send + Sync + Serialize + for<'a> Deserialize<'a>> CachedDbStore<T> {
    pub fn new(
        current_epoch: UserEpoch,
        table: String,
        db: DBPool,
        mapper: RoSharedEpochMapper<EpochMapperStorage>,
    ) -> Self {
        Self {
            db,
            in_tx: false,
            dirty: false,
            epoch: current_epoch,
            table,
            epoch_mapper: mapper,
            cache: RwLock::new(None),
        }
    }

    /// Initialize a new store, with the given state. The initial state is
    /// immediately persisted, as the DB representation of the payload must be
    /// valid even if it is never modified further by the user.
    pub async fn with_value(table: String, db: DBPool, t: T, mapper: RoSharedEpochMapper<EpochMapperStorage>) -> Result<Self, RyhopeError> {
        let initial_epoch = INITIAL_INCREMENTAL_EPOCH;
        {
            let connection = db.get().await.unwrap();
            connection
                .query(
                    &format!(
                        "INSERT INTO {}_meta ({VALID_FROM}, {VALID_UNTIL}, {PAYLOAD})
                        VALUES ($1, $1, $2)",
                        table
                    ),
                    &[&initial_epoch, &Json(t.clone())],
                )
                .await
                .map_err(|err| {
                    RyhopeError::from_db(format!("initializing new store in `{}`", table), err)
                })?;
        }

        Ok(Self {
            db,
            in_tx: false,
            dirty: true,
            epoch: initial_epoch,
            table,
            epoch_mapper: mapper,
            cache: RwLock::new(Some(t)),
        })
    }

    async fn commit_in_transaction(
        &mut self,
        db_tx: &mut Transaction<'_>,
    ) -> Result<(), RyhopeError> {
        ensure(self.in_tx, "not in a transaction")?;
        trace!("[{self}] commiting in transaction");

        if self.dirty {
            let state = self.cache.read().await.clone();
            db_tx
                .query(
                    &format!(
                        "INSERT INTO {}_meta ({VALID_FROM}, {VALID_UNTIL}, {PAYLOAD})
                     VALUES ($1, $1, $2)",
                        self.table
                    ),
                    &[&(self.epoch + 1), &Json(state)],
                )
                .await
                .map_err(|err| {
                    RyhopeError::from_db(format!("updating {}_meta", self.table), err)
                })?;
        } else {
            db_tx
                .query(
                    &format!(
                        "UPDATE {}_meta SET {VALID_UNTIL} = $1 + 1 WHERE {VALID_UNTIL} = $1",
                        self.table
                    ),
                    &[&(self.epoch)],
                )
                .await
                .map_err(|err| {
                    RyhopeError::from_db(format!("updating {}_meta", self.table), err)
                })?;
        }

        Ok(())
    }

    fn on_commit_success(&mut self) {
        trace!("[{self}] commit successful");
        assert!(self.in_tx);
        self.epoch += 1;
        self.dirty = false;
        self.in_tx = false;
    }

    fn on_commit_failed(&mut self) {
        trace!("[{self}] commit failed");
        assert!(self.in_tx);
        let _ = self.cache.get_mut().take();
        self.dirty = false;
        self.in_tx = false;
    }

    async fn fetch_at_inner(&self, epoch: IncrementalEpoch) -> T {
        trace!("[{self}] fetching payload at {}", epoch);
        let connection = self.db.get().await.unwrap();
        connection
            .query_one(
                &format!(
                    "SELECT {PAYLOAD} FROM {}_meta WHERE {VALID_FROM} <= $1 AND $1 <= {VALID_UNTIL}",
                    self.table,
                ),
                &[&epoch],
            )
            .await
            .and_then(|row| row.try_get::<_, Json<T>>(0))
            .map(|x| x.0)
            .with_context(|| {
                anyhow!(
                    "failed to fetch state from `{}_meta` at epoch `{}`",
                    self.table,
                    epoch
                )
            }).unwrap()
    }

    async fn rollback_to_incremental_epoch(&mut self, new_epoch: IncrementalEpoch) -> Result<()> {
        ensure!(
            new_epoch < self.epoch,
            "unable to rollback into the future: requested epoch ({}) > current epoch ({})",
            new_epoch,
            self.epoch
        );
        ensure!(
            new_epoch >= INITIAL_INCREMENTAL_EPOCH,
            "unable to rollback to {} before initial epoch {}",
            new_epoch,
            INITIAL_INCREMENTAL_EPOCH
        );

        let _ = self.cache.get_mut().take();
        let mut connection = self.db.get().await.unwrap();
        let db_tx = connection
            .transaction()
            .await
            .expect("unable to create DB transaction");
        // Roll back all the nodes that would still have been alive
        db_tx
            .query(
                &format!(
                    "UPDATE {}_meta SET {VALID_UNTIL} = $1 WHERE {VALID_UNTIL} > $1",
                    self.table
                ),
                &[&new_epoch],
            )
            .await?;
        // Delete nodes that would not have been born yet
        db_tx
            .query(
                &format!("DELETE FROM {}_meta WHERE {VALID_FROM} > $1", self.table),
                &[&new_epoch],
            )
            .await?;
        db_tx.commit().await?;
        self.epoch = new_epoch;

        Ok(())
    }
}

impl<T> TransactionalStorage for CachedDbStore<T>
where
    T: Debug + Clone + Serialize + for<'a> Deserialize<'a> + Send + Sync,
{
    async fn start_transaction(&mut self) -> Result<(), RyhopeError> {
        trace!("[{self}] starting transaction");
        if self.in_tx {
            return Err(RyhopeError::AlreadyInTransaction);
        }

        self.in_tx = true;
        Ok(())
    }

    async fn commit_transaction(&mut self) -> Result<(), RyhopeError> {
        trace!("[{self}] committing transaction");
        if !self.in_tx {
            return Err(RyhopeError::NotInATransaction);
        }

        let pool = self.db.clone();
        let mut connection = pool.get().await.unwrap();
        let mut db_tx = connection
            .transaction()
            .await
            .expect("unable to create DB transaction");
        self.commit_in_transaction(&mut db_tx).await?;
        let err = db_tx.commit().await;
        if err.is_ok() {
            self.on_commit_success()
        } else {
            self.on_commit_failed()
        };
        err.map_err(|err| RyhopeError::from_db("commiting transaction", err))
    }
}

impl<T> std::fmt::Display for CachedDbStore<T>
where
    T: Debug + Clone + Serialize + for<'a> Deserialize<'a> + Send + Sync,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "CachedDbStore {}@{}", self.table, self.epoch)
    }
}

impl<T> SqlTransactionStorage for CachedDbStore<T>
where
    T: Debug + Clone + Serialize + for<'a> Deserialize<'a> + Send + Sync,
{
    async fn commit_in(
        &mut self,
        tx: &mut tokio_postgres::Transaction<'_>,
    ) -> Result<(), RyhopeError> {
        trace!("[{self}] commit_in");
        self.commit_in_transaction(tx).await
    }

    async fn commit_success(&mut self) {
        trace!("[{self}] commit_success");
        self.on_commit_success()
    }

    async fn commit_failed(&mut self) {
        trace!("[{self}] commit_failed");
        self.on_commit_failed()
    }
}

impl<T> EpochStorage<T> for CachedDbStore<T>
where
    T: Debug + Clone + Sync + Serialize + for<'a> Deserialize<'a> + Send,
{
    async fn fetch(&self) -> Result<T, RyhopeError> {
        trace!("[{self}] fetching payload");
        if self.cache.read().await.is_none() {
            let state = self.fetch_at_inner(self.epoch).await;
            let _ = self.cache.write().await.replace(state.clone());
            Ok(state)
        } else {
            Ok(self.cache.read().await.clone().unwrap())
        }
    }

    async fn fetch_at(&self, epoch: UserEpoch) -> T {
        let epoch = self.epoch_mapper.to_incremental_epoch(epoch).await;
        self.fetch_at_inner(epoch).await
    }

    async fn store(&mut self, t: T) -> Result<(), RyhopeError> {
        trace!("[{self}] storing {t:?}");
        self.dirty = true;
        let _ = self.cache.write().await.insert(t);
        Ok(())
    }

    async fn current_epoch(&self) -> Result<UserEpoch> {
        self.epoch_mapper
            .try_to_user_epoch(self.epoch)
            .await
            .ok_or(CurrenEpochUndefined(self.epoch).into())
    }

    async fn rollback_to(&mut self, new_epoch: UserEpoch) -> Result<(), RyhopeError> {
        let inner_epoch = self.epoch_mapper.try_to_incremental_epoch(new_epoch).await
            .ok_or(anyhow!("IncrementalEpoch not found for epoch {new_epoch}"))?;
        self.rollback_to_incremental_epoch(inner_epoch).await
    }

    async fn rollback(&mut self) -> Result<(), RyhopeError> {
        ensure!(self.epoch > INITIAL_INCREMENTAL_EPOCH, "cannot rollback before initial epoch");
        self.rollback_to_incremental_epoch(self.epoch - 1).await
    }
}

/// A `CachedDbStore` keeps a cache of all the storage operations that occured
/// during the current transaction, while falling back to the given database
/// when referring to older epochs.
pub struct CachedDbTreeStore<T, V>
where
    T: TreeTopology + DbConnector<V>,
    T::Key: ToFromBytea,
    V: Debug + Clone + Send + Sync + Serialize + for<'a> Deserialize<'a>,
{
    /// The latest *commited* epoch
    epoch: UserEpoch,
    /// A pointer to the DB client
    db: DBPool,
    /// DB backing this cache
    table: String,
    // Epoch mapper
    epoch_mapper: RoSharedEpochMapper<EpochMapperStorage>,
    /// Operations pertaining to the in-process transaction.
    pub(super) nodes_cache: HashMap<T::Key, Option<CachedValue<T::Node>>>,
    pub(super) payload_cache: HashMap<T::Key, Option<CachedValue<V>>>,
    _p: PhantomData<T>,
}
impl<T, V> std::fmt::Display for CachedDbTreeStore<T, V>
where
    T: TreeTopology + DbConnector<V>,
    T::Key: ToFromBytea,
    V: Debug + Clone + Send + Sync + Serialize + for<'a> Deserialize<'a>,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "TreeStore {}@{}", self.table, self.epoch)
    }
}
impl<T, V> CachedDbTreeStore<T, V>
where
    T: TreeTopology + DbConnector<V>,
    T::Key: ToFromBytea,
    V: Debug + Clone + Send + Sync + Serialize + for<'a> Deserialize<'a>,
{
    pub fn new(
        current_epoch: IncrementalEpoch,
        table: String,
        db: DBPool,
        mapper: RoSharedEpochMapper<EpochMapperStorage>,
    ) -> Self {
        trace!("[{}] initializing CachedDbTreeStore", table);
        CachedDbTreeStore {
            epoch: current_epoch,
            table,
            db: db.clone(),
            epoch_mapper: mapper,
            nodes_cache: Default::default(),
            payload_cache: Default::default(),
            _p: PhantomData,
        }
    }

    pub fn clear(&mut self) {
        self.nodes_cache.clear();
        self.payload_cache.clear();
    }

    pub(crate) fn new_epoch(&mut self) {
        self.clear();
        self.epoch += 1;
    }

    pub(crate) fn current_epoch(&self) -> IncrementalEpoch {
        self.epoch
    }

    async fn size(&self) -> usize {
        self.size_at(self.current_epoch()).await
    }

    async fn size_at(&self, epoch: IncrementalEpoch) -> usize {
        let connection = self.db.get().await.unwrap();
        connection
            .query_one(
                &format!(
                    "SELECT COUNT(*) FROM {} WHERE {VALID_FROM} <= $1 AND $1 <= {VALID_UNTIL}",
                    self.table
                ),
                &[&epoch],
            )
            .await
            .map(|row| row.get::<_, i64>(0))
            .map_err(|err| RyhopeError::from_db("counting rows", err))
            .unwrap()
            .try_into()
            .unwrap()
    }

    pub(super) async fn rollback_to(&mut self, new_epoch: IncrementalEpoch) -> Result<(), RyhopeError> {
        trace!("[{self}] rolling back to {new_epoch}");
        ensure(
            new_epoch >= INITIAL_INCREMENTAL_EPOCH,
            format!(
                "unable to rollback to {} before initial epoch {}",
                new_epoch, INITIAL_INCREMENTAL_EPOCH
            ),
        )?;
        ensure(
            new_epoch < self.current_epoch(),
            format!(
                "unable to rollback into the future: requested epoch ({}) > current epoch ({})",
                new_epoch,
                self.current_epoch()
            ),
        )?;

        self.nodes_cache.clear();
        self.payload_cache.clear();
        let mut connection = self.db.get().await.unwrap();
        let db_tx = connection
            .transaction()
            .await
            .expect("unable to create DB transaction");
        // Roll back all the nodes that would still have been alive
        db_tx
            .query(
                &format!(
                    "UPDATE {} SET {VALID_UNTIL} = $1 WHERE {VALID_UNTIL} > $1",
                    self.table
                ),
                &[&new_epoch],
            )
            .await
            .map_err(|err| RyhopeError::from_db(format!("time-stamping {}", self.table), err))?;

        // Delete nodes that would not have been born yet
        db_tx
            .query(
                &format!("DELETE FROM {} WHERE {VALID_FROM} > $1", self.table),
                &[&new_epoch],
            )
            .await
            .map_err(|err| RyhopeError::from_db(format!("reaping `{}`", self.table), err))?;

        db_tx
            .commit()
            .await
            .map_err(|err| RyhopeError::from_db("committing transaction", err))?;
        self.epoch = new_epoch;

        Ok(())
    }
}

/// A wrapper around a [`CachedDbTreeStore`] to make it appear as a KV store for
/// nodes. This is an artifice made necessary by the impossibility to implement
/// two different specializations of the same trait for the same type; otherwise
/// [`RoEpochKvStorage`] and [`EpochKvStorage`] could be directly implemented
/// for [`CachedDbTreeStore`] for both `<T::Key, T::Node>` and `<T::Key, V>`.
pub struct NodeProjection<T, V>
where
    T: TreeTopology + DbConnector<V>,
    T::Key: ToFromBytea,
    V: Debug + Clone + Send + Sync + Serialize + for<'a> Deserialize<'a>,
{
    pub(super) wrapped: Arc<RwLock<CachedDbTreeStore<T, V>>>,
}
impl<T, V> std::fmt::Display for NodeProjection<T, V>
where
    T: TreeTopology + DbConnector<V>,
    T::Key: ToFromBytea,
    V: PayloadInDb,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/Nodes", self.wrapped.as_ref().blocking_read())
    }
}

impl<T, V> NodeProjection<T, V>
where
    T: TreeTopology + DbConnector<V>,
    T::Key: ToFromBytea,
    V: Debug + Clone + Send + Sync + Serialize + for<'a> Deserialize<'a>,
{
    async fn try_fetch_at_incremental_epoch(
        &self,
        k: &T::Key,
        epoch: IncrementalEpoch,
    ) -> Result<Option<T::Node>, RyhopeError> {
        let db = self.wrapped.read().await.db.clone();
        let table = self.wrapped.read().await.table.to_owned();
        if epoch == self.wrapped.read().await.current_epoch() {
            // Directly returns the value if it is already in cache, fetch it from
            // the DB otherwise.
            let value = self.wrapped.read().await.nodes_cache.get(k).cloned();
            if let Some(Some(cached_value)) = value {
                Some(cached_value.into_value())
            } else if let Some(value) = T::fetch_node_at(db, &table, k, epoch).await.unwrap() {
                self.wrapped
                    .write()
                    .await
                    .nodes_cache
                    .insert(k.clone(), Some(CachedValue::Read(value.clone())));
                Some(value)
            } else {
                None
            }
        } else {
            T::fetch_node_at(db, &table, k, epoch).await.unwrap()
        }
    }
}

impl<T, V> RoEpochKvStorage<T::Key, T::Node> for NodeProjection<T, V>
where
    T: TreeTopology + DbConnector<V>,
    T::Key: ToFromBytea,
    V: PayloadInDb,
{
    async fn initial_epoch(&self) -> UserEpoch {
        self.wrapped
            .read()
            .await
            .epoch_mapper
            .to_user_epoch(INITIAL_INCREMENTAL_EPOCH)
            .await as UserEpoch
    }

    async fn current_epoch(&self) -> Result<UserEpoch> {
        let inner_epoch = self.wrapped.read().await.current_epoch();
        self.wrapped
            .read()
            .await
            .epoch_mapper
            .try_to_user_epoch(inner_epoch)
            .await
            .ok_or(CurrenEpochUndefined(inner_epoch).into())
    }

    async fn size(&self) -> usize {
        self.wrapped.read().await.size().await
    }

    async fn size_at(&self, epoch: UserEpoch) -> usize {
        let inner_epoch = self
            .wrapped
            .read()
            .await
            .epoch_mapper
            .to_incremental_epoch(epoch)
            .await as UserEpoch;
        self.wrapped.read().await.size_at(inner_epoch).await
    }

    async fn try_fetch_at(&self, k: &T::Key, epoch: UserEpoch) -> Option<T::Node> {
        trace!("[{self}] fetching {k:?}@{epoch}",);
        let inner_epoch = self
            .wrapped
            .read()
            .await
            .epoch_mapper
            .try_to_incremental_epoch(epoch)
            .await;
        if let Some(epoch) = inner_epoch {
            self.try_fetch_at_incremental_epoch(k, epoch).await
        } else {
            None
        }
    }

    async fn keys_at(&self, epoch: UserEpoch) -> Vec<T::Key> {
        let db = self.wrapped.read().await.db.clone();
        let table = self.wrapped.read().await.table.to_owned();

        let inner_epoch = self
            .wrapped
            .read()
            .await
            .epoch_mapper
            .to_incremental_epoch(epoch)
            .await;

        T::fetch_all_keys(db, &table, inner_epoch).await.unwrap()
    }

    async fn random_key_at(&self, epoch: UserEpoch) -> Option<T::Key> {
        let db = self.wrapped.read().await.db.clone();
        let table = self.wrapped.read().await.table.to_owned();

        let inner_epoch = self
            .wrapped
            .read()
            .await
            .epoch_mapper
            .to_incremental_epoch(epoch)
            .await;

        T::fetch_a_key(db, &table, inner_epoch).await.unwrap()
    }

    async fn pairs_at(&self, _epoch: UserEpoch) -> Result<HashMap<T::Key, T::Node>, RyhopeError> {
        unimplemented!("should never be used");
    }

    async fn try_fetch(&self, k: &T::Key) -> Result<Option<T::Node>, RyhopeError> {
        let current_epoch = self.wrapped.read().await.current_epoch();
        self.try_fetch_at_incremental_epoch(k, current_epoch).await
    }

    async fn contains(&self, k: &T::Key) -> Result<bool, RyhopeError> {
        self.try_fetch(k).await.map(|x| x.is_some())
    }

    async fn contains_at(&self, k: &T::Key, epoch: UserEpoch) -> Result<bool, RyhopeError> {
        self.try_fetch_at(k, epoch).await.map(|x| x.is_some())
    }
}
impl<T, V> EpochKvStorage<T::Key, T::Node> for NodeProjection<T, V>
where
    T: TreeTopology + DbConnector<V>,
    T::Key: ToFromBytea,
    T::Node: Sync + Clone,
    V: PayloadInDb,
{
    async fn remove(&mut self, k: T::Key) -> Result<(), RyhopeError> {
        trace!("[{self}] removing {k:?} from cache",);
        self.wrapped.write().await.nodes_cache.insert(k, None);
        Ok(())
    }

    fn update(&mut self, k: T::Key, new_value: T::Node) -> impl Future<Output = Result<(), RyhopeError>> + Send {
        trace!("[{self}] updating cache {k:?} -> {new_value:?}");
        // If the operation is already present from a read, replace it with the
        // new value.
        self.wrapped
            .write()
            .await
            .nodes_cache
            .insert(k, Some(CachedValue::Written(new_value)));
        Ok(())
    }

    async fn store(
        &mut self,
        k: T::Key,
        value: T::Node,
    ) -> Result<(), RyhopeError> {
        trace!("[{self}] storing {k:?} -> {value:?} in cache");
        // If the operation is already present from a read, replace it with the
        // new value.
        self.wrapped
            .write()
            .await
            .nodes_cache
            .insert(k, Some(CachedValue::Written(value)));
        Ok(())
    }

    async fn update_with<F: Fn(&mut T::Node) + Send + Sync>(
        &mut self,
        k: T::Key,
        updater: F,
    ) -> Result<(), RyhopeError>
    where
        Self: Sync + Send,
    {
        if let Some(mut v) = self.try_fetch(&k).await? {
            updater(&mut v);
            self.update(k, v).await
        } else {
            Ok(())
        }
    }

    async fn rollback_to(&mut self, epoch: UserEpoch) -> Result<()> {
        let inner_epoch = self
            .wrapped
            .read()
            .await
            .epoch_mapper
            .to_incremental_epoch(epoch)
            .await;
        self.wrapped.write().await.rollback_to(inner_epoch).await
    }

    async fn rollback(&mut self) -> Result<()> {
        let inner_epoch = self.wrapped.read().await.current_epoch();
        ensure!(inner_epoch > 0, "cannot rollback past the initial epoch");
        self.wrapped.write().await.rollback_to(inner_epoch).await
    }
}

/// A wrapper around a [`CachedDbTreeStore`] to make it appear as a KV store for
/// node payloads. This is an artifice made necessary by the impossibility to
/// implement two different specializations of the same trait for the same type;
/// otherwise [`RoEpochKvStorage`] and [`EpochKvStorage`] could be directly
/// implemented for [`CachedDbTreeStore`] for both `<T::Key, T::Node>` and
/// `<T::Key, V>`.
pub struct PayloadProjection<T, V>
where
    T: TreeTopology + DbConnector<V>,
    T::Key: ToFromBytea,
    V: Debug + Clone + Send + Sync + Serialize + for<'a> Deserialize<'a>,
{
    pub(super) wrapped: Arc<RwLock<CachedDbTreeStore<T, V>>>,
}
impl<T, V> std::fmt::Display for PayloadProjection<T, V>
where
    T: TreeTopology + DbConnector<V>,
    T::Key: ToFromBytea,
    V: PayloadInDb,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/Payload", self.wrapped.blocking_read())
    }
}

impl<T, V> PayloadProjection<T, V>
where
    T: TreeTopology + DbConnector<V>,
    T::Key: ToFromBytea,
    V: PayloadInDb,
{
    async fn try_fetch_at_incremental_epoch(
        &self,
        k: &T::Key,
        epoch: IncrementalEpoch,
    ) -> Option<V> {
        let db = self.wrapped.read().await.db.clone();
        let table = self.wrapped.read().await.table.to_owned();
        if epoch == self.wrapped.read().await.current_epoch() {
            // Directly returns the value if it is already in cache, fetch it from
            // the DB otherwise.
            let value = self.wrapped.read().await.payload_cache.get(k).cloned();
            if let Some(Some(cached_value)) = value {
                Some(cached_value.into_value())
            } else if let Some(value) = T::fetch_payload_at(db, &table, k, epoch).await.unwrap() {
                self.wrapped
                    .write()
                    .await
                    .payload_cache
                    .insert(k.clone(), Some(CachedValue::Read(value.clone())));
                Some(value)
            } else {
                None
            }
        } else {
            T::fetch_payload_at(db, &table, k, epoch).await.unwrap()
        }
    }
}

impl<T, V> RoEpochKvStorage<T::Key, V> for PayloadProjection<T, V>
where
    T: TreeTopology + DbConnector<V>,
    T::Key: ToFromBytea,
    V: PayloadInDb,
{
    async fn initial_epoch(&self) -> UserEpoch {
        self.wrapped
            .read()
            .await
            .epoch_mapper
            .to_user_epoch(INITIAL_INCREMENTAL_EPOCH)
            .await as UserEpoch
    }

    async fn current_epoch(&self) -> Result<UserEpoch> {
        let inner_epoch = self.wrapped.read().await.current_epoch();
        self.wrapped
            .read()
            .await
            .epoch_mapper
            .try_to_user_epoch(inner_epoch as IncrementalEpoch)
            .await
            .ok_or(CurrenEpochUndefined(inner_epoch).into())
    }

    async fn size(&self) -> usize {
        self.wrapped.read().await.size().await
    }

    async fn size_at(&self, epoch: UserEpoch) -> usize {
        let inner_epoch = self
            .wrapped
            .read()
            .await
            .epoch_mapper
            .to_incremental_epoch(epoch)
            .await as UserEpoch;
        self.wrapped.read().await.size_at(inner_epoch).await
    }

    async fn try_fetch_at(&self, k: &T::Key, epoch: UserEpoch) -> Option<V> {
        trace!("[{self}] attempting to fetch payload for {k:?}@{epoch}");
        let inner_epoch = self
            .wrapped
            .read()
            .await
            .epoch_mapper
            .try_to_incremental_epoch(epoch)
            .await;
        if let Some(epoch) = inner_epoch {
            self.try_fetch_at_incremental_epoch(k, epoch).await
        } else {
            None
        }
    }

    async fn try_fetch(&self, k: &T::Key) -> Option<V> {
        let current_epoch = self.wrapped.read().await.current_epoch();
        self.try_fetch_at_incremental_epoch(k, current_epoch).await
    }

    async fn keys_at(&self, epoch: UserEpoch) -> Vec<T::Key> {
        let db = self.wrapped.read().await.db.clone();
        let table = self.wrapped.read().await.table.to_owned();

        let inner_epoch = self
            .wrapped
            .read()
            .await
            .epoch_mapper
            .to_incremental_epoch(epoch)
            .await;

        T::fetch_all_keys(db, &table, inner_epoch).await.unwrap()
    }

    async fn random_key_at(&self, epoch: UserEpoch) -> Option<T::Key> {
        let db = self.wrapped.read().await.db.clone();
        let table = self.wrapped.read().await.table.to_owned();
        let inner_epoch = self
            .wrapped
            .read()
            .await
            .epoch_mapper
            .to_incremental_epoch(epoch)
            .await;

        T::fetch_a_key(db, &table, inner_epoch).await.unwrap()
    }

    async fn pairs_at(&self, epoch: UserEpoch) -> Result<HashMap<T::Key, V>, RyhopeError> {
        let db = self.wrapped.read().await.db.clone();
        let table = self.wrapped.read().await.table.to_owned();
        let inner_epoch = self
            .wrapped
            .read()
            .await
            .epoch_mapper
            .to_incremental_epoch(epoch)
            .await;

        T::fetch_all_pairs(db, &table, inner_epoch).await
    }
}
impl<T, V> EpochKvStorage<T::Key, V> for PayloadProjection<T, V>
where
    T: TreeTopology + DbConnector<V>,
    T::Key: ToFromBytea,
    T::Node: Sync + Clone,
    V: PayloadInDb,
{
    async fn remove(&mut self, k: T::Key) -> Result<(), RyhopeError> {
        trace!("[{self}] removing {k:?} from cache");
        self.wrapped.write().await.nodes_cache.insert(k, None);
        Ok(())
    }

    fn update(&mut self, k: T::Key, new_value: V) -> impl Future<Output = Result<(), RyhopeError>> + Send {
        trace!("[{self}] updating cache {k:?} -> {new_value:?}");
        // If the operation is already present from a read, replace it with the
        // new value.
        self.wrapped
            .write()
            .await
            .payload_cache
            .insert(k, Some(CachedValue::Written(new_value)));
        Ok(())
    }

    async fn store(
        &mut self,
        k: T::Key,
        value: V,
    ) -> Result<(), RyhopeError> {
        trace!("[{self}] storing {k:?} -> {value:?} in cache",);
        // If the operation is already present from a read, replace it with the
        // new value.
        self.wrapped
            .write()
            .await
            .payload_cache
            .insert(k, Some(CachedValue::Written(value)));
        Ok(())
    }

    async fn rollback_to(&mut self, epoch: UserEpoch) -> Result<()> {
        let inner_epoch = self
            .wrapped
            .read()
            .await
            .epoch_mapper
            .to_incremental_epoch(epoch)
            .await;
        self.wrapped.write().await.rollback_to(inner_epoch).await
    }

    async fn rollback(&mut self) -> Result<()> {
        let inner_epoch = self.wrapped.read().await.current_epoch();
        ensure!(inner_epoch > 0, "cannot rollback past the initial epoch");
        self.wrapped.write().await.rollback_to(inner_epoch).await
    }
}

pub(crate) const INITIAL_INCREMENTAL_EPOCH: IncrementalEpoch = 0;

#[derive(Clone, Debug)]
pub struct EpochMapperStorage {
    /// A pointer to the DB client
    db: DBPool,
    /// The table in which the data must be persisted
    table: String,
    in_tx: bool,
    /// Set of `UserEpoch`s being updated in the cache since the last commit to the DB
    dirty: BTreeSet<UserEpoch>,
    pub(super) cache: Arc<RwLock<InMemoryEpochMapper>>,
}

impl EpochMapperStorage {
    pub(crate) fn mapper_table_name(&self) -> String {
        mapper_table_name(&self.table)
    }

    pub(crate) async fn new_from_table(table: String, db: DBPool) -> Result<Self> {
        let cache = {
            let connection = db.get().await?;
            let mapper_table_name = mapper_table_name(table.as_str());
            let mut cache = InMemoryEpochMapper::new_empty();
            let rows = connection
                .query(
                    &format!(
                        "SELECT {USER_EPOCH}, {INCREMENTAL_EPOCH} FROM {}",
                        mapper_table_name,
                    ),
                    &[],
                )
                .await
                .context("while fetching incremental epoch")
                .unwrap();
            for row in rows {
                let user_epoch = row.get::<_, i64>(0) as UserEpoch;
                let incremental_epoch = row.get::<_, i64>(1) as IncrementalEpoch;
                cache
                    .add_epoch_map(user_epoch, incremental_epoch)
                    .await
                    .context("while adding mapping to cache")?;
            }
            cache
        };
        Ok(Self {
            db,
            table,
            in_tx: false,
            dirty: Default::default(),
            cache: Arc::new(RwLock::new(cache)),
        })
    }

    pub(crate) async fn new<const EXTERNAL_EPOCH_MAPPER: bool>(
        table: String,
        db: DBPool,
        initial_epoch: UserEpoch,
    ) -> Result<Self> {
        // Add initial epoch to cache
        let mapper_table_name = mapper_table_name(table.as_str());
        Ok(if EXTERNAL_EPOCH_MAPPER {
            // Initialize from mapper table
            let mapper = Self::new_from_table(table, db).await?;
            // check that there is a mapping initial_epoch -> INITIAL_INCREMENTAL_EPOCH
            ensure!(
                mapper.try_to_incremental_epoch(initial_epoch).await
                    == Some(INITIAL_INCREMENTAL_EPOCH),
                "No initial epoch {initial_epoch} found in mapping table {mapper_table_name}"
            );
            mapper
        } else {
            // add epoch map for `initial_epoch` to the DB
            db.get()
                .await?
                .query(
                    &format!(
                        "INSERT INTO {} ({USER_EPOCH}, {INCREMENTAL_EPOCH})
                            VALUES ($1, $2)",
                        mapper_table_name,
                    ),
                    &[&(initial_epoch as UserEpoch), &INITIAL_INCREMENTAL_EPOCH],
                )
                .await?;
            let cache = InMemoryEpochMapper::new_at(initial_epoch);
            Self {
                db,
                table,
                in_tx: false,
                dirty: Default::default(),
                cache: Arc::new(RwLock::new(cache)),
            }
        })
    }

    /// Add a new epoch mapping for `IncrementalEpoch` `epoch`, assuming that `UserEpoch`s
    /// are also computed incrementally from an initial shift. If there is already a mapping for
    /// `IncrementalEpoch` `epoch`, then this function has no side effects, because it is assumed
    /// that the mapping has already been provided according to another logic.
    pub(crate) async fn new_incremental_epoch(&mut self, epoch: IncrementalEpoch) -> Result<()> {
        if let Some(mapped_epoch) = self.cache.write().await.new_incremental_epoch(epoch) {
            // if a new mapping is actually added to the cache, then we add the `UserEpoch`
            // of this mapping to the `dirty` set, so that it is later committed to the DB
            self.dirty.insert(mapped_epoch);
        }
        Ok(())
    }

    pub(crate) fn start_transaction(&mut self) -> Result<()> {
        ensure!(!self.in_tx, "already in a transaction");
        self.in_tx = true;
        Ok(())
    }

    pub(crate) async fn commit_in_transaction(
        &mut self,
        db_tx: &mut Transaction<'_>,
    ) -> Result<()> {
        for &user_epoch in self.dirty.iter() {
            let incremental_epoch = self
                .cache
                .write()
                .await
                .try_to_incremental_epoch(user_epoch)
                .await
                .ok_or(anyhow!("Epoch {user_epoch} not found in cache"))?;
            db_tx
                .query(
                    &format!(
                        "INSERT INTO {} ({USER_EPOCH}, {INCREMENTAL_EPOCH})
                     VALUES ($1, $2)",
                        self.mapper_table_name()
                    ),
                    &[&(user_epoch as UserEpoch), &incremental_epoch],
                )
                .await?;
        }

        Ok(())
    }

    pub(crate) async fn latest_epoch(&self) -> UserEpoch {
        // always fetch it from the DB as it might be outdated in cache
        let connection = self.db.get().await.unwrap();
        let row = connection
            .query_opt(
                &format!(
                    "SELECT {USER_EPOCH}, {INCREMENTAL_EPOCH} FROM {} 
                    WHERE {USER_EPOCH} = 
                        (SELECT MAX({USER_EPOCH}) FROM {})",
                    self.mapper_table_name(),
                    self.mapper_table_name(),
                ),
                &[],
            )
            .await
            .context("while fetching incremental epoch")
            .unwrap();
        if let Some(row) = row {
            let user_epoch = row.get::<_, i64>(0) as UserEpoch;
            let incremental_epoch = row.get::<_, i64>(1);
            self.cache
                .write()
                .await
                .add_epoch_map(user_epoch, incremental_epoch)
                .await
                .context("while adding mapping to cache")
                .unwrap();
            user_epoch
        } else {
            unreachable!(
                "There should always be at least one row in mapper table {}",
                self.mapper_table_name()
            );
        }
    }

    pub(crate) fn commit_success(&mut self) {
        self.dirty.clear();
        self.in_tx = false;
    }

    pub(crate) async fn commit_failed(&mut self) {
        // revert mappings inserted in the cache since the last commit.
        // we rollback to the smallest epoch found in dirty, if any
        if let Some(epoch) = self.dirty.pop_first() {
            self.cache.write().await.rollback_to(epoch);
        }
        self.dirty.clear();
        self.in_tx = false;
    }

    pub(crate) async fn rollback_to<const EXTERNAL_EPOCH_MAPPER: bool>(
        &mut self,
        epoch: UserEpoch,
    ) -> Result<()> {
        // rollback the cache
        self.cache.write().await.rollback_to(epoch);
        if !EXTERNAL_EPOCH_MAPPER {
            // rollback also DB
            let connection = self.db.get().await?;
            connection
                .query(
                    &format!(
                        "DELETE FROM {} WHERE {USER_EPOCH} > $1",
                        self.mapper_table_name()
                    ),
                    &[&(epoch)],
                )
                .await?;
        }

        Ok(())
    }
}

impl EpochMapper for EpochMapperStorage {
    async fn try_to_incremental_epoch(&self, epoch: UserEpoch) -> Option<IncrementalEpoch> {
        let result = self
            .cache
            .read()
            .await
            .try_to_incremental_epoch(epoch)
            .await;
        if result.is_none() {
            let connection = self.db.get().await.unwrap();
            let row = connection
                .query_opt(
                    &format!(
                        "SELECT {INCREMENTAL_EPOCH} FROM {} WHERE {USER_EPOCH} = $1",
                        self.mapper_table_name()
                    ),
                    &[&(epoch)],
                )
                .await
                .context("while fetching incremental epoch")
                .unwrap();
            if let Some(row) = row {
                let incremental_epoch = row.get::<_, i64>(0) as IncrementalEpoch;
                self.cache
                    .write()
                    .await
                    .add_epoch_map(epoch, incremental_epoch)
                    .await
                    .context("while adding mapping to cache")
                    .unwrap();
                Some(incremental_epoch)
            } else {
                None
            }
        } else {
            result
        }
    }

    async fn try_to_user_epoch(&self, epoch: IncrementalEpoch) -> Option<UserEpoch> {
        let result = self.cache.read().await.try_to_user_epoch(epoch).await;
        if result.is_none() {
            let connection = self.db.get().await.unwrap();
            let row = connection
                .query_opt(
                    &format!(
                        "SELECT {USER_EPOCH} FROM {} WHERE {INCREMENTAL_EPOCH} = $1",
                        self.mapper_table_name()
                    ),
                    &[&(epoch)],
                )
                .await
                .context("while fetching incremental epoch")
                .unwrap();
            if let Some(row) = row {
                let user_epoch = row.get::<_, i64>(0) as UserEpoch;
                self.cache
                    .write()
                    .await
                    .add_epoch_map(user_epoch, epoch)
                    .await
                    .context("while adding mapping to cache")
                    .unwrap();
                Some(user_epoch)
            } else {
                None
            }
        } else {
            result
        }
    }

    async fn add_epoch_map(
        &mut self,
        user_epoch: UserEpoch,
        incremental_epoch: IncrementalEpoch,
    ) -> Result<()> {
        // add to cache
        self.cache
            .write()
            .await
            .add_epoch_map(user_epoch, incremental_epoch)
            .await?;
        // add arbitrary epoch to dirty set
        self.dirty.insert(user_epoch);
        Ok(())
    }
}
