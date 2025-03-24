use crate::{
    error::{ensure, RyhopeError},
    storage::{
        EpochKvStorage, EpochStorage, RoEpochKvStorage, SqlTransactionStorage,
        TransactionalStorage, TreeStorage, WideLineage,
    },
    tree::{
        sbbst::{self, NodeIdx},
        scapegoat, NodeContext, TreeTopology,
    },
    Epoch, EPOCH, KEY, PAYLOAD, VALID_FROM, VALID_UNTIL,
};
use itertools::Itertools;
use postgres_types::Json;
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    fmt::Debug,
    future::Future,
    marker::PhantomData,
    sync::Arc,
};
use tokio::sync::{Mutex, RwLock};
use tokio_postgres::{self, GenericClient, Row, Transaction};
use tracing::*;

use super::{CachedValue, PayloadInDb, ToFromBytea, MAX_PGSQL_BIGINT};

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
        birth_epoch: Epoch,
        v: &Self::Node,
    ) -> impl Future<Output = Result<(), RyhopeError>>;

    /// Within a PgSQL transaction, update the value associated at the given
    /// epoch to the given key.
    fn set_at_in_tx(
        db_tx: &tokio_postgres::Transaction<'_>,
        table: &str,
        k: &Self::Key,
        epoch: Epoch,
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
    fn fetch_node_at<B: GenericClient + Send + Sync>(
        db: Arc<Mutex<B>>,
        table: &str,
        k: &Self::Key,
        epoch: Epoch,
    ) -> impl Future<Output = Result<Option<Self::Node>, RyhopeError>> + Send;

    fn fetch_all_keys<B: GenericClient + Send + Sync>(
        db: Arc<Mutex<B>>,
        table: &str,
        epoch: Epoch,
    ) -> impl Future<Output = Result<Vec<Self::Key>, RyhopeError>> + Send {
        async move {
            let connection = db.lock().await;
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
    fn fetch_a_key<B: GenericClient + Send + Sync>(
        db: Arc<Mutex<B>>,
        table: &str,
        epoch: Epoch,
    ) -> impl Future<Output = Result<Option<Self::Key>, RyhopeError>> + Send {
        async move {
            let connection = db.lock().await;
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
    fn fetch_all_pairs<B: GenericClient + Send + Sync>(
        db: Arc<Mutex<B>>,
        table: &str,
        epoch: Epoch,
    ) -> impl Future<Output = Result<HashMap<Self::Key, V>, RyhopeError>> + std::marker::Send {
        async move {
            let connection = db.lock().await;
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
    fn fetch_payload_at<B: GenericClient + Send + Sync>(
        db: Arc<Mutex<B>>,
        table: &str,
        k: &Self::Key,
        epoch: Epoch,
    ) -> impl std::future::Future<Output = Result<Option<V>, RyhopeError>> + std::marker::Send {
        async move {
            let connection = db.lock().await;
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

    fn wide_lineage_between<S: TreeStorage<Self>, B: GenericClient + Sync + Send>(
        &self,
        s: &S,
        db: Arc<Mutex<B>>,
        table: &str,
        keys_query: &str,
        bounds: (Epoch, Epoch),
    ) -> impl Future<Output = Result<WideLineage<Self::Key, V>, RyhopeError>>;

    /// Return the value associated to the given key at the given epoch.
    #[allow(clippy::type_complexity)]
    fn fetch_many_at<
        S: TreeStorage<Self>,
        I: IntoIterator<Item = (Epoch, Self::Key)> + Send,
        B: GenericClient + Send + Sync,
    >(
        &self,
        s: &S,
        db: Arc<Mutex<B>>,
        table: &str,
        data: I,
    ) -> impl Future<Output = Result<Vec<(Epoch, NodeContext<Self::Key>, V)>, RyhopeError>> + Send;
}

/// Implementation of a [`DbConnector`] for a tree over `K` with empty nodes.
/// Only applies to the SBBST for now.
impl<V> DbConnector<V> for sbbst::Tree
where
    V: Debug + Clone + Send + Sync + Serialize + for<'a> Deserialize<'a>,
{
    fn node_columns() -> &'static [(&'static str, &'static str)] {
        &[]
    }

    async fn fetch_node_at<B: GenericClient + Send + Sync>(
        db: Arc<Mutex<B>>,
        table: &str,
        k: &NodeIdx,
        epoch: Epoch,
    ) -> Result<Option<()>, RyhopeError> {
        db.lock()
            .await
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
        birth_epoch: Epoch,
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

    async fn wide_lineage_between<S: TreeStorage<Self>, B: GenericClient + Sync + Send>(
        &self,
        s: &S,
        db: Arc<Mutex<B>>,
        table: &str,
        keys_query: &str,
        bounds: (Epoch, Epoch),
    ) -> Result<WideLineage<NodeIdx, V>, RyhopeError> {
        // In the SBBST case, parsil will not be able to inject the table name;
        // so we do it here.
        let keys_query = format!("{keys_query} FROM {table}");
        // Execute `keys_query` to retrieve the core keys from the DB
        let core_keys = db
            .lock()
            .await
            .query(&keys_query, &[])
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
        let payload_query = format!(
            "SELECT
               {KEY}, generate_series(GREATEST({VALID_FROM}, $1), LEAST({VALID_UNTIL}, $2)) AS epoch, {PAYLOAD}
             FROM {table}
             WHERE NOT ({VALID_FROM} > $2 OR {VALID_UNTIL} < $1) AND {KEY} = ANY($3)",
        );
        let rows = db
            .lock()
            .await
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
            Epoch,
            (HashMap<NodeIdx, NodeContext<NodeIdx>>, HashMap<NodeIdx, V>),
        > = HashMap::new();
        for row in &rows {
            let epoch = row.get::<_, i64>("epoch");
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
        I: IntoIterator<Item = (Epoch, Self::Key)> + Send,
        B: GenericClient + Send + Sync,
    >(
        &self,
        s: &S,
        db: Arc<Mutex<B>>,
        table: &str,
        data: I,
    ) -> Result<Vec<(Epoch, NodeContext<Self::Key>, V)>, RyhopeError> {
        let data = data.into_iter().collect::<Vec<_>>();
        let connection = db.lock().await;
        let immediate_table = data
            .iter()
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
               let epoch = row.get::<_, Epoch>(1);
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

    async fn fetch_node_at<B: GenericClient + Send + Sync>(
        db: Arc<Mutex<B>>,
        table: &str,
        k: &K,
        epoch: Epoch,
    ) -> Result<Option<Self::Node>, RyhopeError> {
        let connection = db.lock().await;
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
        birth_epoch: Epoch,
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

    async fn wide_lineage_between<S: TreeStorage<Self>, B: GenericClient + Sync + Send>(
        &self,
        _: &S,
        db: Arc<Mutex<B>>,
        table: &str,
        keys_query: &str,
        bounds: (Epoch, Epoch),
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
            max_depth = 2,
            zk_table = table,
            core_keys_query = keys_query,
        );
        let connection = db.lock().await;
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
            Epoch,
            (HashMap<K, NodeContext<K>>, HashMap<K, V>),
        > = HashMap::new();

        for row in &rows {
            let is_core = row.try_get::<_, i32>("is_core").map_err(|err| {
                RyhopeError::invalid_format(format!("fetching `is_core` flag from {row:?}"), err)
            })? > 0;
            let epoch = row.try_get::<_, i64>(EPOCH).map_err(|err| {
                RyhopeError::invalid_format(format!("fetching `epoch` from {row:?}"), err)
            })?;
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
        I: IntoIterator<Item = (Epoch, Self::Key)> + Send,
        B: GenericClient + Sync + Send,
    >(
        &self,
        _s: &S,
        db: Arc<Mutex<B>>,
        table: &str,
        data: I,
    ) -> Result<Vec<(Epoch, NodeContext<Self::Key>, V)>, RyhopeError> {
        let data = data.into_iter().collect::<Vec<_>>();
        let connection = db.lock().await;
        let immediate_table = data
            .iter()
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
            let epoch = row.get::<_, Epoch>(1);
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
pub struct CachedDbStore<
    V: Debug + Clone + Send + Sync + Serialize + for<'a> Deserialize<'a>,
    B: GenericClient,
> {
    /// A pointer to the DB client
    db: Arc<Mutex<B>>,
    /// The first valid epoch
    initial_epoch: Epoch,
    /// Whether a transaction is in process
    in_tx: bool,
    /// True if the wrapped state has been modified
    dirty: bool,
    /// The current epoch
    epoch: Epoch,
    /// The table in which the data must be persisted
    table: String,
    pub(super) cache: RwLock<Option<V>>,
}
impl<T: Debug + Clone + Send + Sync + Serialize + for<'a> Deserialize<'a>, B: GenericClient>
    CachedDbStore<T, B>
{
    pub fn new(
        initial_epoch: Epoch,
        current_epoch: Epoch,
        table: String,
        db: Arc<Mutex<B>>,
    ) -> Self {
        Self {
            initial_epoch,
            db,
            in_tx: false,
            dirty: false,
            epoch: current_epoch,
            table,
            cache: RwLock::new(None),
        }
    }

    /// Initialize a new store, with the given state. The initial state is
    /// immediately persisted, as the DB representation of the payload must be
    /// valid even if it is never modified further by the user.
    pub async fn with_value(
        initial_epoch: Epoch,
        table: String,
        db: Arc<Mutex<B>>,
        t: T,
    ) -> Result<Self, RyhopeError> {
        {
            db.lock()
                .await
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
            initial_epoch,
            in_tx: false,
            dirty: true,
            epoch: initial_epoch,
            table,
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
}

impl<T, B> TransactionalStorage for CachedDbStore<T, B>
where
    T: Debug + Clone + Serialize + for<'a> Deserialize<'a> + Send + Sync,
    B: GenericClient,
{
    fn start_transaction(&mut self) -> Result<(), RyhopeError> {
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

        let db = self.db.clone();
        let mut db = db.lock().await;
        let mut db_tx = db
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

impl<T, B: GenericClient> std::fmt::Display for CachedDbStore<T, B>
where
    T: Debug + Clone + Serialize + for<'a> Deserialize<'a> + Send + Sync,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "CachedDbStore {}@{}", self.table, self.epoch)
    }
}

impl<T, B: GenericClient> SqlTransactionStorage for CachedDbStore<T, B>
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

    fn commit_success(&mut self) {
        trace!("[{self}] commit_success");
        self.on_commit_success()
    }

    fn commit_failed(&mut self) {
        trace!("[{self}] commit_failed");
        self.on_commit_failed()
    }
}

impl<T, B> EpochStorage<T> for CachedDbStore<T, B>
where
    T: Debug + Clone + Sync + Serialize + for<'a> Deserialize<'a> + Send,
    B: GenericClient + Send + Sync,
{
    async fn fetch(&self) -> Result<T, RyhopeError> {
        trace!("[{self}] fetching payload");
        if self.cache.read().await.is_none() {
            let state = self.fetch_at(self.epoch).await?;
            let _ = self.cache.write().await.replace(state.clone());
            Ok(state)
        } else {
            Ok(self.cache.read().await.clone().unwrap())
        }
    }

    async fn fetch_at(&self, epoch: Epoch) -> Result<T, RyhopeError> {
        trace!("[{self}] fetching payload at {}", epoch);
        self.db.lock().await
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
            .map_err(|err| {
                RyhopeError::from_db(
                    format!(
                        "failed to fetch state from `{}_meta` at epoch `{}`",
                        self.table,
                        epoch
                    ),
                    err)
            })
    }

    async fn store(&mut self, t: T) -> Result<(), RyhopeError> {
        trace!("[{self}] storing {t:?}");
        self.dirty = true;
        let _ = self.cache.write().await.insert(t);
        Ok(())
    }

    fn current_epoch(&self) -> Epoch {
        self.epoch
    }

    async fn rollback_to(&mut self, new_epoch: Epoch) -> Result<(), RyhopeError> {
        ensure(
            new_epoch >= self.initial_epoch,
            format!(
                "unable to rollback to {} before initial epoch {}",
                new_epoch, self.initial_epoch
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

        let _ = self.cache.get_mut().take();
        let db = self.db.clone();
        let mut db = db.lock().await;
        let mut db_tx = db
            .transaction()
            .await
            .expect("unable to create DB transaction");
        db_tx
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
            .await
            .map_err(|err| {
                RyhopeError::from_db(format!("time-stamping `{}_meta`", self.table), err)
            })?;
        // Delete nodes that would not have been born yet
        db_tx
            .query(
                &format!("DELETE FROM {}_meta WHERE {VALID_FROM} > $1", self.table),
                &[&new_epoch],
            )
            .await
            .map_err(|err| {
                RyhopeError::from_db(format!("reaping nodes `{}_meta`", self.table), err)
            })?;

        db_tx
            .commit()
            .await
            .map_err(|err| RyhopeError::from_db("committing transaction", err))?;
        self.epoch = new_epoch;

        Ok(())
    }
}

/// A `CachedDbStore` keeps a cache of all the storage operations that occured
/// during the current transaction, while falling back to the given database
/// when referring to older epochs.
pub struct CachedDbTreeStore<T, V, B>
where
    T: TreeTopology + DbConnector<V>,
    T::Key: ToFromBytea,
    V: Debug + Clone + Send + Sync + Serialize + for<'a> Deserialize<'a>,
    B: GenericClient + Send + Sync,
{
    /// The initial epoch
    initial_epoch: Epoch,
    /// The latest *commited* epoch
    epoch: Epoch,
    /// A pointer to the DB client
    db: Arc<Mutex<B>>,
    /// DB backing this cache
    table: String,
    /// Operations pertaining to the in-process transaction.
    pub(super) nodes_cache: HashMap<T::Key, Option<CachedValue<T::Node>>>,
    pub(super) payload_cache: HashMap<T::Key, Option<CachedValue<V>>>,
    _p: PhantomData<T>,
}
impl<T, V, B> std::fmt::Display for CachedDbTreeStore<T, V, B>
where
    T: TreeTopology + DbConnector<V>,
    T::Key: ToFromBytea,
    V: Debug + Clone + Send + Sync + Serialize + for<'a> Deserialize<'a>,
    B: GenericClient + Send + Sync,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "TreeStore {}@{}", self.table, self.epoch)
    }
}
impl<T, V, B> CachedDbTreeStore<T, V, B>
where
    T: TreeTopology + DbConnector<V>,
    T::Key: ToFromBytea,
    V: Debug + Clone + Send + Sync + Serialize + for<'a> Deserialize<'a>,
    B: GenericClient + Send + Sync,
{
    pub fn new(
        initial_epoch: Epoch,
        current_epoch: Epoch,
        table: String,
        db: Arc<Mutex<B>>,
    ) -> Self {
        trace!("[{}] initializing CachedDbTreeStore", table);
        CachedDbTreeStore {
            initial_epoch,
            epoch: current_epoch,
            table,
            db,
            nodes_cache: Default::default(),
            payload_cache: Default::default(),
            _p: PhantomData,
        }
    }

    pub fn clear(&mut self) {
        self.nodes_cache.clear();
        self.payload_cache.clear();
    }

    pub fn new_epoch(&mut self) {
        self.clear();
        self.epoch += 1;
    }

    pub fn initial_epoch(&self) -> Epoch {
        self.initial_epoch
    }

    pub fn current_epoch(&self) -> Epoch {
        self.epoch
    }

    pub async fn size(&self) -> usize {
        self.size_at(self.epoch).await
    }

    pub async fn size_at(&self, epoch: Epoch) -> usize {
        self.db
            .lock()
            .await
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

    pub(super) async fn rollback_to(&mut self, new_epoch: Epoch) -> Result<(), RyhopeError> {
        trace!("[{self}] rolling back to {new_epoch}");
        ensure(
            new_epoch >= self.initial_epoch,
            format!(
                "unable to rollback to {} before initial epoch {}",
                new_epoch, self.initial_epoch
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
        let mut connection = self.db.lock().await;
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
pub struct NodeProjection<T, V, B>
where
    T: TreeTopology + DbConnector<V>,
    T::Key: ToFromBytea,
    V: Debug + Clone + Send + Sync + Serialize + for<'a> Deserialize<'a>,
    B: GenericClient + Send + Sync,
{
    pub(super) wrapped: Arc<std::sync::Mutex<CachedDbTreeStore<T, V, B>>>,
}
impl<T, V, B> std::fmt::Display for NodeProjection<T, V, B>
where
    T: TreeTopology + DbConnector<V>,
    T::Key: ToFromBytea,
    V: PayloadInDb,
    B: GenericClient + Send + Sync,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/Nodes", self.wrapped.lock().unwrap())
    }
}
impl<T, V, B> RoEpochKvStorage<T::Key, T::Node> for NodeProjection<T, V, B>
where
    T: TreeTopology + DbConnector<V>,
    T::Key: ToFromBytea,
    V: PayloadInDb,
    B: GenericClient + Send + Sync,
{
    delegate::delegate! {
        to self.wrapped.lock().unwrap() {
            fn initial_epoch(&self) -> Epoch ;
            fn current_epoch(&self) -> Epoch ;
            async fn size(&self) -> usize;
            async fn size_at(&self, epoch: Epoch) -> usize;
        }
    }

    fn try_fetch_at(
        &self,
        k: &T::Key,
        epoch: Epoch,
    ) -> impl Future<Output = Result<Option<T::Node>, RyhopeError>> + Send {
        trace!("[{self}] fetching {k:?}@{epoch}",);
        let db = self.wrapped.lock().unwrap().db.clone();
        let table = self.wrapped.lock().unwrap().table.to_owned();
        async move {
            if epoch == self.current_epoch() {
                // Directly returns the value if it is already in cache, fetch it from
                // the DB otherwise.
                let value = self.wrapped.lock().unwrap().nodes_cache.get(k).cloned();
                Ok(if let Some(Some(cached_value)) = value {
                    Some(cached_value.into_value())
                } else if let Some(value) = T::fetch_node_at(db, &table, k, epoch).await.unwrap() {
                    let mut guard = self.wrapped.lock().unwrap();
                    guard
                        .nodes_cache
                        .insert(k.clone(), Some(CachedValue::Read(value.clone())));
                    Some(value)
                } else {
                    None
                })
            } else {
                T::fetch_node_at(db, &table, k, epoch).await
            }
        }
    }

    async fn keys_at(&self, epoch: Epoch) -> Vec<T::Key> {
        let db = self.wrapped.lock().unwrap().db.clone();
        let table = self.wrapped.lock().unwrap().table.to_owned();

        T::fetch_all_keys(db, &table, epoch).await.unwrap()
    }

    async fn random_key_at(&self, epoch: Epoch) -> Option<T::Key> {
        let db = self.wrapped.lock().unwrap().db.clone();
        let table = self.wrapped.lock().unwrap().table.to_owned();

        T::fetch_a_key(db, &table, epoch).await.unwrap()
    }

    async fn pairs_at(&self, _epoch: Epoch) -> Result<HashMap<T::Key, T::Node>, RyhopeError> {
        unimplemented!("should never be used");
    }

    async fn try_fetch(&self, k: &T::Key) -> Result<Option<T::Node>, RyhopeError> {
        self.try_fetch_at(k, self.current_epoch()).await
    }

    async fn contains(&self, k: &T::Key) -> Result<bool, RyhopeError> {
        self.try_fetch(k).await.map(|x| x.is_some())
    }

    async fn contains_at(&self, k: &T::Key, epoch: Epoch) -> Result<bool, RyhopeError> {
        self.try_fetch_at(k, epoch).await.map(|x| x.is_some())
    }
}
impl<T, V, B> EpochKvStorage<T::Key, T::Node> for NodeProjection<T, V, B>
where
    T: TreeTopology + DbConnector<V>,
    T::Key: ToFromBytea,
    T::Node: Sync + Clone,
    V: PayloadInDb,
    B: GenericClient + Send + Sync,
{
    delegate::delegate! {
        to self.wrapped.lock().unwrap() {
            async fn rollback_to(&mut self, epoch: Epoch) -> Result<(), RyhopeError>;
        }
    }

    fn remove(&mut self, k: T::Key) -> impl Future<Output = Result<(), RyhopeError>> + Send {
        trace!("[{self}] removing {k:?} from cache",);
        self.wrapped.lock().unwrap().nodes_cache.insert(k, None);
        async { Ok(()) }
    }

    fn update(
        &mut self,
        k: T::Key,
        new_value: T::Node,
    ) -> impl Future<Output = Result<(), RyhopeError>> + Send {
        trace!("[{self}] updating cache {k:?} -> {new_value:?}");
        // If the operation is already present from a read, replace it with the
        // new value.
        self.wrapped
            .lock()
            .unwrap()
            .nodes_cache
            .insert(k, Some(CachedValue::Written(new_value)));
        async { Ok(()) }
    }

    fn store(
        &mut self,
        k: T::Key,
        value: T::Node,
    ) -> impl Future<Output = Result<(), RyhopeError>> + Send {
        trace!("[{self}] storing {k:?} -> {value:?} in cache");
        // If the operation is already present from a read, replace it with the
        // new value.
        self.wrapped
            .lock()
            .unwrap()
            .nodes_cache
            .insert(k, Some(CachedValue::Written(value)));
        async { Ok(()) }
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
}

/// A wrapper around a [`CachedDbTreeStore`] to make it appear as a KV store for
/// node payloads. This is an artifice made necessary by the impossibility to
/// implement two different specializations of the same trait for the same type;
/// otherwise [`RoEpochKvStorage`] and [`EpochKvStorage`] could be directly
/// implemented for [`CachedDbTreeStore`] for both `<T::Key, T::Node>` and
/// `<T::Key, V>`.
pub struct PayloadProjection<T, V, B>
where
    T: TreeTopology + DbConnector<V>,
    T::Key: ToFromBytea,
    V: Debug + Clone + Send + Sync + Serialize + for<'a> Deserialize<'a>,
    B: GenericClient + Send + Sync,
{
    pub(super) wrapped: Arc<std::sync::Mutex<CachedDbTreeStore<T, V, B>>>,
}
impl<T, V, B> std::fmt::Display for PayloadProjection<T, V, B>
where
    T: TreeTopology + DbConnector<V>,
    T::Key: ToFromBytea,
    V: PayloadInDb,
    B: GenericClient + Send + Sync,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/Payload", self.wrapped.lock().unwrap())
    }
}

impl<T, V, B> RoEpochKvStorage<T::Key, V> for PayloadProjection<T, V, B>
where
    T: TreeTopology + DbConnector<V>,
    T::Key: ToFromBytea,
    V: PayloadInDb,
    B: GenericClient + Send + Sync,
{
    delegate::delegate! {
        to self.wrapped.lock().unwrap() {
            fn initial_epoch(&self) -> Epoch ;
            fn current_epoch(&self) -> Epoch ;
            async fn size(&self) -> usize ;
            async fn size_at(&self, epoch: Epoch) -> usize ;
        }
    }

    fn try_fetch_at(
        &self,
        k: &T::Key,
        epoch: Epoch,
    ) -> impl Future<Output = Result<Option<V>, RyhopeError>> + Send {
        trace!("[{self}] attempting to fetch payload for {k:?}@{epoch}");
        let db = self.wrapped.lock().unwrap().db.clone();
        let table = self.wrapped.lock().unwrap().table.to_owned();
        async move {
            if epoch == self.current_epoch() {
                // Directly returns the value if it is already in cache, fetch it from
                // the DB otherwise.
                let value = self.wrapped.lock().unwrap().payload_cache.get(k).cloned();
                if let Some(Some(cached_value)) = value {
                    Ok(Some(cached_value.into_value()))
                } else if let Some(value) = T::fetch_payload_at(db, &table, k, epoch).await? {
                    let mut guard = self.wrapped.lock().unwrap();
                    guard
                        .payload_cache
                        .insert(k.clone(), Some(CachedValue::Read(value.clone())));
                    Ok(Some(value))
                } else {
                    Ok(None)
                }
            } else {
                T::fetch_payload_at(db, &table, k, epoch).await
            }
        }
    }

    async fn keys_at(&self, epoch: Epoch) -> Vec<T::Key> {
        let db = self.wrapped.lock().unwrap().db.clone();
        let table = self.wrapped.lock().unwrap().table.to_owned();

        T::fetch_all_keys(db, &table, epoch).await.unwrap()
    }

    async fn random_key_at(&self, epoch: Epoch) -> Option<T::Key> {
        let db = self.wrapped.lock().unwrap().db.clone();
        let table = self.wrapped.lock().unwrap().table.to_owned();

        T::fetch_a_key(db, &table, epoch).await.unwrap()
    }

    async fn pairs_at(&self, epoch: Epoch) -> Result<HashMap<T::Key, V>, RyhopeError> {
        let db = self.wrapped.lock().unwrap().db.clone();
        let table = self.wrapped.lock().unwrap().table.to_owned();

        T::fetch_all_pairs(db, &table, epoch).await
    }
}
impl<T, V, B> EpochKvStorage<T::Key, V> for PayloadProjection<T, V, B>
where
    T: TreeTopology + DbConnector<V>,
    T::Key: ToFromBytea,
    T::Node: Sync + Clone,
    V: PayloadInDb,
    B: GenericClient + Send + Sync,
{
    delegate::delegate! {
        to self.wrapped.lock().unwrap() {
            async fn rollback_to(&mut self, epoch: Epoch) -> Result<(), RyhopeError>;
        }
    }

    fn remove(&mut self, k: T::Key) -> impl Future<Output = Result<(), RyhopeError>> + Send {
        trace!("[{self}] removing {k:?} from cache");
        self.wrapped.lock().unwrap().nodes_cache.insert(k, None);
        async { Ok(()) }
    }

    fn update(
        &mut self,
        k: T::Key,
        new_value: V,
    ) -> impl Future<Output = Result<(), RyhopeError>> + Send {
        trace!("[{self}] updating cache {k:?} -> {new_value:?}");
        // If the operation is already present from a read, replace it with the
        // new value.
        self.wrapped
            .lock()
            .unwrap()
            .payload_cache
            .insert(k, Some(CachedValue::Written(new_value)));
        async { Ok(()) }
    }

    fn store(
        &mut self,
        k: T::Key,
        value: V,
    ) -> impl Future<Output = Result<(), RyhopeError>> + Send {
        trace!("[{self}] storing {k:?} -> {value:?} in cache",);
        // If the operation is already present from a read, replace it with the
        // new value.
        self.wrapped
            .lock()
            .unwrap()
            .payload_cache
            .insert(k, Some(CachedValue::Written(value)));
        async { Ok(()) }
    }
}
