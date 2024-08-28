use crate::{
    storage::{
        EpochKvStorage, EpochStorage, RoEpochKvStorage, SqlTransactionStorage, TransactionalStorage,
    },
    tree::{sbbst, scapegoat, NodeContext, TreeTopology},
    Epoch,
};
use anyhow::*;
use bb8::Pool;
use bb8_postgres::PostgresConnectionManager;
use postgres_types::Json;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fmt::Debug,
    future::Future,
    marker::PhantomData,
    sync::{Arc, Mutex},
};
use tokio::sync::RwLock;
use tokio_postgres::{self, NoTls, Row, Transaction};

use super::{CachedValue, PayloadInDb, ToFromBytea};

pub type DBPool = Pool<PostgresConnectionManager<NoTls>>;

/// Type implementing this trait define the behavior of a storage tree
/// components regarding their persistence in DB.

pub trait DbConnector<K, N, V>
where
    K: ToFromBytea + Send + Sync,
    V: Serialize + for<'a> Deserialize<'a> + Clone + Send + Sync + Debug,
{
    /// Return a list of pairs column name, SQL type required by the connector.
    fn columns() -> Vec<(&'static str, &'static str)> {
        Self::node_columns()
            .into_iter()
            .cloned()
            .chain(Self::payload_columns().into_iter().cloned())
            .collect()
    }

    /// Return a list of pairs of column names and SQL types required by the
    /// connector to store node-related information.
    fn node_columns() -> &'static [(&'static str, &'static str)];

    /// Return a list of pairs of column names and SQL types required by the
    /// connector to store payload-related information.
    fn payload_columns() -> &'static [(&'static str, &'static str)] {
        &[("payload", "JSONB")]
    }

    /// Within a PgSQL transaction, insert the given value at the given epoch.
    async fn create_node_in_tx(
        db_tx: &tokio_postgres::Transaction<'_>,
        table: &str,
        k: &K,
        birth_epoch: Epoch,
        v: N,
    ) -> Result<()>;

    /// Within a PgSQL transaction, update the value associated at the given
    /// epoch to the given key.
    async fn set_at_in_tx(
        db_tx: &tokio_postgres::Transaction<'_>,
        table: &str,
        k: &K,
        epoch: Epoch,
        v: V,
    ) -> Result<()> {
        db_tx
            .execute(
                &format!(
                    "UPDATE {} SET payload=$3 WHERE key=$1 AND __valid_from<=$2 AND $2<=__valid_until",
                    table
                ),
                &[&k.to_bytea(), &epoch, &Json(v)],
            )
            .await
            .map(|_| ())
            .context("while updating payload")
    }

    /// Return the value associated to the given key at the given epoch.
    fn fetch_node_at(
        db: DBPool,
        table: &str,
        k: &K,
        epoch: Epoch,
    ) -> impl Future<Output = Result<Option<N>>> + Send;

    /// Return the value associated to the given key at the given epoch.
    fn fetch_payload_at(
        db: DBPool,
        table: &str,
        k: &K,
        epoch: Epoch,
    ) -> impl std::future::Future<Output = Result<Option<V>>> + std::marker::Send {
        async move {
            let connection = db.get().await.unwrap();
            connection
            .query(
                &format!(
                    "SELECT payload FROM {} WHERE key=$1 AND __valid_from <= $2 AND $2 <= __valid_until",
                    table
                ),
                &[&(k.to_bytea()), &epoch],
            )
            .await
            .context("while fetching payload from database")
            .and_then(|rows| match rows.len() {
                0 => Ok(None),
                1 => Ok(Some(rows[0].get::<_, Json<V>>(0).0)),
                _ => bail!("internal coherency error: {:?}", rows),
            })
        }
    }

    /// Given a PgSQL row, extract a value from it.
    fn payload_from_row(row: &Row) -> Result<V> {
        row.try_get::<_, Json<V>>("payload")
            .map(|x| x.0)
            .context("while parsing payload from row")
    }

    fn node_from_row(row: &Row) -> Result<N>;

    fn wide_lineage_between(
        &self,
        db: DBPool,
        table: &str,
        keys_query: &str,
        start_epoch: Epoch,
        end_epoch: Epoch,
    ) -> impl Future<Output = Result<HashMap<(K, Epoch), (NodeContext<K>, V)>>>;
}

/// Implementation of a [`DbConnector`] for a tree over `K` with empty nodes.
/// Only applies to the SBBST for now.
impl<K, V> DbConnector<K, (), V> for sbbst::Tree
where
    K: ToFromBytea + Send + Sync,
    V: Debug + Clone + Send + Sync + Serialize + for<'a> Deserialize<'a>,
{
    fn node_columns() -> &'static [(&'static str, &'static str)] {
        &[]
    }

    async fn fetch_node_at(db: DBPool, table: &str, k: &K, epoch: Epoch) -> Result<Option<()>> {
        let connection = db.get().await.unwrap();
        connection
            .query(
                &format!(
                    "SELECT * FROM {} WHERE key=$1 AND __valid_from<=$2 AND $2<=__valid_until",
                    table
                ),
                &[&k.to_bytea(), &epoch],
            )
            .await
            .context("while fetching node")
            .and_then(|rows| match rows.len() {
                0 => Ok(None),
                1 => Ok(Some(())),
                _ => bail!("internal coherency error"),
            })
    }

    fn node_from_row(_r: &Row) -> Result<()> {
        Ok(())
    }

    async fn create_node_in_tx(
        db_tx: &tokio_postgres::Transaction<'_>,
        table: &str,
        k: &K,
        birth_epoch: Epoch,
        _n: (),
    ) -> Result<()> {
        db_tx
            .execute(
                &format!(
                    "INSERT INTO
                     {} (key, __valid_from, __valid_until)
                     VALUES ($1, $2, $2)",
                    table
                ),
                &[&k.to_bytea(), &birth_epoch],
            )
            .await
            .map_err(|e| anyhow!("failed to insert new node row: {e:?}"))
            .map(|_| ())
    }

    async fn wide_lineage_between(
        &self,
        db: DBPool,
        table: &str,
        keys_query: &str,
        start_epoch: Epoch,
        end_epoch: Epoch,
    ) -> Result<HashMap<(K, Epoch), (NodeContext<K>, V)>> {
        todo!()
    }
}

/// Implementation of [`DbConnector`] for any valid key and a scapegoat tree
/// built upon it.
impl<K, V> DbConnector<K, scapegoat::Node<K>, V> for scapegoat::Tree<K>
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
            ("parent", "BYTEA"),
            ("left_child", "BYTEA"),
            ("right_child", "BYTEA"),
            ("subtree_size", "BIGINT"),
        ]
    }

    async fn fetch_node_at(
        db: DBPool,
        table: &str,
        k: &K,
        epoch: Epoch,
    ) -> Result<Option<scapegoat::Node<K>>> {
        let connection = db.get().await.unwrap();
        connection
            .query(
                &format!(
                    "SELECT parent, left_child, right_child, subtree_size FROM {}
                       WHERE key=$1 AND __valid_from <= $2 AND $2 <= __valid_until",
                    table
                ),
                &[&k.to_bytea(), &epoch],
            )
            .await
            .context("while fetching node")
            .and_then(|rows| match rows.len() {
                0 => Ok(None),
                1 => {
                    let r = &rows[0];
                    Ok(Some(scapegoat::Node {
                        k: k.to_owned(),
                        parent: r.get::<_, Option<Vec<u8>>>(0).map(|p| K::from_bytea(p)),
                        left: r.get::<_, Option<Vec<u8>>>(1).map(|p| K::from_bytea(p)),
                        right: r.get::<_, Option<Vec<u8>>>(2).map(|p| K::from_bytea(p)),
                        subtree_size: r.get::<_, i64>(3).try_into()?,
                    }))
                }
                _ => bail!("internal coherency error"),
            })
    }

    fn node_from_row(row: &Row) -> Result<scapegoat::Node<K>> {
        Ok(scapegoat::Node {
            k: K::from_bytea(row.try_get::<_, Vec<u8>>("key")?),
            subtree_size: row.try_get::<_, i64>("subtree_size")?.try_into().unwrap(),
            parent: row
                .try_get::<_, Option<Vec<u8>>>("parent")?
                .map(K::from_bytea),
            left: row
                .try_get::<_, Option<Vec<u8>>>("left_child")?
                .map(K::from_bytea),
            right: row
                .try_get::<_, Option<Vec<u8>>>("right_child")?
                .map(K::from_bytea),
        })
    }

    async fn create_node_in_tx(
        db_tx: &tokio_postgres::Transaction<'_>,
        table: &str,
        k: &K,
        birth_epoch: Epoch,
        n: scapegoat::Node<K>,
    ) -> Result<()> {
        db_tx
            .execute(
                &format!(
                    "INSERT INTO
                     {} (key, __valid_from, __valid_until, subtree_size, parent, left_child, right_child)
                     VALUES ($1, $2, $2, $3, $4, $5, $6)",
                    table
                ),
                &[
                    &k.to_bytea(),
                    &birth_epoch,
                    &(n.subtree_size as i64),
                    &n.parent.as_ref().map(ToFromBytea::to_bytea),
                    &n.left.as_ref().map(ToFromBytea::to_bytea),
                    &n.right.as_ref().map(ToFromBytea::to_bytea),
                ],
            )
            .await
            .map_err(|e| anyhow!("failed to insert new node row: {e:?}"))
            .map(|_| ())
    }

    fn wide_lineage_between(
        &self,
        db: DBPool,
        table: &str,
        keys_query: &str,
        start_epoch: Epoch,
        end_epoch: Epoch,
    ) -> impl Future<Output = Result<HashMap<(K, Epoch), (NodeContext<K>, V)>>> {
        async move { Ok(HashMap::new()) }
    }
}

pub struct CachedDbStore<V: Debug + Clone + Sync + Serialize + for<'a> Deserialize<'a>> {
    /// A pointer to the DB client
    db: DBPool,
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
impl<T: Debug + Clone + Sync + Serialize + for<'a> Deserialize<'a>> CachedDbStore<T> {
    pub fn new(initial_epoch: Epoch, current_epoch: Epoch, table: String, db: DBPool) -> Self {
        Self {
            initial_epoch,
            db,
            in_tx: false,
            dirty: true,
            epoch: current_epoch,
            table,
            cache: RwLock::new(None),
        }
    }

    /// Initialize a new store, with the given state. The initial state is
    /// immediately persisted, as the DB representation of the payload must be
    /// valid even if it is never modified further by the user.
    pub async fn with_value(initial_epoch: Epoch, table: String, db: DBPool, t: T) -> Result<Self> {
        {
            let connection = db.get().await.unwrap();
            connection
                .query(
                    &format!(
                        "INSERT INTO {}_meta (__valid_from, __valid_until, payload)
                     VALUES ($1, $1, $2)",
                        table
                    ),
                    &[&initial_epoch, &Json(t.clone())],
                )
                .await?;
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

    async fn commit_in_transaction(&mut self, db_tx: &mut Transaction<'_>) -> Result<()> {
        ensure!(self.in_tx, "not in a transaction");

        if self.dirty {
            let state = self.cache.read().await.clone();
            db_tx
                .query(
                    &format!(
                        "INSERT INTO {}_meta (__valid_from, __valid_until, payload)
                     VALUES ($1, $1, $2)",
                        self.table
                    ),
                    &[&(self.epoch + 1), &Json(state)],
                )
                .await?;
        } else {
            db_tx
                .query(
                    &format!(
                        "UPDATE {}_meta SET __valid_until = $1 + 1 WHERE __valid_until = $1",
                        self.table
                    ),
                    &[&(self.epoch)],
                )
                .await?;
        }

        Ok(())
    }

    fn on_commit_success(&mut self) {
        self.epoch += 1;
        self.dirty = false;
        self.in_tx = false;
    }

    fn on_commit_failed(&mut self) {
        let _ = self.cache.get_mut().take();
        self.dirty = false;
        self.in_tx = false;
    }
}

impl<T> TransactionalStorage for CachedDbStore<T>
where
    T: Debug + Clone + Serialize + for<'a> Deserialize<'a> + Send + Sync,
{
    fn start_transaction(&mut self) -> Result<()> {
        ensure!(!self.in_tx, "already in a transaction");

        self.in_tx = true;
        Ok(())
    }

    async fn commit_transaction(&mut self) -> Result<()> {
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
        err.context("while commiting transaction")
    }
}

impl<T> SqlTransactionStorage for CachedDbStore<T>
where
    T: Debug + Clone + Serialize + for<'a> Deserialize<'a> + Send + Sync,
{
    async fn commit_in(&mut self, tx: &mut tokio_postgres::Transaction<'_>) -> Result<()> {
        self.commit_in_transaction(tx).await
    }

    fn commit_success(&mut self) {
        self.on_commit_success()
    }

    fn commit_failed(&mut self) {
        self.on_commit_failed()
    }
}

impl<T> EpochStorage<T> for CachedDbStore<T>
where
    T: Debug + Clone + Sync + Serialize + for<'a> Deserialize<'a> + Send,
{
    async fn fetch(&self) -> T {
        if self.cache.read().await.is_none() {
            let connection = self.db.get().await.unwrap();
            let row = connection
                .query_one(
                    // Fetch the row with the most recent __valid_from
                    &format!(
                        "SELECT payload FROM {}_meta WHERE __valid_from <= $1 AND $1 <= __valid_until",
                        self.table
                    ),
                    &[&self.epoch],
                )
                .await
                .expect("failed to fetch state");
            let state = row.get::<_, Json<T>>(0).0;
            let _ = self.cache.write().await.replace(state);
        }
        self.cache.read().await.to_owned().unwrap()
    }

    async fn fetch_at(&self, epoch: Epoch) -> T {
        let connection = self.db.get().await.unwrap();
        connection
            .query_one(
                &format!(
                    "SELECT payload FROM {}_meta WHERE __valid_from <= $1 AND $1 <= __valid_until",
                    self.table,
                ),
                &[&epoch],
            )
            .await
            .map(|row| row.get::<_, Json<T>>(0).0)
            .with_context(|| {
                anyhow!(
                    "failed to fetch state from `{}_meta` at epoch `{}`",
                    self.table,
                    epoch
                )
            })
            .unwrap()
    }

    async fn store(&mut self, t: T) {
        self.dirty = true;
        let _ = self.cache.write().await.insert(t);
    }

    fn current_epoch(&self) -> Epoch {
        self.epoch
    }

    async fn rollback_to(&mut self, new_epoch: Epoch) -> Result<()> {
        ensure!(
            new_epoch >= self.initial_epoch,
            "unable to rollback to {} before initial epoch {}",
            new_epoch,
            self.initial_epoch
        );
        ensure!(
            new_epoch < self.current_epoch(),
            "unable to rollback into the future: requested epoch ({}) > current epoch ({})",
            new_epoch,
            self.current_epoch()
        );

        let _ = self.cache.get_mut().take();
        let mut connection = self.db.get().await.unwrap();
        let db_tx = connection
            .transaction()
            .await
            .expect("unable to create DB transaction");
        // Roll back all living nodes by 1
        db_tx
            .query(
                &format!(
                    "UPDATE {}_meta SET __valid_until = $1 WHERE __valid_until > $1",
                    self.table
                ),
                &[&new_epoch],
            )
            .await?;
        // Delete nodes that would not have been born yet
        db_tx
            .query(
                &format!("DELETE FROM {}_meta WHERE __valid_from > $1", self.table),
                &[&new_epoch],
            )
            .await?;
        db_tx.commit().await?;
        self.epoch = new_epoch;

        Ok(())
    }
}

/// A `CachedDbStore` keeps a cache of all the storage operations that occured
/// during the current transaction, while falling back to the given database
/// when referring to older epochs.
pub struct CachedDbTreeStore<T, V>
where
    T: TreeTopology + DbConnector<T::Key, T::Node, V>,
    T::Key: ToFromBytea,
    V: Debug + Clone + Send + Sync + Serialize + for<'a> Deserialize<'a>,
{
    /// The initial epoch
    initial_epoch: Epoch,
    /// The latest *commited* epoch
    epoch: Epoch,
    /// A pointer to the DB client
    db: DBPool,
    /// DB backing this cache
    table: String,
    /// Operations pertaining to the in-process transaction.
    pub(super) nodes_cache: HashMap<T::Key, Option<CachedValue<T::Node>>>,
    pub(super) payload_cache: HashMap<T::Key, Option<CachedValue<V>>>,
    _p: PhantomData<T>,
}
impl<T, V> CachedDbTreeStore<T, V>
where
    T: TreeTopology + DbConnector<T::Key, T::Node, V>,
    T::Key: ToFromBytea,
    V: Debug + Clone + Send + Sync + Serialize + for<'a> Deserialize<'a>,
{
    pub fn new(initial_epoch: Epoch, current_epoch: Epoch, table: String, db: DBPool) -> Self {
        CachedDbTreeStore {
            initial_epoch,
            epoch: current_epoch,
            table,
            db: db.clone(),
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
        let connection = self.db.get().await.unwrap();
        connection
            .query_one(
                &format!(
                    "SELECT COUNT(*) FROM {} WHERE __valid_from <= $1 AND $1 <= __valid_until",
                    self.table
                ),
                &[&self.epoch],
            )
            .await
            .ok()
            .map(|row| row.get::<_, i64>(0))
            .unwrap_or(0)
            .try_into()
            .context("while counting rows")
            .unwrap()
    }

    pub(super) async fn rollback_to(&mut self, new_epoch: Epoch) -> Result<()> {
        ensure!(
            new_epoch >= self.initial_epoch,
            "unable to rollback to {} before initial epoch {}",
            new_epoch,
            self.initial_epoch
        );
        ensure!(
            new_epoch < self.current_epoch(),
            "unable to rollback into the future: requested epoch ({}) > current epoch ({})",
            new_epoch,
            self.current_epoch()
        );

        self.nodes_cache.clear();
        self.payload_cache.clear();
        let mut connection = self.db.get().await.unwrap();
        let db_tx = connection
            .transaction()
            .await
            .expect("unable to create DB transaction");
        // Roll back all living nodes by 1
        db_tx
            .query(
                &format!(
                    "UPDATE {} SET __valid_until = $1 WHERE __valid_until > $1",
                    self.table
                ),
                &[&new_epoch],
            )
            .await?;
        // Delete nodes that would not have been born yet
        db_tx
            .query(
                &format!("DELETE FROM {} WHERE __valid_from > $1", self.table),
                &[&new_epoch],
            )
            .await?;
        db_tx.commit().await?;
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
    T: TreeTopology + DbConnector<T::Key, T::Node, V>,
    T::Key: ToFromBytea,
    V: Debug + Clone + Send + Sync + Serialize + for<'a> Deserialize<'a>,
{
    pub(super) wrapped: Arc<Mutex<CachedDbTreeStore<T, V>>>,
}
impl<T, V> RoEpochKvStorage<T::Key, T::Node> for NodeProjection<T, V>
where
    T: TreeTopology + DbConnector<T::Key, T::Node, V>,
    T::Key: ToFromBytea,
    V: PayloadInDb,
{
    delegate::delegate! {
        to self.wrapped.lock().unwrap() {
            fn initial_epoch(&self) -> Epoch ;
            fn current_epoch(&self) -> Epoch ;
            async fn size(&self) -> usize;
        }
    }

    fn try_fetch_at(
        &self,
        k: &T::Key,
        epoch: Epoch,
    ) -> impl Future<Output = Option<T::Node>> + Send {
        let db = self.wrapped.lock().unwrap().db.clone();
        let table = self.wrapped.lock().unwrap().table.to_owned();
        async move {
            if epoch == self.current_epoch() {
                // Directly returns the value if it is already in cache, fetch it from
                // the DB otherwise.
                let value = self.wrapped.lock().unwrap().nodes_cache.get(k).cloned();
                if let Some(Some(cached_value)) = value {
                    Some(cached_value.into_value())
                } else if let Some(value) = T::fetch_node_at(db, &table, k, epoch).await.unwrap() {
                    let mut guard = self.wrapped.lock().unwrap();
                    guard
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
}
impl<T, V> EpochKvStorage<T::Key, T::Node> for NodeProjection<T, V>
where
    T: TreeTopology + DbConnector<T::Key, T::Node, V>,
    T::Key: ToFromBytea,
    T::Node: Sync + Clone,
    V: PayloadInDb,
{
    delegate::delegate! {
        to self.wrapped.lock().unwrap() {
            async fn rollback_to(&mut self, epoch: Epoch) -> Result<()>;
        }
    }

    fn remove(&mut self, k: T::Key) -> impl Future<Output = Result<()>> + Send {
        self.wrapped.lock().unwrap().nodes_cache.insert(k, None);
        async { Ok(()) }
    }

    fn update(&mut self, k: T::Key, new_value: T::Node) -> impl Future<Output = Result<()>> + Send {
        // If the operation is already present from a read, replace it with the
        // new value.
        self.wrapped
            .lock()
            .unwrap()
            .nodes_cache
            .insert(k, Some(CachedValue::Written(new_value)));
        async { Ok(()) }
    }

    fn store(&mut self, k: T::Key, value: T::Node) -> impl Future<Output = Result<()>> + Send {
        // If the operation is already present from a read, replace it with the
        // new value.
        self.wrapped
            .lock()
            .unwrap()
            .nodes_cache
            .insert(k, Some(CachedValue::Written(value)));
        async { Ok(()) }
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
    T: TreeTopology + DbConnector<T::Key, T::Node, V>,
    T::Key: ToFromBytea,
    V: Debug + Clone + Send + Sync + Serialize + for<'a> Deserialize<'a>,
{
    pub(super) wrapped: Arc<Mutex<CachedDbTreeStore<T, V>>>,
}
impl<T, V> RoEpochKvStorage<T::Key, V> for PayloadProjection<T, V>
where
    T: TreeTopology + DbConnector<T::Key, T::Node, V>,
    T::Key: ToFromBytea,
    V: PayloadInDb,
{
    delegate::delegate! {
        to self.wrapped.lock().unwrap() {
            fn initial_epoch(&self) -> Epoch ;
            fn current_epoch(&self) -> Epoch ;
            async fn size(&self) -> usize ;
        }
    }

    fn try_fetch_at(&self, k: &T::Key, epoch: Epoch) -> impl Future<Output = Option<V>> + Send {
        let db = self.wrapped.lock().unwrap().db.clone();
        let table = self.wrapped.lock().unwrap().table.to_owned();
        async move {
            if epoch == self.current_epoch() {
                // Directly returns the value if it is already in cache, fetch it from
                // the DB otherwise.
                let value = self.wrapped.lock().unwrap().payload_cache.get(k).cloned();
                if let Some(Some(cached_value)) = value {
                    Some(cached_value.into_value())
                } else if let Some(value) = T::fetch_payload_at(db, &table, k, epoch).await.unwrap()
                {
                    let mut guard = self.wrapped.lock().unwrap();
                    guard
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
}
impl<T, V> EpochKvStorage<T::Key, V> for PayloadProjection<T, V>
where
    T: TreeTopology + DbConnector<T::Key, T::Node, V>,
    T::Key: ToFromBytea,
    T::Node: Sync + Clone,
    V: PayloadInDb,
{
    delegate::delegate! {
        to self.wrapped.lock().unwrap() {
            async fn rollback_to(&mut self, epoch: Epoch) -> Result<()>;
        }
    }

    fn remove(&mut self, k: T::Key) -> impl Future<Output = Result<()>> + Send {
        self.wrapped.lock().unwrap().nodes_cache.insert(k, None);
        async { Ok(()) }
    }

    fn update(&mut self, k: T::Key, new_value: V) -> impl Future<Output = Result<()>> + Send {
        // If the operation is already present from a read, replace it with the
        // new value.
        self.wrapped
            .lock()
            .unwrap()
            .payload_cache
            .insert(k, Some(CachedValue::Written(new_value)));
        async { Ok(()) }
    }

    fn store(&mut self, k: T::Key, value: V) -> impl Future<Output = Result<()>> + Send {
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
