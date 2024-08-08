use std::{collections::HashMap, fmt::Debug, marker::PhantomData};

use anyhow::*;
use async_trait::async_trait;
use bb8::Pool;
use bb8_postgres::PostgresConnectionManager;
use postgres_types::Json;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tokio_postgres;
use tokio_postgres::{NoTls, Row};

use crate::{
    storage::{EpochKvStorage, EpochStorage, RoEpochKvStorage, TransactionalStorage},
    tree::scapegoat,
    Epoch,
};

use super::{CachedValue, ToFromBytea};

pub type DBPool = Pool<PostgresConnectionManager<NoTls>>;

/// Type implementing this trait define the behavior of a storage tree
/// components regarding their persistence in DB.
#[async_trait]
pub trait DbConnector<K, V>
where
    K: ToFromBytea,
    V: Clone + Send + Sync,
{
    /// Return a list of pairs column name, SQL type required by the connector.
    fn columns() -> &'static [(&'static str, &'static str)];

    /// Within a PgSQL transaction, insert the given value at the given epoch.
    async fn insert_in_tx(
        _db_tx: &tokio_postgres::Transaction<'_>,
        _table: &str,
        _k: &K,
        _birth_epoch: Epoch,
        _v: V,
    ) -> Result<()>
    where
        V: 'async_trait,
    {
        unreachable!()
    }

    /// Within a PgSQL transaction, update the value associated at the given
    /// epoch to the given key.
    async fn set_at_in_tx(
        _db_tx: &tokio_postgres::Transaction<'_>,
        _table: &str,
        _k: &K,
        _epoch: Epoch,
        _v: V,
    ) -> Result<()>
    where
        V: 'async_trait,
    {
        unreachable!()
    }

    /// Return the value associated to the given key at the given epoch.
    async fn fetch_at(db: DBPool, table: &str, k: &K, epoch: Epoch) -> Result<Option<V>>;

    /// Given a PgSQL row, extract a value from it.
    fn from_row(r: &Row) -> Result<V>;
}

pub struct PayloadConnector;

#[async_trait]
impl<K, V> DbConnector<K, V> for PayloadConnector
where
    K: ToFromBytea,
    V: Serialize + for<'a> Deserialize<'a> + Clone + Send + Sync + Debug,
    K: Send + Sync,
{
    fn columns() -> &'static [(&'static str, &'static str)] {
        &[("payload", "JSONB")]
    }

    async fn fetch_at(db: DBPool, table: &str, k: &K, epoch: Epoch) -> Result<Option<V>> {
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

    fn from_row(row: &Row) -> Result<V> {
        row.try_get::<_, Json<V>>("payload")
            .map(|x| x.0)
            .context("while parsing payload from row")
    }

    async fn set_at_in_tx(
        db_tx: &tokio_postgres::Transaction<'_>,
        table: &str,
        k: &K,
        epoch: Epoch,
        v: V,
    ) -> Result<()>
    where
        V: 'async_trait,
    {
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
}

// Void nodes are used by the SBBST
pub struct NodeConnector;

#[async_trait]
impl<K> DbConnector<K, ()> for NodeConnector
where
    K: ToFromBytea + Send + Sync,
{
    fn columns() -> &'static [(&'static str, &'static str)] {
        &[]
    }

    async fn fetch_at(db: DBPool, table: &str, k: &K, epoch: Epoch) -> Result<Option<()>> {
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

    fn from_row(_r: &Row) -> Result<()> {
        Ok(())
    }

    async fn insert_in_tx(
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
}

#[async_trait]
impl<K> DbConnector<K, scapegoat::Node<K>> for NodeConnector
where
    K: ToFromBytea + Send + Sync,
{
    fn columns() -> &'static [(&'static str, &'static str)] {
        &[
            ("parent", "BYTEA"),
            ("left_child", "BYTEA"),
            ("right_child", "BYTEA"),
            ("subtree_size", "BIGINT"),
        ]
    }

    async fn fetch_at(
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
                 WHERE key=$1 AND __valid_from<=$2 AND $2<=__valid_until",
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

    fn from_row(r: &Row) -> Result<scapegoat::Node<K>> {
        Ok(scapegoat::Node {
            k: K::from_bytea(r.try_get::<_, Vec<u8>>("key")?),
            subtree_size: r.try_get::<_, i64>("subtree_size")?.try_into().unwrap(),
            parent: r
                .try_get::<_, Option<Vec<u8>>>("parent")?
                .map(K::from_bytea),
            left: r
                .try_get::<_, Option<Vec<u8>>>("left_child")?
                .map(K::from_bytea),
            right: r
                .try_get::<_, Option<Vec<u8>>>("right_child")?
                .map(K::from_bytea),
        })
    }

    async fn insert_in_tx(
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
}

pub struct CachedDbStore<V: Debug + Clone + Sync + Serialize + for<'a> Deserialize<'a>> {
    /// A pointer to the DB client
    db: DBPool,
    in_tx: bool,
    dirty: bool,
    epoch: Epoch,
    table: String,
    pub(super) cache: RwLock<Option<V>>,
}
impl<T: Debug + Clone + Sync + Serialize + for<'a> Deserialize<'a>> CachedDbStore<T> {
    pub fn new(epoch: Epoch, table: String, db: DBPool) -> Self {
        Self {
            db,
            in_tx: false,
            dirty: true,
            epoch,
            table,
            cache: RwLock::new(None),
        }
    }

    /// Initialize a new store, with the given state. The initial state is
    /// immediately persisted, as the DB representation of the payload must be
    /// valid even if it is never modified further by the user.
    pub async fn with_value(epoch: Epoch, table: String, db: DBPool, t: T) -> Result<Self> {
        {
            let connection = db.get().await.unwrap();
            connection
                .query(
                    &format!(
                        "INSERT INTO {}_meta (__valid_from, __valid_until, payload)
                     VALUES ($1, $1, $2)",
                        table
                    ),
                    &[&epoch, &Json(t.clone())],
                )
                .await?;
        }

        Ok(Self {
            db,
            in_tx: false,
            dirty: true,
            epoch,
            table,
            cache: RwLock::new(Some(t)),
        })
    }
}

#[async_trait]
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
        ensure!(self.in_tx, "not in a transaction");

        let connection = self.db.get().await.unwrap();
        if self.dirty {
            let state = self.cache.read().await.clone();
            connection
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
            connection
                .query(
                    &format!(
                        "UPDATE {}_meta SET __valid_until = $1 + 1 WHERE __valid_until = $1",
                        self.table
                    ),
                    &[&(self.epoch)],
                )
                .await?;
        }

        self.epoch += 1;
        self.dirty = false;
        self.in_tx = false;
        Ok(())
    }
}

#[async_trait]
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
            .expect("failed to fetch state")
    }

    async fn store(&mut self, t: T) {
        self.dirty = true;
        let _ = self.cache.write().await.insert(t);
    }

    fn current_epoch(&self) -> Epoch {
        self.epoch
    }

    async fn rollback_to(&mut self, new_epoch: Epoch) -> Result<()> {
        ensure!(new_epoch >= 0, "unable to rollback before epoch 0");
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
pub struct CachedDbKvStore<K, V, F>
where
    K: ToFromBytea + Send + Sync,
    V: Debug + Clone + Send + Sync,
    F: DbConnector<K, V>,
{
    /// The latest *commited* epoch
    epoch: Epoch,
    /// A pointer to the DB client
    db: DBPool,
    /// DB backing this cache
    table: String,
    /// Operations pertaining to the in-process transaction.
    pub(super) cache: RwLock<HashMap<K, Option<CachedValue<V>>>>,
    _p: PhantomData<F>,
}
impl<K, V, F> CachedDbKvStore<K, V, F>
where
    K: ToFromBytea + Send + Sync,
    V: Debug + Clone + Send + Sync,
    F: DbConnector<K, V>,
{
    pub fn new(epoch: Epoch, table: String, db: DBPool) -> Self {
        CachedDbKvStore {
            epoch,
            table,
            db: db.clone(),
            cache: Default::default(),
            _p: PhantomData,
        }
    }

    pub fn new_epoch(&mut self) {
        self.epoch += 1;
        self.cache.get_mut().clear();
    }
}

#[async_trait]
impl<K, V, F> RoEpochKvStorage<K, V> for CachedDbKvStore<K, V, F>
where
    K: ToFromBytea + Send + Sync + std::hash::Hash,
    V: Debug + Clone + Send + Sync,
    F: DbConnector<K, V> + Sync,
{
    fn current_epoch(&self) -> Epoch {
        self.epoch
    }

    async fn try_fetch_at(&self, k: &K, epoch: Epoch) -> Option<V> {
        if epoch == self.current_epoch() {
            // Directly returns the value if it is already in cache, fetch it from
            // the DB otherwise.
            let read_guard = self.cache.read().await;
            let value = read_guard.get(k).cloned();
            drop(read_guard);
            if let Some(Some(cached_value)) = value {
                Some(cached_value.into_value())
            } else if let Some(value) = F::fetch_at(self.db.clone(), &self.table, k, epoch)
                .await
                .unwrap()
            {
                let mut write_guard = self.cache.write().await;
                write_guard.insert(k.clone(), Some(CachedValue::Read(value.clone())));
                Some(value)
            } else {
                None
            }
        } else {
            F::fetch_at(self.db.clone(), &self.table, k, epoch)
                .await
                .unwrap()
        }
    }

    async fn size(&self) -> usize {
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
}

#[async_trait]
impl<K, V, F: DbConnector<K, V> + Send + Sync> EpochKvStorage<K, V> for CachedDbKvStore<K, V, F>
where
    K: ToFromBytea + Send + Sync + std::hash::Hash,
    V: Debug + Clone + Send + Sync,
    F: DbConnector<K, V> + Send + Sync,
{
    // Operations are stored in the cache; persistence to the DB only occurs on
    // transaction commiting.
    async fn update(&mut self, k: K, new_value: V) -> Result<()> {
        // If the operation is already present from a read, replace it with the
        // new value.
        self.cache
            .get_mut()
            .insert(k, Some(CachedValue::Written(new_value)));
        Ok(())
    }

    async fn store(&mut self, k: K, value: V) -> Result<()> {
        // If the operation is already present from a read, replace it with the
        // new value.
        self.cache
            .get_mut()
            .insert(k, Some(CachedValue::Written(value)));
        Ok(())
    }

    async fn remove(&mut self, k: K) -> Result<()> {
        self.cache.get_mut().insert(k, None);
        Ok(())
    }

    async fn rollback_to(&mut self, new_epoch: Epoch) -> Result<()> {
        ensure!(new_epoch >= 0, "unable to rollback before epoch 0");
        ensure!(
            new_epoch < self.current_epoch(),
            "unable to rollback into the future: requested epoch ({}) > current epoch ({})",
            new_epoch,
            self.current_epoch()
        );

        self.cache.get_mut().clear();
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
