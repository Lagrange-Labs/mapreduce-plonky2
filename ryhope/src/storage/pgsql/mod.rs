use crate::storage::RoEpochKvStorage;
use crate::tree::TreeTopology;
use crate::{Epoch, InitSettings};
use std::collections::HashSet;
use std::fmt::Debug;
use std::hash::Hash;

use self::storages::{
    CachedDbKvStore, CachedDbStore, DbConnector, NodeConnector, PayloadConnector,
};

use super::{EpochKvStorage, EpochStorage, PayloadStorage};
use super::{FromSettings, TransactionalStorage, TreeStorage};
use crate::storage::pgsql::storages::DBPool;
use anyhow::*;
use async_trait::async_trait;
use bb8_postgres::PostgresConnectionManager;
use itertools::Itertools;
use log::*;
use serde::{Deserialize, Serialize};
use tokio_postgres::NoTls;

mod storages;

/// A trait that must be implemented by a custom node key. This allows to
/// (de)serialize any custom key to and fro a PgSQL BYTEA.
pub trait ToFromBytea: Clone + Eq {
    /// Return the BYTEA representation of this type to be stored in a PgSQL
    /// column.
    fn to_bytea(&self) -> Vec<u8>;

    /// Rebuild an instance of this type from a BYTEA fetchted from a PgSQL
    /// column.
    fn from_bytea(bytes: Vec<u8>) -> Self;
}

impl ToFromBytea for () {
    fn to_bytea(&self) -> Vec<u8> {
        Vec::new()
    }

    fn from_bytea(_bytes: Vec<u8>) -> Self {}
}

impl ToFromBytea for String {
    fn to_bytea(&self) -> Vec<u8> {
        self.as_bytes().to_vec()
    }

    fn from_bytea(bytes: Vec<u8>) -> Self {
        String::from_utf8(bytes).unwrap()
    }
}

impl ToFromBytea for i64 {
    fn to_bytea(&self) -> Vec<u8> {
        self.to_be_bytes().to_vec()
    }

    fn from_bytea(bytes: Vec<u8>) -> Self {
        Self::from_be_bytes(
            bytes
                .try_into()
                .map_err(|e| format!("unable to deserialize i64 from db: {e:?}"))
                .unwrap(),
        )
    }
}

impl ToFromBytea for usize {
    fn to_bytea(&self) -> Vec<u8> {
        self.to_be_bytes().to_vec()
    }

    fn from_bytea(bytes: Vec<u8>) -> Self {
        Self::from_be_bytes(
            bytes
                .try_into()
                .map_err(|e| format!("unable to deserialize usize from db: {e:?}"))
                .unwrap(),
        )
    }
}

/// Characterize a type that may be used as node payload.
#[async_trait]
pub trait PayloadInDb: Clone + Send + Sync + Debug + Serialize + for<'a> Deserialize<'a> {}
impl<T: Debug + Clone + Send + Sync + Serialize + for<'a> Deserialize<'a>> PayloadInDb for T {}

/// If it exists, remove the given table from the current database.
async fn delete_storage_table(db: DBPool, table: &str) -> Result<()> {
    let connection = db.get().await.unwrap();
    connection
        .execute(&format!("DROP TABLE IF EXISTS {}", table), &[])
        .await
        .with_context(|| format!("unable to delete table `{table}`"))
        .map(|_| ())?;
    connection
        .execute(&format!("DROP TABLE IF EXISTS {}_meta", table), &[])
        .await
        .with_context(|| format!("unable to delete table `{table}`"))
        .map(|_| ())
}

/// Keeps track of which kind of operation came into the cache
#[derive(Clone)]
enum CachedValue<T: Clone> {
    Read(T),
    Written(T),
}
impl<T: Clone> CachedValue<T> {
    fn into_value(self) -> T {
        match self {
            CachedValue::Read(v) | CachedValue::Written(v) => v,
        }
    }

    fn value(&self) -> &T {
        match self {
            CachedValue::Read(v) | CachedValue::Written(v) => v,
        }
    }
}
impl<T: Clone + Debug> Debug for CachedValue<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CachedValue::Read(r) => write!(f, "R:{:?}", r),
            CachedValue::Written(w) => write!(f, "W:{:?}", w),
        }
    }
}

/// The settings required to instantiate a [`PgsqlStorage`] from a PgSQL server.
pub struct SqlStorageSettings {
    /// Connection information to the PgSQL server; may be defined in k=v
    /// format, or as a URI.
    pub db_url: String,
    /// The table to use.
    pub table: String,
}

pub struct PgsqlStorage<T: TreeTopology, V>
where
    V: PayloadInDb + Send + Sync,
    T::Key: ToFromBytea,
    T::Node: Sync + Clone,
    NodeConnector: DbConnector<T::Key, T::Node>,
{
    /// The table in which this tree will be stored
    table: String,
    /// A connection to the PostgreSQL server
    db: DBPool,
    /// The current epoch
    epoch: i64,
    /// Tree state information
    state: CachedDbStore<T::State>,
    /// Topological information
    nodes: CachedDbKvStore<T::Key, T::Node, NodeConnector>,
    /// Node payloads
    data: CachedDbKvStore<T::Key, V, PayloadConnector>,
    /// If any, the transaction progress
    in_tx: bool,
}

#[async_trait]
impl<T, V> FromSettings<T::State> for PgsqlStorage<T, V>
where
    T: TreeTopology,
    T::Key: ToFromBytea,
    T::Node: Sync + Clone,
    T::State: Sync + Clone,
    V: PayloadInDb + Send + Sync,
    NodeConnector: DbConnector<T::Key, T::Node>,
{
    type Settings = SqlStorageSettings;

    async fn from_settings(
        init_settings: InitSettings<T::State>,
        storage_settings: Self::Settings,
    ) -> Result<Self> {
        match init_settings {
            InitSettings::MustExist => {
                Self::load_existing(&storage_settings.db_url, storage_settings.table).await
            }
            InitSettings::MustNotExist(tree_state) => {
                Self::create_new(&storage_settings.db_url, storage_settings.table, tree_state).await
            }
            InitSettings::Reset(tree_settings) => {
                Self::reset(
                    &storage_settings.db_url,
                    storage_settings.table,
                    tree_settings,
                )
                .await
            }
        }
    }
}

/// Return the current epoch for a given table pair. Note that there always will
/// be a matching row, for the state initialization will always commit the
/// initial state to the database, even if the tree is left empty.
///
/// Fail if the DB query fails.
async fn fetch_current_epoch(db: DBPool, table: &str) -> Result<i64> {
    let connection = db.get().await.unwrap();
    connection
        .query_one(&format!("SELECT MAX(valid_until) FROM {table}_meta",), &[])
        .await
        .map(|r| r.get(0))
        .context("while fetching current epoch")
}

impl<T, V> PgsqlStorage<T, V>
where
    T: TreeTopology,
    T::Key: ToFromBytea,
    V: PayloadInDb,
    T::Node: Sync + Clone,
    T::State: Sync + Clone,
    NodeConnector: DbConnector<T::Key, T::Node>,
{
    /// Create a new tree storage and its associated table in the specified table.
    ///
    /// Will fail if the table already exists.
    pub async fn create_new(db_url: &str, table: String, tree_state: T::State) -> Result<Self> {
        debug!("connecting to {db_url}...");
        let db_pool = Self::init_db_pool(db_url).await?;
        debug!("connection successful.");

        ensure!(
            fetch_current_epoch(db_pool.clone(), &table).await.is_err(),
            "table `{table}` already exists"
        );
        Self::create_tables(db_pool.clone(), &table).await?;

        let epoch = 0;
        let r = Self {
            table: table.clone(),
            db: db_pool.clone(),
            epoch,
            in_tx: false,
            nodes: CachedDbKvStore::new(epoch, table.clone(), db_pool.clone()),
            state: CachedDbStore::with_value(epoch, table.clone(), db_pool.clone(), tree_state)
                .await
                .context("failed to store initial state")?,
            data: CachedDbKvStore::new(epoch, table.clone(), db_pool.clone()),
        };
        Ok(r)
    }

    /// Initialize the storage backend from an existing table in database.
    ///
    /// Fails if the specified table does not exist.
    pub async fn load_existing(db_url: &str, table: String) -> Result<Self> {
        debug!("connecting to {db_url}...");
        let db_pool = Self::init_db_pool(db_url).await?;
        debug!("connection successful.");

        let latest_epoch = fetch_current_epoch(db_pool.clone(), &table)
            .await
            .with_context(|| format!("table `{table}` does not exist"))?;
        info!("latest epoch is {latest_epoch}");

        let r = Self {
            table: table.clone(),
            db: db_pool.clone(),
            epoch: latest_epoch,
            state: CachedDbStore::new(latest_epoch, table.clone(), db_pool.clone()),
            nodes: CachedDbKvStore::new(latest_epoch, table.clone(), db_pool.clone()),
            data: CachedDbKvStore::new(latest_epoch, table.clone(), db_pool.clone()),
            in_tx: false,
        };

        Ok(r)
    }

    /// Create a new tree storage and its associated table in the specified
    /// table, deleting it if it already exists.
    pub async fn reset(db_url: &str, table: String, tree_state: T::State) -> Result<Self> {
        debug!("connecting to {db_url}...");
        let db_pool = Self::init_db_pool(db_url).await?;
        debug!("connection successful.");

        delete_storage_table(db_pool.clone(), &table).await?;
        Self::create_tables(db_pool.clone(), &table).await?;
        let epoch = 0;

        let r = Self {
            table: table.clone(),
            db: db_pool.clone(),
            epoch,
            state: CachedDbStore::with_value(epoch, table.clone(), db_pool.clone(), tree_state)
                .await
                .context("failed to store initial state")?,

            nodes: CachedDbKvStore::new(epoch, table.clone(), db_pool.clone()),
            data: CachedDbKvStore::new(epoch, table.clone(), db_pool.clone()),
            in_tx: false,
        };

        Ok(r)
    }

    /// Initialize a DB pool.
    pub async fn init_db_pool(db_url: &str) -> Result<DBPool> {
        let db_manager = PostgresConnectionManager::new_from_stringlike(db_url, NoTls)
            .with_context(|| format!("while connecting to postgreSQL with `{}`", db_url))?;

        let db_pool = DBPool::builder()
            .build(db_manager)
            .await
            .context("while creating the db_pool")?;

        Ok(db_pool)
    }

    /// Create the tables required to store the a tree. For a given tree, two
    /// tables are required: the node table and the meta table. The node table,
    /// named as given, contains all the states of the tree nodes across the
    /// transactions they went through, hence allowing to access any of them at
    /// any timestamp of choice. Its columns are:
    ///   - key: byte-serialized key of this row node in the tree;
    ///   - valid_from: from which epoch this row is valid;
    ///   - valid_until: up to which epoch this row is valid;
    ///   - [tree-specific]: a set of columns defined by the tree DB connector
    ///     storing node-specific values depending on the tree implementation;
    ///   - [payload specific]: a column containing the payload of this node,
    ///     typically a JSONB-encoded serialized value.
    ///
    /// The meta-table, whose name is suffixed by `_meta`, contains similarly
    /// historic data, but storing the underlying tree inner state instead of
    /// the nodes. Combined with the node table, it allows to rebuild the whole
    /// underlying tree at any timestamp. Its columns are:
    ///   - valid_from: from which epoch this row is valid;
    ///   - valid_until: up to which epoch this row is valid;
    ///   - payload: a JSONB-serialized value representing the inner state of
    ///     the tree at the given epoch range.
    ///
    /// Will fail if the CREATE is not valid (e.g. the table already exists)
    async fn create_tables(db: DBPool, table: &str) -> Result<()> {
        let node_columns = <NodeConnector as DbConnector<T::Key, T::Node>>::columns()
            .iter()
            .chain(<PayloadConnector as DbConnector<T::Key, V>>::columns().iter())
            .map(|(name, t)| format!("{name} {t},"))
            .join("\n");

        // The main table will store all the tree nodes and their payload.
        let connection = db.get().await.unwrap();
        connection
            .execute(
                &format!(
                    "CREATE TABLE {table} (
                   key          BYTEA NOT NULL,
                   valid_from   BIGINT NOT NULL,
                   valid_until  BIGINT DEFAULT -1,
                   {node_columns}
                   UNIQUE (key, valid_from))"
                ),
                &[],
            )
            .await
            .map(|_| ())
            .with_context(|| format!("unable to create table `{table}`"))?;

        // The meta table will store everything related to the tree itself.
        connection
            .execute(
                &format!(
                    "CREATE TABLE {table}_meta (
                   valid_from   BIGINT NOT NULL UNIQUE,
                   valid_until  BIGINT DEFAULT -1,
                   payload      JSONB)"
                ),
                &[],
            )
            .await
            .map(|_| ())
            .with_context(|| format!("unable to create table `{table}_meta`"))
    }

    async fn update_all(&self, db_tx: &tokio_postgres::Transaction<'_>) -> Result<()> {
        let update_all = format!(
            "UPDATE {} SET valid_until=$1 WHERE valid_until=$2",
            self.table
        );

        db_tx
            .query(&update_all, &[&(&self.epoch + 1), &self.epoch])
            .await
            .context("while updating timestamps")
            .map(|_| ())
    }

    /// Roll-back to `self.epoch` the lifetime of a row having already been extended to `self.epoch + 1`.
    async fn rollback_one_row(
        &self,
        db_tx: &tokio_postgres::Transaction<'_>,
        key: &T::Key,
    ) -> Result<Option<(T::Node, V)>> {
        let rows = db_tx
            .query(
                &format!(
                    "UPDATE {} SET valid_until={} WHERE key=$1 AND valid_until={} RETURNING *",
                    self.table,
                    self.epoch,
                    self.epoch + 1
                ),
                &[&key.to_bytea()],
            )
            .await?;

        Ok(if rows.is_empty() {
            // The row may not exist
            None
        } else if rows.len() == 1 {
            Some((
                NodeConnector::from_row(&rows[0])?,
                <PayloadConnector as DbConnector<T::Key, V>>::from_row(&rows[0])?,
            ))
        } else {
            panic!("unexpected duplicated row");
        })
    }

    /// Birth a new node at the new epoch
    async fn new_node(
        &self,
        db_tx: &tokio_postgres::Transaction<'_>,
        k: &T::Key,
        n: T::Node,
    ) -> Result<()> {
        NodeConnector::insert_in_tx(db_tx, &self.table, k, self.epoch + 1, n).await
    }
}

#[async_trait]
impl<T: TreeTopology, V: PayloadInDb> TransactionalStorage for PgsqlStorage<T, V>
where
    V: Send + Sync,
    T::Key: ToFromBytea,
    T::Node: Send + Sync + Clone,
    T::State: Send + Sync + Clone,
    NodeConnector: DbConnector<T::Key, T::Node>,
{
    fn start_transaction(&mut self) -> Result<()> {
        ensure!(!self.in_tx, "already in a transaction");
        self.in_tx = true;
        self.state.start_transaction()?;
        Ok(())
    }

    async fn commit_transaction(&mut self) -> Result<()> {
        ensure!(self.in_tx, "not in a transaction");

        // The putative new stamps if everything goes well
        let new_epoch = self.epoch + 1;

        {
            // Open a PgSQL transaction, as we want the batch to be atomically
            // successful or failed.
            let mut connection = self.db.get().await.unwrap();
            let db_tx = connection
                .transaction()
                .await
                .expect("unable to create DB transaction");

            // Pre-emptively extend by 1 the lifetime of the currently alive rows;
            // those that should not be alive in the next epoch will be rolled back
            // later.
            self.update_all(&db_tx).await?;

            // Collect all the keys found in the caches
            let mut cached_keys = HashSet::new();
            {
                let guard = self.nodes.cache.read().await;
                cached_keys.extend(guard.keys().cloned());
            }
            {
                let guard = self.data.cache.read().await;
                cached_keys.extend(guard.keys().cloned());
            }

            for k in cached_keys {
                let node_value = {
                    let guard = self.nodes.cache.read().await;
                    guard.get(&k).cloned()
                };
                let data_value = {
                    let guard = self.data.cache.read().await;
                    guard.get(&k).cloned()
                };

                match (node_value, data_value) {
                    // Nothing or a combination of read-only operations, do nothing
                    (None, None) // will never happen by construction of cached_keys
                    | (None, Some(Some(CachedValue::Read(_))))
                    | (Some(Some(CachedValue::Read(_))), None)
                    | (Some(Some(CachedValue::Read(_))), Some(Some(CachedValue::Read(_)))) => {}

                    // The node has been removed
                    (Some(None), _) => {
                        // k has been deleted; simply roll-back the lifetime of its row.
                        self.rollback_one_row(&db_tx, &k).await?;
                    }

                    // The payload alone has been updated
                    (
                        Some(Some(CachedValue::Read(_))),
                        Some(Some(CachedValue::Written(new_payload))),
                    )
                    | (None, Some(Some(CachedValue::Written(new_payload)))) => {
                        // rollback the old value if any
                        let previous_node = self.rollback_one_row(&db_tx, &k).await?.unwrap().0;
                        // write the new value
                        self.new_node(&db_tx, &k, previous_node).await?;
                        PayloadConnector::set_at_in_tx(
                            &db_tx,
                            &self.table,
                            &k,
                            self.epoch + 1,
                            new_payload.to_owned(),
                        )
                        .await?;
                    }

                    // The node has been updated, maybe its payload as well
                    (Some(Some(CachedValue::Written(new_node))), maybe_new_payload) => {
                        // insertion or displacement in the tree; the row has to be
                        // duplicated/updated and rolled-back
                        let previous_state = self.rollback_one_row(&db_tx, &k).await?;

                        // insert the new row representing the new state of the key...
                        self.new_node(&db_tx, &k, new_node.to_owned()).await?;

                        // the new associated payload is the one present in the
                        // cache if any (that would reflect and insertion or an
                        // update), or the previous one (if the key moved in the
                        // tree, but the payload stayed the same).
                        let previous_payload = previous_state.as_ref().map(|x| x.1.clone());
                        let maybe_new_payload = maybe_new_payload
                            .and_then(|v| v.as_ref().map(|cv| cv.value().to_owned()));
                        let payload = maybe_new_payload
                            .or(previous_payload)
                            .expect("both old and new payloads are both None");
                        PayloadConnector::set_at_in_tx(&db_tx, &self.table, &k, new_epoch, payload)
                            .await?;
                    }

                    // A node cannot be removed through its payload
                    (_, Some(None)) => unreachable!(),
                }
            }

            // Atomically execute the PgSQL transaction
            db_tx
                .commit()
                .await
                .context("while committing transaction")?;
        }

        // Prepare the internal state for a new transaction
        self.in_tx = false;
        self.epoch = new_epoch;
        self.state.commit_transaction().await?;
        self.data.new_epoch();
        self.nodes.new_epoch();
        Ok(())
    }
}

#[async_trait]
impl<T, V> TreeStorage<T> for PgsqlStorage<T, V>
where
    T: TreeTopology,
    V: PayloadInDb + Send,
    T::Key: ToFromBytea,
    T::Node: Sync + Clone,
    T::State: Debug + Sync + Clone + Serialize + for<'a> Deserialize<'a>,
    NodeConnector: DbConnector<T::Key, T::Node>,

    CachedDbKvStore<T::Key, T::Node, NodeConnector>: EpochKvStorage<T::Key, T::Node>,
    CachedDbKvStore<T::Key, V, PayloadConnector>: EpochKvStorage<T::Key, V>,
{
    type NodeStorage = CachedDbKvStore<T::Key, T::Node, NodeConnector>;
    type StateStorage = CachedDbStore<T::State>;

    fn state(&self) -> &Self::StateStorage {
        &self.state
    }

    fn state_mut(&mut self) -> &mut Self::StateStorage {
        &mut self.state
    }

    fn nodes(&self) -> &Self::NodeStorage {
        &self.nodes
    }

    fn nodes_mut(&mut self) -> &mut Self::NodeStorage {
        &mut self.nodes
    }

    async fn born_at(&self, epoch: Epoch) -> Vec<T::Key> {
        let connection = self.db.get().await.unwrap();
        connection
            .query(
                &format!("SELECT key FROM {} WHERE valid_from=$1", self.table),
                &[&epoch],
            )
            .await
            .expect("while fetching newborns from database")
            .iter()
            .map(|r| T::Key::from_bytea(r.get::<_, Vec<u8>>(0)))
            .collect::<Vec<_>>()
    }

    async fn rollback_to(&mut self, epoch: Epoch) -> Result<()> {
        self.state.rollback_to(epoch).await?;
        self.nodes.rollback_to(epoch).await?;
        self.data.rollback_to(epoch).await?;
        self.epoch = epoch;

        // Ensure epochs coherence
        assert_eq!(self.state.current_epoch(), self.nodes.current_epoch());
        assert_eq!(self.state.current_epoch(), self.data.current_epoch());
        assert_eq!(self.state.current_epoch(), self.epoch);

        Ok(())
    }
}

#[async_trait]
impl<T, V> PayloadStorage<T::Key, V> for PgsqlStorage<T, V>
where
    T: TreeTopology,
    V: PayloadInDb + Send,
    T::Key: ToFromBytea,
    T::Node: Sync + Clone,
    T::State: Debug + Sync + Clone + Serialize + for<'a> Deserialize<'a>,
    NodeConnector: DbConnector<T::Key, T::Node>,

    CachedDbKvStore<T::Key, V, PayloadConnector>: EpochKvStorage<T::Key, V>,
    V: Sync,
    PayloadConnector: DbConnector<T::Key, V>,
{
    type DataStorage = CachedDbKvStore<T::Key, V, PayloadConnector>;

    fn data(&self) -> &Self::DataStorage {
        &self.data
    }

    fn data_mut(&mut self) -> &mut Self::DataStorage {
        &mut self.data
    }
}
