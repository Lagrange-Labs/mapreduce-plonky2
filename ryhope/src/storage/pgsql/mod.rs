use self::storages::{CachedDbStore, CachedDbTreeStore, DbConnector};
use super::{
    EpochStorage, FromSettings, MetaOperations, PayloadStorage, SqlTransactionStorage,
    TransactionalStorage, TreeStorage, WideLineage,
};
use crate::{
    error::{ensure, RyhopeError},
    tree::{NodeContext, TreeTopology},
    Epoch, InitSettings, KEY, PAYLOAD, VALID_FROM, VALID_UNTIL,
};
use bb8_postgres::PostgresConnectionManager;
use futures::TryFutureExt;
use itertools::Itertools;
use postgres_types::ToSql;
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, fmt::Debug, future::Future, sync::Arc};
use storages::{NodeProjection, PayloadProjection};
use tokio::sync::Mutex;
use tokio_postgres::{Client, GenericClient, NoTls, ToStatement, Transaction};
use tracing::*;

mod storages;

const MAX_PGSQL_BIGINT: i64 = i64::MAX;

pub type DBPool = bb8::Pool<PostgresConnectionManager<NoTls>>;
pub trait DbBackend: GenericClient + Send + Sync {}

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

impl ToFromBytea for Vec<u8> {
    fn to_bytea(&self) -> Vec<u8> {
        self.clone()
    }

    fn from_bytea(bytes: Vec<u8>) -> Self {
        bytes
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
pub trait PayloadInDb: Clone + Send + Sync + Debug + Serialize + for<'a> Deserialize<'a> {}
impl<T: Debug + Clone + Send + Sync + Serialize + for<'a> Deserialize<'a>> PayloadInDb for T {}

/// If it exists, remove the given table from the current database.
async fn delete_storage_table<B: GenericClient>(db: &B, table: &str) -> Result<(), RyhopeError> {
    db.execute(&format!("DROP TABLE IF EXISTS {}", table), &[])
        .await
        .map_err(|err| RyhopeError::from_db(format!("unable to delete table `{table}`"), err))
        .map(|_| ())?;
    db.execute(&format!("DROP TABLE IF EXISTS {}_meta", table), &[])
        .await
        .map_err(|err| RyhopeError::from_db(format!("unable to delete table `{table}`"), err))
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

/// Multiple ways to get a connection to the database server.
pub enum SqlServerConnection {
    /// Connection information to the PgSQL server; may be defined in k=v
    /// format, or as a URI.
    NewConnection(String),
    /// An existing connection pool
    Pool(DBPool),
}

/// The settings required to instantiate a [`PgsqlStorage`] from a PgSQL server.
pub struct SqlStorageSettings<T> {
    /// The table to use.
    pub(crate) table: String,
    /// A way to connect to the DB server
    pub(crate) source: T,
}
impl SqlStorageSettings<Client> {
    pub fn from_client(source: Client, table: String) -> Self {
        Self { table, source }
    }

    pub async fn from_url(db_url: &str, table: String) -> Result<Self, RyhopeError> {
        // Connect to the database.
        let (client, connection) = tokio_postgres::connect(db_url, NoTls)
            .await
            .map_err(|e| RyhopeError::from_db("connecting to database", e))?;

        // The connection object performs the actual communication with the database,
        // so spawn it off to run on its own.
        tokio::spawn(async move {
            if let Err(e) = connection.await {
                error!("failed to connect to DB: {}", e);
            }
        });

        Ok(Self {
            table,
            source: client,
        })
    }
}

/// Return the current epoch for a given table pair. Note that there always will
/// be a matching row, for the state initialization will always commit the
/// initial state to the database, even if the tree is left empty.
///
/// Fail if the DB query fails.
async fn fetch_epoch_data<B: GenericClient>(
    db: &B,
    table: &str,
) -> Result<(i64, i64), RyhopeError> {
    trace!("fetching epoch data for `{table}`");
    db.query_one(
        &format!("SELECT MIN({VALID_FROM}), MAX({VALID_UNTIL}) FROM {table}_meta",),
        &[],
    )
    .await
    .map(|r| (r.get(0), r.get(1)))
    .map_err(|err| RyhopeError::from_db("fetching current epoch data", err))
}

// /// Initialize a DB pool.
// pub async fn init_db_pool<B: GenericClient>(
//     db_src: &SqlServerConnection,
// ) -> Result<B, RyhopeError> {
//     match db_src {
//         SqlServerConnection::NewConnection(db_url) => {
//             info!("Connecting to `{db_url}`");
//             // Connect to the database.
//             let (client, connection) =
//                 tokio_postgres::connect("host=localhost user=postgres", NoTls).await?;

//             // The connection object performs the actual communication with the database,
//             // so spawn it off to run on its own.
//             tokio::spawn(async move {
//                 if let Err(e) = connection.await {
//                     error!("failed to connect to DB: {}", e);
//                 }
//             });

//             Ok(client)
//         }
//         SqlServerConnection::Pool(pool) => Ok(Box::new(pool.clone().get().await.unwrap())),
//     }
// }

pub struct PgsqlStorage<T, V, B>
where
    T: TreeTopology + DbConnector<V>,
    T::Key: ToFromBytea,
    T::Node: Sync + Clone,
    V: PayloadInDb + Send + Sync,
    B: GenericClient + Send + Sync,
{
    /// The table in which this tree will be stored
    table: String,
    /// A connection to the PostgreSQL server
    db: Arc<Mutex<B>>,
    /// The current epoch
    epoch: i64,
    /// Tree state information
    state: CachedDbStore<T::State, B>,
    /// Topological information
    tree_store: Arc<std::sync::Mutex<CachedDbTreeStore<T, V, B>>>,
    nodes: NodeProjection<T, V, B>,
    payloads: PayloadProjection<T, V, B>,
    /// If any, the transaction progress
    in_tx: bool,
}

impl<T, V> FromSettings<T::State> for PgsqlStorage<T, V, Client>
where
    T: TreeTopology + DbConnector<V>,
    T::Key: ToFromBytea,
    T::Node: Sync + Clone,
    T::State: Sync + Clone,
    V: PayloadInDb + Send + Sync,
{
    type Settings = SqlStorageSettings<Client>;

    async fn from_settings(
        init_settings: InitSettings<T::State>,
        storage_settings: Self::Settings,
    ) -> Result<Self, RyhopeError> {
        match init_settings {
            InitSettings::MustExist => {
                Self::load_existing(storage_settings.source, storage_settings.table).await
            }
            InitSettings::MustNotExist(tree_state) => {
                Self::create_new_at(
                    storage_settings.source,
                    storage_settings.table,
                    tree_state,
                    0,
                )
                .await
            }
            InitSettings::MustNotExistAt(tree_state, epoch) => {
                Self::create_new_at(
                    storage_settings.source,
                    storage_settings.table,
                    tree_state,
                    epoch,
                )
                .await
            }
            InitSettings::Reset(tree_settings) => {
                Self::reset_at(
                    storage_settings.source,
                    storage_settings.table,
                    tree_settings,
                    0,
                )
                .await
            }
            InitSettings::ResetAt(tree_settings, initial_epoch) => {
                Self::reset_at(
                    storage_settings.source,
                    storage_settings.table,
                    tree_settings,
                    initial_epoch,
                )
                .await
            }
        }
    }
}

impl<'a, T, V> FromSettings<T::State> for PgsqlStorage<T, V, Transaction<'a>>
where
    T: TreeTopology + DbConnector<V>,
    T::Key: ToFromBytea,
    T::Node: Sync + Clone,
    T::State: Sync + Clone,
    V: PayloadInDb + Send + Sync,
{
    type Settings = SqlStorageSettings<Transaction<'a>>;

    async fn from_settings(
        init_settings: InitSettings<T::State>,
        storage_settings: Self::Settings,
    ) -> Result<Self, RyhopeError> {
        match init_settings {
            InitSettings::MustExist => {
                Self::load_existing(storage_settings.source, storage_settings.table).await
            }
            InitSettings::MustNotExist(tree_state) => {
                Self::create_new_at(
                    storage_settings.source,
                    storage_settings.table,
                    tree_state,
                    0,
                )
                .await
            }
            InitSettings::MustNotExistAt(tree_state, epoch) => {
                Self::create_new_at(
                    storage_settings.source,
                    storage_settings.table,
                    tree_state,
                    epoch,
                )
                .await
            }
            InitSettings::Reset(tree_settings) => {
                Self::reset_at(
                    storage_settings.source,
                    storage_settings.table,
                    tree_settings,
                    0,
                )
                .await
            }
            InitSettings::ResetAt(tree_settings, initial_epoch) => {
                Self::reset_at(
                    storage_settings.source,
                    storage_settings.table,
                    tree_settings,
                    initial_epoch,
                )
                .await
            }
        }
    }
}

impl<T, V, B> std::fmt::Display for PgsqlStorage<T, V, B>
where
    T: TreeTopology + DbConnector<V>,
    T::Key: ToFromBytea,
    V: PayloadInDb,
    T::Node: Sync + Clone,
    T::State: Sync + Clone,
    B: GenericClient + Send + Sync,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PgSqlStorage {}@{}", self.table, self.epoch)
    }
}

impl<T, V, B> PgsqlStorage<T, V, B>
where
    T: TreeTopology + DbConnector<V>,
    T::Key: ToFromBytea,
    V: PayloadInDb,
    T::Node: Sync + Clone,
    T::State: Sync + Clone,
    B: GenericClient + Send + Sync,
{
    /// Create a new tree storage with the given initial epoch and its
    /// associated tables in the specified table.
    ///
    /// Will fail if the table already exists.
    pub async fn create_new_at(
        db: B,
        table: String,
        tree_state: T::State,
        epoch: Epoch,
    ) -> Result<PgsqlStorage<T, V, B>, RyhopeError> {
        debug!("creating new table for `{table}` at epoch {epoch}");
        ensure(
            fetch_epoch_data(&db, &table).await.is_err(),
            format!("table `{table}` already exists"),
        )?;
        Self::create_tables(&db, &table).await?;

        let db = Arc::new(Mutex::new(db));

        let tree_store = Arc::new(std::sync::Mutex::new(CachedDbTreeStore::new(
            epoch,
            epoch,
            table.clone(),
            db.clone(),
        )));
        let nodes = NodeProjection {
            wrapped: tree_store.clone(),
        };
        let payloads = PayloadProjection {
            wrapped: tree_store.clone(),
        };

        let r = Self {
            table: table.clone(),
            db: db.clone(),
            epoch,
            in_tx: false,
            tree_store,
            nodes,
            payloads,
            state: CachedDbStore::with_value(epoch, table.clone(), db.clone(), tree_state).await?,
        };
        Ok(r)
    }

    /// Create the tables required to store the a tree. For a given tree, two
    /// tables are required: the node table and the meta table. The node table,
    /// named as given, contains all the states of the tree nodes across the
    /// transactions they went through, hence allowing to access any of them at
    /// any timestamp of choice. Its columns are:
    ///   - key: byte-serialized key of this row node in the tree;
    ///   - VALID_FROM: from which epoch this row is valid;
    ///   - VALID_UNTIL: up to which epoch this row is valid;
    ///   - [tree-specific]: a set of columns defined by the tree DB connector
    ///     storing node-specific values depending on the tree implementation;
    ///   - [payload specific]: a column containing the payload of this node,
    ///     typically a JSONB-encoded serialized value.
    ///
    /// The meta-table, whose name is suffixed by `_meta`, contains similarly
    /// historic data, but storing the underlying tree inner state instead of
    /// the nodes. Combined with the node table, it allows to rebuild the whole
    /// underlying tree at any timestamp. Its columns are:
    ///   - VALID_FROM: from which epoch this row is valid;
    ///   - VALID_UNTIL: up to which epoch this row is valid;
    ///   - PAYLOAD: a JSONB-serialized value representing the inner state of
    ///     the tree at the given epoch range.
    ///
    /// Will fail if the CREATE is not valid (e.g. the table already exists)
    async fn create_tables(db: &B, table: &str) -> Result<(), RyhopeError> {
        let node_columns = <T as DbConnector<V>>::columns()
            .iter()
            .map(|(name, t)| format!("{name} {t},"))
            .join("\n");

        // The main table will store all the tree nodes and their payload.
        db.execute(
            &format!(
                "CREATE TABLE {table} (
                   {KEY}          BYTEA NOT NULL,
                   {VALID_FROM}   BIGINT NOT NULL,
                   {VALID_UNTIL}  BIGINT DEFAULT -1,
                   {node_columns}
                   UNIQUE ({KEY}, {VALID_FROM}))"
            ),
            &[],
        )
        .await
        .map(|_| ())
        .map_err(|err| RyhopeError::from_db(format!("creating table `{table}`"), err))?;

        // The meta table will store everything related to the tree itself.
        db.execute(
            &format!(
                "CREATE TABLE {table}_meta (
                   {VALID_FROM}   BIGINT NOT NULL UNIQUE,
                   {VALID_UNTIL}  BIGINT DEFAULT -1,
                   {PAYLOAD}      JSONB)"
            ),
            &[],
        )
        .await
        .map(|_| ())
        .map_err(|err| RyhopeError::from_db(format!("creating table `{table}_meta`"), err))?;

        Ok(())
    }

    /// Initialize the storage backend from an existing table in database.
    ///
    /// Fails if the specified table does not exist.
    pub async fn load_existing(db: B, table: String) -> Result<Self, RyhopeError> {
        let (initial_epoch, latest_epoch) = fetch_epoch_data(&db, &table).await?;
        debug!("loading `{table}`; latest epoch is {latest_epoch}");
        let db = Arc::new(Mutex::new(db));
        let tree_store = Arc::new(std::sync::Mutex::new(CachedDbTreeStore::new(
            initial_epoch,
            latest_epoch,
            table.clone(),
            db.clone(),
        )));
        let nodes = NodeProjection {
            wrapped: tree_store.clone(),
        };
        let payloads = PayloadProjection {
            wrapped: tree_store.clone(),
        };

        let r = Self {
            table: table.clone(),
            db: db.clone(),
            epoch: latest_epoch,
            state: CachedDbStore::new(initial_epoch, latest_epoch, table.clone(), db.clone()),
            tree_store,
            nodes,
            payloads,
            in_tx: false,
        };

        Ok(r)
    }

    /// Create a new tree storage and its associated table in the specified
    /// table, deleting it if it already exists.
    pub async fn reset_at(
        db: B,
        table: String,
        tree_state: T::State,
        initial_epoch: Epoch,
    ) -> Result<Self, RyhopeError> {
        debug!("resetting table `{table}` at epoch {initial_epoch}");
        delete_storage_table(&db, &table).await?;
        Self::create_tables(&db, &table).await?;

        let db = Arc::new(Mutex::new(db));

        let tree_store = Arc::new(std::sync::Mutex::new(CachedDbTreeStore::new(
            initial_epoch,
            initial_epoch,
            table.clone(),
            db.clone(),
        )));
        let nodes = NodeProjection {
            wrapped: tree_store.clone(),
        };
        let payloads = PayloadProjection {
            wrapped: tree_store.clone(),
        };

        let r = Self {
            table: table.clone(),
            db: db.clone(),
            epoch: initial_epoch,
            state: CachedDbStore::with_value(initial_epoch, table.clone(), db.clone(), tree_state)
                .await?,
            tree_store,
            nodes,
            payloads,
            in_tx: false,
        };

        Ok(r)
    }

    /// Close the lifetim of a row to `self.epoch`.
    async fn mark_dead(
        &self,
        db_tx: &tokio_postgres::Transaction<'_>,
        key: &T::Key,
    ) -> Result<Option<(T::Node, V)>, RyhopeError> {
        trace!("[{self}] marking {key:?} as dead @{}", self.epoch);
        let rows = db_tx
            .query(
                &format!(
                    "UPDATE {} SET {VALID_UNTIL}={} WHERE {KEY}=$1 AND {VALID_UNTIL}=$2 RETURNING *",
                    self.table,
                    self.epoch,
                ),
                &[&key.to_bytea(), &MAX_PGSQL_BIGINT],
            )
            .map_err(|err| RyhopeError::from_db("marking dead nodes", err))
            .await?;

        if rows.is_empty() {
            // The row may not exist
            Ok(None)
        } else if rows.len() == 1 {
            Ok(Some((
                T::node_from_row(&rows[0]),
                T::payload_from_row(&rows[0])?,
            )))
        } else {
            return Err(RyhopeError::fatal(format!(
                "[{self}] failed to roll back {key:?} to {}: {} rows matched the roll back query (i.e. {KEY} = {key:?} AND {VALID_UNTIL} = {})",
                self.epoch,
                rows.len(),
                self.epoch+1
            )));
        }
    }

    /// Birth a new node at the new epoch
    async fn new_node(
        &self,
        db_tx: &tokio_postgres::Transaction<'_>,
        k: &T::Key,
        n: T::Node,
    ) -> Result<(), RyhopeError> {
        trace!(
            "[{self}] creating a new instance for {k:?}@{}",
            self.epoch + 1
        );
        T::create_node_in_tx(db_tx, &self.table, k, self.epoch + 1, &n).await
    }

    async fn commit_in_transaction(
        &mut self,
        db_tx: &mut Transaction<'_>,
    ) -> Result<(), RyhopeError> {
        if !self.in_tx {
            return Err(RyhopeError::NotInATransaction);
        }
        trace!("[{self}] commiting in a transaction...");

        // The putative new stamps if everything goes well
        let new_epoch = self.epoch + 1;

        // Collect all the keys found in the caches
        let mut cached_keys = HashSet::new();
        {
            cached_keys.extend(self.tree_store.lock().unwrap().nodes_cache.keys().cloned());
        }
        {
            cached_keys.extend(
                self.tree_store
                    .lock()
                    .map_err(|e| {
                        RyhopeError::fatal(format!("failed to lock tree store mutex: {e:?}"))
                    })?
                    .payload_cache
                    .keys()
                    .cloned(),
            );
        }

        for k in cached_keys {
            let node_value = { self.tree_store.lock().unwrap().nodes_cache.get(&k).cloned() };
            let data_value = {
                self.tree_store
                    .lock()
                    .map_err(|e| {
                        RyhopeError::fatal(format!("failed to lock tree store mutex: {e:?}"))
                    })?
                    .payload_cache
                    .get(&k)
                    .cloned()
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
                        self.mark_dead(db_tx, &k).await?;
                    }

                    // The payload alone has been updated
                    (
                        Some(Some(CachedValue::Read(_))),
                        Some(Some(CachedValue::Written(new_payload))),
                    )
                    | (None, Some(Some(CachedValue::Written(new_payload)))) => {
                        // rollback the old value if any
                        let previous_node = self.mark_dead(db_tx, &k).await?.unwrap().0;
                        // write the new value
                        self.new_node(db_tx, &k, previous_node).await?;
                        T::set_at_in_tx(
                            db_tx,
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
                        let previous_state = self.mark_dead(db_tx, &k).await?;

                        // insert the new row representing the new state of the key...
                        self.new_node(db_tx, &k, new_node.to_owned()).await?;

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
                        T::set_at_in_tx(db_tx, &self.table, &k, new_epoch, payload)
                            .await?;
                    }

                    // A node cannot be removed through its payload
                    (_, Some(None)) => unreachable!(),
                }
        }
        self.state.commit_in(db_tx).await?;
        trace!("[{}] commit successful.", self.table);
        Ok(())
    }

    // FIXME: should return Result
    fn on_commit_success(&mut self) {
        assert!(self.in_tx);
        trace!(
            "[{self}] commit succesful; updating inner state - current epoch {}",
            self.epoch
        );
        self.in_tx = false;
        self.epoch += 1;
        self.state.commit_success();
        self.tree_store.lock().unwrap().new_epoch();
    }

    fn on_commit_failed(&mut self) {
        assert!(self.in_tx);
        trace!(
            "[{self}] commit failed; updating inner state - current epoch {}",
            self.epoch
        );
        self.in_tx = false;
        self.state.commit_failed();
        self.tree_store.lock().unwrap().clear();
    }
}

impl<T: TreeTopology, V: PayloadInDb, B> TransactionalStorage for PgsqlStorage<T, V, B>
where
    V: Send + Sync,
    T: DbConnector<V>,
    T::Key: ToFromBytea,
    T::Node: Send + Sync + Clone,
    T::State: Send + Sync + Clone,
    B: GenericClient + Send + Sync,
{
    fn start_transaction(&mut self) -> Result<(), RyhopeError> {
        if self.in_tx {
            return Err(RyhopeError::AlreadyInTransaction);
        }
        trace!("[{self}] starting a new transaction");
        self.in_tx = true;
        self.state.start_transaction()?;
        Ok(())
    }

    async fn commit_transaction(&mut self) -> Result<(), RyhopeError> {
        if !self.in_tx {
            return Err(RyhopeError::NotInATransaction);
        }
        trace!("[{self}] commiting transaction");
        let db = self.db.clone();
        let mut connection = db.lock().await;
        let mut db_tx = connection
            .transaction()
            .await
            .expect("unable to create DB transaction");

        self.commit_in_transaction(&mut db_tx).await?;

        // Atomically execute the PgSQL transaction
        let err = db_tx
            .commit()
            .await
            .map_err(|err| RyhopeError::from_db("committing transaction", err));
        if err.is_ok() {
            self.on_commit_success();
        } else {
            self.on_commit_failed();
        }
        err
    }
}

impl<T: TreeTopology, V: PayloadInDb, B> SqlTransactionStorage for PgsqlStorage<T, V, B>
where
    V: Send + Sync,
    T: DbConnector<V>,
    T::Key: ToFromBytea,
    T::Node: Send + Sync + Clone,
    T::State: Send + Sync + Clone,
    B: GenericClient + Send + Sync,
{
    async fn commit_in(&mut self, tx: &mut Transaction<'_>) -> Result<(), RyhopeError> {
        trace!("[{self}] API-facing commit_in called");
        self.commit_in_transaction(tx).await
    }

    fn commit_success(&mut self) {
        trace!("[{self}] API-facing commit_success called");
        self.on_commit_success();
    }

    fn commit_failed(&mut self) {
        trace!("[{self}] API-facing commit_failed called");
        self.on_commit_failed()
    }
}

impl<T, V, B> TreeStorage<T> for PgsqlStorage<T, V, B>
where
    T: TreeTopology + DbConnector<V>,
    V: PayloadInDb + Send,
    T::Key: ToFromBytea,
    T::Node: Sync + Clone,
    T::State: Debug + Sync + Clone + Serialize + for<'a> Deserialize<'a>,
    B: GenericClient + Send + Sync,
{
    type StateStorage = CachedDbStore<T::State, B>;
    type NodeStorage = NodeProjection<T, V, B>;

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
        self.db
            .lock()
            .await
            .query(
                &format!("SELECT {KEY} FROM {} WHERE {VALID_FROM}=$1", self.table),
                &[&epoch],
            )
            .await
            .expect("while fetching newborns from database")
            .iter()
            .map(|r| T::Key::from_bytea(r.get::<_, Vec<u8>>(0)))
            .collect::<Vec<_>>()
    }

    async fn rollback_to(&mut self, epoch: Epoch) -> Result<(), RyhopeError> {
        self.state.rollback_to(epoch).await?;
        self.tree_store.lock().unwrap().rollback_to(epoch).await?;
        self.epoch = epoch;

        // Ensure epochs coherence
        assert_eq!(
            self.state.current_epoch(),
            self.tree_store.lock().unwrap().current_epoch()
        );
        assert_eq!(self.state.current_epoch(), self.epoch);

        Ok(())
    }
}

impl<T, V, B> PayloadStorage<T::Key, V> for PgsqlStorage<T, V, B>
where
    Self: TreeStorage<T>,
    T: TreeTopology + DbConnector<V>,
    V: PayloadInDb + Send,
    T::Key: ToFromBytea,
    T::Node: Sync + Clone,
    T::State: Debug + Sync + Clone + Serialize + for<'a> Deserialize<'a>,
    V: Sync,
    B: GenericClient + Send + Sync,
{
    type DataStorage = PayloadProjection<T, V, B>;

    fn data(&self) -> &Self::DataStorage {
        &self.payloads
    }

    fn data_mut(&mut self) -> &mut Self::DataStorage {
        &mut self.payloads
    }
}

impl<T, V, B> MetaOperations<T, V> for PgsqlStorage<T, V, B>
where
    Self: TreeStorage<T>,
    T: TreeTopology + DbConnector<V>,
    V: PayloadInDb + Send,
    T::Key: ToFromBytea,
    T::Node: Sync + Clone,
    T::State: Debug + Sync + Clone + Serialize + for<'a> Deserialize<'a>,
    V: Sync,
    B: GenericClient + Send + Sync,
{
    type KeySource = String;

    async fn wide_lineage_between(
        &self,
        at: Epoch,
        t: &T,
        keys: &Self::KeySource,
        bounds: (Epoch, Epoch),
    ) -> Result<WideLineage<T::Key, V>, RyhopeError> {
        let r = t
            .wide_lineage_between(
                &self.view_at(at),
                self.db.clone(),
                &self.table,
                keys,
                bounds,
            )
            .await?;

        Ok(r)
    }

    fn try_fetch_many_at<I: IntoIterator<Item = (Epoch, <T as TreeTopology>::Key)> + Send>(
        &self,
        t: &T,
        data: I,
    ) -> impl Future<Output = Result<Vec<(Epoch, NodeContext<T::Key>, V)>, RyhopeError>> + Send
    where
        <I as IntoIterator>::IntoIter: Send,
    {
        trace!("[{self}] fetching many contexts & payloads",);
        let table = self.table.to_owned();
        async move { t.fetch_many_at(self, self.db.clone(), &table, data).await }
    }
}
