use self::storages::{CachedDbStore, CachedDbTreeStore, DbConnector};
use super::{
    EpochMapper, EpochStorage, FromSettings, MetaOperations, PayloadStorage, SharedEpochMapper,
    SqlTransactionStorage, TransactionalStorage, TreeStorage, WideLineage,
};
use crate::{
    error::{ensure, RyhopeError},
    mapper_table_name, metadata_table_name,
    storage::pgsql::storages::DBPool,
    tree::{NodeContext, TreeTopology},
    IncrementalEpoch, InitSettings, UserEpoch, INCREMENTAL_EPOCH, KEY, PAYLOAD, USER_EPOCH,
    VALID_FROM, VALID_UNTIL,
};
use bb8_postgres::PostgresConnectionManager;
use epoch_mapper::{EpochMapperStorage, INITIAL_INCREMENTAL_EPOCH};
use futures::TryFutureExt;
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, fmt::Debug, future::Future, sync::Arc};
use storages::{NodeProjection, PayloadProjection};
use tokio::sync::RwLock;
use tokio_postgres::{NoTls, Transaction};
use tracing::*;

mod epoch_mapper;
mod storages;

const MAX_PGSQL_BIGINT: i64 = i64::MAX;

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
async fn delete_storage_table<const EXTERNAL_EPOCH_MAPPER: bool>(db: DBPool, table: &str) -> Result<(), RyhopeError> {
    let connection = db.get().await.unwrap();
    connection
        .execute(&format!("DROP TABLE IF EXISTS {}", table), &[])
        .await
        .map_err(|err| RyhopeError::from_db(format!("unable to delete table `{table}`"), err))
        .map(|_| ())?;
    connection
        .execute(
            &format!("DROP TABLE IF EXISTS {}", metadata_table_name(table)),
            &[],
        )
        .await
        .map_err(|err| RyhopeError::from_db(format!("unable to delete table `{table}`"), err))
        .map(|_| ())?;
    if EXTERNAL_EPOCH_MAPPER {
        // The epoch mapper is external, so we just need to delete the view
        let mapper_table_alias = mapper_table_name(table);
        connection
            .execute(&format!("DROP VIEW IF EXISTS {mapper_table_alias}"), &[])
            .await
            .with_context(|| format!("unable to delete view `{mapper_table_alias}`"))
            .map(|_| ())
    } else {
        // The epoch mapper is internal, so we directly erase the table
        let mapper_table_name = mapper_table_name(table);
        connection
            .execute(
                &format!("DROP TABLE IF EXISTS {mapper_table_name} CASCADE"),
                &[],
            )
            .await
            .with_context(|| format!("unable to delete table `{mapper_table_name}`"))
            .map(|_| ())
    }
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
pub struct SqlStorageSettings {
    /// The table to use.
    pub table: String,
    /// A way to connect to the DB server
    pub source: SqlServerConnection,
    /// In case an external epoch mapper is employed for this storage,
    /// this field contains the name of the table providing such an epoch mapper.
    /// It is None if the epoch mapper is handled internally by the storage
    pub external_mapper: Option<String>,
}

pub struct PgsqlStorage<T, V, const EXTERNAL_EPOCH_MAPPER: bool>
where
    T: TreeTopology + DbConnector<V>,
    T::Key: ToFromBytea,
    T::Node: Sync + Clone,
    V: PayloadInDb + Send + Sync,
{
    /// The table in which this tree will be stored
    table: String,
    /// A connection to the PostgreSQL server
    db: DBPool,
    /// The current epoch
    epoch: IncrementalEpoch,
    /// Epoch mapper
    epoch_mapper: SharedEpochMapper<EpochMapperStorage, EXTERNAL_EPOCH_MAPPER>,
    /// Tree state information
    state: CachedDbStore<T::State>,
    /// Topological information
    tree_store: Arc<RwLock<CachedDbTreeStore<T, V>>>,
    nodes: NodeProjection<T, V>,
    payloads: PayloadProjection<T, V>,
    /// If any, the transaction progress
    in_tx: bool,
}

impl<T, V, const EXTERNAL_EPOCH_MAPPER: bool> FromSettings<T::State>
    for PgsqlStorage<T, V, EXTERNAL_EPOCH_MAPPER>
where
    T: TreeTopology + DbConnector<V>,
    T::Key: ToFromBytea,
    T::Node: Sync + Clone,
    T::State: Sync + Clone,
    V: PayloadInDb + Send + Sync,
{
    type Settings = SqlStorageSettings;

    async fn from_settings(
        init_settings: InitSettings<T::State>,
        storage_settings: Self::Settings,
    ) -> Result<Self, RyhopeError> {
        // check consistency between `EXTERNAL_EPOCH_MAPPER` and `storage_settings.external_mapper`.
        // This check is not relevant if `init_settings` is `MustExist`, as in this case we don't need
        // to create a new mapping table or view.
        if let InitSettings::MustExist = init_settings {
        } else {
            match (
                EXTERNAL_EPOCH_MAPPER,
                storage_settings.external_mapper.is_some(),
            ) {
                (true, false) => {
                    bail!("No external mapper table provided for a storage with external epoch mapper")
                }
                (false, true) => {
                    bail!("External mapper table provided for a storage with no external epoch mapper")
                }
                _ => {}
            }
        };
        match init_settings {
            InitSettings::MustExist => {
                Self::load_existing(&storage_settings.source, storage_settings.table).await
            }
            InitSettings::MustNotExist(tree_state) => {
                Self::create_new_at(
                    &storage_settings.source,
                    storage_settings.table,
                    tree_state,
                    0,
                    storage_settings.external_mapper,
                )
                .await
            }
            InitSettings::MustNotExistAt(tree_state, epoch) => {
                Self::create_new_at(
                    &storage_settings.source,
                    storage_settings.table,
                    tree_state,
                    epoch,
                    storage_settings.external_mapper,
                )
                .await
            }
            InitSettings::Reset(tree_settings) => {
                Self::reset_at(
                    &storage_settings.source,
                    storage_settings.table,
                    tree_settings,
                    0,
                    storage_settings.external_mapper,
                )
                .await
            }
            InitSettings::ResetAt(tree_settings, initial_epoch) => {
                Self::reset_at(
                    &storage_settings.source,
                    storage_settings.table,
                    tree_settings,
                    initial_epoch,
                    storage_settings.external_mapper,
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
async fn fetch_epoch_data(db: DBPool, table: &str) -> Result<(i64, i64), RyhopeError> {
    trace!("fetching epoch data for `{table}`");
    let connection = db.get().await.unwrap();
    connection
        .query_one(
            &format!(
                "SELECT MIN({VALID_FROM}), MAX({VALID_UNTIL}) FROM {}",
                metadata_table_name(table)
            ),
            &[],
        )
        .await
        .map(|r| (r.get(0), r.get(1)))
        .map_err(|err| RyhopeError::from_db("fetching current epoch data", err))
}

impl<T, V, const EXTERNAL_EPOCH_MAPPER: bool> std::fmt::Display
    for PgsqlStorage<T, V, EXTERNAL_EPOCH_MAPPER>
where
    T: TreeTopology + DbConnector<V>,
    T::Key: ToFromBytea,
    V: PayloadInDb,
    T::Node: Sync + Clone,
    T::State: Sync + Clone,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PgSqlStorage {}@{}", self.table, self.epoch)
    }
}
impl<T, V, const EXTERNAL_EPOCH_MAPPER: bool> PgsqlStorage<T, V, EXTERNAL_EPOCH_MAPPER>
where
    T: TreeTopology + DbConnector<V>,
    T::Key: ToFromBytea,
    V: PayloadInDb,
    T::Node: Sync + Clone,
    T::State: Sync + Clone,
{
    /// Create a new tree storage with the given initial epoch and its
    /// associated tables in the specified table.
    ///
    /// Will fail if the table already exists.
    pub async fn create_new_at(
        db_src: &SqlServerConnection,
        table: String,
        tree_state: T::State,
        epoch: UserEpoch,
        mapper_table: Option<String>,
    ) -> Result<Self, RyhopeError> {
        debug!("creating new table for `{table}` at epoch {epoch}");
        let db_pool = Self::init_db_pool(db_src).await?;

        ensure(
            fetch_epoch_data(db_pool.clone(), &table).await.is_err(),
            "table `{table}` already exists"
        );
        Self::create_tables(db_pool.clone(), &table, mapper_table).await?;

        let epoch_mapper = SharedEpochMapper::new(
            EpochMapperStorage::new::<EXTERNAL_EPOCH_MAPPER>(table.clone(), db_pool.clone(), epoch)
                .await?,
        );

        let tree_store = Arc::new(RwLock::new(CachedDbTreeStore::new(
            INITIAL_INCREMENTAL_EPOCH,
            table.clone(),
            db_pool.clone(),
            (&epoch_mapper).into(),
        )));
        let nodes = NodeProjection {
            wrapped: tree_store.clone(),
        };
        let payloads = PayloadProjection {
            wrapped: tree_store.clone(),
        };

        let r = Self {
            table: table.clone(),
            db: db_pool.clone(),
            epoch: 0,
            in_tx: false,
            tree_store,
            nodes,
            payloads,
            state: CachedDbStore::with_value(
                table.clone(),
                db_pool.clone(),
                tree_state,
                (&epoch_mapper).into(),
            )
            .await
            .context("failed to store initial state")?,
            epoch_mapper,
        };
        Ok(r)
    }

    /// Initialize the storage backend from an existing table in database.
    ///
    /// Fails if the specified table does not exist.
    pub async fn load_existing(
        db_src: &SqlServerConnection,
        table: String,
    ) -> Result<Self, RyhopeError> {
        let db_pool = Self::init_db_pool(db_src).await?;

        let (initial_epoch, latest_epoch) = fetch_epoch_data(db_pool.clone(), &table).await?;
        debug!("loading `{table}`; latest epoch is {latest_epoch}");
        ensure!(
            initial_epoch == INITIAL_INCREMENTAL_EPOCH,
            "Wrong internal initial epoch found for existing table {table}: 
                expected {INITIAL_INCREMENTAL_EPOCH}, found {initial_epoch}"
        );
        let epoch_mapper =
            EpochMapperStorage::new_from_table(table.clone(), db_pool.clone()).await?;
        let latest_epoch_in_mapper = epoch_mapper
            .to_incremental_epoch(epoch_mapper.latest_epoch().await)
            .await;
        ensure!(
            latest_epoch_in_mapper == latest_epoch,
            "Mismatch between the latest internal epoch in mapper table and the latest epoch 
            found in the storage: {latest_epoch_in_mapper} != {latest_epoch}"
        );
        let epoch_mapper = SharedEpochMapper::new(epoch_mapper);
        let tree_store = Arc::new(RwLock::new(CachedDbTreeStore::new(
            latest_epoch,
            table.clone(),
            db_pool.clone(),
            (&epoch_mapper).into(),
        )));
        let nodes = NodeProjection {
            wrapped: tree_store.clone(),
        };
        let payloads = PayloadProjection {
            wrapped: tree_store.clone(),
        };

        let r = Self {
            table: table.clone(),
            db: db_pool.clone(),
            epoch: latest_epoch,
            state: CachedDbStore::new(
                latest_epoch,
                table.clone(),
                db_pool.clone(),
                (&epoch_mapper).into(),
            ),
            epoch_mapper,
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
        db_src: &SqlServerConnection,
        table: String,
        tree_state: T::State,
        initial_epoch: UserEpoch,
        mapper_table: Option<String>,
    ) -> Result<Self, RyhopeError> {
        debug!("resetting table `{table}` at epoch {initial_epoch}");
        let db_pool = Self::init_db_pool(db_src).await?;

        delete_storage_table::<EXTERNAL_EPOCH_MAPPER>(db_pool.clone(), &table).await?;
        Self::create_tables(db_pool.clone(), &table, mapper_table).await?;

        let epoch_mapper = SharedEpochMapper::new(
            EpochMapperStorage::new::<EXTERNAL_EPOCH_MAPPER>(
                table.clone(),
                db_pool.clone(),
                initial_epoch,
            )
            .await?,
        );

        let tree_store = Arc::new(RwLock::new(CachedDbTreeStore::new(
            INITIAL_INCREMENTAL_EPOCH,
            table.clone(),
            db_pool.clone(),
            (&epoch_mapper).into(),
        )));
        let nodes = NodeProjection {
            wrapped: tree_store.clone(),
        };
        let payloads = PayloadProjection {
            wrapped: tree_store.clone(),
        };

        let r = Self {
            table: table.clone(),
            db: db_pool.clone(),
            epoch: INITIAL_INCREMENTAL_EPOCH,
            state: CachedDbStore::with_value(
                table.clone(),
                db_pool.clone(),
                tree_state,
                (&epoch_mapper).into(),
            )
            .await?,
            epoch_mapper,
            tree_store,
            nodes,
            payloads,
            in_tx: false,
        };

        Ok(r)
    }

    /// Initialize a DB pool.
    pub async fn init_db_pool(db_src: &SqlServerConnection) -> Result<DBPool, RyhopeError> {
        match db_src {
            SqlServerConnection::NewConnection(db_url) => {
                info!("Connecting to `{db_url}`");
                let db_manager = PostgresConnectionManager::new_from_stringlike(db_url, NoTls)
                    .map_err(|err| {
                        RyhopeError::from_db(
                            format!("while connecting to postgreSQL with `{}`", db_url),
                            err,
                        )
                    })?;
                let db_pool = DBPool::builder()
                    .build(db_manager)
                    .await
                    .map_err(|err| RyhopeError::from_db("creating DB pool", err))?;
                debug!("connection successful.");

                Ok(db_pool)
            }
            SqlServerConnection::Pool(pool) => Ok(pool.clone()),
        }
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
    async fn create_tables(db: DBPool, table: &str, mapper_table: Option<String>) -> Result<(), RyhopeError> {
        let node_columns = <T as DbConnector<V>>::columns()
            .iter()
            .map(|(name, t)| format!("{name} {t},"))
            .join("\n");

        // The main table will store all the tree nodes and their payload.
        let connection = db.get().await.unwrap();
        connection
            .execute(
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

        // create index on `VALID_FROM`
        connection
            .execute(
                &format!("CREATE INDEX {table}_index_from ON {table} ({VALID_FROM})"),
                &[],
            )
            .await
            .map(|_| ())
            .with_context(|| {
                format!("unable to create index on table `{table}` for {VALID_FROM}")
            })?;

        // create index on `VALID_UNTIL`
        connection
            .execute(
                &format!("CREATE INDEX {table}_index_until ON {table} ({VALID_UNTIL})"),
                &[],
            )
            .await
            .map(|_| ())
            .with_context(|| {
                format!("unable to create index on table `{table}` for {VALID_UNTIL}")
            })?;

        // The meta table will store everything related to the tree itself.
        let meta_table = metadata_table_name(table);
        connection
            .execute(
                &format!(
                    "CREATE TABLE {meta_table} (
                   {VALID_FROM}   BIGINT NOT NULL UNIQUE,
                   {VALID_UNTIL}  BIGINT DEFAULT -1,
                   {PAYLOAD}      JSONB)"
                ),
                &[],
            )
            .await
            .map(|_| ())
            .map_err(|err| RyhopeError::from_db(format!("creating table `{meta_table}`"), err))?;

        Ok(())?;

        // create index on `VALID_UNTIL`
        connection
            .execute(
                &format!("CREATE INDEX {meta_table}_index_until ON {meta_table} ({VALID_UNTIL})"),
                &[],
            )
            .await
            .map(|_| ())
            .with_context(|| {
                format!("unable to create index on table `{meta_table}` for {VALID_UNTIL}")
            })?;

        // Create the mapper table if the mapper table is not external, otherwise
        // create a view for the mapper table name expected for `table` to `mapper_table`.
        if EXTERNAL_EPOCH_MAPPER {
            ensure!(
                mapper_table.is_some(),
                "No mapper table name provided for storage with external epoch mapper"
            );
            let mapper_table_alias = mapper_table_name(table);
            let mapper_table_name = mapper_table_name(mapper_table.unwrap().as_str());
            connection
                .execute(
                    &format!(
                        "
                        CREATE VIEW {mapper_table_alias} AS
                        SELECT {USER_EPOCH}, {INCREMENTAL_EPOCH} FROM {mapper_table_name}"
                    ),
                    &[],
                )
                .await
                .map(|_| ())
                .with_context(|| format!("unable to create view for `{mapper_table_alias}`"))
        } else {
            let mapper_table_name = mapper_table_name(table);
            connection
                .execute(
                    &format!(
                        "CREATE TABLE {mapper_table_name} (
                        {USER_EPOCH} BIGINT NOT NULL UNIQUE,
                        {INCREMENTAL_EPOCH} BIGINT NOT NULL UNIQUE
                    )"
                    ),
                    &[],
                )
                .await
                .map(|_| ())
                .with_context(|| format!("unable to create table `{mapper_table_name}`"))
        }
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
            cached_keys.extend(self.tree_store.read().await.nodes_cache.keys().cloned());
        }
        {
            cached_keys.extend(self.tree_store.read().await.payload_cache.keys().cloned());
        }

        for k in cached_keys {
            let node_value = { self.tree_store.read().await.nodes_cache.get(&k).cloned() };
            let data_value = { self.tree_store.read().await.payload_cache.get(&k).cloned() };

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
        // add new incremental epoch to `epoch_mapper` (unless an an epoch map for `self.epoch + 1`
        // have already been added to `self.epoch_mapper`) and commit the new epoch map to DB
        let new_epoch = self.epoch + 1;
        if let Some(mut mapper) = self.epoch_mapper.write_access_ref().await {
            mapper.new_incremental_epoch(new_epoch).await?;
            mapper.commit_in_transaction(db_tx).await?;
        }
        self.state.commit_in(db_tx).await?;
        trace!("[{}] commit successful.", self.table);
        Ok(())
    }

    // FIXME: should return Result
    async fn on_commit_success(&mut self) {
        assert!(self.in_tx);
        trace!(
            "[{self}] commit succesful; updating inner state - current epoch {}",
            self.epoch
        );
        self.in_tx = false;
        self.epoch += 1;
        self.state.commit_success().await;
        self.epoch_mapper
            .apply_fn(|mapper| {
                mapper.commit_success();
                Ok(())
            })
            .await
            .unwrap();
        self.tree_store.write().await.new_epoch();
    }

    async fn on_commit_failed(&mut self) {
        assert!(self.in_tx);
        trace!(
            "[{self}] commit failed; updating inner state - current epoch {}",
            self.epoch
        );
        self.in_tx = false;
        self.state.commit_failed().await;
        if let Some(mut mapper) = self.epoch_mapper.write_access_ref().await {
            mapper.commit_failed().await;
        }
        self.tree_store.write().await.clear();
    }
}

impl<T: TreeTopology, V: PayloadInDb, const EXTERNAL_EPOCH_MAPPER: bool> TransactionalStorage
    for PgsqlStorage<T, V, EXTERNAL_EPOCH_MAPPER>
where
    V: Send + Sync,
    T: DbConnector<V>,
    T::Key: ToFromBytea,
    T::Node: Send + Sync + Clone,
    T::State: Send + Sync + Clone,
{
    async fn start_transaction(&mut self) -> Result<(), RyhopeError> {
        if self.in_tx {
            return Err(RyhopeError::AlreadyInTransaction);
        }
        trace!("[{self}] starting a new transaction");
        self.in_tx = true;
        self.epoch_mapper
            .apply_fn(|mapper| mapper.start_transaction())
            .await?;
        self.state.start_transaction().await?;
        Ok(())
    }

    async fn commit_transaction(&mut self) -> Result<(), RyhopeError> {
        if !self.in_tx {
            return Err(RyhopeError::NotInATransaction);
        }
        trace!("[{self}] commiting transaction");
        let pool = self.db.clone();
        let mut connection = pool.get().await.unwrap();
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
            self.on_commit_success().await;
        } else {
            self.on_commit_failed().await;
        }
        err
    }
}

impl<T: TreeTopology, V: PayloadInDb, const EXTERNAL_EPOCH_MAPPER: bool> SqlTransactionStorage
    for PgsqlStorage<T, V, EXTERNAL_EPOCH_MAPPER>
where
    V: Send + Sync,
    T: DbConnector<V>,
    T::Key: ToFromBytea,
    T::Node: Send + Sync + Clone,
    T::State: Send + Sync + Clone,
{
    async fn commit_in(&mut self, tx: &mut Transaction<'_>) -> Result<(), RyhopeError> {
        trace!("[{self}] API-facing commit_in called");
        self.commit_in_transaction(tx).await
    }

    async fn commit_success(&mut self) {
        trace!("[{self}] API-facing commit_success called");
        self.on_commit_success().await;
    }

    async fn commit_failed(&mut self) {
        trace!("[{self}] API-facing commit_failed called");
        self.on_commit_failed().await
    }
}

impl<T, V, const EXTERNAL_EPOCH_MAPPER: bool> TreeStorage<T>
    for PgsqlStorage<T, V, EXTERNAL_EPOCH_MAPPER>
where
    T: TreeTopology + DbConnector<V>,
    V: PayloadInDb + Send,
    T::Key: ToFromBytea,
    T::Node: Sync + Clone,
    T::State: Debug + Sync + Clone + Serialize + for<'a> Deserialize<'a>,
{
    type StateStorage = CachedDbStore<T::State>;
    type NodeStorage = NodeProjection<T, V>;
    type EpochMapper = SharedEpochMapper<EpochMapperStorage, EXTERNAL_EPOCH_MAPPER>;

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

    async fn born_at(&self, epoch: UserEpoch) -> Vec<T::Key> {
        let inner_epoch = self.epoch_mapper.to_incremental_epoch(epoch).await;
        let connection = self.db.get().await.unwrap();
        connection
            .query(
                &format!("SELECT {KEY} FROM {} WHERE {VALID_FROM}=$1", self.table),
                &[&inner_epoch],
            )
            .await
            .expect("while fetching newborns from database")
            .iter()
            .map(|r| T::Key::from_bytea(r.get::<_, Vec<u8>>(0)))
            .collect::<Vec<_>>()
    }

    async fn rollback_to(&mut self, epoch: UserEpoch) -> Result<(), RyhopeError> {
        self.state.rollback_to(epoch).await?;
        let inner_epoch = self
            .epoch_mapper
            .try_to_incremental_epoch(epoch)
            .await
            .ok_or(anyhow!("IncrementalEpoch for epoch {} not found", epoch))?;
        self.tree_store
            .write()
            .await
            .rollback_to(inner_epoch)
            .await?;
        self.epoch = inner_epoch;

        // rollback epoch mapper
        self.epoch_mapper
            .as_ref()
            .write()
            .await
            .rollback_to::<EXTERNAL_EPOCH_MAPPER>(epoch)
            .await?;

        // Ensure epochs coherence
        assert_eq!(self.epoch, self.tree_store.read().await.current_epoch());
        assert_eq!(
            self.epoch_mapper
                .to_incremental_epoch(self.state.current_epoch().await?)
                .await,
            self.epoch
        );
        assert_eq!(
            self.epoch_mapper
                .to_incremental_epoch(
                    self.epoch_mapper
                        .read_access_ref()
                        .await
                        .latest_epoch()
                        .await
                )
                .await,
            self.epoch,
        );
        Ok(())
    }

    fn epoch_mapper(&self) -> &Self::EpochMapper {
        &self.epoch_mapper
    }

    fn epoch_mapper_mut(&mut self) -> &mut Self::EpochMapper {
        &mut self.epoch_mapper
    }
}

impl<T, V, const EXTERNAL_EPOCH_MAPPER: bool> PayloadStorage<T::Key, V>
    for PgsqlStorage<T, V, EXTERNAL_EPOCH_MAPPER>
where
    Self: TreeStorage<T>,
    T: TreeTopology + DbConnector<V>,
    V: PayloadInDb + Send,
    T::Key: ToFromBytea,
    T::Node: Sync + Clone,
    T::State: Debug + Sync + Clone + Serialize + for<'a> Deserialize<'a>,
    V: Sync,
{
    type DataStorage = PayloadProjection<T, V>;

    fn data(&self) -> &Self::DataStorage {
        &self.payloads
    }

    fn data_mut(&mut self) -> &mut Self::DataStorage {
        &mut self.payloads
    }
}

impl<T, V, const EXTERNAL_EPOCH_MAPPER: bool> MetaOperations<T, V>
    for PgsqlStorage<T, V, EXTERNAL_EPOCH_MAPPER>
where
    Self: TreeStorage<T>,
    T: TreeTopology + DbConnector<V>,
    V: PayloadInDb + Send,
    T::Key: ToFromBytea,
    T::Node: Sync + Clone,
    T::State: Debug + Sync + Clone + Serialize + for<'a> Deserialize<'a>,
    V: Sync,
{
    type KeySource = String;

    async fn wide_lineage_between(
        &self,
        at: UserEpoch,
        t: &T,
        keys: &Self::KeySource,
        bounds: (UserEpoch, UserEpoch),
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

    fn try_fetch_many_at<I: IntoIterator<Item = (UserEpoch, <T as TreeTopology>::Key)> + Send>(
        &self,
        t: &T,
        data: I,
    ) -> impl Future<Output = Result<Vec<(UserEpoch, NodeContext<T::Key>, V)>, RyhopeError>> + Send
    where
        <I as IntoIterator>::IntoIter: Send,
    {
        trace!("[{self}] fetching many contexts & payloads",);
        let table = self.table.to_owned();
        async move {
            let mut data_with_incremental_epochs = vec![];
            for (epoch, key) in data {
                // add current (epoch, key) pair to data to be fetched only if `epoch` is found in the epoch mapper
                if let Some(inner_epoch) = self.epoch_mapper.try_to_incremental_epoch(epoch).await {
                    data_with_incremental_epochs.push((epoch, inner_epoch, key));
                }
            }
            t.fetch_many_at(self, self.db.clone(), &table, data_with_incremental_epochs)
                .await
        }
    }
}
