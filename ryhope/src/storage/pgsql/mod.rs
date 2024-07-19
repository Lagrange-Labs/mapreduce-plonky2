use crate::storage::RoEpochKvStorage;
use crate::tree::TreeTopology;
use crate::{Epoch, InitSettings};

use self::storages::{
    CachedDbKvStore, CachedDbStore, DbConnector, NodeConnector, PayloadConnector,
};

use super::{EpochKvStorage, EpochStorage, PayloadStorage};
use super::{FromSettings, TransactionalStorage, TreeStorage};
use anyhow::*;
use itertools::Itertools;
use log::*;
use postgres::{Client, NoTls};
use serde::{Deserialize, Serialize};
use std::{cell::RefCell, fmt::Debug, hash::Hash, rc::Rc};

mod storages;

/// A trait that must be implemented by a custom node key. This allows to
/// (de)serialize any custom key to and fro a PgSQL BYTEA.
pub trait ToFromBytea: Clone + Sync + Hash + Eq {
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
pub trait PayloadInDb: Clone + Sync + Debug + Serialize + for<'a> Deserialize<'a> {}
impl<T: Debug + Clone + Sync + Serialize + for<'a> Deserialize<'a>> PayloadInDb for T {}

/// If it exists, remove the given table from the current database.
fn delete_storage_table(db: &mut Client, table: &str) -> Result<()> {
    db.execute(&format!("DROP TABLE IF EXISTS {}", table), &[])
        .with_context(|| format!("unable to delete table `{table}`"))
        .map(|_| ())?;
    db.execute(&format!("DROP TABLE IF EXISTS {}_meta", table), &[])
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
impl<T: Clone + Debug> std::fmt::Debug for CachedValue<T> {
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

pub struct PgsqlStorage<T: TreeTopology, V: PayloadInDb>
where
    T::Key: ToFromBytea,
    T::Node: Sync + Clone,
    NodeConnector: DbConnector<T::Key, T::Node>,
{
    /// The table in which this tree will be stored
    table: String,
    /// A connection to the PostgreSQL server
    db: Rc<RefCell<Client>>,
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

impl<T: TreeTopology, V: PayloadInDb> FromSettings<T::State> for PgsqlStorage<T, V>
where
    T::Key: ToFromBytea,
    T::Node: Sync + Clone,
    NodeConnector: DbConnector<T::Key, T::Node>,
{
    type Settings = SqlStorageSettings;

    fn from_settings(
        init_settings: InitSettings<T::State>,
        storage_settings: Self::Settings,
    ) -> Result<Self> {
        match init_settings {
            InitSettings::MustExist => {
                Self::load_existing(&storage_settings.db_url, storage_settings.table)
            }
            InitSettings::MustNotExist(tree_state) => {
                Self::create_new(&storage_settings.db_url, storage_settings.table, tree_state)
            }
            InitSettings::Reset(tree_settings) => Self::reset(
                &storage_settings.db_url,
                storage_settings.table,
                tree_settings,
            ),
        }
    }
}

/// Return, if it exists, the current epoch for a given table pair.
fn fetch_current_epoch(db: &mut Client, table: &str) -> Result<i64> {
    db.query_one(&format!("SELECT MAX(valid_until) FROM {table}_meta",), &[])
        .map(|r| r.get(0))
        .context("while fetching current epoch")
}

impl<T: TreeTopology, V: PayloadInDb> PgsqlStorage<T, V>
where
    T::Key: ToFromBytea,
    T::Node: Sync + Clone,
    T::State: Sync + Clone,
    NodeConnector: DbConnector<T::Key, T::Node>,
{
    /// Create a new tree storage and its associated table in the specified table.
    ///
    /// Will fail if the table already exists.
    pub fn create_new(db_url: &str, table: String, tree_state: T::State) -> Result<Self> {
        debug!("connecting to {db_url}...");
        let mut db = Client::connect(db_url, NoTls)?;
        debug!("connection successful.");

        ensure!(
            fetch_current_epoch(&mut db, &table).is_err(),
            "table `{table}` already exists"
        );
        Self::create_storage_table(&mut db, &table)?;

        let db = Rc::new(RefCell::new(db));
        let epoch = 0;
        let r = Self {
            table: table.clone(),
            db: db.clone(),
            epoch,
            in_tx: false,
            nodes: CachedDbKvStore::new(epoch, table.clone(), db.clone()),
            state: CachedDbStore::with_value(epoch, table.clone(), db.clone(), tree_state),
            data: CachedDbKvStore::new(epoch, table.clone(), db.clone()),
        };
        Ok(r)
    }

    /// Initialize the storage backend from an existing table in database.
    ///
    /// Fails if the specified table does not exist.
    pub fn load_existing(db_url: &str, table: String) -> Result<Self> {
        debug!("connecting to {db_url}...");
        let mut db = Client::connect(db_url, NoTls)?;
        debug!("connection successful.");

        let latest_epoch = fetch_current_epoch(&mut db, &table)
            .with_context(|| format!("table `{table}` does not exist"))?;
        info!("latest epoch is {latest_epoch}");

        let db = Rc::new(RefCell::new(db));

        let r = Self {
            table: table.clone(),
            db: db.clone(),
            epoch: latest_epoch,
            state: CachedDbStore::new(latest_epoch, table.clone(), db.clone()),
            nodes: CachedDbKvStore::new(latest_epoch, table.clone(), db.clone()),
            data: CachedDbKvStore::new(latest_epoch, table.clone(), db.clone()),
            in_tx: false,
        };

        Ok(r)
    }

    /// Create a new tree storage and its associated table in the specified
    /// table, deleting it if it already exists.
    pub fn reset(db_url: &str, table: String, tree_state: T::State) -> Result<Self> {
        info!("connecting to {db_url}...");
        let mut db = Client::connect(db_url, NoTls)?;
        info!("connection successful.");

        delete_storage_table(&mut db, &table)?;
        Self::create_storage_table(&mut db, &table)?;
        let db = Rc::new(RefCell::new(db));
        let epoch = 0;

        let r = Self {
            table: table.clone(),
            db: db.clone(),
            epoch,
            state: CachedDbStore::with_value(epoch, table.clone(), db.clone(), tree_state),
            nodes: CachedDbKvStore::new(epoch, table.clone(), db.clone()),
            data: CachedDbKvStore::new(epoch, table.clone(), db.clone()),
            in_tx: false,
        };

        Ok(r)
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
    fn create_storage_table(db: &mut Client, table: &str) -> Result<()> {
        let node_columns = <NodeConnector as DbConnector<T::Key, T::Node>>::columns()
            .iter()
            .chain(<PayloadConnector as DbConnector<T::Key, V>>::columns().iter())
            .map(|(name, t)| format!("{name} {t},"))
            .join("\n");

        // The main table will store all the tree nodes and their payload.
        db.execute(
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
        .map(|_| ())
        .with_context(|| format!("unable to create table `{table}`"))?;

        // The meta table will store everything related to the tree itself.
        db.execute(
            &format!(
                "CREATE TABLE {table}_meta (
                   valid_from   BIGINT NOT NULL UNIQUE,
                   valid_until  BIGINT DEFAULT -1,
                   payload      JSONB)"
            ),
            &[],
        )
        .map(|_| ())
        .with_context(|| format!("unable to create table `{table}_meta`"))
    }

    fn update_all(&self, db_tx: &mut postgres::Transaction) -> Result<()> {
        let update_all = format!(
            "UPDATE {} SET valid_until=$1 WHERE valid_until=$2",
            self.table
        );

        db_tx
            .query(&update_all, &[&(&self.epoch + 1), &self.epoch])
            .context("while updating timestamps")
            .map(|_| ())
    }

    /// Roll-back to `self.epoch` the lifetime of a row having already been extended to `self.epoch + 1`.
    fn rollback_one_row(
        &self,
        db_tx: &mut postgres::Transaction,
        key: &T::Key,
    ) -> Result<Option<(T::Node, V)>> {
        let rows = db_tx.query(
            &format!(
                "UPDATE {} SET valid_until={} WHERE key=$1 AND valid_until={} RETURNING *",
                self.table,
                self.epoch,
                self.epoch + 1
            ),
            &[&key.to_bytea()],
        )?;

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
    fn new_node(&self, db_tx: &mut postgres::Transaction, k: &T::Key, n: T::Node) -> Result<()> {
        NodeConnector::insert_in_tx(db_tx, &self.table, k, self.epoch + 1, n)
    }
}

impl<T: TreeTopology, V: PayloadInDb> TransactionalStorage for PgsqlStorage<T, V>
where
    T::Key: ToFromBytea,
    T::Node: Sync + Clone,
    T::State: Sync + Clone,
    NodeConnector: DbConnector<T::Key, T::Node>,
{
    fn start_transaction(&mut self) -> Result<()> {
        ensure!(!self.in_tx, "already in a transaction");
        self.in_tx = true;
        self.state.start_transaction()?;
        Ok(())
    }

    fn commit_transaction(&mut self) -> Result<()> {
        ensure!(self.in_tx, "not in a transaction");

        // The putative new stamps if everything goes well
        let new_epoch = self.epoch + 1;

        {
            // Open a PgSQL transaction, as we want the batch to be atomically
            // successful or failed.
            let mut db = self.db.borrow_mut();
            let mut db_tx = db.transaction().expect("unable to create DB transaction");

            // Pre-emptively extend by 1 the lifetime of the currently alive rows;
            // those that should not be alive in the next epoch will be rolled back
            // later.
            self.update_all(&mut db_tx)?;

            // First, handle the corner case of nodes whose payload only have been
            // updated, that will be the only ones appearing in the data cache but
            // not in the node cache.
            // Some read may have been performed outside of a transaction; just ignore them.
            for (k, v) in self
                .data
                .cache
                .borrow()
                .iter()
                .filter(|(k, _)| !self.nodes.cache.borrow().contains_key(k))
            {
                if let Some(CachedValue::Written(v)) = v {
                    // rollback the old value if any
                    let previous_payload = self.rollback_one_row(&mut db_tx, k)?.unwrap();
                    // write the new value
                    self.new_node(&mut db_tx, k, previous_payload.0)?;
                    PayloadConnector::set_at_in_tx(
                        &mut db_tx,
                        &self.table,
                        k,
                        self.epoch + 1,
                        v.to_owned(),
                    )?;
                }
            }

            // Then generically process all the other touched nodes.
            for (k, v) in self.nodes.cache.borrow().iter() {
                match v {
                    Some(cv) => match cv {
                        // read-only accesses during this transaction, nothing to do
                        CachedValue::Read(_) => {}
                        // insertion or displacement in the tree; the row has to be
                        // duplicated/updated and rolled-back
                        CachedValue::Written(node) => {
                            // rollback the old value if any
                            let previous_payload = self.rollback_one_row(&mut db_tx, k)?;
                            let old_payload = previous_payload.as_ref().map(|x| x.1.clone());
                            let maybe_new_payload = self
                                .data
                                .cache
                                .borrow()
                                .get(k)
                                .and_then(|v| v.as_ref().map(|cv| cv.value().to_owned()));

                            // insert the new row representing the new state of the key...
                            self.new_node(&mut db_tx, k, node.to_owned())?;

                            // ... and carry over its associated payload and hash.

                            // the new associated payload is the one present in the
                            // cache if any (that would reflect and insertion or an
                            // update), or the previous one (if the key moved in the
                            // tree, but the payload stayed the same).
                            let payload = maybe_new_payload
                                .or(old_payload)
                                .expect("both old and new payloads are both None");

                            PayloadConnector::set_at_in_tx(
                                &mut db_tx,
                                &self.table,
                                k,
                                new_epoch,
                                payload,
                            )?;
                        }
                    },
                    // k has been deleted; simply roll-back the lifetime of its row.
                    None => {
                        self.rollback_one_row(&mut db_tx, k)?;
                    }
                }
            }

            // Atomically execute the PgSQL transaction
            db_tx.commit().context("while committing transaction")?;
        }

        // Prepare the internal state for a new transaction
        self.in_tx = false;
        self.epoch = new_epoch;
        self.state.commit_transaction()?;
        self.data.new_epoch();
        self.nodes.new_epoch();
        Ok(())
    }
}

impl<T: TreeTopology, V: PayloadInDb> TreeStorage<T> for PgsqlStorage<T, V>
where
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

    fn born_at(&self, epoch: Epoch) -> Vec<T::Key> {
        self.db
            .borrow_mut()
            .query(
                &format!("SELECT key FROM {} WHERE valid_from=$1", self.table),
                &[&epoch],
            )
            .expect("while fetching newborns from database")
            .iter()
            .map(|r| T::Key::from_bytea(r.get::<_, Vec<u8>>(0)))
            .collect::<Vec<_>>()
    }

    fn rollback_to(&mut self, epoch: Epoch) -> Result<()> {
        self.state.rollback_to(epoch)?;
        self.nodes.rollback_to(epoch)?;
        self.data.rollback_to(epoch)?;
        self.epoch = epoch;

        // Ensure epochs coherence
        assert_eq!(self.state.current_epoch(), self.nodes.current_epoch());
        assert_eq!(self.state.current_epoch(), self.data.current_epoch());
        assert_eq!(self.state.current_epoch(), self.epoch);

        Ok(())
    }
}

impl<T: TreeTopology, V: PayloadInDb> PayloadStorage<T::Key, V> for PgsqlStorage<T, V>
where
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
