use anyhow::*;
use postgres::{types::Json, Client, Row};
use serde::{Deserialize, Serialize};
use std::{cell::RefCell, collections::HashMap, fmt::Debug, marker::PhantomData, rc::Rc};

use super::{CachedValue, ToFromBytea};
use crate::{
    storage::{EpochKvStorage, EpochStorage, RoEpochKvStorage, TransactionalStorage},
    tree::scapegoat,
    Epoch,
};

/// Type implementing this trait define the behavior of a storage tree
/// components regarding their persistence in DB.
pub trait DbConnector<K: ToFromBytea, V: Clone + Sync> {
    /// Return a list of pairs column name, SQL type required by the connector.
    fn columns() -> &'static [(&'static str, &'static str)];

    /// Within a PgSQL transaction, insert the given value at the given epoch.
    fn insert_in_tx(
        _db_tx: &mut postgres::Transaction,
        _table: &str,
        _k: &K,
        _birth_epoch: Epoch,
        _v: V,
    ) -> Result<()> {
        unreachable!()
    }

    /// Within a PgSQL transaction, update the value associated at the given
    /// epoch to the given key.
    fn set_at_in_tx(
        _db_tx: &mut postgres::Transaction,
        _table: &str,
        _k: &K,
        _epoch: Epoch,
        _v: V,
    ) -> Result<()> {
        unreachable!()
    }

    /// Return the value associated to the given key at the given epoch.
    fn fetch_at(db: &mut Client, table: &str, k: &K, epoch: Epoch) -> Result<Option<V>>;

    /// Given a PgSQL row, extract a value from it.
    fn from_row(r: &Row) -> Result<V>;
}

pub struct PayloadConnector;
impl<K: ToFromBytea, V: Serialize + for<'a> Deserialize<'a> + Clone + Sync + std::fmt::Debug>
    DbConnector<K, V> for PayloadConnector
{
    fn columns() -> &'static [(&'static str, &'static str)] {
        &[("payload", "JSONB")]
    }

    fn fetch_at(db: &mut Client, table: &str, k: &K, epoch: Epoch) -> Result<Option<V>> {
        db.query(
            &format!(
                "SELECT payload FROM {} WHERE key=$1 AND valid_from <= $2 AND $2 <= valid_until",
                table
            ),
            &[&(k.to_bytea()), &epoch],
        )
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

    fn set_at_in_tx(
        db_tx: &mut postgres::Transaction,
        table: &str,
        k: &K,
        epoch: Epoch,
        v: V,
    ) -> Result<()> {
        db_tx
            .execute(
                &format!(
                    "UPDATE {} SET payload=$3 WHERE key=$1 AND valid_from<=$2 AND $2<=valid_until",
                    table
                ),
                &[&k.to_bytea(), &epoch, &Json(v)],
            )
            .map(|_| ())
            .context("while updating payload")
    }
}

// Void nodes are used by the SBBST
pub struct NodeConnector;
impl<K: ToFromBytea> DbConnector<K, ()> for NodeConnector {
    fn columns() -> &'static [(&'static str, &'static str)] {
        &[]
    }

    fn fetch_at(db: &mut Client, table: &str, k: &K, epoch: Epoch) -> Result<Option<()>> {
        db.query(
            &format!(
                "SELECT * FROM {} WHERE key=$1 AND valid_from<=$2 AND $2<=valid_until",
                table
            ),
            &[&k.to_bytea(), &epoch],
        )
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

    fn insert_in_tx(
        db_tx: &mut postgres::Transaction,
        table: &str,
        k: &K,
        birth_epoch: Epoch,
        _n: (),
    ) -> Result<()> {
        db_tx
            .execute(
                &format!(
                    "INSERT INTO
                     {} (key, valid_from, valid_until)
                     VALUES ($1, $2, $2)",
                    table
                ),
                &[&k.to_bytea(), &birth_epoch],
            )
            .map_err(|e| anyhow!("failed to insert new node row: {e:?}"))
            .map(|_| ())
    }
}
impl<K: ToFromBytea> DbConnector<K, scapegoat::Node<K>> for NodeConnector {
    fn columns() -> &'static [(&'static str, &'static str)] {
        &[
            ("parent", "BYTEA"),
            ("left_child", "BYTEA"),
            ("right_child", "BYTEA"),
            ("subtree_size", "BIGINT"),
        ]
    }

    fn fetch_at(
        db: &mut Client,
        table: &str,
        k: &K,
        epoch: Epoch,
    ) -> Result<Option<scapegoat::Node<K>>> {
        db.query(
            &format!(
                "SELECT parent, left_child, right_child, subtree_size FROM {}
                 WHERE key=$1 AND valid_from<=$2 AND $2<=valid_until",
                table
            ),
            &[&k.to_bytea(), &epoch],
        )
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

    fn insert_in_tx(
        db_tx: &mut postgres::Transaction,
        table: &str,
        k: &K,
        birth_epoch: Epoch,
        n: scapegoat::Node<K>,
    ) -> Result<()> {
        db_tx
            .execute(
                &format!(
                    "INSERT INTO
                     {} (key, valid_from, valid_until, subtree_size, parent, left_child, right_child)
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
            .map_err(|e| anyhow!("failed to insert new node row: {e:?}"))
            .map(|_| ())
    }
}

pub struct CachedDbStore<V: Debug + Clone + Sync + Serialize + for<'a> Deserialize<'a>> {
    /// A pointer to the DB client
    db: Rc<RefCell<Client>>,
    in_tx: bool,
    dirty: bool,
    epoch: Epoch,
    table: String,
    pub(super) cache: RefCell<Option<V>>,
}
impl<T: Debug + Clone + Sync + Serialize + for<'a> Deserialize<'a>> CachedDbStore<T> {
    pub fn new(epoch: Epoch, table: String, db: Rc<RefCell<Client>>) -> Self {
        Self {
            db,
            in_tx: false,
            dirty: true,
            epoch,
            table,
            cache: RefCell::new(None),
        }
    }

    pub fn with_value(epoch: Epoch, table: String, db: Rc<RefCell<Client>>, t: T) -> Self {
        Self {
            db,
            in_tx: false,
            dirty: true,
            epoch,
            table,
            cache: RefCell::new(Some(t)),
        }
    }
}
impl<T: Debug + Clone + Sync + Serialize + for<'a> Deserialize<'a>> TransactionalStorage
    for CachedDbStore<T>
{
    fn start_transaction(&mut self) -> Result<()> {
        ensure!(!self.in_tx, "already in a transaction");

        self.in_tx = true;
        Ok(())
    }

    fn commit_transaction(&mut self) -> Result<()> {
        ensure!(self.in_tx, "not in a transaction");

        if self.dirty {
            let state = self.cache.borrow().clone();
            self.db.borrow_mut().query(
                &format!(
                    "INSERT INTO {}_meta (valid_from, valid_until, payload)
                     VALUES ($1, $1, $2)",
                    self.table
                ),
                &[&(self.epoch + 1), &Json(state)],
            )?;
        } else {
            self.db.borrow_mut().query(
                &format!(
                    "UPDATE {}_meta SET valid_until = $1 + 1 WHERE valid_until = $1",
                    self.table
                ),
                &[&(self.epoch)],
            )?;
        }

        self.epoch += 1;
        self.dirty = false;
        self.in_tx = false;
        Ok(())
    }
}
impl<T: Debug + Clone + Sync + Serialize + for<'a> Deserialize<'a>> EpochStorage<T>
    for CachedDbStore<T>
{
    fn fetch(&self) -> T {
        self.cache
            .borrow_mut()
            .get_or_insert_with(|| {
                self.db
                    .borrow_mut()
                    .query_one(
                        // Fetch the row with the most recent valid_from
                        &format!(
                            "SELECT payload FROM {}_meta WHERE valid_from <= $1 AND $1 <= valid_until",
                            self.table),
                        &[&self.epoch])
                    .map(|row| row.get::<_, Json<T>>(0).0)
                    .expect("failed to fetch state")
            })
            .to_owned()
    }

    fn fetch_at(&self, epoch: Epoch) -> T {
        self.db
            .borrow_mut()
            .query_one(
                &format!(
                    "SELECT payload FROM {}_meta WHERE valid_from <= $1 AND $1 <= valid_until",
                    self.table,
                ),
                &[&epoch],
            )
            .map(|row| row.get::<_, Json<T>>(0).0)
            .expect("failed to fetch state")
    }

    fn store(&mut self, t: T) {
        self.dirty = true;
        let _ = self.cache.borrow_mut().insert(t);
    }

    fn current_epoch(&self) -> Epoch {
        self.epoch
    }

    fn rollback_to(&mut self, new_epoch: Epoch) -> Result<()> {
        ensure!(new_epoch >= 0, "unable to rollback before epoch 0");
        ensure!(
            new_epoch < self.current_epoch(),
            "unable to rollback into the future: requested epoch ({}) > current epoch ({})",
            new_epoch,
            self.current_epoch()
        );

        let _ = self.cache.borrow_mut().take();
        let mut db = self.db.borrow_mut();
        let mut db_tx = db.transaction().expect("unable to create DB transaction");
        // Roll back all living nodes by 1
        db_tx.query(
            &format!(
                "UPDATE {}_meta SET valid_until = $1 WHERE valid_until > $1",
                self.table
            ),
            &[&new_epoch],
        )?;
        // Delete nodes that would not have been born yet
        db_tx.query(
            &format!("DELETE FROM {}_meta WHERE valid_from > $1", self.table),
            &[&new_epoch],
        )?;
        db_tx.commit()?;
        self.epoch = new_epoch;

        Ok(())
    }
}

/// A `CachedDbStore` keeps a cache of all the storage operations that occured
/// during the current transaction, while falling back to the given database
/// when referring to older epochs.
pub struct CachedDbKvStore<K: ToFromBytea, V: Clone + Sync, F: DbConnector<K, V>> {
    /// The latest *commited* epoch
    epoch: Epoch,
    /// A pointer to the DB client
    db: Rc<RefCell<Client>>,
    /// DB backing this cache
    table: String,
    /// Operations pertaining to the in-process transaction.
    pub(super) cache: RefCell<HashMap<K, Option<CachedValue<V>>>>,
    _p: PhantomData<F>,
}
impl<K: ToFromBytea, V: Clone + Sync, F: DbConnector<K, V>> CachedDbKvStore<K, V, F> {
    pub fn new(epoch: Epoch, table: String, db: Rc<RefCell<Client>>) -> Self {
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
        self.cache.borrow_mut().clear();
    }
}

impl<K: ToFromBytea, V: Clone + Sync, F: DbConnector<K, V>> RoEpochKvStorage<K, V>
    for CachedDbKvStore<K, V, F>
{
    fn current_epoch(&self) -> Epoch {
        self.epoch
    }

    fn try_fetch_at(&self, k: &K, epoch: Epoch) -> Option<V> {
        if epoch == self.current_epoch() {
            // Directly returns the value if it is already in cache, fetch it from
            // the DB otherwise.
            self.cache
                .borrow_mut()
                .entry(k.to_owned())
                .or_insert_with(|| {
                    F::fetch_at(&mut self.db.borrow_mut(), &self.table, k, epoch)
                        .unwrap()
                        .map(CachedValue::Read)
                })
                .clone()
                .map(CachedValue::into_value)
        } else {
            F::fetch_at(&mut self.db.borrow_mut(), &self.table, k, epoch).unwrap()
        }
    }

    fn size(&self) -> usize {
        self.db
            .borrow_mut()
            .query_one(
                &format!(
                    "SELECT COUNT(*) FROM {} WHERE valid_from <= $1 AND $1 <= valid_until",
                    self.table
                ),
                &[&self.epoch],
            )
            .ok()
            .map(|row| row.get::<_, i64>(0))
            .unwrap_or(0)
            .try_into()
            .context("while counting rows")
            .unwrap()
    }
}
impl<K: ToFromBytea, V: Clone + Sync, F: DbConnector<K, V>> EpochKvStorage<K, V>
    for CachedDbKvStore<K, V, F>
{
    // Operations are stored in the cache; persistence to the DB only occurs on
    // transaction commiting.
    fn update(&mut self, k: K, new_value: V) -> Result<()> {
        // If the operation is already present from a read, replace it with the
        // new value.
        self.cache
            .borrow_mut()
            .insert(k, Some(CachedValue::Written(new_value)));
        Ok(())
    }

    fn store(&mut self, k: K, value: V) -> Result<()> {
        // If the operation is already present from a read, replace it with the
        // new value.
        self.cache
            .borrow_mut()
            .insert(k, Some(CachedValue::Written(value)));
        Ok(())
    }

    fn remove(&mut self, k: K) -> Result<()> {
        self.cache.borrow_mut().insert(k, None);
        Ok(())
    }

    fn rollback_to(&mut self, new_epoch: Epoch) -> Result<()> {
        ensure!(new_epoch >= 0, "unable to rollback before epoch 0");
        ensure!(
            new_epoch < self.current_epoch(),
            "unable to rollback into the future: requested epoch ({}) > current epoch ({})",
            new_epoch,
            self.current_epoch()
        );

        self.cache.borrow_mut().clear();
        let mut db = self.db.borrow_mut();
        let mut db_tx = db.transaction().expect("unable to create DB transaction");
        // Roll back all living nodes by 1
        db_tx.query(
            &format!(
                "UPDATE {} SET valid_until = $1 WHERE valid_until > $1",
                self.table
            ),
            &[&new_epoch],
        )?;
        // Delete nodes that would not have been born yet
        db_tx.query(
            &format!("DELETE FROM {} WHERE valid_from > $1", self.table),
            &[&new_epoch],
        )?;
        db_tx.commit()?;
        self.epoch = new_epoch;

        Ok(())
    }
}
