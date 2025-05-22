use anyhow::Context;
use std::{collections::BTreeSet, sync::Arc};
use tokio::sync::RwLock;
use tokio_postgres::{Row, Transaction};

use crate::{
    error::{ensure, RyhopeError},
    mapper_table_name,
    storage::{memory::EpochMapperCache, EpochMapper},
    IncrementalEpoch, UserEpoch, INCREMENTAL_EPOCH, USER_EPOCH,
};

use super::storages::DBPool;

pub(crate) const INITIAL_INCREMENTAL_EPOCH: IncrementalEpoch = 0;

/// Implementation of `EpochMapper` persisted to a Postgres DB
#[derive(Clone, Debug)]
pub struct EpochMapperStorage {
    /// A pointer to the DB client
    db: DBPool,
    /// The table in which the data must be persisted
    table: String,
    in_tx: bool,
    /// Set of `UserEpoch`s being updated in the cache since the last commit to the DB
    dirty: BTreeSet<UserEpoch>,
    // Internal cache used to store the mappings between `UserEpoch`s and `IncrementalEpoch`s
    // already fetched from the DB. The main purpose of the cache is avoiding the need to run
    // a SQL query to the DB each time an epoch translation is needed.
    // The current cache implementation relies on the assumption that the epoch mapper is an
    // append-only storage, that is:
    // - Once a mapping between a `UserEpoch` and an `IncrementalEpoch` is add to the DB, it is
    //   no longer modified
    // - An existing mapping between a `UserEpoch` and an `IncrementalEpoch` is never deleted,
    //   unless with a rollback operation
    // This assumption allows to ensure that whenever a data is read from the DB and moved to the
    // cache, it never gets outdated, unless a rollback occurs.
    // Note that, while the underlying DB storage could be shared among multiple `EpochMapperStorage`s,
    // the cache is private to each instance of `EpochMapperStorage`, and it is handled uniquely by the
    // current `EpochMapperStorage`. The usage of a `RwLock` data structure to wrap the cache is only
    // an implementation detail to be able to update the cache also in methods of `EpochMapper` trait
    // which aren't expected to modify the `EpochMapper`
    pub(super) cache: Arc<RwLock<EpochMapperCache<{ Self::MAX_CACHE_ENTRIES }>>>,
}

impl EpochMapperStorage {
    /// Upper bound on the number of epoch mappings that can be stored in an `EpochMapperCache`
    /// to avoid a blowup in memory consumption; the cache will be wiped as soon as the number of
    /// epoch mappings found goes beyond this value
    const MAX_CACHE_ENTRIES: usize = 1000000;

    pub(crate) fn mapper_table_name(&self) -> String {
        mapper_table_name(&self.table)
    }

    pub(crate) async fn new_from_table(table: String, db: DBPool) -> Result<Self, RyhopeError> {
        let cache = {
            let connection = db
                .get()
                .await
                .map_err(|err| RyhopeError::from_bb8("getting a connection", err))?;
            let mapper_table_name = mapper_table_name(table.as_str());
            let rows = connection
                .query(
                    &format!(
                        "SELECT {USER_EPOCH}, {INCREMENTAL_EPOCH} FROM {mapper_table_name} ORDER BY {USER_EPOCH}"
                    ),
                    &[],
                )
                .await
                .context("while fetching incremental epoch")
                .unwrap();
            ensure(
                !rows.is_empty(),
                format!("Loading from empty table {mapper_table_name}"),
            )?;
            let read_row = |row: &Row| {
                let user_epoch = row.get::<_, i64>(0) as UserEpoch;
                let incremental_epoch = row.get::<_, i64>(1) as IncrementalEpoch;
                (user_epoch, incremental_epoch)
            };
            let (user_epoch, incremental_epoch) = read_row(&rows[0]);
            ensure(
                incremental_epoch == INITIAL_INCREMENTAL_EPOCH,
                format!("Wrong initial epoch found in table {mapper_table_name}"),
            )?;
            let mut cache = EpochMapperCache::new_at(user_epoch);
            for row in &rows[1..] {
                let (user_epoch, incremental_epoch) = read_row(row);
                cache.add_epoch_map(user_epoch, incremental_epoch).await?;
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
    ) -> Result<Self, RyhopeError> {
        // Add initial epoch to cache
        let mapper_table_name = mapper_table_name(table.as_str());
        Ok(if EXTERNAL_EPOCH_MAPPER {
            // Initialize from mapper table
            let mapper = Self::new_from_table(table, db).await?;
            // check that there is a mapping initial_epoch -> INITIAL_INCREMENTAL_EPOCH
            ensure(
                mapper.try_to_incremental_epoch(initial_epoch).await
                    == Some(INITIAL_INCREMENTAL_EPOCH),
                "No initial epoch {initial_epoch} found in mapping table {mapper_table_name}",
            )?;
            mapper
        } else {
            // add epoch map for `initial_epoch` to the DB
            db.get()
                .await
                .map_err(|err| RyhopeError::from_bb8("getting a connection", err))?
                .query(
                    &format!(
                        "INSERT INTO {mapper_table_name} ({USER_EPOCH}, {INCREMENTAL_EPOCH})
                            VALUES ($1, $2)"
                    ),
                    &[&(initial_epoch as UserEpoch), &INITIAL_INCREMENTAL_EPOCH],
                )
                .await
                .map_err(|err| {
                    RyhopeError::from_db(format!("Inserting epochs in {mapper_table_name}"), err)
                })?;
            let cache = EpochMapperCache::new_at(initial_epoch);
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
    pub(crate) async fn new_incremental_epoch(
        &mut self,
        epoch: IncrementalEpoch,
    ) -> Result<(), RyhopeError> {
        if let Some(mapped_epoch) = self.cache.write().await.new_incremental_epoch(epoch) {
            // if a new mapping is actually added to the cache, then we add the `UserEpoch`
            // of this mapping to the `dirty` set, so that it is later committed to the DB
            self.dirty.insert(mapped_epoch);
        }
        Ok(())
    }

    pub(crate) fn start_transaction(&mut self) -> Result<(), RyhopeError> {
        if self.in_tx {
            return Err(RyhopeError::AlreadyInTransaction);
        }
        self.in_tx = true;
        Ok(())
    }

    pub(crate) async fn commit_in_transaction(
        &mut self,
        db_tx: &mut Transaction<'_>,
    ) -> Result<(), RyhopeError> {
        // build the set of epoch mappings (user_epoch, incremental_epoch) to be written to the DB
        let mut rows_to_insert = vec![];
        for &user_epoch in self.dirty.iter() {
            let incremental_epoch = self
                .cache
                .read()
                .await
                .try_to_incremental_epoch(user_epoch)
                .await
                .ok_or(RyhopeError::epoch_error(format!(
                    "Epoch {user_epoch} not found in cache"
                )))?;
            rows_to_insert.push(format!("({user_epoch}, {incremental_epoch})"));
        }

        // Insert in the DB table with a single query
        db_tx
            .query(
                &format!(
                    "INSERT INTO {} ({USER_EPOCH}, {INCREMENTAL_EPOCH})
                    VALUES {}",
                    self.mapper_table_name(),
                    rows_to_insert.join(",")
                ),
                &[],
            )
            .await
            .map_err(|err| {
                RyhopeError::from_db(
                    format!("Inserting new epochs in {}", self.mapper_table_name()),
                    err,
                )
            })?;

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
            self.cache
                .write()
                .await
                .rollback_to(epoch)
                .expect("Cannot rollback to older epoch {epoch}");
        }
        self.dirty.clear();
        self.in_tx = false;
    }

    /// Rollback `self` to `UserEpoch` epoch. If `EXTERNAL_EPOCH_MAPPER` is true, then
    /// this method only rollbacks the cache, as the DB is expected to be rolled back
    /// by an external `EpochMapperStorage`; otherwise, the DB is also rolled back
    /// by this method. Thus, this implementation of rollback currently works under the
    /// assumption that the rollback operation will consistently be called also over
    /// the external `EpochMapperStorage`, otherwise the rollback will not be effective
    /// even for the current storage (as it will only wipe the cache, but no the DB)
    pub(crate) async fn rollback_to<const EXTERNAL_EPOCH_MAPPER: bool>(
        &mut self,
        epoch: UserEpoch,
    ) -> Result<(), RyhopeError> {
        // rollback the cache
        self.cache.write().await.rollback_to(epoch)?;
        if !EXTERNAL_EPOCH_MAPPER {
            // rollback also DB
            let connection = self
                .db
                .get()
                .await
                .map_err(|err| RyhopeError::from_bb8("getting connection", err))?;
            connection
                .query(
                    &format!(
                        "DELETE FROM {} WHERE {USER_EPOCH} > $1",
                        self.mapper_table_name()
                    ),
                    &[&(epoch)],
                )
                .await
                .map_err(|err| {
                    RyhopeError::from_db(
                        format!(
                            "Rolling back epoch mapper table {}",
                            self.mapper_table_name()
                        ),
                        err,
                    )
                })?;
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
    ) -> Result<(), RyhopeError> {
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
