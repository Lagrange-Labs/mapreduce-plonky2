use anyhow::*;
use futures::future::BoxFuture;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, fmt::Debug, future::Future, hash::Hash};
use tokio_postgres::Transaction;

use self::updatetree::UpdateTree;
use crate::{
    tree::{NodeContext, TreeTopology},
    Epoch, InitSettings,
};

pub mod memory;
pub mod pgsql;
#[cfg(test)]
mod tests;
pub mod updatetree;
pub mod view;

/// An atomic operation to apply on a KV storage.
pub enum Operation<K, V> {
    /// Insert a new row in the database at the new block state
    Insert(K, V),
    /// Remove a row in the new block state
    Delete(K),
    /// Update the value of the given row in the new block state
    Update(K, V),
}

/// Characterize a type whose new instances can be built from a `Self::Settings`
/// instance.
pub trait FromSettings<T>
where
    Self: Sized,
{
    type Settings;

    async fn from_settings(
        init_settings: InitSettings<T>,
        storage_settings: Self::Settings,
    ) -> Result<Self>;
}

/// A `TreeStorage` stores all data related to the tree structure, i.e. (i) the
/// state of the tree structure, (ii) the putative metadata associated to the
/// tree nodes.
pub trait TreeStorage<T: TreeTopology>: Send + Sync {
    type U;

    /// A storage backend for the underlying tree state
    type StateStorage: EpochStorage<T::State> + Send + Sync;
    /// A storage backend for the underlying tree nodes
    type NodeStorage: EpochKvStorage<T::Key, T::Node> + Send + Sync;

    /// Return a handle to the state storage.
    fn state(&self) -> &Self::StateStorage;

    /// Return a mutable handle to the state storage.
    fn state_mut(&mut self) -> &mut Self::StateStorage;

    /// Return a handle to the nodes storage.
    fn nodes(&self) -> &Self::NodeStorage;

    /// Return a mutable handle to the nodes storage.
    fn nodes_mut(&mut self) -> &mut Self::NodeStorage;

    /// Return a list of the nodes “born” (i.e. dirtied) at `epoch`.
    async fn born_at(&self, epoch: Epoch) -> Vec<T::Key>;

    /// Rollback this tree one epoch in the past
    async fn rollback<F>(&mut self) -> Result<()> {
        self.rollback_to(self.nodes().current_epoch() - 1).await
    }

    /// Rollback this tree to the given epoch
    async fn rollback_to(&mut self, epoch: Epoch) -> Result<()>;

    async fn wide_lineage_between(
        &self,
        keys: Self::U,
        start_epoch: Epoch,
        end_epoch: Epoch,
    ) -> Result<HashMap<(T::Key, Epoch), (NodeContext<T::Key>, T::Node)>>;
}

/// A backend storing the payloads associated to the nodes of a tree.
pub trait PayloadStorage<K: Hash + Eq + Send + Sync, V: Send + Sync> {
    type DataStorage: EpochKvStorage<K, V> + Send + Sync;

    /// A read-only access to the node-associated data.
    fn data(&self) -> &Self::DataStorage;
    /// A mutable access to the node-associated data.
    fn data_mut(&mut self) -> &mut Self::DataStorage;
}

pub trait EpochStorage<T: Debug + Send + Sync + Clone + Serialize + for<'a> Deserialize<'a>>:
    TransactionalStorage
where
    Self: Send + Sync,
{
    /// Return the current epoch of the storage
    fn current_epoch(&self) -> Epoch;

    /// Return the value stored at the current epoch.
    fn fetch(&self) -> impl Future<Output = T> + Send {
        async { self.fetch_at(self.current_epoch()).await }
    }

    /// Return the value stored at the given epoch.
    fn fetch_at(&self, epoch: Epoch) -> impl Future<Output = T> + Send;

    /// Set the stored value at the current epoch.
    fn store(&mut self, t: T) -> impl Future<Output = ()> + Send;

    fn update<F: FnMut(&mut T) + Send>(&mut self, mut f: F) -> impl Future<Output = ()> + Send {
        async move {
            let mut t = self.fetch().await;
            f(&mut t);
            self.store(t).await;
        }
    }

    /// Roll back this storage one epoch in the past.
    async fn rollback(&mut self) -> Result<()> {
        self.rollback_to(self.current_epoch() - 1).await
    }

    /// Roll back this storage to the given epoch
    async fn rollback_to(&mut self, epoch: Epoch) -> Result<()>;
}

/// A read-only, versioned, KV storage. Intended to be implemented in
/// conjunction with [`EpochKvStorage`] or [`WriteOnceEpochKvStorage`] to inject
/// data in the storage.
pub trait RoEpochKvStorage<K: Eq + Hash, V>
where
    Self: Sync,
    K: Send + Sync,
    V: Send + Sync,
{
    /// Return the first registered time stamp of the storage
    fn initial_epoch(&self) -> Epoch;

    /// Return the current time stamp of the storage
    fn current_epoch(&self) -> Epoch;

    /// Return the value associated to `k` in the current epoch.
    ///
    /// Panic if `k` is not associated to any value at the current epoch.
    fn fetch(&self, k: &K) -> impl Future<Output = V> + Send {
        async { self.fetch_at(k, self.current_epoch()).await }
    }

    /// Return the value associated to `k` at the current epoch if it exists,
    /// `None` otherwise.
    fn try_fetch(&self, k: &K) -> impl Future<Output = Option<V>> + Send {
        async { self.try_fetch_at(k, self.current_epoch()).await }
    }

    /// Return the value associated to `k` at the given `epoch`.
    ///
    /// Panic if `k` is not associated to any value at `epoch`.
    fn fetch_at(&self, k: &K, epoch: Epoch) -> impl Future<Output = V> + Send {
        async move { self.try_fetch_at(k, epoch).await.unwrap() }
    }

    /// Return the value associated to `k` at the given `epoch` if it exists,
    /// `None` otherwise.
    fn try_fetch_at(&self, k: &K, epoch: Epoch) -> impl Future<Output = Option<V>> + Send;

    /// Return whether the given key is present at the current epoch.
    async fn contains(&self, k: &K) -> bool {
        self.try_fetch(k).await.is_some()
    }

    /// Return whether the given key is present at the given epoch.
    async fn contains_at(&self, k: &K, epoch: Epoch) -> bool {
        self.try_fetch_at(k, epoch).await.is_some()
    }

    /// Return the number of stored K/V pairs at the current epoch.
    async fn size(&self) -> usize;
}

/// A versioned KV storage only allowed to mutate entries only in the current
/// epoch.
pub trait EpochKvStorage<K: Eq + Hash + Send + Sync, V: Send + Sync>:
    RoEpochKvStorage<K, V>
{
    /// Within a transaction, delete the existing storage entry at `k`.
    ///
    /// Fail if `k` does not exist.
    fn remove(&mut self, k: K) -> impl Future<Output = Result<()>> + Send;

    /// Within a transaction, update the existing storage entry at `k` with
    /// value `new_value`.
    ///
    /// Fail if `k` does not exist.
    fn update(&mut self, k: K, new_value: V) -> impl Future<Output = Result<()>> + Send;

    /// Apply the given function `updater` onto the value associated to `k` and
    /// persist the updated value.
    ///
    /// Fail if `k` does not exist.
    fn update_with<F: Fn(&mut V) + Send + Sync>(
        &mut self,
        k: K,
        updater: F,
    ) -> impl Future<Output = ()> + Send
    where
        Self: Sync + Send,
    {
        async move {
            let mut v = self.fetch(&k).await;
            updater(&mut v);
            self.update(k, v).await.unwrap();
        }
    }

    /// Associate `value` to `k`.
    fn store(&mut self, k: K, value: V) -> impl Future<Output = Result<()>> + Send;

    /// Rollback this storage one epoch back. Please note that this is a
    /// destructive and irreversible operation.
    async fn rollback(&mut self) -> Result<()> {
        self.rollback_to(self.current_epoch() - 1).await
    }

    /// Rollback this storage to the given epoch. Please note that this is a
    /// destructive and irreversible operation.
    async fn rollback_to(&mut self, epoch: Epoch) -> Result<()>;
}

/// Characterizes a trait allowing for epoch-based atomic updates.
pub trait TransactionalStorage {
    /// Start a new transaction, defining a transition between the storage at
    /// two epochs.
    fn start_transaction(&mut self) -> Result<()>;

    /// Closes the current transaction and commit to the new state at the new
    /// epoch.
    async fn commit_transaction(&mut self) -> Result<()>;

    /// Execute the given function acting on `Self` within a transaction.
    ///
    /// Will fail if the transaction failed.
    async fn in_transaction<Fut, F: FnOnce(&mut Self) -> Fut>(&mut self, f: F) -> Result<()>
    where
        Fut: Future<Output = Result<()>>,
    {
        self.start_transaction()?;
        f(self).await?;
        self.commit_transaction().await
    }
}

/// This trait is similar to [`TransactionalStorage`], but let the caller re-use
/// an existing SQL transaction rather than letting the implementer handle
/// transaction creation & execution.
pub(crate) trait SqlTransactionStorage: TransactionalStorage {
    /// Similar to the [`commit`] method of [`TransactionalStorage`], but
    /// re-using a given transaction.
    async fn commit_in(&mut self, tx: &mut Transaction<'_>) -> Result<()>;

    /// Types implementing this trait may implement this method if there is code
    /// they want to have run after the transaction successful execution, _e.g._
    /// to clean up inner state and/or caches.
    ///
    /// This hook **MUST** be called after the **SUCCESSFUL** execution of the
    /// transaction given to [`commit_in`]. It **MUST NOT** be called if the
    /// transaction execution failed.
    fn commit_success(&mut self);

    /// This hook **MUST** be called after the **FAILED** execution of the
    /// transaction given to [`commit_in`]. It **MUST NOT** be called if the
    /// transaction execution is successful.
    fn commit_failed(&mut self);
}

/// Similar to [`TransactionalStorage`], but returns a [`Minitree`] of the
/// affected [`Key`]s on transaction commit.
pub trait TreeTransactionalStorage<K: Clone + Hash + Eq + Send + Sync, V: Send + Sync>:
    EpochKvStorage<K, V>
{
    /// Start a new transaction, defining a transition between the storage at
    /// two epochs.
    async fn start_transaction(&mut self) -> Result<()>;

    /// Closes the current transaction and commit to the new state at the new
    /// epoch.
    ///
    /// Return the hierarchy of `Key` affected by the transaction and requiring
    /// a re-proof.
    async fn commit_transaction(&mut self) -> Result<UpdateTree<K>>;

    /// Execute the given function acting on `Self` within a transaction.
    ///
    /// Will fail if the transaction failed.

    async fn in_transaction<F: FnOnce(&mut Self) -> BoxFuture<'_, Result<()>> + Sync>(
        &mut self,
        f: F,
    ) -> Result<UpdateTree<K>> {
        self.start_transaction().await?;
        f(self).await?;
        self.commit_transaction().await
    }

    /// Consume an iterator of [`Operation<K>`] and apply all of them within a
    /// single transaction.
    ///
    /// Return the hierarchy of `Key` affected by the transaction and requiring
    /// a re-proof.
    ///
    /// Fail if any of the operation fails.
    async fn transaction_from_batch<I: IntoIterator<Item = Operation<K, V>>>(
        &mut self,
        ops: I,
    ) -> Result<UpdateTree<K>> {
        self.start_transaction().await?;
        for op in ops.into_iter() {
            match op {
                Operation::Insert(k, v) => self.store(k, v).await?,
                Operation::Delete(k) => self.remove(k).await?,
                Operation::Update(k, v) => self.update(k, v).await?,
            }
        }
        self.commit_transaction().await
    }
}

/// This trait is similar to [`TreeTransactionalStorage`], but let the caller
/// re-use an existing SQL transaction rather than letting the implementer
/// handle transaction creation & execution.
///
/// This trait requires that the caller take care of the following precautions:
///
///   * a **single** transaction in a **single** connection must be used;
///
///   * the `post_commit` hook **must** be called after, and only after, a
///   successful SQL transaction execution.
pub trait SqlTreeTransactionalStorage<K: Clone + Hash + Eq + Send + Sync, V: Send + Sync>:
    TreeTransactionalStorage<K, V>
{
    /// Similar to the [`commit`] method of [`TreeTransactionalStorage`], but
    /// re-using a given transaction.
    async fn commit_in(&mut self, tx: &mut Transaction<'_>) -> Result<UpdateTree<K>>;

    /// Types implementing this trait may implement this method if there is code
    /// they want to have run after the transaction successful execution, _e.g._
    /// to clean up inner state and/or caches.
    ///
    /// This hook **MUST** be called after the **SUCCESSFUL** execution of the
    /// transaction given to [`commit_in`]. It **MUST NOT** be called if the
    /// transaction execution failed.
    fn commit_success(&mut self);

    /// This hook **MUST** be called after the **FAILED** execution of the
    /// transaction given to [`commit_in`]. It **MUST NOT** be called if the
    /// transaction execution is successful.
    fn commit_failed(&mut self);
}
