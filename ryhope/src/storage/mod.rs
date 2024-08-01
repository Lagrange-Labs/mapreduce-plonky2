use std::{fmt::Debug, hash::Hash};

use anyhow::*;
use async_trait::async_trait;
use futures::future::BoxFuture;
use serde::{Deserialize, Serialize};

use crate::{tree::TreeTopology, Epoch, InitSettings};

use self::updatetree::UpdateTree;

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
#[async_trait]
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
#[async_trait]
pub trait TreeStorage<T: TreeTopology>: Send + Sync {
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
}

/// A backend storing the payloads associated to the nodes of a tree.
#[async_trait]
pub trait PayloadStorage<K: Hash + Eq + Send + Sync, V: Send + Sync> {
    type DataStorage: EpochKvStorage<K, V> + Send + Sync;

    /// A read-only access to the node-associated data.
    fn data(&self) -> &Self::DataStorage;
    /// A mutable access to the node-associated data.
    fn data_mut(&mut self) -> &mut Self::DataStorage;
}

#[async_trait]
pub trait EpochStorage<T: Debug + Send + Sync + Clone + Serialize + for<'a> Deserialize<'a>>:
    TransactionalStorage
where
    Self: Send + Sync,
{
    /// Return the current epoch of the storage
    fn current_epoch(&self) -> Epoch;

    /// Return the value stored at the current epoch.
    async fn fetch(&self) -> T {
        self.fetch_at(self.current_epoch()).await
    }

    /// Return the value stored at the given epoch.
    async fn fetch_at(&self, epoch: Epoch) -> T;

    /// Set the stored value at the current epoch.
    async fn store(&mut self, t: T);

    async fn update<F: FnMut(&mut T) + Send>(&mut self, mut f: F) {
        let mut t = self.fetch().await;
        f(&mut t);
        self.store(t).await;
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
#[async_trait]
pub trait RoEpochKvStorage<K: Eq + Hash, V>
where
    K: Send + Sync,
    V: Send + Sync,
{
    /// Return the current time stamp of the storage
    fn current_epoch(&self) -> Epoch;

    /// Return the value associated to `k` in the current epoch.
    ///
    /// Panic if `k` is not associated to any value at the current epoch.
    async fn fetch(&self, k: &K) -> V {
        self.fetch_at(k, self.current_epoch()).await
    }

    /// Return the value associated to `k` at the current epoch if it exists,
    /// `None` otherwise.
    async fn try_fetch(&self, k: &K) -> Option<V> {
        self.try_fetch_at(k, self.current_epoch()).await
    }

    /// Return the value associated to `k` at the given `epoch`.
    ///
    /// Panic if `k` is not associated to any value at `epoch`.
    async fn fetch_at(&self, k: &K, epoch: Epoch) -> V {
        self.try_fetch_at(k, epoch).await.unwrap()
    }

    /// Return the value associated to `k` at the given `epoch` if it exists,
    /// `None` otherwise.
    async fn try_fetch_at(&self, k: &K, epoch: Epoch) -> Option<V>;

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
#[async_trait]
pub trait EpochKvStorage<K: Eq + Hash + Send + Sync, V: Send + Sync>:
    RoEpochKvStorage<K, V>
{
    /// Within a transaction, delete the existing storage entry at `k`.
    ///
    /// Fail if `k` does not exist.
    async fn remove(&mut self, k: K) -> Result<()>;

    /// Within a transaction, update the existing storage entry at `k` with
    /// value `new_value`.
    ///
    /// Fail if `k` does not exist.
    async fn update(&mut self, k: K, new_value: V) -> Result<()>;

    /// Apply the given function `updater` onto the value associated to `k` and
    /// persist the updated value.
    ///
    /// Fail if `k` does not exist.
    async fn update_with<F: Fn(&mut V) + Send + Sync>(&mut self, k: K, updater: F)
    where
        Self: Sync,
        K: Sync + 'async_trait,
    {
        let mut v = self.fetch(&k).await;
        updater(&mut v);
        self.update(k, v).await.unwrap();
    }

    /// Associate `value` to `k`.
    async fn store(&mut self, k: K, value: V) -> Result<()>;

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
#[async_trait]
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
    async fn in_transaction<F: Fn(&mut Self) -> BoxFuture<'_, Result<()>> + Send>(
        &mut self,
        f: F,
    ) -> Result<()> {
        self.start_transaction()?;
        f(self).await?;
        self.commit_transaction().await
    }
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
