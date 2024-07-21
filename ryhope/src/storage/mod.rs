use anyhow::*;
use serde::{Deserialize, Serialize};
use std::{fmt::Debug, hash::Hash};

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
pub trait FromSettings<T>
where
    Self: Sized,
{
    type Settings;

    fn from_settings(
        init_settings: InitSettings<T>,
        storage_settings: Self::Settings,
    ) -> Result<Self>;
}

/// A `TreeStorage` stores all data related to the tree structure, i.e. (i) the
/// state of the tree structure, (ii) the putative metadata associated to the
/// tree nodes.
pub trait TreeStorage<T: TreeTopology> {
    /// A storage backend for the underlying tree state
    type StateStorage: EpochStorage<T::State>;
    /// A storage backend for the underlying tree nodes
    type NodeStorage: EpochKvStorage<T::Key, T::Node>;

    /// Return a handle to the state storage.
    fn state(&self) -> &Self::StateStorage;

    /// Return a mutable handle to the state storage.
    fn state_mut(&mut self) -> &mut Self::StateStorage;

    /// Return a handle to the nodes storage.
    fn nodes(&self) -> &Self::NodeStorage;

    /// Return a mutable handle to the nodes storage.
    fn nodes_mut(&mut self) -> &mut Self::NodeStorage;

    /// Return a list of the nodes “born” (i.e. dirtied) at `epoch`.
    fn born_at(&self, epoch: Epoch) -> Vec<T::Key>;

    /// Rollback this tree one epoch in the past
    fn rollback(&mut self) -> Result<()> {
        self.rollback_to(self.nodes().current_epoch() - 1)
    }

    /// Rollback this tree to the given epoch
    fn rollback_to(&mut self, epoch: Epoch) -> Result<()>;
}

/// A backend storing the payloads associated to the nodes of a tree.
pub trait PayloadStorage<K: Hash + Eq, V> {
    type DataStorage: EpochKvStorage<K, V>;

    /// A read-only access to the node-associated data.
    fn data(&self) -> &Self::DataStorage;
    /// A mutable access to the node-associated data.
    fn data_mut(&mut self) -> &mut Self::DataStorage;
}

pub trait EpochStorage<T: Debug + Sync + Clone + Serialize + for<'a> Deserialize<'a>>:
    TransactionalStorage
{
    /// Return the current epoch of the storage
    fn current_epoch(&self) -> Epoch;

    /// Return the value stored at the current epoch.
    fn fetch(&self) -> T {
        self.fetch_at(self.current_epoch())
    }

    /// Return the value stored at the given epoch.
    fn fetch_at(&self, epoch: Epoch) -> T;

    /// Set the stored value at the current epoch.
    fn store(&mut self, t: T);

    fn update<F: FnMut(&mut T)>(&mut self, mut f: F) {
        let mut t = self.fetch();
        f(&mut t);
        self.store(t);
    }

    /// Roll back this storage one epoch in the past.
    fn rollback(&mut self) -> Result<()> {
        self.rollback_to(self.current_epoch() - 1)
    }

    /// Roll back this storage to the given epoch
    fn rollback_to(&mut self, epoch: Epoch) -> Result<()>;
}

/// A read-only, versioned, KV storage. Intended to be implemented in
/// conjunction with [`EpochKvStorage`] or [`WriteOnceEpochKvStorage`] to inject
/// data in the storage.
pub trait RoEpochKvStorage<K: Eq + Hash, V> {
    /// Return the current time stamp of the storage
    fn current_epoch(&self) -> Epoch;

    /// Return the value associated to `k` in the current epoch.
    ///
    /// Panic if `k` is not associated to any value at the current epoch.
    fn fetch(&self, k: &K) -> V {
        self.fetch_at(k, self.current_epoch())
    }

    /// Return the value associated to `k` at the current epoch if it exists,
    /// `None` otherwise.
    fn try_fetch(&self, k: &K) -> Option<V> {
        self.try_fetch_at(k, self.current_epoch())
    }

    /// Return the value associated to `k` at the given `epoch`.
    ///
    /// Panic if `k` is not associated to any value at `epoch`.
    fn fetch_at(&self, k: &K, epoch: Epoch) -> V {
        self.try_fetch_at(k, epoch).unwrap()
    }

    /// Return the value associated to `k` at the given `epoch` if it exists,
    /// `None` otherwise.
    fn try_fetch_at(&self, k: &K, epoch: Epoch) -> Option<V>;

    /// Return whether the given key is present at the current epoch.
    fn contains(&self, k: &K) -> bool {
        self.try_fetch(k).is_some()
    }

    /// Return whether the given key is present at the given epoch.
    fn contains_at(&self, k: &K, epoch: Epoch) -> bool {
        self.try_fetch_at(k, epoch).is_some()
    }

    /// Return the number of stored K/V pairs at the current epoch.
    fn size(&self) -> usize;
}

/// A versioned KV storage only allowed to mutate entries only in the current
/// epoch.
pub trait EpochKvStorage<K: Eq + Hash, V>: RoEpochKvStorage<K, V> {
    /// Within a transaction, delete the existing storage entry at `k`.
    ///
    /// Fail if `k` does not exist.
    fn remove(&mut self, k: K) -> Result<()>;

    /// Within a transaction, update the existing storage entry at `k` with
    /// value `new_value`.
    ///
    /// Fail if `k` does not exist.
    fn update(&mut self, k: K, new_value: V) -> Result<()>;

    /// Apply the given function `updater` onto the value associated to `k` and
    /// persist the updated value.
    ///
    /// Fail if `k` does not exist.
    fn update_with<F: Fn(&mut V)>(&mut self, k: K, updater: F) {
        let mut v = self.fetch(&k);
        updater(&mut v);
        self.update(k, v).unwrap();
    }

    /// Associate `value` to `k`.
    fn store(&mut self, k: K, value: V) -> Result<()>;

    /// Rollback this storage one epoch back. Please note that this is a
    /// destructive and irreversible operation.
    fn rollback(&mut self) -> Result<()> {
        self.rollback_to(self.current_epoch() - 1)
    }

    /// Rollback this storage to the given epoch. Please note that this is a
    /// destructive and irreversible operation.
    fn rollback_to(&mut self, epoch: Epoch) -> Result<()>;
}

/// Characterizes a trait allowing for epoch-based atomic updates.
pub trait TransactionalStorage {
    /// Start a new transaction, defining a transition between the storage at
    /// two epochs.
    fn start_transaction(&mut self) -> Result<()>;

    /// Closes the current transaction and commit to the new state at the new
    /// epoch.
    fn commit_transaction(&mut self) -> Result<()>;

    /// Execute the given function acting on `Self` within a transaction.
    ///
    /// Will fail if the transaction failed.
    fn in_transaction<F: Fn(&mut Self) -> Result<()>>(&mut self, f: F) -> Result<()> {
        self.start_transaction()?;
        f(self)?;
        self.commit_transaction()
    }
}

/// Similar to [`TransactionalStorage`], but returns a [`Minitree`] of the
/// affected [`Key`]s on transaction commit.
pub trait TreeTransactionalStorage<K: Clone + Hash + Eq, V>: EpochKvStorage<K, V> {
    /// Start a new transaction, defining a transition between the storage at
    /// two epochs.
    fn start_transaction(&mut self) -> Result<()>;

    /// Closes the current transaction and commit to the new state at the new
    /// epoch.
    ///
    /// Return the hierarchy of `Key` affected by the transaction and requiring
    /// a re-proof.
    fn commit_transaction(&mut self) -> Result<UpdateTree<K>>;

    /// Execute the given function acting on `Self` within a transaction.
    ///
    /// Will fail if the transaction failed.
    fn in_transaction<F: FnOnce(&mut Self) -> Result<()>>(
        &mut self,
        f: F,
    ) -> Result<UpdateTree<K>> {
        self.start_transaction()?;
        f(self)?;
        self.commit_transaction()
    }

    /// Consume an itertor of [`Operation<K>`] and apply all of them within a
    /// single transaction.
    ///
    /// Return the hierarchy of `Key` affected by the transaction and requiring
    /// a re-proof.
    ///
    /// Fail if any of the operation fails.
    fn transaction_from_batch<I: IntoIterator<Item = Operation<K, V>>>(
        &mut self,
        ops: I,
    ) -> Result<UpdateTree<K>> {
        self.start_transaction()?;
        for op in ops.into_iter() {
            match op {
                Operation::Insert(k, v) => self.store(k, v)?,
                Operation::Delete(k) => self.remove(k)?,
                Operation::Update(k, v) => self.update(k, v)?,
            }
        }
        self.commit_transaction()
    }
}
