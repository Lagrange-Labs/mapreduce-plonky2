use anyhow::*;
use futures::future::BoxFuture;
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    fmt::Debug,
    future::Future,
    hash::Hash,
};
use tokio_postgres::Transaction;
use view::TreeStorageView;

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

    fn from_settings(
        init_settings: InitSettings<T>,
        storage_settings: Self::Settings,
    ) -> impl Future<Output = Result<Self>>;
}

pub struct WideLineage<K, V>
where
    K: Debug + Hash + Eq + Clone + Sync + Send,
{
    /// The keys touched by the query itself
    pub core_keys: Vec<(Epoch, K)>,
    /// An epoch -> (K -> NodeContext, K -> Payload) mapping
    #[allow(clippy::type_complexity)]
    epoch_lineages: HashMap<Epoch, (HashMap<K, NodeContext<K>>, HashMap<K, V>)>,
}

impl<K: Debug + Hash + Eq + Clone + Sync + Send, V: Clone> WideLineage<K, V> {
    pub fn is_touched_key(&self, to_search: &K) -> bool {
        self.core_keys.iter().any(|(_, k)| k == to_search)
    }
    pub fn num_touched_rows(&self) -> usize {
        self.core_keys.len()
    }

    pub fn ctx_and_payload_at(&self, epoch: Epoch, key: &K) -> Option<(NodeContext<K>, V)> {
        match (
            self.node_context_at(epoch, key),
            self.payload_at(epoch, key),
        ) {
            (Some(e), Some(f)) => Some((e, f)),
            _ => None,
        }
    }
    pub fn node_context_at(&self, epoch: Epoch, key: &K) -> Option<NodeContext<K>> {
        self.epoch_lineages
            .get(&epoch)
            .and_then(|h| h.0.get(key))
            .cloned()
    }
    pub fn payload_at(&self, epoch: Epoch, key: &K) -> Option<V> {
        self.epoch_lineages
            .get(&epoch)
            .and_then(|h| h.1.get(key))
            .cloned()
    }

    /// Returns the list of keys touching the query associated with each epoch
    pub fn keys_by_epochs(&self) -> HashMap<Epoch, HashSet<K>> {
        self.core_keys
            .iter()
            .fold(HashMap::new(), |mut acc, (epoch, k)| {
                acc.entry(*epoch).or_default().insert(k.clone());
                acc
            })
    }
    pub fn update_tree_for(&self, epoch: Epoch) -> Option<UpdateTree<K>> {
        let epoch_data = self.epoch_lineages.get(&epoch)?;
        let all_paths = self
            .core_keys
            .iter()
            .filter(|(e, _)| *e == epoch)
            .map(|(_, k)| {
                let mut path = vec![k.clone()];
                // ok to unwrap since we passed the filter, so that key must exist
                // otherwise it's ryhope failure
                let mut ctx = epoch_data.0.get(k).unwrap_or_else(|| panic!(
                    "lineage should get all core keys, but {k:?} is missing"
                ));
                // go back up to there is no more parent anymore, i.e. the root
                while ctx.parent.is_some() {
                    let parent_k = ctx.parent.as_ref().unwrap();
                    ctx = epoch_data
                        .0
                        .get(parent_k)
                        .unwrap_or_else(|| panic!("lineage should get all ascendant keys, but {parent_k:?} (for {k:?}) is missing"));
                    path.push(parent_k.clone());
                }
                // NOTE: these paths are *ascending*, whereas the update tree is
                // built from *descending* ones.
                path.reverse();
                path
            })
            .collect_vec();
        if all_paths.is_empty() {
            None
        } else {
            Some(UpdateTree::from_paths(all_paths, epoch))
        }
    }
}

/// A `TreeStorage` stores all data related to the tree structure, i.e. (i) the
/// state of the tree structure, (ii) the putative metadata associated to the
/// tree nodes.
pub trait TreeStorage<T: TreeTopology>: Sized + Send + Sync {
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
    fn born_at(&self, epoch: Epoch) -> impl Future<Output = Vec<T::Key>>;

    /// Rollback this tree one epoch in the past
    fn rollback<F>(&mut self) -> impl Future<Output = Result<()>> {
        self.rollback_to(self.nodes().current_epoch() - 1)
    }

    /// Rollback this tree to the given epoch
    fn rollback_to(&mut self, epoch: Epoch) -> impl Future<Output = Result<()>>;

    /// Return an epoch-locked, read-only, [`TreeStorage`] offering a view on
    /// this Merkle tree as it was at the given epoch.
    fn view_at<'a>(&'a self, epoch: Epoch) -> TreeStorageView<'a, T, Self>
    where
        T: 'a,
    {
        TreeStorageView::<'a, T, Self>::new(self, epoch)
    }
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
    fn rollback(&mut self) -> impl Future<Output = Result<()>> {
        self.rollback_to(self.current_epoch() - 1)
    }

    /// Roll back this storage to the given epoch
    fn rollback_to(&mut self, epoch: Epoch) -> impl Future<Output = Result<()>>;
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
    fn contains(&self, k: &K) -> impl Future<Output = bool> {
        async { self.try_fetch(k).await.is_some() }
    }

    /// Return whether the given key is present at the given epoch.
    fn contains_at(&self, k: &K, epoch: Epoch) -> impl Future<Output = bool> {
        async move { self.try_fetch_at(k, epoch).await.is_some() }
    }

    /// Return the number of stored K/V pairs at the current epoch.
    fn size(&self) -> impl Future<Output = usize> {
        self.size_at(self.current_epoch())
    }

    /// Return the number of stored K/V pairs at the given epoch.
    fn size_at(&self, epoch: Epoch) -> impl Future<Output = usize>;

    /// Return all the keys existing at the given epoch.
    fn keys_at(&self, epoch: Epoch) -> impl Future<Output = Vec<K>>;

    /// Return a key alive at epoch, if any.
    fn random_key_at(&self, epoch: Epoch) -> impl Future<Output = Option<K>>;

    /// Return all the valid key/value pairs at the given `epoch`.
    ///
    /// NOTE: be careful when using this function, it is not lazy.
    fn pairs_at(&self, epoch: Epoch) -> impl Future<Output = Result<HashMap<K, V>>>;
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
    fn rollback(&mut self) -> impl Future<Output = Result<()>> {
        self.rollback_to(self.current_epoch() - 1)
    }

    /// Rollback this storage to the given epoch. Please note that this is a
    /// destructive and irreversible operation.
    fn rollback_to(&mut self, epoch: Epoch) -> impl Future<Output = Result<()>>;
}

/// Characterizes a trait allowing for epoch-based atomic updates.
pub trait TransactionalStorage {
    /// Start a new transaction, defining a transition between the storage at
    /// two epochs.
    fn start_transaction(&mut self) -> Result<()>;

    /// Closes the current transaction and commit to the new state at the new
    /// epoch.
    fn commit_transaction(&mut self) -> impl Future<Output = Result<()>>;

    /// Execute the given function acting on `Self` within a transaction.
    ///
    /// Will fail if the transaction failed.
    fn in_transaction<Fut, F: FnOnce(&mut Self) -> Fut>(
        &mut self,
        f: F,
    ) -> impl Future<Output = Result<()>>
    where
        Fut: Future<Output = Result<()>>,
    {
        async {
            self.start_transaction()?;
            f(self).await?;
            self.commit_transaction().await
        }
    }
}

/// This trait is similar to [`TransactionalStorage`], but let the caller re-use
/// an existing SQL transaction rather than letting the implementer handle
/// transaction creation & execution.
pub trait SqlTransactionStorage: TransactionalStorage {
    /// Similar to the [`commit`] method of [`TransactionalStorage`], but
    /// re-using a given transaction.
    fn commit_in(&mut self, tx: &mut Transaction<'_>) -> impl Future<Output = Result<()>>;

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
    fn start_transaction(&mut self) -> impl Future<Output = Result<()>>;

    /// Closes the current transaction and commit to the new state at the new
    /// epoch.
    ///
    /// Return the hierarchy of `Key` affected by the transaction and requiring
    /// a re-proof.
    fn commit_transaction(&mut self) -> impl Future<Output = Result<UpdateTree<K>>>;

    /// Execute the given function acting on `Self` within a transaction.
    ///
    /// Will fail if the transaction failed.
    fn in_transaction<F: FnOnce(&mut Self) -> BoxFuture<'_, Result<()>> + Sync>(
        &mut self,
        f: F,
    ) -> impl Future<Output = Result<UpdateTree<K>>> {
        async {
            self.start_transaction().await?;
            f(self).await?;
            self.commit_transaction().await
        }
    }

    /// Consume an iterator of [`Operation<K>`] and apply all of them within a
    /// single transaction.
    ///
    /// Return the hierarchy of `Key` affected by the transaction and requiring
    /// a re-proof.
    ///
    /// Fail if any of the operation fails.
    fn transaction_from_batch<I: IntoIterator<Item = Operation<K, V>>>(
        &mut self,
        ops: I,
    ) -> impl Future<Output = Result<UpdateTree<K>>> {
        async {
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
///     successful SQL transaction execution.
pub trait SqlTreeTransactionalStorage<K: Clone + Hash + Eq + Send + Sync, V: Send + Sync>:
    TreeTransactionalStorage<K, V>
{
    /// Similar to the [`commit`] method of [`TreeTransactionalStorage`], but
    /// re-using a given transaction.
    fn commit_in(
        &mut self,
        tx: &mut Transaction<'_>,
    ) -> impl Future<Output = Result<UpdateTree<K>>>;

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

/// The meta-operations trait gathers high-level operations that may be
/// optimized depending on the backend.
pub trait MetaOperations<T: TreeTopology, V: Send + Sync>:
    TreeStorage<T> + PayloadStorage<T::Key, V>
{
    /// The type of the artefact used to retrieve a dynamic set of keys for the
    /// [`TreeStorage`] implementing this trait.
    type KeySource;

    /// Fetch the subtree defined as the 2-depth extension of the subtree formed
    /// by the union of all the paths-to-the-root for the given keys.
    fn wide_lineage_between(
        &self,
        at: Epoch,
        t: &T,
        keys: &Self::KeySource,
        bounds: (Epoch, Epoch),
    ) -> impl Future<Output = Result<WideLineage<T::Key, V>>>;

    fn wide_update_trees(
        &self,
        at: Epoch,
        t: &T,
        keys: &Self::KeySource,
        bounds: (Epoch, Epoch),
    ) -> impl Future<Output = Result<Vec<UpdateTree<T::Key>>>> {
        async move {
            let wide_lineage = self.wide_lineage_between(at, t, keys, bounds).await?;
            let mut r = Vec::new();
            for (epoch, nodes) in wide_lineage.epoch_lineages.iter() {
                if let Some(root) = t.root(&self.view_at(*epoch)).await {
                    r.push(UpdateTree::from_map(*epoch, &root, &nodes.0));
                }
            }
            Ok(r)
        }
    }
    #[allow(clippy::type_complexity)]
    fn try_fetch_many_at<I: IntoIterator<Item = (Epoch, T::Key)> + Send>(
        &self,
        t: &T,
        data: I,
    ) -> impl Future<Output = Result<Vec<(Epoch, NodeContext<T::Key>, V)>>> + Send
    where
        <I as IntoIterator>::IntoIter: Send;
}
