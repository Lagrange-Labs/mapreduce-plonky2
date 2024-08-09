use futures::{stream, StreamExt};
use std::{collections::HashSet, marker::PhantomData};

use anyhow::*;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use storage::{
    updatetree::{Next, UpdatePlan, UpdateTree},
    view::TreeStorageView,
    EpochKvStorage, EpochStorage, FromSettings, PayloadStorage, RoEpochKvStorage,
    TransactionalStorage, TreeStorage, TreeTransactionalStorage,
};
use tree::{MutableTree, NodeContext, PrintableTree, TreeTopology};

pub mod storage;
#[cfg(test)]
mod tests;
pub mod tree;

/// A timestamp in a versioned storage. Using a signed type allows for easy
/// detection & debugging of erroneous subtractions.
pub type Epoch = i64;

/// A payload attached to a node, that may need to compute aggregated values
/// from the bottom of the tree to the top. If not, simply do not override the
/// default definition of `aggregate`.
#[async_trait]
pub trait NodePayload: Sized + Serialize + for<'a> Deserialize<'a> {
    /// Set an aggregate value for the current node, computable from the payload
    /// of its children.
    ///
    /// Return true if the payload has been modified and must be updated in the
    /// storage, false otherwise.
    fn aggregate<I: Iterator<Item = Option<Self>>>(&mut self, _children: I) {}
}

/// Define how to initialize a Merkle tree KV DB depending on the current status
/// of the persisted data, if any.
pub enum InitSettings<T> {
    /// Fail to initialize if the data does not already exist.
    MustExist,
    /// Fail to initialize if the tree already exists, create with the given
    /// state it otherwise.
    MustNotExist(T),
    /// Ensure that the tree is re-created with the given settings, erasing it
    /// if it exists.
    Reset(T),
}

/// An `MerkleTreeKvDb` wraps together:
///  - a tree of keys;
///  - a transactional storage for its nodes;
///  - a transactional storage for the data associated to the keys.
///
/// It behaves as a transactional epoch key-value database that returns, for
/// each transaction, the tree of interdependence between the altered keys, be
/// it either by direct insertion and/or deletion or because they have been
/// dirtied in cascade by operations on the tree.
///
/// It ensures that within the rules of the transactional epoch storage
/// framework, the tree, the nodes and the data are all kept in a coherent
/// state.
pub struct MerkleTreeKvDb<
    // Tree type
    T: TreeTopology + MutableTree,
    // Node payload
    V: NodePayload + Send + Sync,
    // Tree & data storage
    S: TransactionalStorage
        + TreeStorage<T>
        + PayloadStorage<T::Key, V>
        + FromSettings<T::State>
        + Send
        + Sync,
> {
    /// The tree where the key hierarchy will be stored
    tree: T,
    /// The storage where to store the node associated data
    storage: S,
    /// A transaction-lived set of keys having been dirtied in the tree
    dirty: HashSet<T::Key>,
    /// [ignore]
    _p: PhantomData<V>,
}
impl<
        T: TreeTopology + MutableTree + Send,
        V: NodePayload + Send + Sync,
        S: TransactionalStorage + TreeStorage<T> + PayloadStorage<T::Key, V> + FromSettings<T::State>,
    > MerkleTreeKvDb<T, V, S>
{
    /// Create a new `EpochTreeStorage` from the given parameters.
    ///
    /// * `init_settings` - the initial state of the underlying tree
    /// * `storage_settings` - the settings to build the storage backend
    ///
    /// Fails if the tree construction or either of the storage initialization
    /// failed.
    pub async fn new(
        init_settings: InitSettings<T::State>,
        storage_settings: S::Settings,
    ) -> Result<Self> {
        let storage = S::from_settings(init_settings, storage_settings)
            .await
            .context("while creating data storage")?;

        Ok(MerkleTreeKvDb {
            tree: Default::default(),
            storage,
            dirty: Default::default(),
            _p: PhantomData,
        })
    }

    /// Returns the storage state, which can be useful to fetch information like the shift on sbbst
    pub async fn storage_state(&self) -> <T as TreeTopology>::State {
        self.storage.state().fetch().await
    }
    /// Compute a bottom-up-aggregated value on the payload of the nodes,
    /// recursively from the leaves up to the root node.
    async fn aggregate(&mut self, mut plan: UpdatePlan<T::Key>) -> Result<()> {
        while let Some(Next::Ready(k)) = plan.next() {
            let c = self.tree.node_context(&k, &self.storage).await.unwrap();
            let mut child_data = vec![];
            for c in c.iter_children() {
                if let Some(k) = c {
                    child_data.push(Some(self.storage.data().fetch(k).await));
                } else {
                    child_data.push(None);
                }
            }

            let mut payload = self.storage.data().fetch(&k).await;
            payload.aggregate(child_data.into_iter());
            plan.done(&k)?;
            self.storage.data_mut().store(k, payload).await?
        }
        Ok(())
    }

    /// Return, if any, the set of nodes that will be touched, either directly
    /// or as a result of the aggregation update process, byt the operations
    /// defined in the current transactions.
    ///
    /// The set will be empty if their is no transaction active.
    pub async fn touched(&mut self) -> HashSet<T::Key> {
        stream::iter(self.dirty.iter())
            .filter_map(|k| async { self.tree.lineage(k, &self.storage).await })
            .flat_map(|p| stream::iter(p.into_full_path()))
            .collect::<_>()
            .await
    }

    /// Return the key mapped to the current root of the Merkle tree.
    pub async fn root(&self) -> Option<T::Key> {
        self.tree.root(&self.storage).await
    }
    pub async fn root_at(&self, epoch: Epoch) -> Option<T::Key> {
        let view = self.view_at(epoch);
        self.tree.root(&view).await
    }

    pub async fn root_data_at(&self, epoch: Epoch) -> Option<V> {
        let view = self.view_at(epoch);
        if let Some(root) = self.tree.root(&view).await {
            let root = self.storage.data().fetch_at(&root, epoch).await;
            Some(root)
        } else {
            None
        }
    }

    /// Return the current root hash of the Merkle tree.
    pub async fn root_data(&self) -> Option<V> {
        if let Some(root) = self.tree.root(&self.storage).await {
            let root = self.storage.data().fetch(&root).await;
            Some(root)
        } else {
            None
        }
    }

    /// Return the current root hash of the Merkle tree at the given epoch.
    pub async fn root_hash_at(&self, epoch: Epoch) -> Option<V> {
        let view = self.view_at(epoch);
        if let Some(root) = self.tree.root(&view).await {
            Some(self.storage.data().fetch_at(&root, epoch).await)
        } else {
            None
        }
    }

    /// Fetch a value from the storage and returns its [`NodeContext`] in the
    /// tree as well.
    ///
    /// Fail if `k` does not exist in the tree.
    pub async fn try_fetch_with_context(&self, k: &T::Key) -> Option<(NodeContext<T::Key>, V)> {
        if let Some(ctx) = self.tree.node_context(k, &self.storage).await {
            if let Some(v) = self.try_fetch(k).await {
                return Some((ctx, v));
            }
        }
        None
    }

    /// Fetch a value at the given `epoch` from the storage and returns its
    /// [`NodeContext`] in the tree as well.
    ///
    /// Fail if `k` does not exist in the tree.
    pub async fn try_fetch_with_context_at(
        &self,
        k: &T::Key,
        epoch: Epoch,
    ) -> Option<(NodeContext<T::Key>, V)> {
        if let Some(ctx) = self.tree.node_context(k, &self.view_at(epoch)).await {
            if let Some(v) = self.try_fetch_at(k, epoch).await {
                return Some((ctx, v));
            }
        }
        None
    }

    /// Fetch, if it exists, a value from the storage and returns its
    /// [`NodeContext`] in the tree as well.
    pub async fn fetch_with_context(&self, k: &T::Key) -> (NodeContext<T::Key>, V) {
        self.try_fetch_with_context(k).await.unwrap()
    }

    /// Fetch, if it exists, a value from the storage at the given epoch and
    /// returns its [`NodeContext`] in the tree as well.
    pub async fn fetch_with_context_at(
        &self,
        k: &T::Key,
        epoch: Epoch,
    ) -> (NodeContext<T::Key>, V) {
        self.try_fetch_with_context_at(k, epoch).await.unwrap()
    }

    /// A reference to the underlying tree.
    pub fn tree(&self) -> &T {
        &self.tree
    }

    /// Forward tree-like operations to self.tree while injecting the storage
    pub async fn parent(&self, k: T::Key) -> Option<T::Key> {
        self.tree.parent(k, &self.storage).await
    }

    pub async fn node_context(&self, k: &T::Key) -> Option<NodeContext<T::Key>> {
        self.tree.node_context(k, &self.storage).await
    }

    /// Return an epoch-locked, read-only, [`TreeStorage`] offering a view on
    /// this Merkle tree as it was at the given epoch.
    pub fn view_at(&self, epoch: Epoch) -> TreeStorageView<'_, T, S> {
        TreeStorageView::<'_, T, S>::new(&self.storage, epoch)
    }

    /// Return the update tree generated by the transaction defining the given
    /// epoch.
    pub async fn diff_at(&self, epoch: Epoch) -> Option<UpdateTree<T::Key>> {
        if epoch > self.current_epoch() {
            None
        } else {
            let dirtied = self.storage.born_at(epoch).await;
            let s = TreeStorageView::<'_, T, S>::new(&self.storage, epoch);

            let mut paths = vec![];
            for k in dirtied {
                if let Some(p) = self.tree.lineage(&k, &s).await {
                    paths.push(p.into_full_path().collect::<Vec<_>>());
                }
            }

            let ut = UpdateTree::from_paths(paths, epoch);
            Some(ut)
        }
    }
}

// Data-related read-only operation are directly forwarded to the data
// storage.
//
// Write operations need to (i) be forwarded to the key tree, and (ii) see their
// dirty keys accumulated in order to build the dirty keys tree at the commiting
// of the transaction.
#[async_trait]
impl<
        T: TreeTopology + MutableTree,
        V: NodePayload + Send + Sync,
        S: TransactionalStorage + TreeStorage<T> + PayloadStorage<T::Key, V> + FromSettings<T::State>,
    > RoEpochKvStorage<T::Key, V> for MerkleTreeKvDb<T, V, S>
{
    fn current_epoch(&self) -> Epoch {
        self.storage.data().current_epoch()
    }

    async fn fetch_at(&self, k: &T::Key, timestamp: Epoch) -> V {
        self.storage.data().fetch_at(k, timestamp).await
    }

    async fn try_fetch_at(&self, k: &T::Key, epoch: Epoch) -> Option<V> {
        self.storage.data().try_fetch_at(k, epoch).await
    }

    async fn size(&self) -> usize {
        self.storage.data().size().await
    }
}

#[async_trait]
impl<
        T: TreeTopology + MutableTree,
        V: NodePayload + Sync + Send,
        S: TransactionalStorage + TreeStorage<T> + PayloadStorage<T::Key, V> + FromSettings<T::State>,
    > EpochKvStorage<T::Key, V> for MerkleTreeKvDb<T, V, S>
{
    async fn remove(&mut self, k: T::Key) -> Result<()> {
        self.dirty
            .extend(self.tree.delete(&k, &mut self.storage).await?);
        self.storage.data_mut().remove(k).await?;
        Ok(())
    }

    async fn update(&mut self, k: T::Key, new_value: V) -> Result<()> {
        self.storage.data_mut().update(k.clone(), new_value).await?;
        self.dirty.insert(k);
        Ok(())
    }

    async fn update_with<F: Fn(&mut V) + Send + Sync>(&mut self, k: T::Key, updater: F) {
        self.storage
            .data_mut()
            .update_with(k.clone(), updater)
            .await;
        self.dirty.insert(k);
    }

    async fn store(&mut self, k: T::Key, value: V) -> Result<()> {
        let ds = self.tree.insert(k.clone(), &mut self.storage).await?;
        self.dirty.extend(ds.into_full_path());
        self.storage.data_mut().store(k, value).await
    }

    /// Rollback this storage to the given epoch. Please note that this is a
    /// destructive and irreversible operation; to merely get a view on the
    /// storage at a given epoch, use the `view_at` method.
    async fn rollback_to(&mut self, epoch: Epoch) -> Result<()> {
        self.storage.rollback_to(epoch).await
    }
}

// Transaction-related operations must be forwared both to the node and the data
// storages. Moreover, the dirty keys tree must be built on successful
// transaction commiting.
impl<
        T: TreeTopology + MutableTree + Send + Sync,
        V: NodePayload + Send + Sync,
        S: TransactionalStorage + TreeStorage<T> + PayloadStorage<T::Key, V> + FromSettings<T::State>,
    > TreeTransactionalStorage<T::Key, V> for MerkleTreeKvDb<T, V, S>
{
    async fn start_transaction(&mut self) -> Result<()> {
        self.storage.start_transaction()?;
        Ok(())
    }

    async fn commit_transaction(&mut self) -> Result<UpdateTree<T::Key>> {
        let mut paths = vec![];
        for k in self.dirty.drain() {
            if let Some(p) = self.tree.lineage(&k, &self.storage).await {
                paths.push(p.into_full_path().collect::<Vec<_>>());
            }
        }

        let update_tree = UpdateTree::from_paths(paths, self.current_epoch() + 1);

        let plan = update_tree.clone().into_workplan();

        self.aggregate(plan.clone()).await?;
        self.storage.commit_transaction().await?;

        Ok(update_tree)
    }
}

impl<
        T: TreeTopology + MutableTree + PrintableTree,
        V: NodePayload + Send + Sync,
        S: TransactionalStorage + TreeStorage<T> + PayloadStorage<T::Key, V> + FromSettings<T::State>,
    > MerkleTreeKvDb<T, V, S>
{
    pub async fn print_tree(&self) {
        self.tree.print(&self.storage).await
    }
}
