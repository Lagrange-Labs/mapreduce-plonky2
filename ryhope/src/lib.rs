use anyhow::*;
use delegate::delegate;
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, marker::PhantomData};

use storage::{
    updatetree::{Next, UpdatePlan, UpdateTree},
    view::TreeStorageView,
    EpochKvStorage, FromSettings, PayloadStorage, RoEpochKvStorage, TransactionalStorage,
    TreeStorage, TreeTransactionalStorage,
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
    V: NodePayload,
    // Tree & data storage
    S: TransactionalStorage + TreeStorage<T> + PayloadStorage<T::Key, V> + FromSettings<T::State>,
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
        T: TreeTopology + MutableTree,
        V: NodePayload,
        S: TransactionalStorage + TreeStorage<T> + PayloadStorage<T::Key, V> + FromSettings<T::State>,
    > MerkleTreeKvDb<T, V, S>
{
    /// Create a new `EpochTreeStorage` from the given parameters.
    ///
    /// * `tree_settings` - the settings passed to the tree constructor
    /// * `node_storage_settings` - the settings to build the node storage
    /// * `data_storage_settings` - the settings to build the data storage
    ///
    /// Fails if the tree construction or either of the storage initialization
    /// failed.
    pub fn new(
        init_settings: InitSettings<T::State>,
        storage_settings: S::Settings,
    ) -> Result<Self> {
        let storage = S::from_settings(init_settings, storage_settings)
            .context("while creating data storage")?;

        Ok(MerkleTreeKvDb {
            tree: Default::default(),
            storage,
            dirty: Default::default(),
            _p: PhantomData,
        })
    }

    /// Compute a bottom-up-aggregated value on the payload of the nodes,
    /// recursively from the leaves up to the root node.
    fn aggregate(&mut self, mut plan: UpdatePlan<T::Key>) -> Result<()> {
        while let Some(Next::Ready(k)) = plan.next() {
            let c = self.tree.node_context(&k, &self.storage).unwrap();

            let child_data = c
                .iter_children()
                .map(|c| c.map(|k| self.storage.data().fetch(k)));
            let mut payload = self.storage.data().fetch(&k);
            payload.aggregate(child_data);
            plan.done(&k)?;
            self.storage.data_mut().store(k, payload)?
        }
        Ok(())
    }

    /// Return the key mapped to the current root of the Merkle tree.
    pub fn root(&self) -> Option<T::Key> {
        self.tree.root(&self.storage)
    }

    /// Return the current root hash of the Merkle tree.
    pub fn root_data(&self) -> Option<V> {
        self.tree
            .root(&self.storage)
            .map(|r| self.storage.data().fetch(&r))
    }

    /// Return the current root hash of the Merkle tree at the given epoch.
    pub fn root_hash_at(&self, epoch: Epoch) -> Option<V> {
        self.tree
            .root(&self.storage)
            .map(|r| self.storage.data().fetch_at(&r, epoch))
    }

    /// Fetch a value from the storage and returns its [`NodeContext`] in the
    /// tree as well.
    ///
    /// Fail if `k` does not exist in the tree.
    pub fn try_fetch_with_context(&self, k: &T::Key) -> Option<(NodeContext<T::Key>, V)> {
        self.tree
            .node_context(k, &self.storage)
            .and_then(|ctx| self.try_fetch(k).map(|v| (ctx, v)))
    }

    /// Fetch, if it exists, a value from the storage and returns its
    /// [`NodeContext`] in the tree as well.
    pub fn fetch_with_context(&self, k: &T::Key) -> (NodeContext<T::Key>, V) {
        self.try_fetch_with_context(k).unwrap()
    }

    /// A reference to the underlying tree.
    pub fn tree(&self) -> &T {
        &self.tree
    }

    /// Forward tree-like operations to self.tree while injecting the storage
    pub fn parent(&self, k: T::Key) -> Option<T::Key> {
        self.tree.parent(k, &self.storage)
    }

    pub fn node_context(&self, k: &T::Key) -> Option<NodeContext<T::Key>> {
        self.tree.node_context(k, &self.storage)
    }

    /// Return an epoch-locked, read-only, [`TreeStorage`] offering a view on
    /// this Merkle tree as it was at the given epoch.
    pub fn view_at(&self, epoch: Epoch) -> TreeStorageView<'_, T, S> {
        TreeStorageView::<'_, T, S>::new(&self.storage, epoch)
    }

    /// Return the update tree generated by the transaction defining the given
    /// epoch.
    pub fn diff_at(&self, epoch: Epoch) -> Option<UpdateTree<T::Key>> {
        if epoch > self.current_epoch() {
            None
        } else {
            let dirtied = self.storage.born_at(epoch);
            let s = TreeStorageView::<'_, T, S>::new(&self.storage, epoch);
            let paths = dirtied
                .iter()
                .filter_map(|k| self.tree.lineage(k, &s))
                .map(|p| p.into_full_path().collect::<Vec<_>>())
                .collect::<Vec<_>>();

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
impl<
        T: TreeTopology + MutableTree,
        V: NodePayload,
        S: TransactionalStorage + TreeStorage<T> + PayloadStorage<T::Key, V> + FromSettings<T::State>,
    > RoEpochKvStorage<T::Key, V> for MerkleTreeKvDb<T, V, S>
{
    delegate! {
        to self.storage.data() {
            fn current_epoch(&self) -> Epoch ;
            fn fetch_at(&self, k: &T::Key, timestamp: Epoch) -> V ;
            fn try_fetch_at(&self, k: &T::Key, timestamp: Epoch) -> Option<V> ;
            fn size(&self) -> usize;
        }
    }
}

impl<
        T: TreeTopology + MutableTree,
        V: NodePayload,
        S: TransactionalStorage + TreeStorage<T> + PayloadStorage<T::Key, V> + FromSettings<T::State>,
    > EpochKvStorage<T::Key, V> for MerkleTreeKvDb<T, V, S>
{
    fn remove(&mut self, k: T::Key) -> Result<()> {
        self.dirty.extend(self.tree.delete(&k, &mut self.storage)?);
        self.storage.data_mut().remove(k)?;
        Ok(())
    }

    fn store(&mut self, k: T::Key, value: V) -> Result<()> {
        let ds = self.tree.insert(k.clone(), &mut self.storage)?;
        self.dirty.extend(ds.into_full_path());
        self.storage.data_mut().store(k, value)
    }

    fn update(&mut self, k: T::Key, new_value: V) -> Result<()> {
        self.storage.data_mut().update(k.clone(), new_value)?;
        self.dirty.insert(k);
        Ok(())
    }

    fn update_with<F: Fn(&mut V)>(&mut self, k: T::Key, updater: F) {
        self.storage.data_mut().update_with(k.clone(), updater);
        self.dirty.insert(k);
    }

    /// Rollback this storage to the given epoch. Please note that this is a
    /// destructive and irreversible operation; to merely get a view on the
    /// storage at a given epoch, use the `view_at` method.
    fn rollback_to(&mut self, epoch: Epoch) -> Result<()> {
        self.storage.rollback_to(epoch)
    }
}

// Transaction-related operations must be forwared both to the node and the data
// storages. Moreover, the dirty keys tree must be built on successful
// transaction commiting.
impl<
        T: TreeTopology + MutableTree,
        V: NodePayload,
        S: TransactionalStorage + TreeStorage<T> + PayloadStorage<T::Key, V> + FromSettings<T::State>,
    > TreeTransactionalStorage<T::Key, V> for MerkleTreeKvDb<T, V, S>
{
    fn start_transaction(&mut self) -> Result<()> {
        self.storage.start_transaction()?;
        Ok(())
    }

    fn commit_transaction(&mut self) -> Result<UpdateTree<T::Key>> {
        let paths = self
            .dirty
            .iter()
            .filter_map(|k| self.tree.lineage(k, &self.storage))
            .map(|p| p.into_full_path().collect::<Vec<_>>())
            .collect::<Vec<_>>();
        self.dirty.clear();

        let update_tree = UpdateTree::from_paths(paths, self.current_epoch() + 1);

        let plan = update_tree.clone().into_workplan();

        self.aggregate(plan.clone())?;
        self.storage.commit_transaction()?;

        Ok(update_tree)
    }
}

impl<
        T: TreeTopology + MutableTree + PrintableTree,
        V: NodePayload,
        S: TransactionalStorage + TreeStorage<T> + PayloadStorage<T::Key, V> + FromSettings<T::State>,
    > MerkleTreeKvDb<T, V, S>
{
    fn print_tree(&self) {
        self.tree.print(&self.storage)
    }
}
