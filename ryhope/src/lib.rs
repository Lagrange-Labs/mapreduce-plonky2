use error::RyhopeError;
use futures::{stream, StreamExt};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    fmt::Debug,
    future::Future,
    hash::Hash,
    marker::PhantomData,
};
use storage::{
    updatetree::{Next, UpdatePlan, UpdateTree},
    view::TreeStorageView,
    EpochKvStorage, EpochStorage, FromSettings, MetaOperations, PayloadStorage, RoEpochKvStorage,
    SqlTransactionStorage, SqlTreeTransactionalStorage, TransactionalStorage, TreeStorage,
    TreeTransactionalStorage, WideLineage,
};
use tokio_postgres::Transaction;
use tracing::*;
use tree::{sbbst, scapegoat, MutableTree, NodeContext, NodePath, PrintableTree, TreeTopology};

pub mod error;
pub mod storage;
#[cfg(test)]
mod tests;
pub mod tree;

/// The column containing the node key in the zkTable
pub const KEY: &str = "__key";
/// The column containing the node payload in the zkTable
pub const PAYLOAD: &str = "__payload";
/// The column containing the epoch in queries
pub const EPOCH: &str = "__epoch";
/// The column containing the first epoch of validity of the row in the zkTable
pub const VALID_FROM: &str = "__valid_from";
/// The column containing the last epoch of validity of the row in the zkTable
pub const VALID_UNTIL: &str = "__valid_until";
/// The column containing epoch values that are meaningful for the user-exposed table
pub const USER_EPOCH: &str = "__user_epoch";
/// The column containing the incremental epochs employed in the zkTable
pub const INCREMENTAL_EPOCH: &str = "__incremental_epoch";

/// A timestamp in a versioned storage. It corresponds to the actual epochs used internally in
/// the storage implementations, which are assumed to be sequential.
/// Using a signed type allows for easy detection & debugging of erroneous subtractions.
pub type IncrementalEpoch = i64;

/// Represents the epochs of the storage as defined by the user.
/// The storages provided here allows to decouple these epochs from the `IncrementalEpoch`s
/// being used internally, allowing users to define epochs for the storage which are not
/// necessarily incremental. The only assumption is that these user-defined epochs
/// are monotonically increasing.
pub type UserEpoch = i64;

pub fn mapper_table_name(table_name: &str) -> String {
    format!("{}_mapper", table_name)
}

pub(crate) fn metadata_table_name(table_name: &str) -> String {
    format!("{}_meta", table_name)
}

/// A payload attached to a node, that may need to compute aggregated values
/// from the bottom of the tree to the top. If not, simply do not override the
/// default definition of `aggregate`.
pub trait NodePayload: Debug + Sized + Serialize + for<'a> Deserialize<'a> {
    /// Set an aggregate value for the current node, computable from the payload
    /// of its children.
    fn aggregate<I: Iterator<Item = Option<Self>>>(&mut self, children: I) {
        self.aggregate_with_context(children, &mut ())
    }

    /// Set an aggregate value for the current node, computable from the payload
    /// of its children and some external generic data.
    fn aggregate_with_context<I: Iterator<Item = Option<Self>>, T>(
        &mut self,
        _children: I,
        _context: &mut T,
    ) {
    }
}

impl NodePayload for serde_json::Value {
    fn aggregate<I: Iterator<Item = Option<Self>>>(&mut self, _children: I) {}
}

/// Define how to initialize a Merkle tree KV DB depending on the current status
/// of the persisted data, if any.
pub enum InitSettings<T> {
    /// Fail to initialize if the data does not already exist.
    MustExist,
    /// Fail to initialize if the tree already exists, create with the given
    /// state otherwise.
    MustNotExist(T),
    /// Fail to initialize if the tree already exists, create with the given
    /// state and starting at the given epoch otherwise.
    MustNotExistAt(T, UserEpoch),
    /// Ensure that the tree is re-created with the given settings, erasing it
    /// if it exists.
    Reset(T),
    /// Ensure that the tree is re-created with the given settings and at the
    /// given initial epoch, erasing it if it exists.
    ResetAt(T, UserEpoch),
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
> where
    T::Key: Debug,
{
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
where
    T::Key: Debug,
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
    ) -> Result<Self, RyhopeError> {
        let storage = S::from_settings(init_settings, storage_settings).await?;

        Ok(MerkleTreeKvDb {
            tree: Default::default(),
            storage,
            dirty: Default::default(),
            _p: PhantomData,
        })
    }

    /// Returns the storage state, which can be useful to fetch information like the shift on sbbst
    pub async fn storage_state(&self) -> Result<<T as TreeTopology>::State, RyhopeError> {
        self.storage.state().fetch().await
    }

    /// Compute a bottom-up-aggregated value on the payload of the nodes,
    /// recursively from the leaves up to the root node.
    async fn aggregate(&mut self, mut plan: UpdatePlan<T::Key>) -> Result<(), RyhopeError> {
        while let Some(Next::Ready(item)) = plan.next() {
            let c = self
                .tree
                .node_context(item.k(), &self.storage)
                .await?
                .unwrap();
            let mut child_data = vec![];
            for c in c.iter_children() {
                if let Some(k) = c {
                    child_data.push(self.storage.data().try_fetch(k).await?);
                } else {
                    child_data.push(None);
                }
            }

            let mut payload = self
                .storage
                .data()
                .try_fetch(item.k())
                .await?
                .expect("the node can not not be present");
            payload.aggregate(child_data.into_iter());
            plan.done(&item)?;
            self.storage
                .data_mut()
                .store(item.k().to_owned(), payload)
                .await?
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
            .filter_map(|k| async { self.tree.lineage(k, &self.storage).await.unwrap() })
            .flat_map(|p| stream::iter(p.into_full_path()))
            .collect::<_>()
            .await
    }

    /// Return the key mapped to the current root of the Merkle tree.
    pub async fn root(&self) -> Result<Option<T::Key>, RyhopeError> {
        self.tree.root(&self.storage).await
    }

    /// Return the key mapped to the root of the Merkle tree at the given epoch.
    pub async fn root_at(&self, epoch: UserEpoch) -> Result<Option<T::Key>, RyhopeError> {
        self.tree.root(&self.storage.view_at(epoch)).await
    }

    /// Return the current payload of the Merkle tree root.
    pub async fn root_data(&self) -> Result<Option<V>, RyhopeError> {
        Ok(if let Some(root) = self.tree.root(&self.storage).await? {
            self.storage.data().try_fetch(&root).await?
        } else {
            None
        })
    }

    /// Return the payload of the Merkle tree root at the given epoch.
    pub async fn root_data_at(&self, epoch: UserEpoch) -> Result<Option<V>, RyhopeError> {
        Ok(
            if let Some(root) = self.tree.root(&self.storage.view_at(epoch)).await? {
                self.storage.data().try_fetch_at(&root, epoch).await?
            } else {
                None
            },
        )
    }

    /// Fetch a value from the storage and returns its [`NodeContext`] in the
    /// tree as well.
    ///
    /// Fail if `k` does not exist in the tree.
    pub async fn try_fetch_with_context(
        &self,
        k: &T::Key,
    ) -> Result<Option<(NodeContext<T::Key>, V)>, RyhopeError> {
        Ok(
            if let Some(ctx) = self.tree.node_context(k, &self.storage).await? {
                self.try_fetch(k).await?.map(|v| (ctx, v))
            } else {
                None
            },
        )
    }

    /// Fetch a value at the given `epoch` from the storage and returns its
    /// [`NodeContext`] in the tree as well.
    ///
    /// Fail if `k` does not exist in the tree.
    pub async fn try_fetch_with_context_at(
        &self,
        k: &T::Key,
        epoch: UserEpoch,
    ) -> Result<Option<(NodeContext<T::Key>, V)>, RyhopeError> {
        if let Some(ctx) = self
            .tree
            .node_context(k, &self.storage.view_at(epoch))
            .await?
        {
            if let Some(v) = self.try_fetch_at(k, epoch).await? {
                return Ok(Some((ctx, v)));
            }
        }
        Ok(None)
    }

    /// Fetch, if it exists, a value from the storage and returns its
    /// [`NodeContext`] in the tree as well.
    pub async fn fetch_with_context(
        &self,
        k: &T::Key,
    ) -> Result<Option<(NodeContext<T::Key>, V)>, RyhopeError> {
        self.try_fetch_with_context(k).await
    }

    /// Fetch, if it exists, a value from the storage at the given epoch and
    /// returns its [`NodeContext`] in the tree as well.
    pub async fn fetch_with_context_at(
        &self,
        k: &T::Key,
        epoch: UserEpoch,
    ) -> Result<Option<(NodeContext<T::Key>, V)>, RyhopeError> {
        self.try_fetch_with_context_at(k, epoch).await
    }

    /// A reference to the underlying tree.
    pub fn tree(&self) -> &T {
        &self.tree
    }

    /// Forward tree-like operations to self.tree while injecting the storage
    pub async fn parent(&self, k: T::Key) -> Result<Option<T::Key>, RyhopeError> {
        self.tree.parent(k, &self.storage).await
    }

    pub async fn node_context(
        &self,
        k: &T::Key,
    ) -> Result<Option<NodeContext<T::Key>>, RyhopeError> {
        self.tree.node_context(k, &self.storage).await
    }

    pub async fn node_context_at(
        
        &self,
       
        k: &T::Key,
       
        epoch: UserEpoch,
    ,
    ) -> Result<Option<NodeContext<T::Key>>, RyhopeError> {
        self.tree
            .node_context(k, &self.storage.view_at(epoch))
            .await
    }

    /// Return, if it exists, a [`NodePath`] for the given key in the underlying
    /// tree representing its ascendance up to the tree root.
    pub async fn lineage(&self, k: &T::Key) -> Result<Option<NodePath<T::Key>>, RyhopeError> {
        self.tree.lineage(k, &self.storage).await
    }

    /// Return, if it exists, a [`NodePath`] for the given key at the given
    /// epoch in the underlying tree representing its ascendance up to the tree
    /// root.
    pub async fn lineage_at(
        &self,
        k: &T::Key,
        epoch: UserEpoch,
    ) -> Result<Option<NodePath<T::Key>>, RyhopeError> {
        let s = TreeStorageView::<'_, T, S>::new(&self.storage, epoch);
        self.tree.lineage(k, &s).await
    }

    /// Return the union of the lineages of the keys in the given iterator at
    /// the specified epoch.
    pub async fn ascendance_at<I: IntoIterator<Item = T::Key>>(
        &self,
        ks: I,
        epoch: UserEpoch,
    ) -> Result<HashSet<T::Key>, RyhopeError> {
        self.tree.ascendance(ks, &self.view_at(epoch)).await
    }

    /// Return a handle to this merkle tree storage, as it stands at its most
    /// recent epoch.
    pub fn now(&self) -> &S {
        &self.storage
    }

    /// Return an epoch-locked, read-only, [`TreeStorage`] offering a view on
    /// this Merkle tree as it was at the given epoch.
    pub fn view_at(&self, epoch: UserEpoch) -> TreeStorageView<'_, T, S> {
        TreeStorageView::<'_, T, S>::new(&self.storage, epoch)
    }

    /// Return the update tree generated by the transaction defining the given
    /// epoch.
    pub async fn diff_at(&self, epoch: UserEpoch) -> Result<Option<UpdateTree<T::Key>>, RyhopeError> {
        let current_epoch = self.current_epoch().await?;
        Ok(if epoch <= current_epoch {
            let dirtied = self.storage.born_at(epoch).await;
            let s = TreeStorageView::<'_, T, S>::new(&self.storage, epoch);

            let mut paths = vec![];
            for k in dirtied {
                if let Some(p) = self.tree.lineage(&k, &s).await? {
                    paths.push(p.into_full_path().collect::<Vec<_>>());
                }
            }

            let ut = UpdateTree::from_paths(paths, epoch);
            Ok(Some(ut))
        } else {
            None
        })
    }
}

impl<
        T: TreeTopology + MutableTree + Send,
        V: NodePayload + Send + Sync,
        S: TransactionalStorage
            + TreeStorage<T>
            + PayloadStorage<T::Key, V>
            + FromSettings<T::State>
            + MetaOperations<T, V>,
    > MerkleTreeKvDb<T, V, S>
{
    pub async fn wide_update_trees_at(
        &self,
        at: UserEpoch,
        keys_query: &S::KeySource,
        bounds: (UserEpoch, UserEpoch),
    ) -> Result<Vec<UpdateTree<T::Key>>, RyhopeError> {
        self.storage
            .wide_update_trees(at, &self.tree, keys_query, bounds)
            .await
    }

    pub async fn try_fetch_many_at<I: IntoIterator<Item = (UserEpoch, T::Key)> + Send>(
        &self,
        data: I,
    ) -> Result<Vec<(UserEpoch, NodeContext<T::Key>, V)>, RyhopeError>
    where
        <I as IntoIterator>::IntoIter: Send,
    {
        self.storage.try_fetch_many_at(&self.tree, data).await
    }

    pub async fn wide_lineage_between(
        &self,
        at: UserEpoch,
        keys_query: &S::KeySource,
        bounds: (UserEpoch, UserEpoch),
    ) -> Result<WideLineage<T::Key, V>, RyhopeError> {
        self.storage
            .wide_lineage_between(at, &self.tree, keys_query, bounds)
            .await
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
        V: NodePayload + Send + Sync,
        S: TransactionalStorage + TreeStorage<T> + PayloadStorage<T::Key, V> + FromSettings<T::State>,
    > RoEpochKvStorage<T::Key, V> for MerkleTreeKvDb<T, V, S>
{
    /// Return the first registered time stamp of the storage
    fn initial_epoch(&self) -> impl Future<Output = UserEpoch> + Send {
        self.storage.data().initial_epoch()
    }

    fn current_epoch(&self) -> impl Future<Output = Result<UserEpoch>> + Send {
        self.storage.data().current_epoch()
    }

    async fn fetch_at(&self, k: &T::Key, timestamp: UserEpoch) -> V {
        self.storage.data().fetch_at(k, timestamp).await
    }

    async fn fetch(&self, k: &T::Key) -> V {
        self.storage.data().fetch(k).await
    }

    async fn try_fetch_at(&self, k: &T::Key, epoch: UserEpoch) -> Result<Option<V>, RyhopeError> {
        self.storage.data().try_fetch_at(k, epoch).await
    }

    async fn try_fetch(&self, k: &T::Key) -> Option<V> {
        self.storage.data().try_fetch(k).await
    }

    async fn size_at(&self, epoch: UserEpoch) -> usize {
        self.storage.data().size_at(epoch).await
    }

    async fn size(&self) -> usize {
        self.storage.data().size().await
    }

    async fn keys_at(&self, epoch: UserEpoch) -> Vec<T::Key> {
        self.storage.data().keys_at(epoch).await
    }

    async fn random_key_at(&self, epoch: UserEpoch) -> Option<T::Key> {
        self.storage.data().random_key_at(epoch).await
    }

    async fn pairs_at(&self, epoch: UserEpoch) -> Result<HashMap<T::Key, V>, RyhopeError> {
        self.storage.data().pairs_at(epoch).await
    }
}

impl<
        T: TreeTopology + MutableTree,
        V: NodePayload + Sync + Send,
        S: TransactionalStorage + TreeStorage<T> + PayloadStorage<T::Key, V> + FromSettings<T::State>,
    > EpochKvStorage<T::Key, V> for MerkleTreeKvDb<T, V, S>
{
    async fn remove(&mut self, k: T::Key) -> Result<(), RyhopeError> {
        trace!("[MerkleTreeKvDb] removing {k:?}");
        self.dirty
            .extend(self.tree.delete(&k, &mut self.storage).await?);
        self.storage.data_mut().remove(k).await?;
        Ok(())
    }

    async fn update(&mut self, k: T::Key, new_value: V) -> Result<(), RyhopeError> {
        trace!("[MerkleTreeKvDb] updating {k:?} -> {new_value:?}");
        self.storage.data_mut().update(k.clone(), new_value).await?;
        self.dirty.insert(k);
        Ok(())
    }

    async fn update_with<F: Fn(&mut V) + Send + Sync>(
        &mut self,
        k: T::Key,
        updater: F,
    ) -> Result<(), RyhopeError> {
        self.storage
            .data_mut()
            .update_with(k.clone(), updater)
            .await?;
        self.dirty.insert(k);
        Ok(())
    }

    async fn store(&mut self, k: T::Key, value: V) -> Result<(), RyhopeError> {
        trace!("[MerkleTreeKvDb] storing {k:?} -> {value:?}");
        let ds = self.tree.insert(k.clone(), &mut self.storage).await?;
        self.dirty.extend(ds.into_full_path());
        self.storage.data_mut().store(k, value).await
    }

    /// Rollback this storage to the given epoch. Please note that this is a
    /// destructive and irreversible operation; to merely get a view on the
    /// storage at a given epoch, use the `view_at` method.
    async fn rollback_to(&mut self, epoch: UserEpoch) -> Result<(), RyhopeError> {
        trace!("[MerkleTreeKvDb] rolling back to {epoch}");
        self.storage.rollback_to(epoch).await
    }

    async fn rollback(&mut self) -> Result<()> {
        trace!("[MerkleTreeKvDb] rolling back");
        self.storage.rollback().await
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
    async fn start_transaction(&mut self) -> Result<(), RyhopeError> {
        trace!("[MerkleTreeKvDb] calling start_transaction");
        self.storage.start_transaction().await?;
        Ok(())
    }

    async fn commit_transaction(&mut self) -> Result<UpdateTree<T::Key>, RyhopeError> {
        trace!("[MerkleTreeKvDb@] calling commit_transaction");
        let mut paths = vec![];
        for k in self.dirty.drain() {
            if let Some(p) = self.tree.lineage(&k, &self.storage).await? {
                paths.push(p.into_full_path().collect::<Vec<_>>());
            }
        }

        let update_tree = UpdateTree::from_paths(paths, self.current_epoch().await?);

        let plan = update_tree.clone().into_workplan();

        self.aggregate(plan.clone()).await?;
        self.storage.commit_transaction().await?;

        Ok(update_tree)
    }
}

impl<
        T: TreeTopology + MutableTree + Send + Sync,
        V: NodePayload + Send + Sync,
        S: SqlTransactionStorage + TreeStorage<T> + PayloadStorage<T::Key, V> + FromSettings<T::State>,
    > SqlTreeTransactionalStorage<T::Key, V> for MerkleTreeKvDb<T, V, S>
{
    async fn commit_in(
        &mut self,
        tx: &mut Transaction<'_>,
    ) -> Result<UpdateTree<T::Key>, RyhopeError> {
        trace!("[MerkleTreeKvDb] calling commit_in");
        let mut paths = vec![];
        for k in self.dirty.drain() {
            if let Some(p) = self.tree.lineage(&k, &self.storage).await? {
                paths.push(p.into_full_path().collect::<Vec<_>>());
            }
        }

        let update_tree = UpdateTree::from_paths(paths, self.current_epoch().await?);
        let plan = update_tree.clone().into_workplan();
        self.aggregate(plan.clone()).await?;
        self.storage.commit_in(tx).await?;

        Ok(update_tree)
    }

    async fn commit_success(&mut self) {
        trace!("[MerkleTreeKvDb] triggering commit_success");
        self.storage.commit_success().await
    }

    async fn commit_failed(&mut self) {
        trace!("[MerkleTreeKvDb] triggering commit_failed");
        self.storage.commit_failed().await
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

/// Create a new index tree-specific `EpochTreeStorage` from the given parameters.
///
/// * `genesis_block` - the first block number that will be inserted
/// * `storage_settings` - the settings to build the storage backend
/// * `reset_if_exist` - if true, an existing tree would be deleted
///
/// Fails if the tree construction or either of the storage initialization
/// failed.
pub async fn new_index_tree<
    V: NodePayload + Send + Sync,
    S: TransactionalStorage
        + TreeStorage<sbbst::EpochTree>
        + PayloadStorage<sbbst::NodeIdx, V>
        + FromSettings<sbbst::State>,
>(
    genesis_block: UserEpoch,
    storage_settings: S::Settings,
    reset_if_exist: bool,
) -> Result<MerkleTreeKvDb<sbbst::EpochTree, V, S>, RyhopeError> {
    if genesis_block <= 0 {
        return Err(RyhopeError::fatal("the genesis block must be positive"));
    }

    let initial_epoch = genesis_block - 1;
    let tree_settings = sbbst::EpochTree::with_shift(initial_epoch.try_into().unwrap());

    MerkleTreeKvDb::new(
        if reset_if_exist {
            InitSettings::ResetAt(tree_settings, initial_epoch)
        } else {
            InitSettings::MustNotExistAt(tree_settings, initial_epoch)
        },
        storage_settings,
    )
    .await
}

/// Create a new row tree-specific `EpochTreeStorage` from the given parameters.
///
/// * `genesis_block` - the first block number that will be inserted
/// * `storage_settings` - the settings to build the storage backend
/// * `reset_if_exist` - if true, an existing tree would be deleted
///
/// Fails if the tree construction or either of the storage initialization
/// failed.
pub async fn new_row_tree<
    K: Debug + Sync + Send + Clone + Eq + Hash + Ord + Serialize + for<'a> Deserialize<'a>,
    V: NodePayload + Send + Sync,
    S: TransactionalStorage
        + TreeStorage<scapegoat::Tree<K>>
        + PayloadStorage<K, V>
        + FromSettings<scapegoat::State<K>>,
>(
    genesis_block: UserEpoch,
    alpha: scapegoat::Alpha,
    storage_settings: S::Settings,
    reset_if_exist: bool,
) -> Result<MerkleTreeKvDb<scapegoat::Tree<K>, V, S>, RyhopeError> {
    if genesis_block <= 0 {
        return Err(RyhopeError::fatal("the genesis block must be positive"));
    }

    let initial_epoch = genesis_block - 1;
    let tree_settings = scapegoat::Tree::empty(alpha);

    MerkleTreeKvDb::new(
        if reset_if_exist {
            InitSettings::ResetAt(tree_settings, initial_epoch)
        } else {
            InitSettings::MustNotExistAt(tree_settings, initial_epoch)
        },
        storage_settings,
    )
    .await
}
