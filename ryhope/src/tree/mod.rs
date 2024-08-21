use anyhow::*;
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, fmt::Debug, future::Future, hash::Hash};

use crate::storage::TreeStorage;

pub mod sbbst;
pub mod scapegoat;

/// A representation of a path in the tree leading to `target` from the root.
#[derive(Debug)]
pub struct NodePath<K> {
    /// The list of parents to traverse to reach `target` from the root.
    ascendance: Vec<K>,
    /// The end of the path
    target: K,
}
impl<K> NodePath<K> {
    /// Return an iterator over references to the keys forming the full path
    /// from the root to `target` (included).
    pub fn full_path(&self) -> impl Iterator<Item = &K> {
        self.ascendance.iter().chain(std::iter::once(&self.target))
    }
    /// Return an iterator over the keys forming the full path from the root to
    /// `target` (included).
    pub fn into_full_path(self) -> impl Iterator<Item = K> {
        self.ascendance
            .into_iter()
            .chain(std::iter::once(self.target))
    }
}

/// Define common topological operations on trees.
pub trait TreeTopology: Default + Send + Sync {
    type Key: Debug + Clone + Hash + Eq + Sync + Send;
    type Node: Debug + Sync + Send;
    /// Minimal data required to persist the tree.
    type State: Send + Sync + Clone + Debug + Serialize + for<'a> Deserialize<'a>;

    /// Return the number of nodes currently stored in the tree
    async fn size<S: TreeStorage<Self>>(&self, s: &S) -> usize;

    /// Return the root of the tree.
    ///
    /// May be empty, e.g. if the tree is empty.
    async fn root<S: TreeStorage<Self>>(&self, s: &S) -> Option<Self::Key>;

    /// Return the parent of `n`, or None if `n` is the root of the tree.
    async fn parent<S: TreeStorage<Self>>(&self, n: Self::Key, s: &S) -> Option<Self::Key>;

    /// Return whether `k` exists in the tree.
    async fn contains<S: TreeStorage<Self>>(&self, k: &Self::Key, s: &S) -> bool;

    /// Return, if it has some, the children of `k`.
    ///
    /// Return nothing if `k` is not in the tree.
    async fn children<S: TreeStorage<Self>>(
        &self,
        k: &Self::Key,
        s: &S,
    ) -> Option<(Option<Self::Key>, Option<Self::Key>)>;

    /// Returns the [`NodePath`] from the root of the tree to `k`.
    async fn lineage<S: TreeStorage<Self>>(
        &self,
        k: &Self::Key,
        s: &S,
    ) -> Option<NodePath<Self::Key>>;

    /// Return the union of the lineages of all the `ns`
    async fn ascendance<S: TreeStorage<Self>>(
        &self,
        ns: &[Self::Key],
        s: &S,
    ) -> HashSet<Self::Key> {
        let mut ascendance = HashSet::new();
        for n in ns {
            if let Some(np) = self.lineage(&n, s).await {
                ascendance.extend(np.into_full_path());
            }
        }
        ascendance
    }

    /// Return the immediate neighborhood of the given `k`, if it exists, in the
    /// tree.
    fn node_context<S: TreeStorage<Self>>(
        &self,
        k: &Self::Key,
        s: &S,
    ) -> impl Future<Output = Option<NodeContext<Self::Key>>> + Send;
}

/// Define operations to mutate a tree.
pub trait MutableTree: TreeTopology {
    /// Insert the given key in the tree; fail if it is already present.
    ///
    /// Return the [`NodePath`] to the newly inserted node.
    fn insert<S: TreeStorage<Self>>(
        &mut self,
        k: Self::Key,
        s: &mut S,
    ) -> impl Future<Output = Result<NodePath<Self::Key>>> + Send;

    /// Remove the given key from the tree; fail if it is already present.
    ///
    /// Return the `Key`s of the nodes affected by the deletion.
    fn delete<S: TreeStorage<Self>>(
        &mut self,
        k: &Self::Key,
        s: &mut S,
    ) -> impl Future<Output = Result<Vec<Self::Key>>> + Send;
}

/// A data structure encompassing the immediate neighborhood of a node.
#[derive(Clone, Debug)]
pub struct NodeContext<K> {
    /// The considered node ID
    pub node_id: K,
    /// If any, the node ID of its parent
    pub parent: Option<K>,
    /// The node ID of its left child, if it has one
    pub left: Option<K>,
    /// The node ID of its right child, if it has one
    pub right: Option<K>,
}
impl<K> NodeContext<K> {
    /// Return true if this node has no children
    pub fn is_leaf(&self) -> bool {
        self.left.is_none() && self.right.is_none()
    }

    /// Return true if the reference has but a child.
    pub fn is_partial(&self) -> bool {
        self.left.is_some() != self.right.is_some()
    }

    /// Iterate, in order from left to right, over the children (if any) of this
    /// node.
    pub fn iter_children(&self) -> impl Iterator<Item = Option<&K>> {
        [self.left.as_ref(), self.right.as_ref()].into_iter()
    }
}

pub trait PrintableTree: TreeTopology {
    async fn print<S: TreeStorage<Self>>(&self, s: &S);
}
