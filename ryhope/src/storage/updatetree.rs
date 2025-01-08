use crate::{
    tree::{NodeContext, TreeTopology},
    Epoch,
};
use anyhow::*;
use futures::{future::BoxFuture, FutureExt};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeSet, HashMap},
    fmt::Debug,
    hash::Hash,
};

use super::TreeStorage;

/// A UpdateTree represent the hierarchy of nodes whose hash will need to be
/// recomputed, and feature ancillary functions to this purpose.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UpdateTree<K: Clone + Hash + Eq> {
    /// The epoch stemming from the application of this update tree
    epoch: Epoch,
    /// An arena-like storage of all the nodes in the tree
    nodes: Vec<UpdateTreeNode<K>>,
    /// key -> arena index mapping
    idx: HashMap<K, usize>,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct UpdateTreeNode<K: Clone + Hash + Eq> {
    /// If any, the parent of this node
    parent: Option<usize>,
    /// Indices of the children nodes in the node arena
    children: BTreeSet<usize>,
    /// The key born by this node
    k: K,
    /// Whether this node is a leaf of an update path
    is_path_end: bool,
}
impl<K: Debug + Clone + Hash + Eq> UpdateTreeNode<K> {
    fn is_leaf(&self) -> bool {
        self.children.is_empty()
    }
}

impl<K: Clone + Hash + Eq> UpdateTree<K> {
    pub fn root(&self) -> &K {
        &self.nodes[0].k
    }

    fn node(&self, i: usize) -> &UpdateTreeNode<K> {
        &self.nodes[i]
    }

    fn node_mut(&mut self, i: usize) -> &mut UpdateTreeNode<K> {
        &mut self.nodes[i]
    }

    pub fn node_from_key(&self, k: &K) -> Option<&UpdateTreeNode<K>> {
        self.idx.get(k).map(|i| self.node(*i))
    }
}

impl<K: Debug + Clone + Hash + Eq> UpdateTree<K> {
    /// Create an empty `UpdateTree`.
    fn empty(epoch: Epoch) -> Self {
        Self {
            epoch,
            nodes: Vec::new(),
            idx: Default::default(),
        }
    }

    pub fn impacted_keys(&self) -> Vec<K> {
        self.nodes.iter().map(|n| n.k.clone()).collect()
    }

    /// Instantiate a new `UpdateTree` containing all the provided paths.
    pub fn from_paths<I: IntoIterator<Item = Vec<K>>>(paths: I, epoch: Epoch) -> Self {
        let mut paths = paths.into_iter();
        if let Some(path) = paths.next() {
            let mut r = Self::from_path(path, epoch);
            for path in paths {
                r.extend_with_path(path);
            }
            r
        } else {
            Self::empty(epoch)
        }
    }

    /// Instantiate a new `UpdateTree` from a seminal path from the root to a
    /// node.
    pub fn from_path(mut path: Vec<K>, epoch: Epoch) -> Self {
        path.reverse();
        if let Some(root_k) = path.pop() {
            let mut tree = UpdateTree {
                epoch,
                nodes: vec![UpdateTreeNode {
                    parent: None,
                    children: BTreeSet::new(),
                    k: root_k.clone(),
                    is_path_end: path.is_empty(),
                }],
                idx: Default::default(),
            };
            tree.idx.insert(root_k, 0);
            tree.rec_from_path(0, path);
            tree
        } else {
            panic!("empty path");
        }
    }

    fn rec_from_path(&mut self, current: usize, mut path: Vec<K>) {
        if let Some(k) = path.pop() {
            if let Some(child) = self
                .node(current)
                .children
                .iter()
                .find(|i| self.node(**i).k == k)
            {
                self.rec_from_path(*child, path);
            } else {
                let new_i = self.nodes.len();
                if self.idx.insert(k.clone(), new_i).is_some() {
                    panic!("duplicated key found in path");
                }
                self.node_mut(current).children.insert(new_i);
                // we add a children to current, so `is_path_end` should be false
                self.node_mut(current).is_path_end = false;
                self.nodes.push(UpdateTreeNode {
                    parent: Some(current),
                    children: BTreeSet::new(),
                    k,
                    is_path_end: path.is_empty(),
                });
                self.rec_from_path(new_i, path);
            }
        }
    }

    /// Extend an `UpdateTree` with a new path from the root to a node.
    pub fn extend_with_path(&mut self, mut path: Vec<K>) {
        path.reverse();
        if let Some(k) = path.pop() {
            assert_eq!(k, self.node(0).k);
            self.rec_from_path(0, path);
        }
    }

    /// Create a workplan from this tree, consuming it.
    pub fn into_workplan(self) -> UpdatePlan<K> {
        UpdatePlan::new(self, 1)
    }

    /// Create a workplan of subtrees up to `batch_size` elements from this
    /// tree, consuming it.
    pub fn into_batched_workplan(self, subtree_size: usize) -> UpdatePlan<K> {
        UpdatePlan::new(self, subtree_size)
    }

    /// Return the epoch generated by this tree.
    pub fn epoch(&self) -> Epoch {
        self.epoch
    }

    /// Return the number of nodes in the subtree spanned at the given key,
    /// including the root.
    pub fn subtree_size_i(&self, i: usize) -> usize {
        let n = &self.node(i);
        1 + n
            .children
            .iter()
            .map(|c| self.subtree_size_i(*c))
            .sum::<usize>()
    }

    /// Return a new `UpdateTree` corresponding to the subtree spanned by the node
    /// of index `new_root`.
    ///
    /// Panic if the given key does not exist.
    pub fn spin_off(&mut self, new_root: usize) -> UpdateTree<K> {
        // First, insert all the nodes...
        let mut nodes = Vec::with_capacity(self.subtree_size_i(new_root));
        let mut idx = HashMap::new();
        for old_node_i in self.descendants(new_root) {
            let i = nodes.len();
            let old_node = self.node(old_node_i);
            let k = old_node.k.to_owned();
            idx.insert(self.node(old_node_i).k.clone(), i);
            nodes.push(UpdateTreeNode {
                k,
                parent: None,
                children: BTreeSet::new(),
                is_path_end: old_node.is_path_end,
            });
        }

        // ...then re-create all the topological information
        for old_node_i in self.descendants(new_root) {
            let old_node = self.node(old_node_i);
            let new_node_i = idx[&self.node(old_node_i).k];

            // Only update the parent if this is not the new root
            //NOTE: maybe it would make sense to keep the parent relationship?
            if old_node_i != new_root {
                if let Some(old_parent_i) = old_node.parent {
                    let new_parent_i = idx[&self.node(old_parent_i).k];
                    nodes[new_node_i].parent = Some(new_parent_i);
                }
            }

            // Re-create the parent/child relationships
            nodes[new_node_i].children = old_node
                .children
                .iter()
                .map(|old_child_i| idx[&self.node(*old_child_i).k])
                .collect();
        }

        UpdateTree {
            epoch: self.epoch,
            nodes,
            idx,
        }
    }

    /// Return an iterator over the children ID in the subtree spanned by the
    /// given node, including the node itself.
    pub fn descendants(&self, k: usize) -> Box<dyn Iterator<Item = usize> + '_> {
        let n = &self.node(k);
        Box::new(
            std::iter::once(k).chain(
                n.children
                    .iter()
                    .flat_map(|child_i| self.descendants(*child_i)),
            ),
        )
    }
}

impl<K: Debug + Clone + Hash + Eq + Sync + Send> UpdateTree<K> {
    fn rec_build<'a, T: TreeTopology<Key = K>, S: TreeStorage<T>>(
        &'a mut self,
        t: &'a T,
        current: &'a K,
        nodes: &'a S,
    ) -> BoxFuture<'a, usize> {
        async {
            let context = t.node_context(current, nodes).await.unwrap();
            let new_i = self.nodes.len();
            self.idx.insert(current.clone(), new_i);
            // Important here to push the top node first, as the UpdateTree expects
            // nodes[0] to be the implicit root.
            self.nodes.push(UpdateTreeNode {
                parent: context
                    .parent
                    .clone()
                    .map(|p| self.idx.get(&p).unwrap())
                    .copied(),
                children: Default::default(),
                k: current.to_owned(),
                is_path_end: context.is_leaf(),
            });
            for c in context.iter_children().flatten() {
                let c_i = self.rec_build(t, c, nodes).await;
                self.nodes[new_i].children.insert(c_i);
            }
            new_i
        }
        .boxed()
    }

    /// Instantiate a new `UpdateTree` mirroring the integrality of the provided tree.
    pub async fn from_tree<T: TreeTopology<Key = K> + Sync, S: TreeStorage<T>>(
        t: &T,
        s: &S,
        epoch: Epoch,
    ) -> Self {
        let mut r = Self::empty(epoch);
        if let Some(root) = t.root(s).await {
            r.rec_build(t, &root, s).await;
        }
        r
    }
}

impl<K: Clone + Hash + Eq + Sync + Send + std::fmt::Debug> UpdateTree<K> {
    /// Instantiate a new `UpdateTree` mirroring the hierarchy of nodes
    /// described by the given map of [`NodeContext`].
    ///
    /// This method assumes that the given map correctly encodes a binary tree
    /// and will not perform any check.
    pub fn from_map(epoch: Epoch, root: &K, nodes: &HashMap<K, NodeContext<K>>) -> Self {
        let mut r = Self::empty(epoch);
        r.rec_from_map(root, nodes, None);
        r
    }

    fn rec_from_map(
        &mut self,
        current: &K,
        nodes: &HashMap<K, NodeContext<K>>,
        parent_i: Option<usize>,
    ) -> Option<usize> {
        if let Some(context) = nodes.get(current) {
            let current_i = self.nodes.len();
            if self.idx.insert(current.clone(), current_i).is_some() {
                panic!("duplicated key found");
            }
            self.nodes.push(UpdateTreeNode {
                parent: parent_i,
                children: BTreeSet::new(),
                k: current.clone(),
                is_path_end: context.is_leaf(),
            });
            for child in [context.left.as_ref(), context.right.as_ref()]
                .iter()
                .flatten()
            {
                if let Some(child_i) = self.rec_from_map(child, nodes, Some(current_i)) {
                    self.node_mut(current_i).children.insert(child_i);
                }
            }
            Some(current_i)
        } else {
            None
        }
    }

    fn rec_print(&self, i: usize, indent: usize) {
        let n = self.node(i);
        if n.children.is_empty() {
            println!("{}{:?}", " ".repeat(indent), n.k);
        } else {
            let mid = n.children.len() / 2;

            for j in n.children.iter().take(mid) {
                self.rec_print(*j, indent + 2);
            }

            println!("{}{:?}", " ".repeat(indent), n.k);

            for j in n.children.iter().skip(mid) {
                self.rec_print(*j, indent + 2);
            }
        }
    }

    pub fn print(&self) {
        if self.nodes.is_empty() {
            return;
        }
        self.rec_print(0, 0);
    }
}

/// The answer returned by the update plan.
#[derive(Debug)]
pub enum Next<T: Clone> {
    /// A node is ready to be processed.
    Ready(T),
    /// There are still nodes to process, but their children have not been
    /// processed yet.
    NotYet,
}

/// The items that are produced by the [`WorkPlan`].
#[derive(Clone, Serialize, Deserialize)]
pub enum WorkplanItem<K: Clone + Hash + Eq + Debug> {
    Subtree {
        /// The key where the subtree is rooted in the global [`UpdateTree`].
        k: K,
        /// The subtree representing the batch contained in this item; it may
        /// degenerate to a single element if the batch size was 1.
        subtree: UpdateTree<K>,
    },
    Node {
        /// The leaf key
        k: K,
        is_path_end: bool,
    },
}
impl<K: Clone + Hash + Eq + Debug> WorkplanItem<K> {
    pub fn k(&self) -> &K {
        match self {
            WorkplanItem::Subtree { k, .. } | WorkplanItem::Node { k, .. } => k,
        }
    }
}

/// An update plan to recompute all the hashes of the touched nodes stored in a
/// given [`UpdateTree`] in such a way that children are always computed before
/// their parents.
///
/// The [`Iterator`] implementation return either `None` when all nodes have
/// been processed, or an instance of `Next` while there remains nodes to be
/// processed. If `Next::Ready` is returned, then the given node can be safely
/// processed. If `Next::NotYet` is returned, then there are still nodes to
/// process, but their children have not been processed yet. In this case, the
/// `[done(k)]` method shall be invoked to mark processed, which will allow
/// `next()` to return their parents on its next invokation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UpdatePlan<T: Debug + Clone + Hash + Eq> {
    pub t: UpdateTree<T>,
    batch_size: usize,
    anchors: Vec<T>,
}
impl<T: Debug + Clone + Hash + Eq> UpdatePlan<T> {
    fn new(t: UpdateTree<T>, max_subtree_size: usize) -> Self {
        UpdatePlan {
            // Mark all the leaves as being ready to be processed
            anchors: t
                .nodes
                .iter()
                .filter(|n| n.is_leaf())
                .map(|n| n.k.clone())
                .collect(),
            t,
            batch_size: max_subtree_size,
        }
    }

    /// Mark the given item as having been completed. Its dependent will not be
    /// generated by the iterator until the item has been marked as completed.
    pub fn done(&mut self, item: &WorkplanItem<T>) -> Result<()> {
        let i = *self
            .t
            .idx
            .get(item.k())
            .ok_or_else(|| anyhow!("unknwown key"))?;

        // May happen when restarting a plan
        self.anchors.retain(|k| k != item.k());

        // Root node is hardcoded to 0
        if i == 0 {
            self.t.nodes.clear();
        } else {
            let parent = self.t.node(i).parent.unwrap();
            debug_assert!(self.t.node(parent).children.contains(&i));
            self.t.node_mut(parent).children.remove(&i);
            if self.t.node(parent).children.is_empty() {
                self.anchors.push(self.t.nodes[parent].k.clone());
            }
        }
        Ok(())
    }

    /// Indicated whether this workplan has been entirely consumed.
    pub fn completed(&self) -> bool {
        self.t.nodes.is_empty()
    }

    /// Generate a new [`WorkplanItem`] satisfying, if possible, the given batch
    /// size criterion.
    ///
    /// The subtree generated is the highest parent of the next anchor such that
    /// the subtree it spans satisfies the batch size criterion. Note that if
    /// the batch size is equal to 1, the behavior is identical to a leaf-first
    /// traversal of the tree.
    fn find_next_subtree(&mut self) -> Option<WorkplanItem<T>> {
        self.anchors.pop().map(|anchor| {
            if self.batch_size == 1 {
                WorkplanItem::Node {
                    is_path_end: self.t.nodes[self.t.idx[&anchor]].is_path_end,
                    k: anchor,
                }
            } else {
                // Move up the tree from the first anchor to the furthest
                // ancestor satisfying the batch size.
                let mut spin_off_root = self.t.idx[&anchor];
                while let Some(parent) = self.t.node(spin_off_root).parent {
                    if self.t.subtree_size_i(parent) > self.batch_size {
                        break;
                    } else {
                        spin_off_root = parent;
                    }
                }

                let produced_subtree_size = self.t.subtree_size_i(spin_off_root);
                if produced_subtree_size > self.batch_size {
                    log::warn!(
                        "unable to produce subtree smaller than {}; producing subtree of size {}",
                        self.batch_size,
                        produced_subtree_size
                    )
                }

                WorkplanItem::Subtree {
                    k: self.t.node(spin_off_root).k.clone(),
                    subtree: self.t.spin_off(spin_off_root),
                }
            }
        })
    }
}
impl<T: Debug + Clone + Hash + Eq> Iterator for UpdatePlan<T> {
    type Item = Next<WorkplanItem<T>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.t.nodes.is_empty() {
            None
        } else {
            Some(if let Some(k) = self.find_next_subtree() {
                Next::Ready(k)
            } else {
                Next::NotYet
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        storage::{
            memory::InMemory,
            updatetree::{Next, WorkplanItem},
        },
        tree::sbbst,
    };

    use super::UpdateTree;

    #[test]
    /// Test a 1-sized batch update tree, i.e. a leaf-first traversal of the
    /// tree.
    fn mt_creation() {
        let paths = [
            vec![1, 3, 57, 9, 0],
            vec![1, 3, 89, 20],
            vec![1, 3, 57, 9, 10],
            vec![1, 3, 57, 43, 1874],
        ];

        let mut mt = UpdateTree::from_path(paths[0].to_vec(), 3);
        for path in paths.iter().skip(1) {
            mt.extend_with_path(path.to_vec());
        }

        mt.print();

        let mut workplan = mt.into_workplan();

        loop {
            let mut done = vec![];
            while let Some(Next::Ready(k)) = workplan.next() {
                println!("Doing {}", k.k());
                done.push(k);
                workplan.t.print();
            }

            for d in done.iter() {
                workplan.done(d).unwrap();
            }
            if done.is_empty() {
                break;
            }
        }

        assert!(workplan.completed());
    }

    #[test]
    /// Test the traversal of the plan for multiple batch sizes, including 0 and
    /// a batch size larger than the tree itself (i.e. the whole tree is
    /// consumed at once).
    fn mt_creation_staggered() {
        simple_logger::init().unwrap();

        let paths = [
            vec![1, 3, 57, 9, 0],
            vec![1, 3, 89, 20],
            vec![1, 3, 57, 9, 10],
            vec![1, 3, 57, 43, 1874],
        ];

        let mut mt = UpdateTree::from_path(paths[0].to_vec(), 3);
        for path in paths.iter().skip(1) {
            mt.extend_with_path(path.to_vec());
        }

        mt.print();

        // Ensure that for all batch sizes, from 0 to the tree size + 1:
        // 1. The traversal does not fail;
        // 2. The traversal finishes;
        // 3. The traversal indeed produces all of the nodes.
        for batch_size in 0..=mt.nodes.len() + 1 {
            let mut workplan = mt.clone().into_batched_workplan(batch_size);
            let mut count_done = 0;

            while let Some(Next::Ready(item)) = workplan.next() {
                match &item {
                    WorkplanItem::Subtree { subtree, .. } => {
                        workplan.t.print();
                        subtree.print();
                        count_done += subtree.nodes.len();
                    }
                    WorkplanItem::Node { k, .. } => {
                        println!("k = {k:?}");
                        count_done += 1;
                    }
                }
                workplan.done(&item).unwrap();
            }

            assert_eq!(count_done, mt.nodes.len());
            assert!(workplan.completed());
        }
    }

    #[tokio::test]
    async fn from_tree() {
        let t = sbbst::Tree;
        let storage = InMemory::<sbbst::Tree, ()>::new(sbbst::Tree::with_capacity(10));
        let ut = UpdateTree::from_tree(&t, &storage, 1).await;
        ut.print();
    }
}
