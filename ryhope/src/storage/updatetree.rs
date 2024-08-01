use crate::{tree::TreeTopology, Epoch};
use anyhow::*;
use futures::future::BoxFuture;
use futures::FutureExt;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeSet, HashMap},
    hash::Hash,
};

use super::TreeStorage;

/// A UpdateTree represent the hierarchy of nodes whose hash will need to be
/// recomputed, and feature ancillary functions to this purpose.
#[derive(Clone, Serialize, Deserialize)]
pub struct UpdateTree<K: Clone + Hash + Eq> {
    /// The epoch stemming from the application of this update tree
    epoch: Epoch,
    /// An arena-like storage of all the nodes in the tree
    nodes: Vec<UpdateTreeNode<K>>,
    /// key -> arena index mapping
    idx: HashMap<K, usize>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct UpdateTreeNode<K: Clone + Hash + Eq> {
    /// If any, the parent of this node
    parent: Option<usize>,
    /// Indices of the children nodes in the node arena
    children: BTreeSet<usize>,
    /// The key born by this node
    k: K,
}
impl<K: Clone + Hash + Eq> UpdateTreeNode<K> {
    fn is_leaf(&self) -> bool {
        self.children.is_empty()
    }
}

impl<K: Clone + Hash + Eq + Sync + Send> UpdateTree<K> {
    /// Create an empty `UpdateTree`.
    fn empty(epoch: Epoch) -> Self {
        Self {
            epoch,
            nodes: Vec::new(),
            idx: Default::default(),
        }
    }

    fn rec_build<'a, T: TreeTopology<Key = K>, S: TreeStorage<T>>(
        &'a mut self,
        t: &'a T,
        current: &'a K,
        nodes: &'a S,
    ) -> BoxFuture<'a, usize> {
        async move {
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
            if let Some(child) = self.nodes[current]
                .children
                .iter()
                .find(|i| self.nodes[**i].k == k)
            {
                self.rec_from_path(*child, path);
            } else {
                let new_i = self.nodes.len();
                if self.idx.insert(k.clone(), new_i).is_some() {
                    panic!("duplicated key found in path");
                }
                self.nodes[current].children.insert(new_i);
                self.nodes.push(UpdateTreeNode {
                    parent: Some(current),
                    children: BTreeSet::new(),
                    k,
                });
                self.rec_from_path(new_i, path);
            }
        }
    }

    /// Extend an `UpdateTree` with a new path from the root to a node.
    pub fn extend_with_path(&mut self, mut path: Vec<K>) {
        path.reverse();
        if let Some(k) = path.pop() {
            assert!(k == self.nodes[0].k);
            self.rec_from_path(0, path);
        }
    }

    /// Create a workplan from this tree, consuming it.
    pub fn into_workplan(self) -> UpdatePlan<K> {
        UpdatePlan::new(self)
    }

    /// Return the epoch generated by this tree.
    pub fn epoch(&self) -> Epoch {
        self.epoch
    }
}

impl<K: Clone + Hash + Eq + std::fmt::Debug> UpdateTree<K> {
    fn rec_print(&self, i: usize, indent: usize) {
        let n = &self.nodes[i];
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

/// An update plan to recompute all the hashes of the touched nodes stored in a
/// given [`UpdateTree`] in such a way that children are always computed before
/// their parents.
///
/// The [`Iterator`] implementation return either `None` when all nodes have
/// been processed, or an instance of `Next` while there remains nodes to be
/// processed. If `Next::Ready` is returned, then the given node can be safely
/// processed. If `Next::NotYet` is returned, then there are still noded to
/// process, but their children have not been processed yet. In this case, the
/// `[done(k)]` method shall be invoked to mark processed, which will allow
/// `next()` to return their parents on its next invokation.
#[derive(Clone)]
pub struct UpdatePlan<T: Clone + Hash + Eq> {
    pub t: UpdateTree<T>,
    ready: Vec<T>,
}
impl<T: Clone + Hash + Eq> UpdatePlan<T> {
    fn new(t: UpdateTree<T>) -> Self {
        let mut r = UpdatePlan {
            t,
            ready: Default::default(),
        };

        // Mark all the leaves as being ready to be processed
        for n in r.t.nodes.iter_mut() {
            if n.is_leaf() {
                r.ready.push(n.k.clone());
            }
        }

        r
    }

    pub fn done(&mut self, k: &T) -> Result<()> {
        let i = *self.t.idx.get(k).ok_or_else(|| anyhow!("unknwown key"))?;

        // May happen when restarting a plan
        self.ready.retain(|x| x != k);

        // Root node is hardcoded to 0
        if i == 0 {
            self.t.nodes.clear();
        } else {
            let parent = self.t.nodes[i].parent.unwrap();
            debug_assert!(self.t.nodes[parent].children.contains(&i));
            self.t.nodes[parent].children.remove(&i);
            if self.t.nodes[parent].children.is_empty() {
                self.ready.push(self.t.nodes[parent].k.clone());
            }
        }
        Ok(())
    }
}
impl<T: Clone + Hash + Eq> Iterator for UpdatePlan<T> {
    type Item = Next<T>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.t.nodes.is_empty() {
            None
        } else {
            Some(if let Some(k) = self.ready.pop() {
                Next::Ready(k)
            } else {
                Next::NotYet
            })
        }
    }
}

#[cfg(test)]
mod test {
    use crate::{
        storage::{memory::InMemory, updatetree::Next},
        tree::sbbst,
    };

    use super::UpdateTree;

    #[test]
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
                println!("Doing {}", k);
                done.push(k);
                workplan.t.print();
            }

            for d in done.iter() {
                workplan.done(dbg!(d)).unwrap();
            }
            if done.is_empty() {
                break;
            }
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
