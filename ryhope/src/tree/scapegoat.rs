use super::PrintableTree;
use super::{MutableTree, NodeContext, NodePath, TreeTopology};
use crate::storage::{EpochKvStorage, EpochStorage, RoEpochKvStorage, TreeStorage};
use anyhow::*;
use serde::{Deserialize, Serialize};
use std::{cmp::Ordering, fmt::Debug, hash::Hash, marker::PhantomData};

/// The representation of a fraction as its numerator and denominator, allowing
/// for efficient generation of the fraction and its inverse.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Alpha(f32);
impl Alpha {
    /// Return an α such that the scapegoat tree systematically performs the
    /// balancing operation.
    pub fn fully_balanced() -> Alpha {
        Alpha(0.5)
    }

    /// Return an α such that the scapegoat tree never performs the balancing
    /// operation.
    pub fn never_balanced() -> Alpha {
        Alpha(1.0)
    }

    pub fn new(x: f32) -> Alpha {
        assert!((0.5..=1.0).contains(&x), "α must be in the [0.5; 1] range");
        Alpha(x)
    }

    fn inverse(&self) -> f32 {
        1. / self.0
    }
}

/// Store meta-data related to the topology in the scapegoat tree.
#[derive(Debug, Clone)]
pub struct Node<Key> {
    /// The key stored in this node
    pub(crate) k: Key,
    /// The number of nodes in the subtree spawned from this node
    pub(crate) subtree_size: usize,
    /// If any, this node parent
    pub(crate) parent: Option<Key>,
    /// If any, the slot of this node left child in the arena
    pub(crate) left: Option<Key>,
    /// If any, the slot of this node right child in the arena
    pub(crate) right: Option<Key>,
}
impl<Key> Node<Key> {
    fn new(k: Key) -> Self {
        Node {
            k,
            subtree_size: 1,
            parent: None,
            left: None,
            right: None,
        }
    }

    pub fn build(
        k: Key,
        subtree_size: usize,
        parent: Option<Key>,
        left: Option<Key>,
        right: Option<Key>,
    ) -> Self {
        Node {
            k,
            subtree_size,
            parent,
            left,
            right,
        }
    }

    fn new_with_parent(k: Key, parent: Key) -> Self {
        Node {
            k,
            subtree_size: 1,
            parent: Some(parent),
            left: None,
            right: None,
        }
    }

    fn left(&self) -> Option<&Key> {
        self.left.as_ref()
    }

    fn right(&self) -> Option<&Key> {
        self.right.as_ref()
    }
}
impl<Key: PartialEq> PartialEq for Node<Key> {
    fn eq(&self, other: &Self) -> bool {
        self.k == other.k
            && self.subtree_size == other.subtree_size
            && self.left == other.left
            && self.right == other.right
    }
}

/// Information pertaining to the neighbourhood of a node.
#[derive(Clone, Debug)]
pub struct NodeUpstream<K> {
    /// The ID of the considered node
    id: K,
    /// If any, the node parent ID
    parent: Option<K>,
    /// If applicable, whether the node is the left or right child of its parent
    direction: Ordering,
}
impl<K: Clone> NodeUpstream<K> {
    /// Move the context one edge down in the tree; the current `position`
    /// becomes the `parent`, and `cursor` becomes the new `position`.
    fn shift(&mut self, direction: Ordering, cursor: K) {
        self.parent = Some(self.id.clone());
        self.direction = direction;
        self.id = cursor;
    }

    /// True if this node is the right child of its parent.
    fn is_right(&self) -> bool {
        self.direction == Ordering::Greater
    }
}

/// The inner state of a scapegoat tree.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct State<K> {
    /// The current number of nodes in the tree
    node_count: usize,
    /// If any, the ID of the root node
    root: Option<K>,
    /// The α parameter of the scapegoat tree
    alpha: Alpha,
}

pub struct Tree<K: Debug + Sync + Clone + Eq + Hash + Ord + Serialize + for<'a> Deserialize<'a>>(
    PhantomData<K>,
);
impl<K: Debug + Sync + Clone + Eq + Hash + Ord + Serialize + for<'a> Deserialize<'a>> Default
    for Tree<K>
{
    fn default() -> Self {
        Tree(PhantomData)
    }
}

impl<K: Debug + Sync + Clone + Eq + Hash + Ord + Serialize + for<'a> Deserialize<'a>> Tree<K> {
    pub fn empty(alpha: Alpha) -> State<K> {
        State {
            node_count: 0,
            root: None,
            alpha,
        }
    }

    fn rec_depth<S: TreeStorage<Tree<K>>>(k: &K, s: &S) -> usize {
        let n = &s.nodes().fetch(k);
        let depth_l = n
            .left
            .as_ref()
            .map(|j| Self::rec_depth(j, s) + 1)
            .unwrap_or(0);
        let depth_r = n
            .right
            .as_ref()
            .map(|j| Self::rec_depth(j, s) + 1)
            .unwrap_or(0);
        depth_l.max(depth_r)
    }

    /// Return the depth of the tree, _i.e._ the longest path from the root to a leaf.
    pub fn depth<S: TreeStorage<Tree<K>>>(&self, s: &S) -> usize {
        if let Some(root) = s.state().fetch().root.as_ref() {
            Self::rec_depth(root, s)
        } else {
            0
        }
    }

    /// Insert the key `k` in the tree.
    ///
    /// Fail if `k` is already present in the tree.
    pub fn insert<S: TreeStorage<Tree<K>>>(&mut self, k: K, nodes: &mut S) -> Result<NodePath<K>> {
        self._insert(k, false, nodes)
    }

    /// Insert the key `k` in the tree; do nothing if it is already present.
    pub fn maybe_insert<S: TreeStorage<Tree<K>>>(
        &mut self,
        k: K,
        nodes: &mut S,
    ) -> Result<NodePath<K>> {
        self._insert(k, true, nodes)
    }

    /// Return all the nodes located below `from` in the tree, including `from`.
    pub fn descendants<S: TreeStorage<Tree<K>>>(&self, from: &K, s: &S) -> Vec<K> {
        let mut todo = vec![from.to_owned()];
        let mut r = vec![from.to_owned()];

        while let Some(i) = todo.pop() {
            if let Some(left) = s.nodes().fetch(&i).left() {
                todo.push(left.to_owned());
                r.push(left.to_owned());
            }

            if let Some(right) = s.nodes().fetch(&i).right() {
                todo.push(right.to_owned());
                r.push(right.to_owned());
            }
        }

        r
    }

    /// Return, if any, the `NodeContext` associated to `k`.
    pub fn context<S: TreeStorage<Tree<K>>>(&self, k: &K, s: &S) -> Result<NodeUpstream<K>> {
        if let Some(root) = s.state().fetch().root.as_ref() {
            let mut context = NodeUpstream {
                parent: None,
                direction: Ordering::Equal,
                id: root.to_owned(),
            };

            loop {
                let current = &s.nodes().fetch(&context.id);
                match k.cmp(&current.k) {
                    Ordering::Less => {
                        if let Some(left) = current.left.as_ref() {
                            debug_assert!(
                                s.nodes().fetch(left).parent.as_ref() == Some(&context.id)
                            );
                            context.shift(Ordering::Less, left.to_owned());
                        } else {
                            bail!("key not found in tree")
                        }
                    }
                    Ordering::Equal => {
                        return Ok(context);
                    }
                    Ordering::Greater => {
                        if let Some(right) = current.right.as_ref() {
                            debug_assert!(
                                s.nodes().fetch(right).parent.as_ref() == Some(&context.id)
                            );
                            context.shift(Ordering::Greater, right.to_owned());
                        } else {
                            bail!("key not found in tree")
                        }
                    }
                }
            }
        } else {
            bail!("the tree is empty")
        }
    }

    /// Return, if it exists, the path leading from the tree root to the node
    /// containing `k`.
    pub fn find_with_path<S: TreeStorage<Tree<K>>>(&self, k: &K, s: &S) -> Option<NodePath<K>> {
        let mut path = Vec::with_capacity(self.size(s).ilog2() as usize);

        if let Some(root) = s.state().fetch().root.as_ref() {
            let mut cursor = root.to_owned();
            loop {
                let current = s.nodes().fetch(&cursor);
                match k.cmp(&current.k) {
                    Ordering::Less => {
                        if let Some(left) = current.left() {
                            path.push(cursor.to_owned());
                            cursor = left.to_owned();
                        } else {
                            return None;
                        }
                    }
                    Ordering::Equal => {
                        return Some(NodePath {
                            target: cursor.to_owned(),
                            ascendance: path,
                        });
                    }
                    Ordering::Greater => {
                        if let Some(right) = current.right() {
                            path.push(cursor.to_owned());
                            cursor = right.to_owned();
                        } else {
                            return None;
                        }
                    }
                }
            }
        } else {
            None
        }
    }

    /// Delete the node carrying `k` from the tree.
    ///
    /// Fail if `k` is not present
    pub fn unlink<S: TreeStorage<Tree<K>>>(&mut self, k: &K, s: &mut S) -> Result<Vec<K>> {
        let to_remove_context = self
            .find_with_path(k, s)
            .ok_or_else(|| anyhow!("key not found in tree"))?;
        let to_remove = to_remove_context.target;

        let binding = s.nodes().fetch(&to_remove);
        let to_remove_left_child = binding.left();
        let mut to_remove_right_child = s.nodes().fetch(&to_remove).right().cloned();

        let new_child = match (to_remove_left_child, to_remove_right_child.as_ref()) {
            (None, None) => None,
            (None, r @ Some(_)) => r.cloned(),
            (l @ Some(_), None) => l.cloned(),
            (Some(_), Some(right)) => {
                let mut min_idx: K = right.to_owned();
                let mut min_parent_idx = to_remove.clone();

                loop {
                    let min_node = s.nodes().fetch(&min_idx);
                    match min_node.left() {
                        Some(lt_idx) => {
                            min_parent_idx = min_idx.to_owned();
                            min_idx = lt_idx.clone();
                        }
                        None => match min_node.right() {
                            Some(_) => {
                                let unlink_new_child = min_node.right();
                                if min_parent_idx == to_remove {
                                    to_remove_right_child = unlink_new_child.cloned();
                                } else {
                                    s.nodes_mut().update_with(min_parent_idx.to_owned(), |n| {
                                        n.left = unlink_new_child.cloned();
                                        n.subtree_size -= 1;
                                    });
                                    if let Some(u) = unlink_new_child {
                                        s.nodes_mut().update_with(u.to_owned(), |n| {
                                            n.parent = Some(min_parent_idx.to_owned())
                                        });
                                    }
                                }
                                break;
                            }
                            None => {
                                if min_parent_idx == to_remove {
                                    to_remove_right_child = None;
                                } else {
                                    s.nodes_mut()
                                        .update_with(min_parent_idx.to_owned(), |n| n.left = None);
                                    s.nodes_mut().update_with(min_parent_idx.to_owned(), |n| {
                                        n.subtree_size -= 1
                                    });
                                }
                                break;
                            }
                        },
                    };
                }

                let min_node_sub_tree_size = s.nodes().fetch(&to_remove).subtree_size - 1;
                s.nodes_mut().update_with(min_idx.to_owned(), |min_node| {
                    min_node.right = to_remove_right_child.clone();
                    min_node.left = to_remove_left_child.cloned();
                    min_node.subtree_size = min_node_sub_tree_size;
                });
                if let Some(i) = to_remove_right_child {
                    s.nodes_mut()
                        .update_with(i.to_owned(), |n| n.parent = Some(min_idx.to_owned()))
                }
                if let Some(i) = to_remove_left_child {
                    s.nodes_mut()
                        .update_with(i.to_owned(), |n| n.parent = Some(min_idx.to_owned()))
                }

                Some(min_idx)
            }
        };

        let dirties = match to_remove_context.ascendance.last() {
            Some(parent) => {
                {
                    s.nodes_mut().update_with(parent.to_owned(), |parent_node| {
                        if parent_node.left().map(|l| *l == to_remove).unwrap_or(false) {
                            parent_node.left = new_child.clone();
                        } else {
                            parent_node.right = new_child.clone();
                        }
                    });
                }
                if let Some(ref i) = new_child {
                    s.nodes_mut()
                        .update_with(i.to_owned(), |n| n.parent = Some(parent.to_owned()));
                    // NOTE: optimality would require to remove unchanged leaf nodes
                    self.descendants(new_child.as_ref().unwrap(), s)
                } else {
                    vec![]
                }
            }
            None => {
                s.state_mut().update(|r| r.root = new_child.clone());
                if let Some(new_child_k) = new_child.as_ref() {
                    s.nodes_mut()
                        .update_with(new_child_k.to_owned(), |n| n.parent = None);
                }
                new_child.map(|n| vec![n]).unwrap_or_default()
            }
        };

        s.nodes_mut().remove(to_remove)?;
        s.state_mut().update(|r| r.node_count -= 1);

        for ancestor in to_remove_context.ascendance {
            debug_assert!(s.nodes().fetch(&ancestor).subtree_size > 1);
            s.nodes_mut()
                .update_with(ancestor.to_owned(), |n| n.subtree_size -= 1);
        }

        Ok(dirties)
    }

    // --------------------------------------------------------------------------
    // Private methods
    // --------------------------------------------------------------------------
    fn rec_print<S: TreeStorage<Tree<K>>>(i: &K, d: usize, s: &S) {
        let n = &s.nodes().fetch(i);
        if let Some(left) = n.left() {
            Self::rec_print(left, d + 1, s);
        }
        println!(
            "{}{:?}/{} ({})",
            "  |".repeat(d),
            n.k,
            n.parent
                .as_ref()
                .map(|x| format!("{:?}", x))
                .unwrap_or("None".to_string()),
            n.subtree_size
        );
        if let Some(right) = n.right() {
            Self::rec_print(right, d + 1, s);
        }
    }

    /// Insert the key `k` in the tree. If it already exists, do nothing if
    /// `can_replace` is true, otherwise return an error.
    fn _insert<S: TreeStorage<Tree<K>>>(
        &mut self,
        k: K,
        can_replace: bool,
        s: &mut S,
    ) -> Result<NodePath<K>> {
        let path = if let Some(root) = s.state().fetch().root.as_ref() {
            let mut path = Vec::with_capacity(s.state().fetch().node_count.max(1).ilog2() as usize);
            let mut cursor = root.to_owned();
            loop {
                let n = s.nodes().fetch(&cursor);
                // Keep track of the insertion path to update the sub-tree sizes
                path.push(cursor.to_owned());
                match k.cmp(&n.k) {
                    Ordering::Less => {
                        if let Some(left) = n.left() {
                            cursor = left.to_owned();
                        } else {
                            s.nodes_mut()
                                .update_with(cursor.to_owned(), |n| n.left = Some(k.clone()));
                            s.nodes_mut().store(
                                k.clone(),
                                Node::new_with_parent(k.clone(), cursor.to_owned()),
                            )?;
                            break;
                        }
                    }
                    Ordering::Equal => {
                        if can_replace {
                            path.pop().unwrap();
                            // No re-balancing is guaranteed
                            return Ok(NodePath {
                                target: k.clone(),
                                ascendance: path,
                            });
                        } else {
                            bail!("key already exists in tree")
                        }
                    }
                    Ordering::Greater => {
                        if let Some(right) = n.right() {
                            cursor = right.to_owned();
                        } else {
                            s.nodes_mut()
                                .update_with(cursor.to_owned(), |n| n.right = Some(k.clone()));
                            s.nodes_mut().store(
                                k.clone(),
                                Node::new_with_parent(k.clone(), cursor.to_owned()),
                            )?;
                            break;
                        }
                    }
                }
            }

            // If the insert is successful, update the sub-tree sizes
            for p in path.iter() {
                s.nodes_mut()
                    .update_with(p.to_owned(), |n| n.subtree_size += 1);
            }
            s.state_mut().update(|r| r.node_count += 1);

            if path.len() > self.depth_criterion(s.state().fetch().node_count, s) {
                self.find_scapegoat(&path, s)
                    .map(|scapegoat| {
                        self.rebalance_at(scapegoat, s)
                            .into_iter()
                            .map(|n| s.nodes().fetch(&n).k.to_owned())
                            .collect()
                    })
                    .unwrap_or_default()
            } else {
                path
            }
        } else {
            s.nodes_mut().store(k.clone(), Node::new(k.clone()))?;
            s.state_mut().update(|r| {
                r.root = Some(k.clone());
                r.node_count += 1;
            });
            vec![]
        };
        Ok(NodePath {
            target: k.clone(),
            ascendance: path,
        })
    }

    /// Prune the subtree spanning `from` and replace it by its balanced version.
    fn rebalance_at<S: TreeStorage<Tree<K>>>(
        &mut self,
        from: NodeUpstream<K>,
        s: &mut S,
    ) -> Vec<K> {
        let mut sub_nodes = self.descendants(&from.id, s);
        sub_nodes.sort_unstable_by(|i, j| s.nodes().fetch(i).k.cmp(&s.nodes().fetch(j).k));
        self.rebuild_at(&from, &sub_nodes, s);
        sub_nodes
    }

    /// Given a subtree root `from` and a list of nodes sorted by their keys,
    /// build the balanced binary tree below `from` containing all of
    /// `sorted_nodes`.
    fn rebuild_at<S: TreeStorage<Tree<K>>>(
        &mut self,
        from: &NodeUpstream<K>,
        sorted_nodes: &[K],
        s: &mut S,
    ) {
        struct NodeSection {
            start: usize,
            mid: usize,
            end: usize,
        }
        impl NodeSection {
            fn from_bounds(start: usize, end: usize) -> Self {
                NodeSection {
                    start,
                    mid: start + (end - start) / 2,
                    end,
                }
            }
        }

        let sorted_end = sorted_nodes.len() - 1;
        let new_root_id = sorted_end / 2;
        let new_root = &sorted_nodes[new_root_id];
        let mut ax = Vec::with_capacity(sorted_nodes.len());

        // Init worklist with middle node (balanced subtree root)
        ax.push((new_root_id, NodeSection::from_bounds(0, sorted_end)));

        // Update tree root or subtree parent
        if let Some(root_idx) = s.state().fetch().root.as_ref() {
            if sorted_nodes.contains(root_idx) {
                s.state_mut().update(|r| r.root = Some(new_root.to_owned()));
            } else {
                let old_subtree_root = self.context(&s.nodes().fetch(&from.id).k, s).unwrap();
                if let Some(parent_idx) = old_subtree_root.parent.clone() {
                    s.nodes_mut()
                        .update_with(parent_idx.clone(), |parent_node| {
                            if old_subtree_root.is_right() {
                                parent_node.right = Some(new_root.to_owned());
                            } else {
                                parent_node.left = Some(new_root.to_owned());
                            }
                        });
                    s.nodes_mut().update_with(new_root.to_owned(), |n| {
                        n.parent = Some(parent_idx.to_owned())
                    });
                }
            }
        }

        // Iteratively re-assign all children
        while let Some((sorted_idx, parent_section)) = ax.pop() {
            let parent_idx = &sorted_nodes[sorted_idx];
            s.nodes_mut()
                .update_with(parent_idx.to_owned(), |parent_node| {
                    parent_node.left = None;
                    parent_node.right = None;
                });

            // Set left child
            if parent_section.start < parent_section.mid {
                let child_section =
                    NodeSection::from_bounds(parent_section.start, parent_section.mid - 1);
                let child_idx = &sorted_nodes[child_section.mid];
                s.nodes_mut().update_with(parent_idx.to_owned(), |n| {
                    n.left = Some(child_idx.to_owned())
                });
                s.nodes_mut().update_with(child_idx.to_owned(), |n| {
                    n.parent = Some(parent_idx.to_owned())
                });
                ax.push((child_section.mid, child_section));
            }

            // Set right child
            if parent_section.mid < parent_section.end {
                let child_section =
                    NodeSection::from_bounds(parent_section.mid + 1, parent_section.end);
                let child_idx = &sorted_nodes[child_section.mid];
                s.nodes_mut().update_with(parent_idx.to_owned(), |n| {
                    n.right = Some(child_idx.to_owned())
                });
                s.nodes_mut().update_with(child_idx.to_owned(), |n| {
                    n.parent = Some(parent_idx.to_owned())
                });
                ax.push((child_section.mid, child_section));
            }

            s.nodes_mut().update_with(parent_idx.to_owned(), |n| {
                n.subtree_size = parent_section.end - parent_section.start + 1
            });
        }
    }

    /// Given a path in the tree, chose a scapegoat node in it.
    fn find_scapegoat<S: TreeStorage<Tree<K>>>(
        &self,
        path: &[K],
        s: &S,
    ) -> Option<NodeUpstream<K>> {
        for (i, p) in path.iter().enumerate().skip(1) {
            let len = path.len() - 1;
            if len > self.depth_criterion(s.nodes().fetch(p).subtree_size, s) {
                let direction = if s
                    .nodes()
                    .fetch(&path[i - 1])
                    .left
                    .map(|l| l == *p)
                    .unwrap_or(false)
                {
                    Ordering::Less
                } else {
                    Ordering::Greater
                };
                return Some(NodeUpstream {
                    parent: Some(path[i - 1].clone()),
                    direction,
                    id: p.clone(),
                });
            }
        }
        None
    }

    fn _recompute_subtree_sizes<S: TreeStorage<Tree<K>>>(k: &K, s: &mut S) -> usize {
        let n_k = s.nodes().fetch(k).clone();

        let left_size = {
            if let Some(left) = n_k.left() {
                Self::_recompute_subtree_sizes(left, s)
            } else {
                0
            }
        };

        let right_size = if let Some(right) = n_k.right() {
            Self::_recompute_subtree_sizes(right, s)
        } else {
            0
        };

        let subtree_size = 1 + left_size + right_size;

        s.nodes_mut()
            .update_with(k.to_owned(), |n| n.subtree_size = subtree_size);
        subtree_size
    }

    fn depth_criterion<S: TreeStorage<Tree<K>>>(&self, node_count: usize, s: &S) -> usize {
        (node_count as f32)
            .log(s.state().fetch().alpha.inverse())
            .floor() as usize
    }
}

impl<K: Sync + Debug + Ord + Clone + Hash + Serialize + for<'a> Deserialize<'a>> TreeTopology
    for Tree<K>
{
    type Key = K;
    type Node = Node<K>;
    type State = State<K>;

    fn size<S: TreeStorage<Tree<K>>>(&self, s: &S) -> usize {
        if let Some(root) = s.state().fetch().root.as_ref() {
            s.nodes().fetch(root).subtree_size
        } else {
            0
        }
    }

    fn root<S: TreeStorage<Tree<K>>>(&self, s: &S) -> Option<K> {
        s.state().fetch().root.clone()
    }

    fn parent<S: TreeStorage<Tree<K>>>(&self, n: K, s: &S) -> Option<K> {
        self.context(&n, s)
            .unwrap()
            .parent
            .map(|p| s.nodes().fetch(&p).k.to_owned())
    }

    fn lineage<S: TreeStorage<Tree<K>>>(&self, n: &K, s: &S) -> Option<NodePath<K>> {
        self.find_with_path(n, s)
    }

    fn children<S: TreeStorage<Tree<K>>>(&self, k: &K, s: &S) -> Option<(Option<K>, Option<K>)> {
        s.nodes().try_fetch(k).map(|node| {
            (
                node.left
                    .as_ref()
                    .map(|left| s.nodes().fetch(left).k.clone()),
                node.right
                    .as_ref()
                    .map(|right| s.nodes().fetch(right).k.clone()),
            )
        })
    }

    fn node_context<S: TreeStorage<Tree<K>>>(&self, k: &K, s: &S) -> Option<NodeContext<K>> {
        self.context(k, s).ok().map(|c| NodeContext {
            node_id: c.id.clone(),
            parent: c.parent,
            left: s.nodes().try_fetch(&c.id).and_then(|n| n.left),
            right: s.nodes().try_fetch(&c.id).and_then(|n| n.right),
        })
    }

    fn contains<S: TreeStorage<Tree<K>>>(&self, k: &K, s: &S) -> bool {
        s.nodes().try_fetch(k).is_some()
    }
}

impl<K: Debug + Sync + Clone + Eq + Hash + Ord + Serialize + for<'a> Deserialize<'a>> MutableTree
    for Tree<K>
{
    fn insert<S: TreeStorage<Tree<K>>>(&mut self, k: K, s: &mut S) -> Result<NodePath<K>> {
        self.insert(k, s)
    }

    fn delete<S: TreeStorage<Tree<K>>>(&mut self, k: &K, s: &mut S) -> Result<Vec<K>> {
        self.unlink(k, s)
    }
}

impl<K: Debug + Sync + Clone + Eq + Hash + Ord + Serialize + for<'a> Deserialize<'a>> PrintableTree
    for Tree<K>
{
    fn print<S: TreeStorage<Tree<K>>>(&self, s: &S) {
        if let Some(root) = s.state().fetch().root.as_ref() {
            Self::rec_print(root, 0, s);
        } else {
            println!("EMPTY TREE");
        }
    }
}