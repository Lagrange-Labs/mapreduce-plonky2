//! To store the block tree, a balanced BST is chosen, for its good balance
//! between:
//!   * limiting the number of intermediate proofs to recompute on insertion;
//!   * minimizing the depth of the nodes.
//!
//! Determining the parent of any node in such a tree may be split in two cases:
//! (i) when the tree is saturated (i.e. there are exactly 2×n - 1 nodes in the
//! tree), and (ii) the unsaturated case, i.e. there are 2×n - 1 < m < 2×(n+1) -
//! 1 nodes in the tree.
//!
//! In the first case, a closed form solution is established in the following
//! way. First, we note that a saturated balanced BST can be modelled as a stack
//! of floor(M/2) cascading layers, where M is the largest value in the tree.
//! Each layer, indexed in increasing order from the bottom-most one, takes the
//! value l^i_n = n×2^(i+1) + 2^i, for l^i_n < M. This model is represented
//! below for M = 8:
//!
//! l^2_n = 8×n + 4     4    4: rank 0, ... in layer l^2
//!                   /   \
//! l^1_n = 4×n + 2   2   6  2: rank 0, 6: rank 1, ... in layer l^1
//!                  / \ / \
//! l^0_n = 2×n + 1  1 3 5 7 1: rank 0, 3: rank 1, ... in layer l^0
//!
//! In this framework, any node can be uniquely identified by its layer, and its
//! position within this layer. From the binary structure of the tree, it is
//! known that the parent of a node of value x (and thus rank n) in layer l^i is
//! the node in the layer l^i+1 of value either x + 2^i or x - 2^i, depending on
//! whether the rank n of x in layer l_k is respectively even or odd.
//!
//! Therefore determining the parent of a node of general value x is achieved by:
//!   1. determine the layer i to which x belongs, which is the smaller power of
//!   2 to which x is congruent, i.e. the number of trailing zeros in its binary
//!   representation;
//!   2. determine x rank n in the layer l^i, which is equal to (x - 2^i)/2^(i+1);
//!   3. if n is even then x parent is n + 2^i, or n - 2^i if n is odd.
//!
//!
//! The second case, i.e. the general case of a non-saturated balanced BST, is
//! greatly simplified by the fact that relative relationships are conserved
//! when an unsaturated tree is expanded into the saturated one stemming from
//! the same root, i.e. nodes having a parenthood relaionship in an unsaturated
//! tree will still be in the same direct lineage from the root. Therefore, a
//! simple way to determine the direct parent of a node in an unsaturatred tree
//! is to rerusively follow the lineage to root it would have in the tree
//! expanded to saturation, then stop at the first ancestor present in the
//! unsaturated tree; or, in pseudo-code:
//!
//! let s_tree = extend_to_saturated(tree)
//! parent = parent(s_tree, n)
//! while parent > max(tree)
//!   parent = parent(s_tree, parent)
use super::{MutableTree, NodeContext, NodePath, TreeTopology};
use crate::{
    storage::{EpochKvStorage, EpochStorage, TreeStorage},
    tree::PrintableTree,
};
use anyhow::*;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Represents a user-facing index, in the shift+1..max range.
pub type NodeIdx = usize;

/// Represents an index projected in the canonical range 1..max.
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub(crate) struct InnerIdx(pub(crate) NodeIdx);
impl std::ops::Add<usize> for InnerIdx {
    type Output = Self;

    fn add(self, rhs: usize) -> Self::Output {
        InnerIdx(self.0 + rhs)
    }
}
impl std::ops::AddAssign<usize> for InnerIdx {
    fn add_assign(&mut self, rhs: usize) {
        self.0 = self.0 + rhs;
    }
}
impl std::ops::Sub<usize> for InnerIdx {
    type Output = Self;

    fn sub(self, rhs: usize) -> Self::Output {
        InnerIdx(self.0 - rhs)
    }
}
impl std::ops::SubAssign<usize> for InnerIdx {
    fn sub_assign(&mut self, rhs: usize) {
        self.0 = self.0 - rhs;
    }
}

#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
struct OuterIdx(NodeIdx);
impl std::ops::Sub<usize> for OuterIdx {
    type Output = Self;

    fn sub(self, rhs: usize) -> Self::Output {
        OuterIdx(self.0 - rhs)
    }
}

/// Contains the data required to rebuild the topology of the block tree
/// containing blocks from 1 to `max`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct State {
    /// The largest block that will be stored in this tree (inclusive)
    pub(crate) max: InnerIdx,
    /// The actual beginning of the tree w.r.t. 1
    pub shift: usize,
}

impl State {
    pub fn root(&self) -> NodeIdx {
        self.outer_root()
    }

    pub fn ascendance<I: IntoIterator<Item = NodeIdx>>(&self, ns: I) -> HashSet<NodeIdx> {
        let mut ascendance = HashSet::new();
        let inner_max = self.inner_max();
        for n in ns.into_iter() {
            let inner_idx = self.inner_idx(n);
            if inner_idx <= inner_max {
                if let Some(lineage) = self.lineage_inner(&inner_idx) {
                    for n in lineage.into_full_path() {
                        if n <= inner_max {
                            ascendance.insert(self.outer_idx(n));
                        }
                    }
                }
            }
        }

        ascendance
    }

    pub fn parent(&self, n: NodeIdx) -> Option<NodeIdx> {
        let n = self.inner_idx(n);
        if n > self.inner_max() {
            panic!("{n:?} not in tree");
        }

        if n == self.inner_root() {
            return None;
        }

        let mut parent = parent_in_saturated(n);
        while parent > self.inner_max() {
            parent = parent_in_saturated(parent);
        }

        Some(self.outer_idx(parent))
    }

    pub fn lineage(&self, n: &NodeIdx) -> Option<NodePath<NodeIdx>> {
        if let Some(lineage_inner) = self.lineage_inner(&self.inner_idx(*n)) {
            let mut ascendance = vec![];
            for n in lineage_inner.ascendance {
                ascendance.push(self.outer_idx(n));
            }
            Some(NodePath {
                ascendance,
                target: self.outer_idx(lineage_inner.target),
            })
        } else {
            None
        }
    }

    pub fn node_context(&self, k: &NodeIdx) -> Option<NodeContext<NodeIdx>> {
        if let Some(inner) = self.node_context_inner(&self.inner_idx(*k)) {
            let parent_outer = if let Some(parent) = inner.parent {
                Some(self.outer_idx(parent))
            } else {
                None
            };

            let left_outer = if let Some(left) = inner.left {
                Some(self.outer_idx(left))
            } else {
                None
            };

            let right_outer = if let Some(right) = inner.right {
                Some(self.outer_idx(right))
            } else {
                None
            };
            Some(NodeContext {
                node_id: self.outer_idx(inner.node_id),
                parent: parent_outer,
                left: left_outer,
                right: right_outer,
            })
        } else {
            None
        }
    }

    pub fn children(&self, n: &NodeIdx) -> Option<(Option<NodeIdx>, Option<NodeIdx>)> {
        if let Some((l, r)) = self.children_inner(&self.inner_idx(*n)) {
            let l_option = if let Some(l) = l {
                Some(self.outer_idx(l))
            } else {
                None
            };
            let r_option = if let Some(r) = r {
                Some(self.outer_idx(r))
            } else {
                None
            };
            Some((l_option, r_option))
        } else {
            None
        }
    }

    /// Return the largest value currently stored in the tree
    fn outer_max(&self) -> NodeIdx {
        self.outer_idx(self.inner_max())
    }

    fn inner_max(&self) -> InnerIdx {
        self.max
    }

    /// Return the root of the tree, as a non-shifted node index.
    fn inner_root(&self) -> InnerIdx {
        InnerIdx(if self.inner_max().0 > 0 {
            1 << self.inner_max().0.ilog2()
        } else {
            0
        })
    }
    /// Re-shift an index from the canonical range to the actual one
    fn outer_idx(&self, n: InnerIdx) -> NodeIdx {
        (n + self.shift).0
    }
    /// Return the root of the tree, as a shifted node index.
    fn outer_root(&self) -> NodeIdx {
        self.outer_idx(self.inner_root())
    }
    /// Un-shift an index into the canonical range
    fn inner_idx(&self, n: NodeIdx) -> InnerIdx {
        InnerIdx(n - self.shift)
    }

    fn parent_inner(&self, n: InnerIdx) -> Option<InnerIdx> {
        if n > self.inner_max() {
            panic!("{n:?} not in tree");
        }

        if n == self.inner_root() {
            return None;
        }

        let mut parent = parent_in_saturated(n);
        while parent > self.inner_max() {
            parent = parent_in_saturated(parent);
        }

        Some(parent)
    }

    fn lineage_inner(&self, n: &InnerIdx) -> Option<NodePath<InnerIdx>> {
        if n.0 > self.inner_max().0 {
            return None;
        }

        let mut r = Vec::with_capacity(self.inner_max().0.ilog2() as usize);
        let mut current = *n;
        while let Some(parent) = self.parent_inner(current) {
            current = parent;
            r.push(parent);
        }
        // The API requires the lineage in top-downe order
        r.reverse();

        Some(NodePath {
            ascendance: r,
            target: *n,
        })
    }

    fn children_inner(&self, n: &InnerIdx) -> Option<(Option<InnerIdx>, Option<InnerIdx>)> {
        if let Some((maybe_left, maybe_right)) = children_inner_in_saturated(n) {
            let has_left = maybe_left.0 <= self.inner_max().0;
            let left_child = if has_left { Some(maybe_left) } else { None };

            // Return directly if the right child is in range.
            if maybe_right.0 <= self.inner_max().0 {
                return Some((left_child, Some(maybe_right)));
            }

            // Return None as the right child directly if the left child is
            // also out of range. Since we could not find a descendant of
            // right child which is less than the left child.
            if !has_left {
                return Some((left_child, None));
            }

            // Try to find a descendant as the left child which is in range.
            // And set it as the current right child.
            let mut right_child = Some(maybe_right);
            while let Some(c) = right_child {
                if c.0 <= self.inner_max().0 {
                    break;
                }

                right_child = children_inner_in_saturated(&c).map(|(l, _r)| l);
            }

            return Some((left_child, right_child));
        }
        None
    }

    fn node_context_inner(&self, k: &InnerIdx) -> Option<NodeContext<InnerIdx>> {
        if *k <= self.inner_max() {
            let children = self.children_inner(k);
            Some(NodeContext {
                node_id: *k,
                parent: self.parent_inner(*k),
                left: children.and_then(|x| x.0),
                right: children.and_then(|x| x.1),
            })
        } else {
            None
        }
    }
}

#[derive(Default)]
pub struct Tree;
impl Tree {
    pub fn empty() -> State {
        State {
            max: InnerIdx(0),
            shift: 0,
        }
    }

    pub fn with_shift(shift: usize) -> State {
        State {
            max: InnerIdx(0),
            shift,
        }
    }

    pub fn with_shift_and_capacity(shift: usize, max: NodeIdx) -> State {
        State {
            max: InnerIdx(max),
            shift,
        }
    }

    pub fn with_capacity(max: NodeIdx) -> State {
        State {
            max: InnerIdx(max),
            shift: 0,
        }
    }
}

async fn shift<S: TreeStorage<Tree>>(s: &S) -> usize {
    s.state().fetch().await.shift
}

/// Return the parent that `n` would have if this tree was saturated.
fn parent_in_saturated(n: InnerIdx) -> InnerIdx {
    if n.0 == 0 {
        panic!("{n:?} not in tree")
    }

    let layer = n.0.trailing_zeros();
    let rank_in_layer = (n.0 - (1 << layer)) / (1 << (layer + 1));
    if rank_in_layer % 2 == 0 {
        n + (1 << layer)
    } else {
        n - (1 << layer)
    }
}

fn children_inner_in_saturated(n: &InnerIdx) -> Option<(InnerIdx, InnerIdx)> {
    let parent_layer = n.0.trailing_zeros();
    if parent_layer == 0 {
        return None;
    }

    let parent_rank = (n.0 - (1 << parent_layer)) / (1 << (parent_layer + 1));

    let child_layer = parent_layer - 1;
    let left_child_rank = 2 * parent_rank;
    let right_child_rank = 2 * parent_rank + 1;

    let maybe_left = InnerIdx(left_child_rank * (1 << (child_layer + 1)) + (1 << child_layer));
    let maybe_right = InnerIdx(right_child_rank * (1 << (child_layer + 1)) + (1 << child_layer));

    Some((maybe_left, maybe_right))
}

impl TreeTopology for Tree {
    /// Max, shift
    type State = State;
    type Key = NodeIdx;
    type Node = ();

    async fn size<S: TreeStorage<Tree>>(&self, s: &S) -> usize {
        let state = s.state().fetch().await;
        state.inner_max().0
    }

    async fn ascendance<S: TreeStorage<Tree>, I: IntoIterator<Item = Self::Key>>(
        &self,
        ns: I,
        s: &S,
    ) -> HashSet<NodeIdx> {
        let state = s.state().fetch().await;
        state.ascendance(ns)
    }

    async fn root<S: TreeStorage<Tree>>(&self, s: &S) -> Option<NodeIdx> {
        let state = s.state().fetch().await;
        Some(state.root())
    }

    async fn parent<S: TreeStorage<Tree>>(&self, n: NodeIdx, s: &S) -> Option<NodeIdx> {
        let state = s.state().fetch().await;
        state.parent(n)
    }

    async fn lineage<S: TreeStorage<Tree>>(&self, n: &NodeIdx, s: &S) -> Option<NodePath<NodeIdx>> {
        let state = s.state().fetch().await;
        state.lineage(n)
    }

    async fn children<S: TreeStorage<Tree>>(
        &self,
        n: &NodeIdx,
        s: &S,
    ) -> Option<(Option<NodeIdx>, Option<NodeIdx>)> {
        let state = s.state().fetch().await;
        state.children(n)
    }

    async fn node_context<S: TreeStorage<Self>>(
        &self,
        k: &NodeIdx,
        s: &S,
    ) -> Option<NodeContext<NodeIdx>> {
        let state = s.state().fetch().await;
        state.node_context(k)
    }

    async fn contains<S: TreeStorage<Tree>>(&self, k: &NodeIdx, s: &S) -> bool {
        let state = s.state().fetch().await;
        state.inner_idx(*k) <= state.inner_max()
    }
}

impl MutableTree for Tree {
    // The SBBST only support appending exactly after the current largest key.
    async fn insert<S: TreeStorage<Tree>>(
        &mut self,
        k: NodeIdx,
        s: &mut S,
    ) -> Result<NodePath<NodeIdx>> {
        ensure!(
            k >= shift(s).await,
            "invalid insert in SBST: index `{k}` smaller than origin `{}`",
            shift(s).await
        );

        let state = s.state().fetch().await;
        if state.inner_idx(k) != state.inner_max() + 1 {
            bail!(
                "invalid insert in SBBST: trying to insert {}, but next insert should be {} (shift = {})",
                k,
                state.outer_idx(state.inner_max() +1),
                state.shift,
            );
        } else {
            s.state_mut().update(|state| state.max += 1).await;
        }
        s.nodes_mut().store(k, ()).await?;

        Ok(self.lineage(&k, s).await.unwrap())
    }

    async fn delete<S: TreeStorage<Tree>>(
        &mut self,
        _k: &NodeIdx,
        _: &mut S,
    ) -> Result<Vec<NodeIdx>> {
        unreachable!("SBBST does not support deletion")
    }
}

impl PrintableTree for Tree {
    async fn print<S: TreeStorage<Tree>>(&self, s: &S) {
        let state = s.state().fetch().await;
        let max_layer = state.inner_root().0.trailing_zeros();
        for layer in (0..max_layer).rev() {
            let spacing = " ".repeat((2 * layer + 1).try_into().unwrap());
            for rank in 0..state.inner_max().0 {
                let maybe_left = rank * (1 << (layer + 1)) + (1 << layer);
                if maybe_left <= state.inner_max().0 {
                    let n = InnerIdx(maybe_left);
                    print!("{}{}", state.outer_idx(n), spacing);
                }
            }
            println!()
        }
    }
}
