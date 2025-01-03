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
//!      2 to which x is congruent, i.e. the number of trailing zeros in its binary
//!      representation;
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
    error::RyhopeError,
    storage::{EpochKvStorage, EpochMapper, EpochStorage, TreeStorage},
    tree::PrintableTree, IncrementalEpoch, UserEpoch,
};
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, future::Future};

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
        self.outer_idx(self.inner_root()).0
    }

    async fn root_with_mapper<M: IndexMapper>(&self, mapper: &M) -> NodeIdx {
        self.outer_root(mapper).await
    }

    pub async fn ascendance<I: IntoIterator<Item = NodeIdx>>(&self, ns: I) -> HashSet<NodeIdx> {
        self.ascendance_with_mapper(ns, self).await
    }
    
    async fn ascendance_with_mapper<I: IntoIterator<Item = NodeIdx>, M: IndexMapper>(&self, ns: I, mapper: &M) -> HashSet<NodeIdx> {
        let mut ascendance = HashSet::new();
        let inner_max = self.inner_max();
        for n in ns.into_iter() {
            let inner_idx = mapper.to_inner_idx(OuterIdx(n)).await;
            if inner_idx <= inner_max {
                if let Some(lineage) = self.lineage_inner(&inner_idx) {
                    for n in lineage.into_full_path() {
                        if n <= inner_max {
                            ascendance.insert(mapper.to_outer_idx(n).await.0);
                        }
                    }
                }
            }
        }

        ascendance
    }

    pub async fn parent(&self, n: NodeIdx) -> Option<NodeIdx> {
        self.parent_with_mapper(n, self).await
    }

    async fn parent_with_mapper<M: IndexMapper>(&self, n: NodeIdx, mapper: &M) -> Option<NodeIdx> {
        let n = mapper.to_inner_idx(OuterIdx(n)).await;
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

        Some(mapper.to_outer_idx(parent).await.0)
    }

    pub async fn lineage(&self, n: &NodeIdx) -> Option<NodePath<NodeIdx>> {
        self.lineage_with_mapper(n, self).await
    }

    async fn lineage_with_mapper<M: IndexMapper>(&self, n: &NodeIdx, mapper: &M) -> Option<NodePath<NodeIdx>> {
        if let Some(lineage_inner) = self.lineage_inner(&mapper.to_inner_idx(OuterIdx(*n)).await) {
            let mut ascendance = vec![];
            for n in lineage_inner.ascendance {
                ascendance.push(mapper.to_outer_idx(n).await.0);
            }
            Some(NodePath {
                ascendance,
                target: mapper.to_outer_idx(lineage_inner.target).await.0,
            })
        } else {
            None
        }
    }

    pub fn node_context(&self, k: &NodeIdx) -> Option<NodeContext<NodeIdx>> {
        // Not a simple call to `node_context_with_mapper` since we need a non-async version
        // to be employed in circuits
        self.node_context_inner(&self.inner_idx(OuterIdx(*k))).map(|inner| {

            NodeContext {
                node_id: self.outer_idx(inner.node_id).0,
                parent: inner.parent.map(|idx| self.outer_idx(idx).0),
                left: inner.left.map(|idx| self.outer_idx(idx).0),
                right: inner.right.map(|idx| self.outer_idx(idx).0),
            }
        })
    }

    async fn node_context_with_mapper<M: IndexMapper>(&self, k: &NodeIdx, mapper: &M) -> Option<NodeContext<NodeIdx>> {
        if let Some(inner) = self.node_context_inner(&mapper.to_inner_idx(OuterIdx(*k)).await) {

            let parent_outer = mapper.to_outer_idx_map(inner.parent).await.map(|idx| idx.0);
            let left_outer = mapper.to_outer_idx_map(inner.left).await.map(|idx| idx.0);
            let right_outer = mapper.to_outer_idx_map(inner.right).await.map(|idx| idx.0);

            Some(NodeContext {
                node_id: mapper.to_outer_idx(inner.node_id).await.0,
                parent: parent_outer,
                left: left_outer,
                right: right_outer,
            })
        } else {
            None
        }
    }

    pub async fn children(&self, n: &NodeIdx) -> Option<(Option<NodeIdx>, Option<NodeIdx>)> {
        self.children_with_mapper(n, self).await
    }

    async fn children_with_mapper<M: IndexMapper>(&self, n: &NodeIdx, mapper: &M) -> Option<(Option<NodeIdx>, Option<NodeIdx>)> {
        if let Some((l, r)) = self.children_inner(&mapper.to_inner_idx(OuterIdx(*n)).await) {
            Some((
                mapper.to_outer_idx_map(l).await.map(|idx| idx.0), 
                mapper.to_outer_idx_map(r).await.map(|idx| idx.0)
            ))
        } else {
            None
        }
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

    /// Return the root of the tree, as a shifted node index.
    async fn outer_root<M: IndexMapper>(&self, mapper: &M) -> NodeIdx {
        mapper.to_outer_idx(self.inner_root()).await.0
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

    fn inner_idx(&self, outer_idx: OuterIdx) -> InnerIdx {
        InnerIdx(outer_idx.0 - self.shift)
    }

    fn outer_idx(&self, inner_idx: InnerIdx) -> OuterIdx {
        OuterIdx((inner_idx + self.shift).0)
    }
}


trait IndexMapper: Sized + Send + Sync + Clone {
    fn to_inner_idx(&self, outer_idx: OuterIdx) -> impl Future<Output = InnerIdx> + Send;

    fn to_outer_idx(&self, inner_idx: InnerIdx) -> impl Future<Output = OuterIdx> + Send;

    fn to_inner_idx_map(&self, outer_idx: Option<OuterIdx>) -> impl Future<Output = Option<InnerIdx>> + Send {
        async move {
            match outer_idx {
                Some(outer_idx) => Some(self.to_inner_idx(outer_idx).await),
                None => None,
            }
        }
    }

    fn to_outer_idx_map(&self, inner_idx: Option<InnerIdx>) -> impl Future<Output = Option<OuterIdx>> + Send {
        async move {
            match inner_idx {
                Some(inner_idx) => Some(self.to_outer_idx(inner_idx).await),
                None => None,
            }
        }
    }
}

impl<T: EpochMapper> IndexMapper for T {
    async fn to_inner_idx(&self, outer_idx: OuterIdx) -> InnerIdx {
        InnerIdx(self.to_incremental_epoch(outer_idx.0 as UserEpoch).await.try_into().unwrap())
    }

    async fn to_outer_idx(&self, inner_idx: InnerIdx) -> OuterIdx {
        OuterIdx(self.to_user_epoch(inner_idx.0 as IncrementalEpoch).await as usize)
    }
}

impl IndexMapper for State {
    async fn to_inner_idx(&self, outer_idx: OuterIdx) -> InnerIdx {
        self.inner_idx(outer_idx)
    }

    async fn to_outer_idx(&self, inner_idx: InnerIdx) -> OuterIdx {
        self.outer_idx(inner_idx)
    }
}


#[derive(Default)]
pub struct Tree<const IS_EPOCH_TREE: bool>;

/// Type alias to represent a generic sbbst with incremental keys
pub type IncrementalTree = Tree<false>;
/// Type alias to represent a generic sbbst with monotonically increasing keys being
/// used as epochs of the storage
pub type EpochTree = Tree<true>;

impl<const IS_EPOCH_TREE: bool> Tree<IS_EPOCH_TREE> {
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


    async fn to_inner_idx<S: TreeStorage<Self>>(&self, s: &S, state: &State, n: OuterIdx) -> InnerIdx {
        if IS_EPOCH_TREE {
            s.epoch_mapper().to_inner_idx(n).await
        } else {
            state.to_inner_idx(n).await
        }
    }

    async fn to_outer_idx<S: TreeStorage<Self>>(&self, s: &S, state: &State, n: InnerIdx) -> OuterIdx {
        if IS_EPOCH_TREE {
            s.epoch_mapper().to_outer_idx(n).await
        } else {
            state.to_outer_idx(n).await
        }
    }
}

async fn shift<const IS_EPOCH_TREE: bool, S: TreeStorage<Tree<IS_EPOCH_TREE>>>(s: &S) -> Result<usize, RyhopeError> {
    s.state().fetch().await.map(|s| s.shift)
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

impl<const IS_EPOCH_TREE: bool> TreeTopology for Tree<IS_EPOCH_TREE>{
    /// Max, shift
    type State = State;
    type Key = NodeIdx;
    type Node = ();

    async fn size<S: TreeStorage<Self>>(&self, s: &S) -> Result<usize, RyhopeError> {
        s.state().fetch().await.map(|s| s.inner_max().0)
    }

    async fn ascendance<S: TreeStorage<Self>, I: IntoIterator<Item = Self::Key>>(
        &self,
        ns: I,
        s: &S,
    ) -> Result<HashSet<NodeIdx>, RyhopeError> {
        let state = s.state().fetch().await;
        if IS_EPOCH_TREE {
            state.ascendance_with_mapper(ns, s.epoch_mapper()).await
        } else {
            state.ascendance(ns).await
        }
    }

    async fn root<S: TreeStorage<Self>>(&self, s: &S) -> Result<Option<NodeIdx>, RyhopeError> {
        s.state().fetch().await.map(|s| Some(if IS_EPOCH_TREE {
            state.root_with_mapper(s.epoch_mapper()).await
        } else {
            s.root()
        }))
    }

    async fn parent<S: TreeStorage<Self>>(&self, n: NodeIdx, s: &S) -> Result<Option<NodeIdx>, RyhopeError> {
        let state = s.state().fetch().await;
        if IS_EPOCH_TREE {
            state.parent_with_mapper(n, s.epoch_mapper()).await
        } else {
            state.parent(n).await
        }
    }

    async fn lineage<S: TreeStorage<Self>>(&self, n: &NodeIdx, s: &S) -> Result<Option<NodePath<NodeIdx>>, RyhopeError> {
        let state = s.state().fetch().await?;
        if IS_EPOCH_TREE {
            state.lineage_with_mapper(n, s.epoch_mapper()).await
        } else {
            state.lineage(n).await
        }
    }

    async fn children<S: TreeStorage<Self>>(
        &self,
        n: &NodeIdx,
        s: &S,
    ) -> Result<Option<(Option<NodeIdx>, Option<NodeIdx>)>, RyhopeError> {
        let state = s.state().fetch().await?;
        if IS_EPOCH_TREE {
            state.children_with_mapper(n, s.epoch_mapper()).await 
        } else {
            state.children(n).await
        }
    }

    async fn node_context<S: TreeStorage<Self>>(
        &self,
        k: &NodeIdx,
        s: &S,
    ) -> Result<Option<NodeContext<NodeIdx>>, RyhopeError> {
        let state = s.state().fetch().await;
        if IS_EPOCH_TREE {
            state.node_context_with_mapper(k, s.epoch_mapper()).await
        } else {
            state.node_context(k)
        }
    }

    async fn contains<S: TreeStorage<Self>>(&self, k: &NodeIdx, s: &S) -> Result<bool, RyhopeError> {
        let state = s.state().fetch().await;
        self.to_inner_idx(s, &state, OuterIdx(*k)).await <= state.inner_max()
    }
}

impl<const IS_EPOCH_TREE: bool> MutableTree for Tree<IS_EPOCH_TREE> {
    // The SBBST only support appending exactly after the current largest key.
    async fn insert<S: TreeStorage<Self>>(
        &mut self,
        k: NodeIdx,
        s: &mut S,
    ) -> Result<NodePath<NodeIdx>, RyhopeError> {
        let shift = shift(s).await?;
        crate::error::ensure(
            k >= shift,
            format!(
                "invalid insert in SBST: index `{k}` smaller than origin `{}`",
                shift
            ),
        )?;

        let state = s.state().fetch().await;
        // compute the inner key of the next item to be inserted
        let expected_inner_k = state.inner_max() + 1;
        if IS_EPOCH_TREE {
            // we need to check that k >= last epoch inserted
            let max_outer = s.epoch_mapper().to_outer_idx(state.inner_max()).await;
            ensure!(
                max_outer <= OuterIdx(k),
                format!(
                    "Trying to insert an epoch {k} smaller than a previous inserted epoch {}",
                    max_outer.0
                )
            );
            // in this case, k must be mapped to `expected_inner_k` in the epoch mapper
            s.epoch_mapper_mut().add_epoch_map(
                k as UserEpoch, 
                expected_inner_k.0 as IncrementalEpoch
            ).await?;
        } else {
            // in this case, we need to check that the inner key corresponding to k 
            // is equal to `expected_inner_k`
            let inner_k = state.to_inner_idx(OuterIdx(k)).await;
            ensure!(inner_k == expected_inner_k,
                format!(
                    "invalid insert in SBBST: trying to insert {}, but next insert should be {} (shift = {})",
                    k,
                    state.to_outer_idx(expected_inner_k).await.0,
                    state.shift,
                ),
            );
        }
        s.state_mut().update(|state| state.max += 1).await;
        s.nodes_mut().store(k, ()).await?;

        Ok(self.lineage(&k, s).await?.unwrap())
    }

    async fn delete<S: TreeStorage<Self>>(
        &mut self,
        _k: &NodeIdx,
        _: &mut S,
    ) -> Result<Vec<NodeIdx>, RyhopeError> {
        unreachable!("SBBSTs do not support deletion")
    }
}

impl<const IS_EPOCH_TREE: bool> PrintableTree for Tree<IS_EPOCH_TREE> {
    async fn tree_to_string<S: TreeStorage<Self>>(&self, s: &S) -> String {
        let mut r = String::new();

        let state = s.state().fetch().await.unwrap();
        let max_layer = state.inner_root().0.trailing_zeros();
        for layer in (0..max_layer).rev() {
            let spacing = " ".repeat((2 * layer + 1).try_into().unwrap());
            for rank in 0..state.inner_max().0 {
                let maybe_left = rank * (1 << (layer + 1)) + (1 << layer);
                if maybe_left <= state.inner_max().0 {
                    let n = InnerIdx(maybe_left);
                    r.push_str(&format!("{}{}", self.to_outer_idx(s, &state, n).await.0, spacing))
                }
            }
            r.push('\n');
        }

        r
    }

    // TODO: Leave the warning for `k`, since we will implement it later.
    async fn subtree_to_string<S: TreeStorage<Self>>(&self, s: &S, _k: &Self::Key) -> String {
        self.tree_to_string(s).await
    }
}
