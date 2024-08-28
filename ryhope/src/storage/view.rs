//! This module offers facilities to “time-travel”, i.e. access the successive
//! states of a tree at given epochs.
use std::{collections::HashMap, fmt::Debug, marker::PhantomData};

use anyhow::*;
use serde::{Deserialize, Serialize};

use crate::{
    tree::{NodeContext, TreeTopology},
    Epoch,
};

use super::{EpochKvStorage, EpochStorage, RoEpochKvStorage, TransactionalStorage, TreeStorage};

/// An epoch-locked, read-only, view over an [`EpochStorage`].
pub struct StorageView<
    's,
    T: Debug + Sync + Clone + Serialize + for<'a> Deserialize<'a> + Send,
    S: EpochStorage<T>,
>(
    /// The wrapped [`EpochStorage`]
    &'s S,
    /// The target epoch
    Epoch,
    /// [ignore]
    PhantomData<T>,
);

impl<
        's,
        T: Debug + Sync + Clone + Serialize + for<'a> Deserialize<'a> + Send,
        S: EpochStorage<T> + Sync,
    > TransactionalStorage for StorageView<'s, T, S>
where
    T: Send,
{
    fn start_transaction(&mut self) -> Result<()> {
        unimplemented!("storage views are read only")
    }

    async fn commit_transaction(&mut self) -> Result<()> {
        unimplemented!("storage views are read only")
    }
}

impl<
        's,
        T: Debug + Sync + Clone + Serialize + for<'a> Deserialize<'a> + Send,
        S: EpochStorage<T> + Sync,
    > EpochStorage<T> for StorageView<'s, T, S>
where
    T: Send,
{
    fn current_epoch(&self) -> Epoch {
        self.1
    }

    async fn fetch_at(&self, epoch: Epoch) -> T {
        if epoch != self.1 {
            unimplemented!(
                "this storage view is locked at {}; {epoch} unreachable",
                self.1
            )
        } else {
            self.0.fetch_at(self.1).await
        }
    }

    async fn fetch(&self) -> T {
        self.0.fetch_at(self.1).await
    }

    async fn store(&mut self, _: T) {
        unimplemented!("storage views are read only")
    }

    async fn rollback_to(&mut self, _epoch: Epoch) -> Result<()> {
        unimplemented!("storage views are read only")
    }
}

/// An epoch-locked, read-only, view over an [`EpochKvStorage`].
pub struct KvStorageAt<'a, T: TreeTopology, S: RoEpochKvStorage<T::Key, T::Node>> {
    /// The wrapped [`RoEpochKvStorage`]
    wrapped: &'a S,
    /// The epoch at which the wrapped storage is being looked at
    current_epoch: Epoch,
    /// [ignore]
    _p: PhantomData<T>,
}

impl<'a, T: TreeTopology, S: RoEpochKvStorage<T::Key, T::Node> + Sync>
    RoEpochKvStorage<T::Key, T::Node> for KvStorageAt<'a, T, S>
{
    fn initial_epoch(&self) -> Epoch {
        self.wrapped.initial_epoch()
    }

    fn current_epoch(&self) -> Epoch {
        self.current_epoch
    }

    async fn try_fetch_at(&self, k: &T::Key, epoch: Epoch) -> Option<T::Node> {
        if epoch != self.current_epoch {
            unimplemented!(
                "this storage view is locked at {}; {epoch} unreachable",
                self.current_epoch
            )
        } else {
            self.wrapped.try_fetch_at(k, self.current_epoch).await
        }
    }

    async fn fetch(&self, k: &T::Key) -> T::Node {
        self.wrapped.fetch_at(k, self.current_epoch).await
    }

    async fn size(&self) -> usize {
        self.wrapped.size().await
    }
}

impl<'a, T: TreeTopology, S: RoEpochKvStorage<T::Key, T::Node> + Sync>
    EpochKvStorage<T::Key, T::Node> for KvStorageAt<'a, T, S>
{
    async fn remove(&mut self, _: T::Key) -> Result<()> {
        unimplemented!("storage views are read only")
    }

    async fn update(&mut self, _: T::Key, _: T::Node) -> Result<()> {
        unimplemented!("storage views are read only")
    }

    async fn store(&mut self, _: T::Key, _: T::Node) -> Result<()> {
        unimplemented!("storage views are read only")
    }

    async fn rollback_to(&mut self, _epoch: Epoch) -> Result<()> {
        unimplemented!("storage views are read only")
    }
}

/// An epoch-locked, read-only view over a [`TreeStorage`].
pub struct TreeStorageView<'a, T: TreeTopology, S: TreeStorage<T>> {
    /// The wrapped [`TreeStorage`]
    pub wrapped: &'a S,
    /// The target epoch
    pub epoch: Epoch,
    /// A wrapper over the state storage of `wrapped`
    pub state: StorageView<'a, T::State, S::StateStorage>,
    /// A wrapper over the node storage of `wrapped`
    pub nodes: KvStorageAt<'a, T, S::NodeStorage>,
    /// [ignore]
    pub _t: PhantomData<T>,
}
impl<'a, T: TreeTopology + 'a, S: TreeStorage<T> + 'a> TreeStorageView<'a, T, S> {
    /// Create a new view on `s` locked at `epoch`.
    pub fn new(s: &'a S, epoch: Epoch) -> Self {
        Self {
            wrapped: s,
            epoch,
            state: StorageView(s.state(), epoch, PhantomData),
            nodes: KvStorageAt {
                wrapped: s.nodes(),
                current_epoch: epoch,
                _p: PhantomData,
            },
            _t: PhantomData,
        }
    }
}

impl<'a, T: TreeTopology + 'a + Send, S: TreeStorage<T> + 'a> TreeStorage<T>
    for TreeStorageView<'a, T, S>
where
    <S as TreeStorage<T>>::NodeStorage: Sync,
{
    type U = <S as TreeStorage<T>>::U;

    type StateStorage = StorageView<'a, T::State, S::StateStorage>;
    type NodeStorage = KvStorageAt<'a, T, S::NodeStorage>;

    fn state(&self) -> &Self::StateStorage {
        &self.state
    }

    fn state_mut(&mut self) -> &mut Self::StateStorage {
        unimplemented!("storage views are read only")
    }

    fn nodes(&self) -> &Self::NodeStorage {
        &self.nodes
    }

    fn nodes_mut(&mut self) -> &mut Self::NodeStorage {
        unimplemented!("storage views are read only")
    }

    async fn born_at(&self, epoch: Epoch) -> Vec<T::Key> {
        self.wrapped.born_at(epoch).await
    }

    async fn rollback_to(&mut self, _epoch: Epoch) -> Result<()> {
        unimplemented!("storage views are read only")
    }

    async fn wide_lineage_between(
        &self,
        keys: Self::U,
        start_epoch: Epoch,
        end_epoch: Epoch,
    ) -> Result<HashMap<(T::Key, Epoch), (NodeContext<T::Key>, T::Node)>> {
        self.wrapped
            .wide_lineage_between(keys, start_epoch, end_epoch.min(self.epoch))
            .await
    }
}
