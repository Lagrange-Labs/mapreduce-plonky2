//! This module offers facilities to “time-travel”, i.e. access the successive
//! states of a tree at given epochs.
use anyhow::*;
use serde::{Deserialize, Serialize};
use std::{fmt::Debug, marker::PhantomData};

use crate::{tree::TreeTopology, Epoch};

use super::{EpochKvStorage, EpochStorage, RoEpochKvStorage, TransactionalStorage, TreeStorage};

/// An epoch-locked, read-only, view over an [`EpochStorage`].
pub struct StorageView<
    's,
    T: Debug + Sync + Clone + Serialize + for<'a> Deserialize<'a>,
    S: EpochStorage<T>,
>(
    /// The wrapped [`EpochStorage`]
    &'s S,
    /// The target epoch
    Epoch,
    /// [ignore]
    PhantomData<T>,
);
impl<'s, T: Debug + Sync + Clone + Serialize + for<'a> Deserialize<'a>, S: EpochStorage<T>>
    TransactionalStorage for StorageView<'s, T, S>
{
    fn start_transaction(&mut self) -> Result<()> {
        unimplemented!("storage views are read only")
    }

    fn commit_transaction(&mut self) -> Result<()> {
        unimplemented!("storage views are read only")
    }
}
impl<'s, T: Debug + Sync + Clone + Serialize + for<'a> Deserialize<'a>, S: EpochStorage<T>>
    EpochStorage<T> for StorageView<'s, T, S>
{
    fn current_epoch(&self) -> Epoch {
        self.1
    }

    fn fetch_at(&self, epoch: Epoch) -> T {
        if epoch != self.1 {
            unimplemented!(
                "this storage view is locked at {}; {epoch} unreachable",
                self.1
            )
        } else {
            self.0.fetch_at(self.1)
        }
    }

    fn fetch(&self) -> T {
        self.0.fetch_at(self.1)
    }

    fn store(&mut self, _: T) {
        unimplemented!("storage views are read only")
    }

    fn rollback_to(&mut self, _epoch: Epoch) -> Result<()> {
        unimplemented!("storage views are read only")
    }
}

/// An epoch-locked, read-only, view over an [`EpochKvStorage`].
pub struct KvStorageAt<'a, T: TreeTopology, S: RoEpochKvStorage<T::Key, T::Node>>(
    /// The wrapped [`EpochKvStorage`]
    &'a S,
    /// The target epoch
    Epoch,
    /// [ignore]
    PhantomData<T>,
);
impl<'a, T: TreeTopology, S: RoEpochKvStorage<T::Key, T::Node>> RoEpochKvStorage<T::Key, T::Node>
    for KvStorageAt<'a, T, S>
{
    fn current_epoch(&self) -> Epoch {
        self.1
    }

    fn try_fetch_at(&self, k: &T::Key, epoch: Epoch) -> Option<T::Node> {
        if epoch != self.1 {
            unimplemented!(
                "this storage view is locked at {}; {epoch} unreachable",
                self.1
            )
        } else {
            self.0.try_fetch_at(k, self.1)
        }
    }

    fn fetch(&self, k: &T::Key) -> T::Node {
        self.0.fetch_at(k, self.1)
    }

    fn size(&self) -> usize {
        self.0.size()
    }
}
impl<'a, T: TreeTopology, S: RoEpochKvStorage<T::Key, T::Node>> EpochKvStorage<T::Key, T::Node>
    for KvStorageAt<'a, T, S>
{
    fn remove(&mut self, _: T::Key) -> Result<()> {
        unimplemented!("storage views are read only")
    }

    fn update(&mut self, _: T::Key, _: T::Node) -> Result<()> {
        unimplemented!("storage views are read only")
    }

    fn store(&mut self, _: T::Key, _: T::Node) -> Result<()> {
        unimplemented!("storage views are read only")
    }

    fn rollback_to(&mut self, _epoch: Epoch) -> Result<()> {
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
            nodes: KvStorageAt(s.nodes(), epoch, PhantomData),
            _t: PhantomData,
        }
    }
}
impl<'a, T: TreeTopology + 'a, S: TreeStorage<T> + 'a> TreeStorage<T>
    for TreeStorageView<'a, T, S>
{
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

    fn born_at(&self, epoch: Epoch) -> Vec<T::Key> {
        self.wrapped.born_at(epoch)
    }

    fn rollback_to(&mut self, _epoch: Epoch) -> Result<()> {
        unimplemented!("storage views are read only")
    }
}