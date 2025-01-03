//! This module offers facilities to “time-travel”, i.e. access the successive
//! states of a tree at given epochs.
use std::{collections::HashMap, fmt::Debug, future::Future, marker::PhantomData};

use serde::{Deserialize, Serialize};

use crate::{error::RyhopeError, tree::TreeTopology, UserEpoch};

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
    UserEpoch,
    /// [ignore]
    PhantomData<T>,
);

impl<
        T: Debug + Sync + Clone + Serialize + for<'a> Deserialize<'a> + Send,
        S: EpochStorage<T> + Sync,
    > TransactionalStorage for StorageView<'_, T, S>
where
    T: Send,
{
    async fn start_transaction(&mut self) -> Result<(), RyhopeError> {
        unimplemented!("storage views are read only")
    }

    async fn commit_transaction(&mut self) -> Result<(), RyhopeError> {
        unimplemented!("storage views are read only")
    }
}

impl<
        T: Debug + Sync + Clone + Serialize + for<'a> Deserialize<'a> + Send,
        S: EpochStorage<T> + Sync,
    > EpochStorage<T> for StorageView<'_, T, S>
where
    T: Send,
{
    async fn current_epoch(&self) -> UserEpoch {
        self.1
    }

    async fn fetch_at(&self, epoch: UserEpoch) -> Result<T, RyhopeError> {
        if epoch != self.1 {
            unimplemented!(
                "this storage view is locked at {}; {epoch} unreachable",
                self.1
            )
        } else {
            self.0.fetch_at(self.1).await
        }
    }

    async fn fetch(&self) -> Result<T, RyhopeError> {
        self.0.fetch_at(self.1).await
    }

    async fn store(&mut self, _: T) -> Result<(), RyhopeError> {
        unimplemented!("storage views are read only")
    }

    async fn rollback_to(&mut self, _epoch: UserEpoch) -> Result<(), RyhopeError> {
        unimplemented!("storage views are read only")
    }
}

/// An epoch-locked, read-only, view over an [`EpochKvStorage`].
pub struct KvStorageAt<'a, T: TreeTopology, S: RoEpochKvStorage<T::Key, T::Node>> {
    /// The wrapped [`RoEpochKvStorage`]
    wrapped: &'a S,
    /// The epoch at which the wrapped storage is being looked at
    current_epoch: UserEpoch,
    /// [ignore]
    _p: PhantomData<T>,
}

impl<T: TreeTopology, S: RoEpochKvStorage<T::Key, T::Node> + Sync> RoEpochKvStorage<T::Key, T::Node>
    for KvStorageAt<'_, T, S>
{
    fn initial_epoch(&self) -> impl Future<Output = UserEpoch> + Send {
        self.wrapped.initial_epoch()
    }

    async fn current_epoch(&self) -> Result<UserEpoch> {
        Ok(self.current_epoch)
    }

    async fn try_fetch_at(&self, k: &T::Key, epoch: UserEpoch) -> Result<Option<T::Node>, RyhopeError> {
        if epoch > self.current_epoch {
            unimplemented!(
                "this storage view is locked at {}; {epoch} unreachable",
                self.current_epoch
            )
        } else {
            self.wrapped.try_fetch_at(k, self.current_epoch).await
        }
    }

    async fn try_fetch(&self, k: &T::Key) -> Option<T::Node> {
        self.wrapped.try_fetch_at(k, self.current_epoch).await
    }

    async fn fetch(&self, k: &T::Key) -> T::Node {
        self.wrapped.fetch_at(k, self.current_epoch).await
    }

    async fn size(&self) -> usize {
        self.wrapped.size_at(self.current_epoch).await
    }

    async fn size_at(&self, epoch: UserEpoch) -> usize {
        self.wrapped.size_at(epoch).await
    }

    async fn keys_at(&self, epoch: UserEpoch) -> Vec<T::Key> {
        self.wrapped.keys_at(epoch).await
    }

    async fn random_key_at(&self, epoch: UserEpoch) -> Option<T::Key> {
        self.wrapped.random_key_at(epoch).await
    }

    async fn pairs_at(&self, epoch: UserEpoch) -> Result<HashMap<T::Key, T::Node>, RyhopeError> {
        if epoch > self.current_epoch {
            unimplemented!(
                "this storage view is locked at {}; {epoch} unreachable",
                self.current_epoch
            )
        } else {
            self.wrapped.pairs_at(epoch).await
        }
    }
}

impl<T: TreeTopology, S: RoEpochKvStorage<T::Key, T::Node> + Sync> EpochKvStorage<T::Key, T::Node>
    for KvStorageAt<'_, T, S>
{
    async fn remove(&mut self, _: T::Key) -> Result<(), RyhopeError> {
        unimplemented!("storage views are read only")
    }

    async fn update(&mut self, _: T::Key, _: T::Node) -> Result<(), RyhopeError> {
        unimplemented!("storage views are read only")
    }

    async fn store(&mut self, _: T::Key, _: T::Node) -> Result<(), RyhopeError> {
        unimplemented!("storage views are read only")
    }

    async fn rollback_to(&mut self, _epoch: UserEpoch) -> Result<(), RyhopeError> {
        unimplemented!("storage views are read only")
    }
    
    async fn rollback(&mut self) -> Result<(), RyhopeError> {
        unimplemented!("storage views are read only")
    }
}

/// An epoch-locked, read-only view over a [`TreeStorage`].
pub struct TreeStorageView<'a, T: TreeTopology, S: TreeStorage<T>> {
    /// The wrapped [`TreeStorage`]
    pub wrapped: &'a S,
    /// The target epoch
    pub epoch: UserEpoch,
    /// A wrapper over the state storage of `wrapped`
    pub state: StorageView<'a, T::State, S::StateStorage>,
    /// A wrapper over the node storage of `wrapped`
    pub nodes: KvStorageAt<'a, T, S::NodeStorage>,
    epoch_mapper: &'a S::EpochMapper,
    /// [ignore]
    pub _t: PhantomData<T>,
}
impl<'a, T: TreeTopology + 'a, S: TreeStorage<T> + 'a> TreeStorageView<'a, T, S> {
    /// Create a new view on `s` locked at `epoch`.
    pub fn new(s: &'a S, epoch: UserEpoch) -> Self {
        Self {
            wrapped: s,
            epoch,
            state: StorageView(s.state(), epoch, PhantomData),
            nodes: KvStorageAt {
                wrapped: s.nodes(),
                current_epoch: epoch,
                _p: PhantomData,
            },
            epoch_mapper: s.epoch_mapper(),
            _t: PhantomData,
        }
    }
}

impl<'a, T: TreeTopology + 'a + Send, S: TreeStorage<T> + 'a> TreeStorage<T>
    for TreeStorageView<'a, T, S>
where
    <S as TreeStorage<T>>::NodeStorage: Sync,
{
    type StateStorage = StorageView<'a, T::State, S::StateStorage>;
    type NodeStorage = KvStorageAt<'a, T, S::NodeStorage>;
    type EpochMapper = S::EpochMapper;

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

    async fn born_at(&self, epoch: UserEpoch) -> Vec<T::Key> {
        self.wrapped.born_at(epoch).await
    }

    async fn rollback_to(&mut self, _epoch: UserEpoch) -> Result<(), RyhopeError> {
        unimplemented!("storage views are read only")
    }

    fn epoch_mapper(&self) -> &Self::EpochMapper {
        self.epoch_mapper
    }

    fn epoch_mapper_mut(&mut self) -> &mut Self::EpochMapper {
        unimplemented!("storage views are read only")
    }
}
