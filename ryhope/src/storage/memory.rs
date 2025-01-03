use anyhow::*;
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use std::hash::Hash;
use std::{collections::HashMap, fmt::Debug};

use crate::error::{ensure, RyhopeError};
use crate::tree::TreeTopology;
use crate::{IncrementalEpoch, InitSettings, UserEpoch};

use super::{
    CurrenEpochUndefined, EpochKvStorage, EpochMapper, EpochStorage, FromSettings, PayloadStorage,
    RoEpochKvStorage, RoSharedEpochMapper, SharedEpochMapper, TransactionalStorage, TreeStorage,
};

/// A RAM-backed implementation of a transactional epoch storage for a single value.
///
/// The successive states of the persisted value are stored at each transaction
/// in `ts` and can be accesses at any epoch from there.
///
/// There is a 1-1 mapping between epoch and position in the stacked history;
/// i.e. `ts[0]` := epoch 0; therefore, `ts` is initialized to the list
/// containing the initial value of the stored value, which corresponds to the
/// behavior of a freshly created, empty tree, that has a non-null, initial
/// state.
pub struct VersionedStorage<T>
where
    T: Debug + Send + Sync + Clone + Serialize + for<'a> Deserialize<'a>,
{
    /// Whether a transaction has been started and not yet commited.
    in_tx: bool,
    /// The successive states of the persisted value.
    ts: Vec<Option<T>>,
    /// The shared data structure used to map epochs
    epoch_mapper: RoSharedEpochMapper<InMemoryEpochMapper>,
}
impl<T> VersionedStorage<T>
where
    T: Debug + Send + Sync + Clone + Serialize + for<'b> Deserialize<'b>,
{
    fn new(initial_state: T, epoch_mapper: RoSharedEpochMapper<InMemoryEpochMapper>) -> Self {
        Self {
            in_tx: false,
            ts: vec![Some(initial_state)],
            epoch_mapper,
        }
    }

    fn inner_epoch(&self) -> IncrementalEpoch {
        (self.ts.len() - 1).try_into().unwrap()
    }

    fn fetch_at_incremental_epoch(&self, epoch: IncrementalEpoch) -> T {
        assert!(epoch >= 0);
        self.ts[epoch as usize].clone().unwrap()
    }

    fn rollback_to_incremental_epoch(&mut self, epoch: IncrementalEpoch) -> Result<()> {
        ensure!(
            epoch <= self.inner_epoch(),
            "unable to rollback to epoch `{}` more recent than current epoch `{}`",
            epoch,
            self.inner_epoch()
        );

        self.ts.resize((epoch + 1).try_into().unwrap(), None);
        Ok(())
    }
}

impl<T> TransactionalStorage for VersionedStorage<T>
where
    T: Debug + Send + Sync + Clone + Serialize + for<'b> Deserialize<'b>,
{
    async fn start_transaction(&mut self) -> Result<(), RyhopeError> {
        if self.in_tx {
            return Err(RyhopeError::AlreadyInTransaction);
        }
        self.in_tx = true;
        if let Some(latest) = self.ts.last().cloned() {
            self.ts.push(latest);
        } else {
            self.ts.push(None);
        }
        Ok(())
    }

    async fn commit_transaction(&mut self) -> Result<(), RyhopeError> {
        if !self.in_tx {
            return Err(RyhopeError::NotInATransaction);
        }
        self.in_tx = false;
        Ok(())
    }
}

impl<T> EpochStorage<T> for VersionedStorage<T>
where
    T: Debug + Send + Sync + Clone + Serialize + for<'b> Deserialize<'b>,
{
    async fn current_epoch(&self) -> Result<UserEpoch> {
        self.epoch_mapper.try_to_user_epoch(self.inner_epoch())
        .await
        .ok_or(CurrenEpochUndefined(self.inner_epoch()).into())
    }

    async fn fetch_at(&self, epoch: UserEpoch) -> T {
        let epoch = self.epoch_mapper.to_incremental_epoch(epoch).await;
        self.fetch_at_incremental_epoch(epoch)
    }

    async fn fetch(&self) -> T {
        self.fetch_at_incremental_epoch(self.inner_epoch())
    }

    async fn store(&mut self, t: T) -> Result<(), RyhopeError> {
        assert!(self.in_tx);
        let latest = self.ts.len() - 1;
        self.ts[latest] = Some(t);
        Ok(())
    }

    async fn rollback_to(&mut self, epoch: UserEpoch) -> Result<()> {
        let inner_epoch = self
            .epoch_mapper
            .try_to_incremental_epoch(epoch)
            .await
            .ok_or(anyhow!(format!(
                "trying to rollback to an invalid epoch {}",
                epoch
            )))?;
        self.rollback_to_incremental_epoch(inner_epoch)
    }

    async fn rollback(&mut self) -> Result<()> {
        ensure!(self.inner_epoch() > 0, "unable to rollback before epoch 0");
        self.rollback_to_incremental_epoch(self.inner_epoch() - 1)
    }
}

/// A RAM-backed implementation of a transactional epoch storage.
///
/// The successive transactions leading to the current state are stored in a
/// list of hashmaps, each representing the alteration pertaining to the
/// associated epoch.
///
/// There is a 1-1 mapping between epoch and position in the stacked history;
/// i.e. `mem[0]` := epoch 0; therefore, `mem` is initialized to the empty map,
/// as there is (at least for now) a usecase where a tree is non-empty at epoch
/// 0.
#[derive(Debug)]
pub struct VersionedKvStorage<
    K: Hash + Eq + Clone + Debug + Send + Sync,
    V: Clone + Debug + Send + Sync,
> {
    /// In the diffs, the value carried by the insertion/modification of a key
    /// is represented as a Some, whereas a deletion is represented by
    /// associating k to None.
    mem: Vec<HashMap<K, Option<V>>>,
    /// The shared data structure used to map epochs
    epoch_mapper: RoSharedEpochMapper<InMemoryEpochMapper>,
}
impl<K: Hash + Eq + Clone + Debug + Send + Sync, V: Clone + Debug + Send + Sync> Default
    for VersionedKvStorage<K, V>
{
    fn default() -> Self {
        Self::new()
    }
}

impl<K: Hash + Eq + Clone + Debug + Send + Sync, V: Clone + Debug + Send + Sync>
    VersionedKvStorage<K, V>
{
    pub fn new() -> Self {
        let epoch_mapper = SharedEpochMapper::new(InMemoryEpochMapper::new_at(0));
        Self::new_with_mapper(epoch_mapper)
    }

    pub fn new_with_mapper(mapper: RoSharedEpochMapper<InMemoryEpochMapper>) -> Self {
        VersionedKvStorage {
            mem: vec![Default::default()],
            epoch_mapper: mapper,
        }
    }

    fn new_epoch(&mut self) {
        self.mem.push(Default::default());
    }

    fn inner_epoch(&self) -> IncrementalEpoch {
        // There is a 1-1 mapping between the epoch and the position in the list of
        // diffs; epoch 0 being the initial empty state.
        (self.mem.len() - 1).try_into().unwrap()
    }

    fn try_fetch_at_incremental_epoch(&self, k: &K, epoch: IncrementalEpoch) -> Option<V> {
        assert!(epoch >= 0); // To fetch a key at a given epoch, the list of diffs up to the
                             // requested epoch is iterated in reverse. The first occurence of k,
                             // i.e. the most recent one, will be the current value.
                             //
                             // If this occurence is a None, it means that k has been deleted.

        for i in (0..=epoch as usize).rev() {
            let maybe = self.mem[i].get(k);
            if let Some(found) = maybe {
                return Ok(found.to_owned());
            };
        }

        None
    }

    fn rollback_to_incremental_epoch(&mut self, epoch: IncrementalEpoch) -> Result<()> {
        ensure!(epoch >= 0, "unable to rollback before epoch 0",);
        ensure!(
            epoch <= self.inner_epoch(),
            "unable to rollback to epoch `{}` more recent than current epoch `{}`",
            epoch,
            self.inner_epoch()
        );

        self.mem.truncate((epoch + 1).try_into().unwrap());

        Ok(())
    }
}

impl<K, V> RoEpochKvStorage<K, V> for VersionedKvStorage<K, V>
where
    K: Hash + Eq + Clone + Debug + Send + Sync,
    V: Clone + Debug + Send + Sync,
{
    async fn initial_epoch(&self) -> UserEpoch {
        self.epoch_mapper.to_user_epoch(0).await as UserEpoch
    }

    async fn current_epoch(&self) -> Result<UserEpoch> {
        self.epoch_mapper
            .try_to_user_epoch(self.inner_epoch())
            .await
            .ok_or(CurrenEpochUndefined(self.inner_epoch()).into())
    }

    async fn try_fetch(&self, k: &K) -> Option<V> {
        self.try_fetch_at_incremental_epoch(k, self.inner_epoch())
    }

    async fn try_fetch_at(&self, k: &K, epoch: UserEpoch) -> Option<V> {
        self.epoch_mapper
            .try_to_incremental_epoch(epoch)
            .await
            .and_then(|inner_epoch| self.try_fetch_at_incremental_epoch(k, inner_epoch))
    }

    fn rollback_to_incremental_epoch(&mut self, epoch: IncrementalEpoch) -> Result<()> {
        ensure!(
            epoch >= 0,
            "unable to rollback before epoch 0",
        );
        ensure!(
            epoch <= self.inner_epoch(),
            "unable to rollback to epoch `{}` more recent than current epoch `{}`",
            epoch,
            self.inner_epoch()
        );

        self.mem.truncate((epoch + 1).try_into().unwrap());

        Ok(())
    }
}

impl<K, V> RoEpochKvStorage<K, V> for VersionedKvStorage<K, V>
where
    K: Hash + Eq + Clone + Debug + Send + Sync,
    V: Clone + Debug + Send + Sync,
{
    async fn initial_epoch(&self) -> UserEpoch {
        self.epoch_mapper.to_user_epoch(0).await as UserEpoch
    }

    async fn current_epoch(&self) -> Result<UserEpoch> {
        self.epoch_mapper.try_to_user_epoch(self.inner_epoch()).await
            .ok_or(CurrenEpochUndefined(self.inner_epoch()).into())
    }

    async fn try_fetch(&self, k: &K) -> Option<V> {
        self.try_fetch_at_incremental_epoch(k, self.inner_epoch())
    }

    async fn try_fetch_at(&self, k: &K, epoch: UserEpoch) -> Option<V> {
        self.epoch_mapper.try_to_incremental_epoch(epoch).await
            .and_then(|inner_epoch| {
            self.try_fetch_at_incremental_epoch(k, inner_epoch)
        })
    }

    // Expensive, but only used in test context.
    async fn size(&self) -> usize {
        let all_keys = self
            .mem
            .iter()
            .flat_map(|epoch| epoch.keys())
            .collect::<HashSet<_>>();

        let mut count = 0;
        for k in all_keys {
            if self.try_fetch(k).await.unwrap().is_some() {
                count += 1;
            }
        }
        count
    }

    async fn size_at(&self, epoch: UserEpoch) -> usize {
        let inner_epoch = self.epoch_mapper.to_incremental_epoch(epoch).await;
        assert!(inner_epoch >= 0); // To fetch a key at a given epoch, the list of diffs up to the
        let mut keys = HashSet::new();

        for i in 0..=inner_epoch as usize {
            keys.extend(self.mem[i].keys())
        }

        keys.len()
    }

    async fn keys_at(&self, epoch: UserEpoch) -> Vec<K> {
        let inner_epoch = self.epoch_mapper.to_incremental_epoch(epoch).await;
        assert!(inner_epoch >= 0);
        let mut keys = HashSet::new();

        for i in 0..=inner_epoch as usize {
            for (k, v) in self.mem[i].iter() {
                if v.is_some() {
                    keys.insert(k);
                } else {
                    keys.remove(k);
                }
            }
        }

        keys.into_iter().cloned().collect()
    }

    async fn random_key_at(&self, epoch: UserEpoch) -> Option<K> {
        self.epoch_mapper
            .try_to_incremental_epoch(epoch)
            .await
            .and_then(|inner_epoch| {
                assert!(inner_epoch >= 0);

                for i in (0..=inner_epoch as usize).rev() {
                    for (k, v) in self.mem[i].iter() {
                        if v.is_some() {
                            return Some(k.clone());
                        }
                    }
                }

                None
            })
    }

    async fn pairs_at(&self, epoch: UserEpoch) -> Result<HashMap<K, V>> {
        let inner_epoch = self
            .epoch_mapper
            .try_to_incremental_epoch(epoch)
            .await
            .ok_or(anyhow!("Try fetching an invalid epoch {epoch}"))?;
        assert!(inner_epoch >= 0);
        let mut pairs = HashMap::new();
        for i in 0..=inner_epoch as usize {
            for (k, v) in self.mem[i].iter() {
                if let Some(v) = v.clone() {
                    pairs.insert(k.clone(), v);
                } else {
                    pairs.remove(k);
                }
            }
        }
        Ok(pairs)
    }
}

impl<K, V> EpochKvStorage<K, V> for VersionedKvStorage<K, V>
where
    K: Hash + Eq + Clone + Debug + Send + Sync,
    V: Clone + Debug + Send + Sync,
{
    async fn remove(&mut self, k: K) -> Result<(), RyhopeError> {
        ensure(self.try_fetch(&k).await?.is_some(), "key not found")?;
        self.mem.last_mut().unwrap().insert(k, None);
        Ok(())
    }

    async fn update(&mut self, k: K, new_value: V) -> Result<(), RyhopeError> {
        ensure(self.try_fetch(&k).await?.is_some(), "key not found")?;
        self.mem.last_mut().unwrap().insert(k, Some(new_value));
        Ok(())
    }

    async fn store(&mut self, k: K, value: V) -> Result<(), RyhopeError> {
        self.mem.last_mut().unwrap().insert(k, Some(value));
        Ok(())
    }

    async fn rollback_to(&mut self, epoch: UserEpoch) -> Result<()> {
        let inner_epoch = self
            .epoch_mapper
            .try_to_incremental_epoch(epoch)
            .await
            .ok_or(anyhow!("Try to rollback to an invalid epoch {epoch}"))?;
        self.rollback_to_incremental_epoch(inner_epoch)
    }

    async fn rollback(&mut self) -> Result<()> {
        ensure!(self.inner_epoch() > 0, "unable to rollback before epoch 0");
        self.rollback_to_incremental_epoch(self.inner_epoch() - 1)
    }
}
#[derive(Clone, Debug)]
pub struct InMemoryEpochMapper(BTreeMap<UserEpoch, IncrementalEpoch>);

impl InMemoryEpochMapper {
    pub(crate) fn new_empty() -> Self {
        Self(BTreeMap::new())
    }

    pub(crate) fn new_at(initial_epoch: UserEpoch) -> Self {
        let mut map = BTreeMap::new();
        map.insert(initial_epoch, 0);
        Self(map)
    }

    pub(crate) fn initial_epoch(&self) -> UserEpoch {
        let (initial_epoch, initial_inner_epoch) = self.0.iter().next().unwrap();
        assert_eq!(*initial_inner_epoch, 0);
        *initial_epoch
    }

    pub(crate) fn last_epoch(&self) -> UserEpoch {
        *self.0.iter().next_back().unwrap().0
    }

    fn try_to_incremental_epoch_inner(&self, epoch: UserEpoch) -> Option<IncrementalEpoch> {
        self.0.get(&epoch).copied()
    }

    fn try_to_user_epoch_inner(&self, epoch: IncrementalEpoch) -> Option<UserEpoch> {
        self.0.iter().nth(epoch as usize).map(|el| *el.0)
    }

    /// Add a new epoch mapping for `IncrementalEpoch` `epoch`, assuming that `UserEpoch`s
    /// are also computed incrementally from an initial shift. If there is already a mapping for
    /// `IncrementalEpoch` `epoch`, then this function has no side effects, because it is assumed
    /// that the mapping has already been provided according to another, non-incremental, logic.
    /// This function returns the `UserEpoch` being mapper to `epoch`, in case a new mapping
    /// is actually inserted.
    pub(crate) fn new_incremental_epoch(&mut self, epoch: IncrementalEpoch) -> Option<UserEpoch> {
        // compute last arbitrary epoch being inserted in the map
        let last_epoch = self.last_epoch();
        // check if `epoch` has already been inserted in the map
        match self.try_to_user_epoch_inner(epoch) {
            Some(matched_epoch) => {
                // `epoch` has already been inserted, only check that
                // `matched_epoch` corresponds to the last inserted `UserEpoch`
                assert_eq!(last_epoch, matched_epoch,);
                None
            }
            None => {
                // get arbitrary epoch corresponding to the new incremental epoch.
                // in this implementation, it is computed assuming that also
                // `UserEpoch`s are incremental, and so the epoch to be inserted
                // is simply `last_epoch + 1`
                let mapped_epoch = last_epoch + 1;
                // add the epoch mapping to `self`
                self.add_epoch(mapped_epoch, epoch)
                    .ok()
                    .map(|_| mapped_epoch)
            }
        }
    }

    pub(crate) fn rollback_to(&mut self, epoch: UserEpoch) {
        // erase from the map all epochs greater than `epoch`
        let to_be_erased_epochs = self
            .0
            .iter()
            .rev()
            .map_while(|el| if *el.0 > epoch { Some(*el.0) } else { None })
            .collect_vec();
        to_be_erased_epochs.into_iter().for_each(|epoch| {
            self.0.remove(&epoch);
        });
    }

    fn add_epoch(
        &mut self,
        user_epoch: UserEpoch,
        incremental_epoch: IncrementalEpoch,
    ) -> Result<()> {
        // double check that we are either replacing an existing `IncrementalEpoch`
        // in the map or we are adding the next incremental one. This check ensures
        // that `IncrementalEpoch`s found in the map are always incremental
        let num_epochs = self.0.len();
        ensure!(
            incremental_epoch as usize <= num_epochs,
            "Inserted IncrementalEpoch is too big: found {incremental_epoch}, maximum is {num_epochs}"
        );
        // check that the `user_epoch` being added is associated to the correct
        // `incremental_epoch`, according to the ordering in the map
        if let Some(smaller_epoch) = self.try_to_user_epoch_inner(incremental_epoch - 1) {
            ensure!(user_epoch > smaller_epoch);
        }
        if let Some(bigger_epoch) = self.try_to_user_epoch_inner(incremental_epoch + 1) {
            ensure!(user_epoch < bigger_epoch)
        }
        // if we are replacing an existing `IncrementalEpoch`, ensure that
        // we remove the old mapping entry
        if let Some(epoch) = self.try_to_user_epoch_inner(incremental_epoch) {
            self.0.remove(&epoch);
        }

        self.0.insert(user_epoch, incremental_epoch);
        Ok(())
    }
}

impl EpochMapper for InMemoryEpochMapper {
    async fn try_to_incremental_epoch(&self, epoch: UserEpoch) -> Option<IncrementalEpoch> {
        self.try_to_incremental_epoch_inner(epoch)
    }

    async fn try_to_user_epoch(&self, epoch: IncrementalEpoch) -> Option<UserEpoch> {
        self.try_to_user_epoch_inner(epoch)
    }

    async fn add_epoch_map(
        &mut self,
        user_epoch: UserEpoch,
        incremental_epoch: IncrementalEpoch,
    ) -> Result<()> {
        self.add_epoch(user_epoch, incremental_epoch)
    }
}

/// A RAM-backed storage for tree data.
pub struct InMemory<T: TreeTopology, V: Clone + Debug + Send + Sync, const READ_ONLY: bool> {
    /// Storage for tree state.
    state: VersionedStorage<<T as TreeTopology>::State>,
    /// Storage for topological data.
    nodes: VersionedKvStorage<<T as TreeTopology>::Key, <T as TreeTopology>::Node>,
    /// Storage for node-associated data.
    data: VersionedKvStorage<<T as TreeTopology>::Key, V>,
    epoch_mapper: SharedEpochMapper<InMemoryEpochMapper, READ_ONLY>,
    /// Whether a transaction is currently opened.
    in_tx: bool,
}

impl<T: TreeTopology, V: Clone + Debug + Send + Sync, const READ_ONLY: bool>
    InMemory<T, V, READ_ONLY>
{
    /// Initialize a new `InMemory` storage with read-only epoch mapper
    pub fn new_with_mapper(
        tree_state: T::State,
        epoch_mapper: SharedEpochMapper<InMemoryEpochMapper, READ_ONLY>,
    ) -> Self {
        Self {
            state: VersionedStorage::new(tree_state, (&epoch_mapper).into()),
            nodes: VersionedKvStorage::new_with_mapper((&epoch_mapper).into()),
            data: VersionedKvStorage::new_with_mapper((&epoch_mapper).into()),
            epoch_mapper,
            in_tx: false,
        }
    }

    pub fn new_with_epoch(tree_state: T::State, initial_epoch: UserEpoch) -> Self {
        let epoch_mapper = SharedEpochMapper::new(InMemoryEpochMapper::new_at(initial_epoch));
        Self {
            state: VersionedStorage::new(tree_state, (&epoch_mapper).into()),
            nodes: VersionedKvStorage::new_with_mapper((&epoch_mapper).into()),
            data: VersionedKvStorage::new_with_mapper((&epoch_mapper).into()),
            epoch_mapper,
            in_tx: false,
        }
    }
}

impl<T: TreeTopology, V: Clone + Debug + Send + Sync> FromSettings<T::State>
    for InMemory<T, V, true>
{
    type Settings = SharedEpochMapper<InMemoryEpochMapper, true>;

    async fn from_settings(
        init_settings: InitSettings<T::State>,
        storage_settings: Self::Settings,
    ) -> Result<Self> {
        match init_settings {
            InitSettings::MustExist => unimplemented!(),
            InitSettings::MustNotExist(tree_state) | InitSettings::Reset(tree_state) => {
                Ok(Self::new_with_mapper(tree_state, storage_settings))
            }
            InitSettings::MustNotExistAt(tree_state, initial_epoch)
            | InitSettings::ResetAt(tree_state, initial_epoch) => {
                // check that initial_epoch is in epoch_mapper
                ensure!(
                    storage_settings.read_access_ref().await.initial_epoch() == initial_epoch,
                    "Initial epoch {initial_epoch} not found in the epoch mapper provided as input"
                );
                Ok(Self::new_with_mapper(tree_state, storage_settings))
            }
        }
    }
}

impl<T: TreeTopology, V: Clone + Debug + Send + Sync> FromSettings<T::State>
    for InMemory<T, V, false>
{
    type Settings = ();

    async fn from_settings(
        init_settings: InitSettings<T::State>,
        _storage_settings: Self::Settings,
    ) -> Result<Self, RyhopeError> {
        match init_settings {
            InitSettings::MustExist => unimplemented!(),
            InitSettings::MustNotExist(tree_state) | InitSettings::Reset(tree_state) => {
                Ok(Self::new_with_epoch(tree_state, 0))
            }
            InitSettings::MustNotExistAt(tree_state, initial_epoch)
            | InitSettings::ResetAt(tree_state, initial_epoch) => {
                Ok(Self::new_with_epoch(tree_state, initial_epoch))
            }
        }
    }
}

impl<T, V, const READ_ONLY: bool> TreeStorage<T> for InMemory<T, V, READ_ONLY>
where
    T: TreeTopology,
    T::Node: Clone,
    V: Clone + Debug + Sync + Send,
{
    type StateStorage = VersionedStorage<T::State>;
    type NodeStorage = VersionedKvStorage<T::Key, T::Node>;
    type EpochMapper = SharedEpochMapper<InMemoryEpochMapper, READ_ONLY>;

    fn nodes(&self) -> &Self::NodeStorage {
        &self.nodes
    }

    fn nodes_mut(&mut self) -> &mut Self::NodeStorage {
        &mut self.nodes
    }

    fn state(&self) -> &Self::StateStorage {
        &self.state
    }

    fn state_mut(&mut self) -> &mut Self::StateStorage {
        &mut self.state
    }

    async fn born_at(&self, epoch: UserEpoch) -> Vec<T::Key> {
        let inner_epoch = self.epoch_mapper.to_incremental_epoch(epoch).await;
        assert!(inner_epoch >= 0);
        self.nodes.mem[inner_epoch as usize]
            .keys()
            .cloned()
            .collect()
    }

    async fn rollback_to(&mut self, epoch: UserEpoch) -> Result<(), RyhopeError> {
        println!("Rolling back to {epoch}");
        self.state.rollback_to(epoch).await?;
        self.nodes.rollback_to(epoch).await?;
        self.data.rollback_to(epoch).await?;

        // Rollback epoch_mapper as well
        self.epoch_mapper
            .apply_fn(|mapper| {
                mapper.rollback_to(epoch);
                Ok(())
            })
            .await?;

        assert_eq!(self.state.inner_epoch(), self.nodes.inner_epoch());
        assert_eq!(self.state.inner_epoch(), self.data.inner_epoch());

        Ok(())
    }

    fn epoch_mapper(&self) -> &Self::EpochMapper {
        &self.epoch_mapper
    }

    fn epoch_mapper_mut(&mut self) -> &mut Self::EpochMapper {
        &mut self.epoch_mapper
    }
}

impl<T, V, const READ_ONLY: bool> PayloadStorage<<T as TreeTopology>::Key, V>
    for InMemory<T, V, READ_ONLY>
where
    T: TreeTopology,
    <T as TreeTopology>::Key: Clone,
    V: Clone + Debug + Send + Sync,
{
    type DataStorage = VersionedKvStorage<<T as TreeTopology>::Key, V>;

    fn data(&self) -> &Self::DataStorage {
        &self.data
    }

    fn data_mut(&mut self) -> &mut Self::DataStorage {
        &mut self.data
    }
}

impl<T, V, const READ_ONLY: bool> TransactionalStorage for InMemory<T, V, READ_ONLY>
where
    T: TreeTopology,
    V: Clone + Debug + Send + Sync,
{
    async fn start_transaction(&mut self) -> Result<(), RyhopeError> {
        if self.in_tx {
            return Err(RyhopeError::AlreadyInTransaction);
        }

        self.state.start_transaction().await?;
        self.data.new_epoch();
        self.nodes.new_epoch();
        self.in_tx = true;

        let new_epoch = self.state.inner_epoch();
        assert_eq!(new_epoch, self.nodes.inner_epoch());
        assert_eq!(new_epoch, self.data.inner_epoch());

        // add new_epoch to epoch mapper, if it is not READ_ONLY
        self.epoch_mapper
            .apply_fn(|mapper| {
                mapper.new_incremental_epoch(new_epoch);
                Ok(())
            })
            .await?;

        Ok(())
    }

    async fn commit_transaction(&mut self) -> Result<(), RyhopeError> {
        if !self.in_tx {
            return Err(RyhopeError::NotInATransaction);
        }

        self.state.commit_transaction().await?;
        self.in_tx = false;
        Ok(())
    }
}
