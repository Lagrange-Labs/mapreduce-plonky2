use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashSet};
use std::hash::Hash;
use std::{collections::HashMap, fmt::Debug};

use crate::error::{ensure, RyhopeError};
use crate::tree::TreeTopology;
use crate::{IncrementalEpoch, InitSettings, UserEpoch};

use super::{
    EpochKvStorage, EpochMapper, EpochStorage, FromSettings, PayloadStorage, RoEpochKvStorage,
    RoSharedEpochMapper, SharedEpochMapper, TransactionalStorage, TreeStorage,
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

    fn fetch_at_incremental_epoch(&self, epoch: IncrementalEpoch) -> Result<T, RyhopeError> {
        assert!(epoch >= 0);
        self.ts[epoch as usize].clone().ok_or(RyhopeError::internal(
            "No entry found in storage for epoch {epoch}",
        ))
    }

    fn rollback_to_incremental_epoch(
        &mut self,
        epoch: IncrementalEpoch,
    ) -> Result<(), RyhopeError> {
        ensure(
            epoch <= self.inner_epoch(),
            format!(
                "unable to rollback to epoch `{}` more recent than current epoch `{}`",
                epoch,
                self.inner_epoch()
            ),
        )?;

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
    async fn current_epoch(&self) -> Result<UserEpoch, RyhopeError> {
        self.epoch_mapper
            .try_to_user_epoch(self.inner_epoch())
            .await
            .ok_or(RyhopeError::CurrenEpochUndefined(self.inner_epoch()))
    }

    async fn fetch_at(&self, epoch: UserEpoch) -> Result<T, RyhopeError> {
        let epoch = self
            .epoch_mapper
            .try_to_incremental_epoch(epoch)
            .await
            .ok_or(RyhopeError::epoch_error(format!(
                "IncrementalEpoch not found for epoch {epoch}"
            )))?;
        self.fetch_at_incremental_epoch(epoch)
    }

    async fn fetch(&self) -> Result<T, RyhopeError> {
        self.fetch_at_incremental_epoch(self.inner_epoch())
    }

    async fn store(&mut self, t: T) -> Result<(), RyhopeError> {
        assert!(self.in_tx);
        let latest = self.ts.len() - 1;
        self.ts[latest] = Some(t);
        Ok(())
    }

    async fn rollback_to(&mut self, epoch: UserEpoch) -> Result<(), RyhopeError> {
        let inner_epoch = self
            .epoch_mapper
            .try_to_incremental_epoch(epoch)
            .await
            .ok_or(RyhopeError::epoch_error(format!(
                "trying to rollback to an invalid epoch {}",
                epoch
            )))?;
        self.rollback_to_incremental_epoch(inner_epoch)
    }

    async fn rollback(&mut self) -> Result<(), RyhopeError> {
        ensure(self.inner_epoch() > 0, "unable to rollback before epoch 0")?;
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
        assert!(epoch >= 0);
        // To fetch a key at a given epoch, the list of diffs up to the
        // requested epoch is iterated in reverse. The first occurence of k,
        // i.e. the most recent one, will be the current value.
        //
        // If this occurence is a None, it means that k has been deleted.
        for i in (0..=epoch as usize).rev() {
            let maybe = self.mem[i].get(k);
            if let Some(found) = maybe {
                return found.to_owned();
            };
        }

        None
    }

    fn rollback_to_incremental_epoch(
        &mut self,
        epoch: IncrementalEpoch,
    ) -> Result<(), RyhopeError> {
        ensure(epoch >= 0, "unable to rollback before epoch 0")?;
        ensure(
            epoch <= self.inner_epoch(),
            format!(
                "unable to rollback to epoch `{}` more recent than current epoch `{}`",
                epoch,
                self.inner_epoch()
            ),
        )?;

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

    async fn current_epoch(&self) -> Result<UserEpoch, RyhopeError> {
        self.epoch_mapper
            .try_to_user_epoch(self.inner_epoch())
            .await
            .ok_or(RyhopeError::CurrenEpochUndefined(self.inner_epoch()))
    }

    async fn try_fetch(&self, k: &K) -> Result<Option<V>, RyhopeError> {
        Ok(self.try_fetch_at_incremental_epoch(k, self.inner_epoch()))
    }

    async fn try_fetch_at(&self, k: &K, epoch: UserEpoch) -> Result<Option<V>, RyhopeError> {
        Ok(self
            .epoch_mapper
            .try_to_incremental_epoch(epoch)
            .await
            .and_then(|inner_epoch| self.try_fetch_at_incremental_epoch(k, inner_epoch)))
    }

    // Expensive, but only used in test context.
    async fn size(&self) -> Result<usize, RyhopeError> {
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
        Ok(count)
    }

    async fn size_at(&self, epoch: UserEpoch) -> Result<usize, RyhopeError> {
        let inner_epoch = self.epoch_mapper.to_incremental_epoch(epoch).await;
        assert!(inner_epoch >= 0); // To fetch a key at a given epoch, the list of diffs up to the
        let mut keys = HashSet::new();

        for i in 0..=inner_epoch as usize {
            keys.extend(self.mem[i].keys())
        }

        Ok(keys.len())
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

    async fn pairs_at(&self, epoch: UserEpoch) -> Result<HashMap<K, V>, RyhopeError> {
        let inner_epoch = self
            .epoch_mapper
            .try_to_incremental_epoch(epoch)
            .await
            .ok_or(RyhopeError::epoch_error(format!(
                "IncrementalEpoch not found for epoch {epoch}"
            )))?;
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

    async fn rollback_to(&mut self, epoch: UserEpoch) -> Result<(), RyhopeError> {
        let inner_epoch = self
            .epoch_mapper
            .try_to_incremental_epoch(epoch)
            .await
            .ok_or(RyhopeError::epoch_error(format!(
                "Try to rollback to an invalid epoch {epoch}"
            )))?;
        self.rollback_to_incremental_epoch(inner_epoch)
    }

    async fn rollback(&mut self) -> Result<(), RyhopeError> {
        ensure(self.inner_epoch() > 0, "unable to rollback before epoch 0")?;
        self.rollback_to_incremental_epoch(self.inner_epoch() - 1)
    }
}

/// Item representing a mapping between a `UserEpoch` and an `IncrementalEpoch`, which
/// is stored in an instance of `InMemoryEpochMapper`. The item can be `Complete` or
/// `Partial`, depending on whether it contains both a `UserEpoch` and an `IncrementalEpoch`
/// or only one of the 2.
/// Partial `EpochMapItem`s will never be stored as entries of `InMemoryEpochMapper`: they will
/// be employed only to implement the lookup methods defined in `EpochMapper` trait, which finds
/// the epoch mapping corresponding to either a given `UserEpoch` or a given `IncrementalEpoch`.
/// In layman terms, since both `UserEpoch`s and `IncrementalEpoch`s are expected to be monotonically
/// increasing in an epoch mapper, the epoch mappings can be easily kept sorted by both `UserEpoch` and
/// `IncrementalEpoch`. Therefore, finding an entry corresponding to a given `UserEpoch` (resp. `IncrementalEpoch`)
/// can be efficienctly done as follow:
/// - Define a Partial `EpochMapItem` wrapping the given `UserEpoch` (resp. `IncrementalEpoch`)
/// - Find the mapping with the given `UserEpoch` (resp. `IncrementalEpoch`) in the sorted set by compare
///   the defined Partial `EpochMapItem` with other entries found in the epoch mapper (which are all Complete);
///   the comparison is done by looking only at their `UserEpoch` (resp. `IncrementalEpoch`) values
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EpochMapItem {
    PartialUser(UserEpoch),
    PartialIncremental(IncrementalEpoch),
    Complete(UserEpoch, IncrementalEpoch),
}

impl EpochMapItem {
    /// Convert an `EpochMapItem` to the wrapped `UserEpoch` and
    /// `IncrementalEpoch`. This method is expected to be called
    /// only for complete `EpochMapItem`s, i.e., ones that wrap
    /// both a `UserEpoch` and an `IncrementalEpoch`;
    /// the method will panic if this assumption is not satisfied
    fn to_epochs(self) -> (UserEpoch, IncrementalEpoch) {
        if let EpochMapItem::Complete(user_epoch, incremental_epoch) = self {
            (user_epoch, incremental_epoch)
        } else {
            panic!("Invalid `EpochMapItem` being unpacked")
        }
    }
}

impl PartialOrd for EpochMapItem {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for EpochMapItem {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Implement the partial order relationship employed to compare
        // `EpochMapItem`s. It is partial since by construction we will never
        // compare 2 Partial `EpochMapItem`s
        match (self, other) {
            (
                EpochMapItem::PartialUser(first_user_epoch),
                EpochMapItem::Complete(second_user_epoch, _),
            ) => first_user_epoch.cmp(second_user_epoch),
            (
                EpochMapItem::PartialIncremental(first_incremental_epoch),
                EpochMapItem::Complete(_, second_incremental_epoch),
            ) => first_incremental_epoch.cmp(second_incremental_epoch),
            (
                EpochMapItem::Complete(first_user_epoch, _),
                EpochMapItem::PartialUser(second_user_epoch),
            ) => first_user_epoch.cmp(second_user_epoch),
            (
                EpochMapItem::Complete(_, first_incremental_epoch),
                EpochMapItem::PartialIncremental(second_incremental_epoch),
            ) => first_incremental_epoch.cmp(second_incremental_epoch),
            (
                EpochMapItem::Complete(first_user_epoch, first_incremental_epoch),
                EpochMapItem::Complete(second_user_epoch, second_incremental_epoch),
            ) => {
                let user_epoch_cmp = first_user_epoch.cmp(second_user_epoch);
                let incremental_epoch_cmp = first_incremental_epoch.cmp(second_incremental_epoch);
                assert_eq!(
                    user_epoch_cmp, incremental_epoch_cmp,
                    "Breaking invariant of `EpochMapper`: both `UserEpoch` and `IncrementalEpoch`
                    must be monotonically increasing"
                );
                user_epoch_cmp
            }
            _ =>
            // all other cases are partial `EpochMapItem`s, which are never compared
            {
                unreachable!()
            }
        }
    }
}

#[derive(Clone, Debug)]
/// Data structure employed both for in-memory implementation of an `EpochMapper`,
/// and as a memory cache for the DB-based `EpochMapper` implementation.
/// The flag `IS_CACHE` is employed to specify whether the data structure is employed
/// as a cache or as a standalone in-memory `EpochMapper`.
/// It basically handles two types of epochs mappings, depending on how the epoch maps
/// are inserted by users:
///
/// - If the `UserEpoch`s being inserted are all incrementals, starting from an
///   initial offset, then an optimized implementation is employed for this conversion
/// - Otherwise, there is a more generic implementation that can handle any monotonically
///   increasing sequence of `UserEpoch`s
///
/// The first implementation is used while the `UserEpoch`s being inserted followed the
/// incremental pattern; as soon as a non-incremental `UserEpoch` is inserted, then the
/// implementation falls back to the more generic generic implementation
pub struct InMemoryEpochMapperGeneric<const IS_CACHE: bool, const MAX_ENTRIES: usize> {
    // Generic implementation to map monotonically increasing `UserEpoch`s to `IncrementalEpoch`s
    generic_map: BTreeSet<EpochMapItem>,
    // Optimized implementation for incremental `UserEpoch`s
    incremental_epochs_map: Option<IncrementalEpochMap>,
}
/// In-memory implementation of `EpochMapper`, which allows to map a
/// `UserEpoch` to an `IncrementalEpoch` used by storages
pub type InMemoryEpochMapper = InMemoryEpochMapperGeneric<false, { usize::MAX }>;
/// In-memory cache of the DB-based implementation of `EpochMapper`
pub(crate) type EpochMapperCache<const MAX_ENTRIES: usize> =
    InMemoryEpochMapperGeneric<true, MAX_ENTRIES>;

#[derive(Clone, Debug)]
/// Data structure employed to map `UserEpoch`s with `IncrementalEpoch`s in case
/// `UserEpoch`s are all sequential. In this case, it is sufficient to simply store:
/// - The initial offset to convert between `UserEpoch`s and `IncrementalEpoch`s
/// - The last inserted `UserEpoch`
struct IncrementalEpochMap {
    offset: UserEpoch,
    last_epoch: UserEpoch,
}

impl<const IS_CACHE: bool, const MAX_ENTRIES: usize>
    InMemoryEpochMapperGeneric<IS_CACHE, MAX_ENTRIES>
{
    pub(crate) fn new_at(initial_epoch: UserEpoch) -> Self {
        // by default, we assume epochs are incremental, so we initialize
        // the optimized epochs map
        Self {
            generic_map: BTreeSet::new(),
            incremental_epochs_map: Some(IncrementalEpochMap {
                offset: initial_epoch,
                last_epoch: initial_epoch,
            }),
        }
    }

    pub(crate) fn initial_epoch(&self) -> UserEpoch {
        match self.incremental_epochs_map {
            Some(IncrementalEpochMap {
                offset: initial_epoch,
                ..
            }) => initial_epoch,
            None => {
                let (initial_epoch, initial_inner_epoch) =
                self.generic_map.iter().next().expect(
                    "Initial epoch is always expected to be inserted at build-time in the storage",
                ).to_epochs();
                assert_eq!(initial_inner_epoch, 0);
                initial_epoch
            }
        }
    }

    pub(crate) fn last_epoch(&self) -> UserEpoch {
        match self.incremental_epochs_map {
            Some(IncrementalEpochMap { last_epoch, .. }) => last_epoch,
            None => {
                self.generic_map
                    .iter()
                    .next_back()
                    .expect(
                        "No epoch found in `InMemoryEpochMapper`, 
                it is assumed there is always at least one epoch",
                    )
                    .to_epochs()
                    .0
            }
        }
    }

    /// Return the maximum number of epoch mapping entries that can be stored in `self`, if any.
    fn max_number_of_entries(&self) -> Option<usize> {
        (IS_CACHE && self.incremental_epochs_map.is_none()).then_some(MAX_ENTRIES)
    }

    fn try_to_user_epoch_inner(&self, epoch: IncrementalEpoch) -> Option<UserEpoch> {
        match self.incremental_epochs_map {
            Some(IncrementalEpochMap {
                offset: initial_epoch,
                last_epoch,
            }) => {
                let user_epoch = epoch + initial_epoch;
                // return `user_epoch` only if it is at most `last_epoch`
                (user_epoch <= last_epoch).then_some(user_epoch)
            }
            None => {
                // To lookup an `IncrementalEpoch` in `self.generic_map`, we build
                // an instance of `EpochMapItem::PartialIncremental` for the
                // `IncrementalEpoch` `epoch`.
                // The partial order relationship defined for `EpochMapItem` allows to
                // efficiently find in the `BTreeSet` the epoch map with `IncrementalEpoch`
                // corresponding to `epoch`, if any
                let epoch_map_item = EpochMapItem::PartialIncremental(epoch);
                self.generic_map
                    .get(&epoch_map_item)
                    .map(|item| item.to_epochs().0)
            }
        }
    }

    /// Add a new epoch mapping for `IncrementalEpoch` `epoch`, assuming that `UserEpoch`s
    /// are also computed incrementally from an initial shift. If there is already a mapping for
    /// `IncrementalEpoch` `epoch`, then this function has no side effects, because it is assumed
    /// that the mapping has already been provided according to another, non-incremental, logic.
    /// This function returns the `UserEpoch` being mapper to `epoch`, in case a new mapping
    /// is actually inserted.
    pub(crate) fn new_incremental_epoch(&mut self, epoch: IncrementalEpoch) -> Option<UserEpoch> {
        // compute last arbitrary epoch having been inserted in the map
        let last_epoch = self.last_epoch();
        // check if `epoch` has already been inserted in the map
        match self.try_to_user_epoch_inner(epoch) {
            Some(matched_epoch) => {
                // `epoch` has already been inserted, only check that
                // `matched_epoch` corresponds to the last inserted `UserEpoch`
                assert_eq!(last_epoch, matched_epoch);
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

    pub(crate) fn rollback_to(&mut self, epoch: UserEpoch) -> Result<(), RyhopeError> {
        // first, check that we are rolling back to a valid epoch
        let last_epoch = self.last_epoch();
        ensure(
            epoch <= last_epoch,
            "cannot rollback to epoch greater than last epoch",
        )?;
        let initial_epoch = self.initial_epoch();
        ensure(
            epoch >= initial_epoch,
            "cannot rollback to epoch smaller than initial epoch",
        )?;
        match self.incremental_epochs_map.as_mut() {
            Some(IncrementalEpochMap { last_epoch, .. }) => {
                *last_epoch = epoch;
            }
            None => {
                // first, check that the epoch we are rolling back to exists
                ensure(
                    self.generic_map.contains(&EpochMapItem::PartialUser(epoch)),
                    format!("Trying to rollback to non-existing epoch {epoch}"),
                )?;
                // now, erase all epochs greater than `epoch`
                while self.generic_map.last().unwrap().to_epochs().0 > epoch {
                    self.generic_map.pop_last();
                }
            }
        }

        Ok(())
    }

    // Move from the optimized implementation for incremental `UserEpoch`s to the generic map
    // implementation. This method is called when a request to add a non-incremental `UserEpoch`
    // is detected
    fn falback_to_generic_map(&mut self) {
        let IncrementalEpochMap {
            offset: initial_epoch,
            last_epoch,
        } = self.incremental_epochs_map.take().unwrap();
        self.generic_map = (initial_epoch..=last_epoch)
            .enumerate()
            .take(self.max_number_of_entries().unwrap_or(
                usize::MAX, // this is practically unbounded
            )) // fill up to the maximum number of entries allowed to be stored, if any
            .map(|(i, epoch)| EpochMapItem::Complete(epoch, i as IncrementalEpoch))
            .collect();
    }

    // Add new mapping `user_epoch -> incremental_epoch` to `self` to the generic map implementation;
    // this method has to be called only when the caller knows that the generic map implementation is
    // used to map `UserEpoch`s to `IncrementalEpoch`s
    fn add_epoch_to_generic_map(
        &mut self,
        user_epoch: UserEpoch,
        incremental_epoch: IncrementalEpoch,
    ) -> Result<(), RyhopeError> {
        // if we are replacing an existing `IncrementalEpoch`, ensure that
        // we remove the old mapping entry
        if let Some(epoch) = self.try_to_user_epoch_inner(incremental_epoch) {
            let epoch_map_item = EpochMapItem::Complete(epoch, incremental_epoch);
            self.generic_map.remove(&epoch_map_item);
        }

        self.generic_map
            .insert(EpochMapItem::Complete(user_epoch, incremental_epoch));

        // check if we need to remove an item since we got to the maximum number of entries allowed
        // to be stored
        if let Some(max_entries) = self.max_number_of_entries() {
            if self.generic_map.len() > max_entries {
                // remove the second item in the mapping (as the first one contains the initial epoch)
                let second_item = *self.generic_map.iter().nth(1).unwrap();
                self.generic_map.remove(&second_item);
            }
        }

        Ok(())
    }

    fn add_epoch(
        &mut self,
        user_epoch: UserEpoch,
        incremental_epoch: IncrementalEpoch,
    ) -> Result<(), RyhopeError> {
        match self.incremental_epochs_map {
            Some(IncrementalEpochMap {
                offset: initial_epoch,
                last_epoch,
            }) => {
                ensure(user_epoch >= initial_epoch,
                    format!("Trying to insert an epoch {user_epoch} smaller than initial epoch {initial_epoch}")
                )?;
                // we need to fallback to the generic map implementation if:
                // - either we are insering a new `user_epoch` which is no longer incremental
                // - or we are updating the last inserted `incremental_epoch` with a bigger `user_epoch`
                let last_incremental_epoch = last_epoch - initial_epoch;
                if user_epoch > last_epoch + 1
                    || (last_incremental_epoch == incremental_epoch && user_epoch > last_epoch)
                {
                    // fallback to generic map
                    self.falback_to_generic_map();
                    self.add_epoch_to_generic_map(user_epoch, incremental_epoch)?;
                } else {
                    // In all other cases, we need to check that
                    // `incremental_epoch == user_epoch - initial_epoch`, to keep the epochs
                    // incremental
                    ensure(user_epoch - initial_epoch == incremental_epoch,
                        format!(
                            "Trying to insert an invalid incremental epoch: expected {}, found {incremental_epoch}",
                            user_epoch - initial_epoch,
                    ))?;
                    // If we are adding a new `user_epoch`, we update `last_epoch`;
                    // otherwise, it's a no-operation
                    if user_epoch == last_epoch + 1 {
                        self.incremental_epochs_map.as_mut().unwrap().last_epoch = user_epoch;
                    }
                }
            }
            None => {
                self.add_epoch_to_generic_map(user_epoch, incremental_epoch)?;
            }
        }

        Ok(())
    }
}

impl<const IS_CACHE: bool, const MAX_ENTRIES: usize> EpochMapper
    for InMemoryEpochMapperGeneric<IS_CACHE, MAX_ENTRIES>
{
    async fn try_to_incremental_epoch(&self, epoch: UserEpoch) -> Option<IncrementalEpoch> {
        match self.incremental_epochs_map {
            Some(IncrementalEpochMap {
                offset: initial_epoch,
                last_epoch,
            }) => (epoch <= last_epoch && epoch >= initial_epoch).then(|| epoch - initial_epoch),
            None => {
                // To lookup an`UserEpoch` in `self.generic_map`, we build
                // an instance of `EpochMapItem::PartialUser` for the
                // `UserEpoch` `epoch`.
                // The partial order relationship defined for `EpochMapItem` allows to
                // efficiently find in the `BTreeSet` the epoch map with `UserEpoch`
                // corresponding to `epoch`, if any
                let epoch_map_item = EpochMapItem::PartialUser(epoch);
                self.generic_map
                    .get(&epoch_map_item)
                    .map(|item| item.to_epochs().1)
            }
        }
    }

    async fn try_to_user_epoch(&self, epoch: IncrementalEpoch) -> Option<UserEpoch> {
        self.try_to_user_epoch_inner(epoch)
    }

    async fn add_epoch_map(
        &mut self,
        user_epoch: UserEpoch,
        incremental_epoch: IncrementalEpoch,
    ) -> Result<(), RyhopeError> {
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
    /// Mapper between used-defined epochs and internal incremental epochs
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
    ) -> Result<Self, RyhopeError> {
        match init_settings {
            InitSettings::MustExist => unimplemented!(),
            InitSettings::MustNotExist(tree_state) | InitSettings::Reset(tree_state) => {
                Ok(Self::new_with_mapper(tree_state, storage_settings))
            }
            InitSettings::MustNotExistAt(tree_state, initial_epoch)
            | InitSettings::ResetAt(tree_state, initial_epoch) => {
                // check that initial_epoch is in epoch_mapper
                ensure(
                    storage_settings.read_access_ref().await.initial_epoch() == initial_epoch,
                    format!("Initial epoch {initial_epoch} not found in the epoch mapper provided as input")
                )?;
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
            .apply_fn(|mapper| mapper.rollback_to(epoch))
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
