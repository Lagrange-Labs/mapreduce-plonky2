use anyhow::*;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::hash::Hash;
use std::{collections::HashMap, fmt::Debug};

use crate::tree::TreeTopology;
use crate::{Epoch, InitSettings};

use super::{
    EpochKvStorage, EpochStorage, FromSettings, PayloadStorage, RoEpochKvStorage,
    TransactionalStorage, TreeStorage,
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
    /// The initial epoch
    epoch_offset: Epoch,
}
impl<T> VersionedStorage<T>
where
    T: Debug + Send + Sync + Clone + Serialize + for<'a> Deserialize<'a>,
{
    fn new(initial_state: T) -> Self {
        Self::new_at(initial_state, 0)
    }

    fn new_at(initial_state: T, epoch: Epoch) -> Self {
        Self {
            in_tx: false,
            ts: vec![Some(initial_state)],
            epoch_offset: epoch,
        }
    }
}

impl<T> TransactionalStorage for VersionedStorage<T>
where
    T: Debug + Send + Sync + Clone + Serialize + for<'a> Deserialize<'a>,
{
    fn start_transaction(&mut self) -> Result<()> {
        ensure!(!self.in_tx, "already in a trnsaction");
        self.in_tx = true;
        if let Some(latest) = self.ts.last().cloned() {
            self.ts.push(latest);
        } else {
            self.ts.push(None);
        }
        Ok(())
    }

    async fn commit_transaction(&mut self) -> Result<()> {
        ensure!(self.in_tx, "not in a transaction");
        self.in_tx = false;
        Ok(())
    }
}

impl<T> EpochStorage<T> for VersionedStorage<T>
where
    T: Debug + Send + Sync + Clone + Serialize + for<'a> Deserialize<'a>,
{
    fn current_epoch(&self) -> Epoch {
        let inner_epoch: Epoch = (self.ts.len() - 1).try_into().unwrap();
        inner_epoch + self.epoch_offset
    }

    async fn fetch_at(&self, epoch: Epoch) -> T {
        let epoch = epoch - self.epoch_offset;
        assert!(epoch >= 0);
        self.ts[epoch as usize].clone().unwrap()
    }

    async fn store(&mut self, t: T) {
        assert!(self.in_tx);
        let latest = self.ts.len() - 1;
        self.ts[latest] = Some(t);
    }

    async fn rollback_to(&mut self, epoch: Epoch) -> Result<()> {
        ensure!(
            epoch >= self.epoch_offset,
            "unable to rollback before epoch {}",
            self.epoch_offset
        );

        let epoch = epoch - self.epoch_offset;
        ensure!(
            epoch <= self.current_epoch(),
            "unable to rollback to epoch `{}` more recent than current epoch `{}`",
            epoch,
            self.current_epoch()
        );

        self.ts.resize((epoch + 1).try_into().unwrap(), None);
        Ok(())
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
pub struct VersionedKvStorage<K: Debug, V: Debug> {
    /// In the diffs, the value carried by the insertion/modification of a key
    /// is represented as a Some, whereas a deletion is represented by
    /// associating k to None.
    mem: Vec<HashMap<K, Option<V>>>,
    /// The initial epoch
    epoch_offset: Epoch,
}
impl<K: Debug, V: Debug> VersionedKvStorage<K, V> {
    pub fn new() -> Self {
        Self::new_at(0)
    }

    pub fn new_at(initial_epoch: Epoch) -> Self {
        VersionedKvStorage {
            mem: vec![Default::default()],
            epoch_offset: initial_epoch,
        }
    }

    pub fn new_epoch(&mut self) {
        self.mem.push(Default::default());
    }
}

impl<K, V> RoEpochKvStorage<K, V> for VersionedKvStorage<K, V>
where
    K: Hash + Eq + Clone + Debug + Send + Sync,
    V: Clone + Debug + Send + Sync,
{
    fn initial_epoch(&self) -> Epoch {
        self.epoch_offset
    }

    fn current_epoch(&self) -> Epoch {
        // There is a 1-1 mapping between the epoch and the position in the list of
        // diffs; epoch 0 being the initial empty state.
        let inner_epoch: Epoch = (self.mem.len() - 1) as Epoch;
        inner_epoch + self.epoch_offset
    }

    async fn try_fetch_at(&self, k: &K, epoch: Epoch) -> Option<V> {
        assert!(epoch >= self.epoch_offset);
        let epoch = epoch - self.epoch_offset;
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

    // Expensive, but only used in test context.
    async fn size(&self) -> usize {
        let all_keys = self
            .mem
            .iter()
            .flat_map(|epoch| epoch.keys())
            .collect::<HashSet<_>>();

        let mut count = 0;
        for k in all_keys {
            if self.try_fetch(k).await.is_some() {
                count += 1;
            }
        }
        count
    }

    async fn size_at(&self, epoch: Epoch) -> usize {
        assert!(epoch >= self.epoch_offset);
        let epoch = epoch - self.epoch_offset;
        let mut keys = HashSet::new();

        for i in 0..=epoch as usize {
            keys.extend(self.mem[i].keys())
        }

        keys.len()
    }

    async fn keys_at(&self, epoch: Epoch) -> Vec<K> {
        assert!(epoch >= self.epoch_offset);
        let epoch = epoch - self.epoch_offset;
        let mut keys = HashSet::new();

        for i in 0..=epoch as usize {
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

    async fn pairs_at(&self, epoch: Epoch) -> Result<HashMap<K, V>> {
        assert!(epoch >= self.epoch_offset);
        let mut pairs = HashMap::new();
        for i in 0..=epoch as usize {
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
    async fn remove(&mut self, k: K) -> Result<()> {
        ensure!(self.try_fetch(&k).await.is_some(), "key not found");
        self.mem.last_mut().unwrap().insert(k, None);
        Ok(())
    }

    async fn update(&mut self, k: K, new_value: V) -> Result<()> {
        ensure!(self.try_fetch(&k).await.is_some(), "key not found");
        self.mem.last_mut().unwrap().insert(k, Some(new_value));
        Ok(())
    }

    async fn store(&mut self, k: K, value: V) -> Result<()> {
        self.mem.last_mut().unwrap().insert(k, Some(value));
        Ok(())
    }

    async fn rollback_to(&mut self, epoch: Epoch) -> Result<()> {
        ensure!(
            epoch >= self.epoch_offset,
            "unable to rollback before epoch {}",
            self.epoch_offset
        );
        let epoch = epoch - self.epoch_offset;
        ensure!(
            epoch <= self.current_epoch(),
            "unable to rollback to epoch `{}` more recent than current epoch `{}`",
            epoch,
            self.current_epoch()
        );

        self.mem.truncate((epoch + 1).try_into().unwrap());

        Ok(())
    }
}

/// A RAM-backed storage for tree data.
pub struct InMemory<T: TreeTopology, V: Debug + Sync> {
    /// Storage for tree state.
    state: VersionedStorage<<T as TreeTopology>::State>,
    /// Storage for topological data.
    nodes: VersionedKvStorage<<T as TreeTopology>::Key, <T as TreeTopology>::Node>,
    /// Storage for node-associated data.
    data: VersionedKvStorage<<T as TreeTopology>::Key, V>,
    /// Whether a transaction is currently opened.
    in_tx: bool,
}
impl<T: TreeTopology, V: Debug + Sync> InMemory<T, V> {
    pub fn new(tree_state: T::State) -> Self {
        Self::new_at(tree_state, 0)
    }

    pub fn new_at(tree_state: T::State, initial_epoch: Epoch) -> Self {
        Self {
            state: VersionedStorage::new_at(tree_state, initial_epoch),
            nodes: VersionedKvStorage::new_at(initial_epoch),
            data: VersionedKvStorage::new_at(initial_epoch),
            in_tx: false,
        }
    }
}

impl<T: TreeTopology, V: Debug + Sync> FromSettings<T::State> for InMemory<T, V> {
    type Settings = ();

    async fn from_settings(
        init_settings: InitSettings<T::State>,
        _storage_settings: Self::Settings,
    ) -> Result<Self> {
        match init_settings {
            InitSettings::MustExist => unimplemented!(),
            InitSettings::MustNotExist(tree_state) | InitSettings::Reset(tree_state) => {
                Ok(Self::new(tree_state))
            }
            InitSettings::MustNotExistAt(tree_state, initial_epoch)
            | InitSettings::ResetAt(tree_state, initial_epoch) => {
                Ok(Self::new_at(tree_state, initial_epoch))
            }
        }
    }
}

impl<T, V> TreeStorage<T> for InMemory<T, V>
where
    T: TreeTopology,
    T::Node: Clone,
    V: Clone + Debug + Sync + Send,
{
    type StateStorage = VersionedStorage<T::State>;
    type NodeStorage = VersionedKvStorage<T::Key, T::Node>;

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

    async fn born_at(&self, epoch: Epoch) -> Vec<T::Key> {
        assert!(epoch >= self.nodes.epoch_offset);
        self.nodes.mem[(epoch - self.nodes.epoch_offset) as usize]
            .keys()
            .cloned()
            .collect()
    }

    async fn rollback_to(&mut self, epoch: Epoch) -> Result<()> {
        println!("Rolling back to {epoch}");
        self.state.rollback_to(epoch).await?;
        self.nodes.rollback_to(epoch).await?;
        self.data.rollback_to(epoch).await?;

        assert_eq!(self.state.current_epoch(), self.nodes.current_epoch());
        assert_eq!(self.state.current_epoch(), self.data.current_epoch());

        Ok(())
    }
}

impl<T, V> PayloadStorage<<T as TreeTopology>::Key, V> for InMemory<T, V>
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

impl<T, V> TransactionalStorage for InMemory<T, V>
where
    T: TreeTopology,
    V: Clone + Debug + Send + Sync,
{
    fn start_transaction(&mut self) -> Result<()> {
        ensure!(!self.in_tx, "already in a transaction");
        self.state.start_transaction()?;
        self.data.new_epoch();
        self.nodes.new_epoch();
        self.in_tx = true;
        Ok(())
    }

    async fn commit_transaction(&mut self) -> Result<()> {
        ensure!(self.in_tx, "not in a transaction");
        self.state.commit_transaction().await?;
        self.in_tx = false;
        Ok(())
    }
}
