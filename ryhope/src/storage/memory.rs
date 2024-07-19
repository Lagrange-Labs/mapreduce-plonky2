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
pub struct VersionedStorage<T: Debug + Sync + Clone + Serialize + for<'a> Deserialize<'a>> {
    /// Whether a transaction has been started and not yet commited.
    in_tx: bool,
    /// The successive states of the persisted value.
    ts: Vec<Option<T>>,
}
impl<T: Debug + Sync + Clone + Serialize + for<'a> Deserialize<'a>> VersionedStorage<T> {
    fn new(initial_state: T) -> Self {
        Self {
            in_tx: false,
            ts: vec![Some(initial_state)],
        }
    }
}
impl<T: Debug + Sync + Clone + Serialize + for<'a> Deserialize<'a>> TransactionalStorage
    for VersionedStorage<T>
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

    fn commit_transaction(&mut self) -> Result<()> {
        ensure!(self.in_tx, "not in a transaction");
        self.in_tx = false;
        Ok(())
    }
}
impl<T: Debug + Sync + Clone + Serialize + for<'a> Deserialize<'a>> EpochStorage<T>
    for VersionedStorage<T>
{
    fn current_epoch(&self) -> Epoch {
        (self.ts.len() - 1).try_into().unwrap()
    }

    fn fetch_at(&self, epoch: Epoch) -> T {
        self.ts[epoch as usize].clone().unwrap()
    }

    fn store(&mut self, t: T) {
        assert!(self.in_tx);
        let latest = self.ts.len() - 1;
        self.ts[latest] = Some(t);
    }

    fn rollback_to(&mut self, epoch: Epoch) -> Result<()> {
        ensure!(epoch >= 0, "unable to rollback before epoch 0");
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
}
impl<K: Debug, V: Debug> VersionedKvStorage<K, V> {
    pub fn new() -> Self {
        VersionedKvStorage {
            mem: vec![Default::default()],
        }
    }

    pub fn new_epoch(&mut self) {
        self.mem.push(Default::default());
    }
}

impl<K: Hash + Eq + Clone + Debug, V: Clone + Debug> RoEpochKvStorage<K, V>
    for VersionedKvStorage<K, V>
{
    fn current_epoch(&self) -> Epoch {
        // There is a 1-1 mapping between the epoch and the position in the list of
        // diffs; epoch 0 being the initial empty state.
        (self.mem.len() - 1) as Epoch
    }

    fn try_fetch_at(&self, k: &K, epoch: Epoch) -> Option<V> {
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
    fn size(&self) -> usize {
        let all_keys = self
            .mem
            .iter()
            .flat_map(|epoch| epoch.keys())
            .collect::<HashSet<_>>();

        all_keys.iter().filter_map(|k| self.try_fetch(k)).count()
    }
}

impl<K: Hash + Eq + Clone + Debug, V: Clone + Debug> EpochKvStorage<K, V>
    for VersionedKvStorage<K, V>
{
    fn remove(&mut self, k: K) -> Result<()> {
        ensure!(self.try_fetch(&k).is_some(), "key not found");
        self.mem.last_mut().unwrap().insert(k, None);
        Ok(())
    }

    fn update(&mut self, k: K, new_value: V) -> Result<()> {
        ensure!(self.try_fetch(&k).is_some(), "key not found");
        self.mem.last_mut().unwrap().insert(k, Some(new_value));
        Ok(())
    }

    fn store(&mut self, k: K, value: V) -> Result<()> {
        self.mem.last_mut().unwrap().insert(k, Some(value));
        Ok(())
    }

    fn rollback_to(&mut self, epoch: Epoch) -> Result<()> {
        ensure!(epoch >= 0, "unable to rollback before epoch 0");
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
pub struct InMemory<T: TreeTopology, V: Debug> {
    /// Storage for tree state.
    state: VersionedStorage<<T as TreeTopology>::State>,
    /// Storage for topological data.
    nodes: VersionedKvStorage<<T as TreeTopology>::Key, <T as TreeTopology>::Node>,
    /// Storage for node-associated data.
    data: VersionedKvStorage<<T as TreeTopology>::Key, V>,
    /// Whether a transaction is currently opened.
    in_tx: bool,
}
impl<T: TreeTopology, V: Debug> InMemory<T, V> {
    pub fn new(tree_state: T::State) -> Self {
        Self {
            state: VersionedStorage::new(tree_state),
            nodes: VersionedKvStorage::new(),
            data: VersionedKvStorage::new(),
            in_tx: false,
        }
    }
}

impl<T: TreeTopology, V: Debug> FromSettings<T::State> for InMemory<T, V> {
    type Settings = ();

    fn from_settings(
        init_settings: InitSettings<T::State>,
        _storage_settings: Self::Settings,
    ) -> Result<Self> {
        match init_settings {
            InitSettings::MustExist => unimplemented!(),
            InitSettings::MustNotExist(tree_state) | InitSettings::Reset(tree_state) => {
                Ok(Self::new(tree_state))
            }
        }
    }
}

impl<T: TreeTopology, V: Clone + Debug> TreeStorage<T> for InMemory<T, V>
where
    T::Node: Clone,
{
    type StateStorage = VersionedStorage<<T as TreeTopology>::State>;
    type NodeStorage = VersionedKvStorage<<T as TreeTopology>::Key, <T as TreeTopology>::Node>;

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

    fn born_at(&self, epoch: Epoch) -> Vec<T::Key> {
        self.nodes.mem[epoch as usize].keys().cloned().collect()
    }

    fn rollback_to(&mut self, epoch: Epoch) -> Result<()> {
        println!("Rolling back to {epoch}");
        self.state.rollback_to(epoch)?;
        self.nodes.rollback_to(epoch)?;
        self.data.rollback_to(epoch)?;

        assert_eq!(self.state.current_epoch(), self.nodes.current_epoch());
        assert_eq!(self.state.current_epoch(), self.data.current_epoch());

        Ok(())
    }
}

impl<T: TreeTopology, V: Clone + Debug> PayloadStorage<<T as TreeTopology>::Key, V>
    for InMemory<T, V>
where
    <T as TreeTopology>::Key: Clone,
{
    type DataStorage = VersionedKvStorage<<T as TreeTopology>::Key, V>;

    fn data(&self) -> &Self::DataStorage {
        &self.data
    }

    fn data_mut(&mut self) -> &mut Self::DataStorage {
        &mut self.data
    }
}

impl<T: TreeTopology, V: Clone + Debug> TransactionalStorage for InMemory<T, V> {
    fn start_transaction(&mut self) -> Result<()> {
        ensure!(!self.in_tx, "already in a transaction");
        self.state.start_transaction()?;
        self.data.new_epoch();
        self.nodes.new_epoch();
        self.in_tx = true;
        Ok(())
    }

    fn commit_transaction(&mut self) -> Result<()> {
        ensure!(self.in_tx, "not in a transaction");
        self.state.commit_transaction()?;
        self.in_tx = false;
        Ok(())
    }
}
