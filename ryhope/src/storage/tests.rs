use std::collections::HashSet;

use crate::{
    storage::{
        memory::InMemory,
        pgsql::{PgsqlStorage, SqlStorageSettings},
        EpochKvStorage, PayloadStorage, RoEpochKvStorage, TreeStorage,
    },
    tree::{
        sbbst,
        scapegoat::{self, Alpha},
        PrintableTree, TreeTopology,
    },
    InitSettings, MerkleTreeKvDb, NodePayload,
};
use anyhow::*;
use itertools::Itertools;
use rand::{Rng, SeedableRng};
use serde::{Deserialize, Serialize};

use super::TreeTransactionalStorage;

fn db_url() -> String {
    std::env::var("DB_URL").unwrap_or("host=localhost dbname=storage".to_string())
}

impl NodePayload for usize {}
impl NodePayload for String {}
impl NodePayload for i64 {}

#[test]
fn storage_in_memory() -> Result<()> {
    type K = String;
    type V = usize;

    type TestTree = scapegoat::Tree<K>;
    type Storage = InMemory<TestTree, V>;

    let mut s = MerkleTreeKvDb::<TestTree, V, Storage>::new(
        InitSettings::Reset(scapegoat::Tree::empty(Alpha::new(0.8))),
        (),
    )?;
    with_storage(&mut s)?;

    for i in 1..=6 {
        println!("\nEpoch = {i}");
        let ss = s.view_at(i);
        s.tree().print(&ss);
        s.diff_at(i).unwrap().print();

        match i {
            1 => {
                assert!(ss.nodes().try_fetch(&"les".to_string()).is_some())
            }
            2 => {
                assert!(ss.nodes().try_fetch(&"les".to_string()).is_some())
            }
            3 => {
                assert!(ss.nodes().try_fetch(&"les".to_string()).is_none())
            }
            4 => {}
            5 => {
                assert!(ss.nodes().try_fetch(&"automne".to_string()).is_some())
            }
            6 => {
                assert!(ss.nodes().try_fetch(&"automne".to_string()).is_none())
            }
            _ => {}
        }
    }

    Ok(())
}

#[test]
fn storage_in_pgsql() -> Result<()> {
    type K = String;
    type V = usize;

    type TestTree = scapegoat::Tree<K>;
    type Storage = PgsqlStorage<TestTree, V>;

    let mut s = MerkleTreeKvDb::<TestTree, V, Storage>::new(
        InitSettings::Reset(scapegoat::Tree::empty(Alpha::new(0.8))),
        SqlStorageSettings {
            db_url: db_url(),
            table: "simple".to_string(),
        },
    )?;
    with_storage(&mut s)?;
    println!("Old one");
    s.print_tree();

    let s2 = MerkleTreeKvDb::<TestTree, V, Storage>::new(
        InitSettings::MustExist,
        SqlStorageSettings {
            db_url: db_url(),
            table: "simple".to_string(),
        },
    )?;
    println!("New one");
    s2.print_tree();

    assert_eq!(s2.root_data(), s.root_data());
    assert_eq!(s.tree().size(&s2.storage), s2.tree().size(&s2.storage));

    for i in 1..=6 {
        println!("\nEpoch = {i}");
        let ss = s.view_at(i);
        s.tree().print(&ss);
        s.diff_at(i).unwrap().print();

        match i {
            1 => {
                assert!(ss.nodes().try_fetch(&"les".to_string()).is_some())
            }
            2 => {
                assert!(ss.nodes().try_fetch(&"les".to_string()).is_some())
            }
            3 => {
                assert!(ss.nodes().try_fetch(&"les".to_string()).is_none())
            }
            4 => {}
            5 => {
                assert!(ss.nodes().try_fetch(&"automne".to_string()).is_some())
            }
            6 => {
                assert!(ss.nodes().try_fetch(&"automne".to_string()).is_none())
            }
            _ => {}
        }
    }

    Ok(())
}

/// A simple payload carrying a value, and aggregating the min and max of values
/// bore by descendants.
#[derive(Debug, Clone, Serialize, Deserialize)]
// value, min, max
struct MinMaxi64(i64, i64, i64);
impl From<i64> for MinMaxi64 {
    fn from(x: i64) -> Self {
        MinMaxi64(x, x, x)
    }
}
impl From<usize> for MinMaxi64 {
    fn from(x: usize) -> Self {
        let x: i64 = x.try_into().unwrap();
        MinMaxi64(x, x, x)
    }
}
impl NodePayload for MinMaxi64 {
    fn aggregate<'a, I: Iterator<Item = Option<Self>>>(&mut self, children: I) {
        let min_max = children
            .flatten()
            .fold((self.0, self.0), |ax, c| (ax.0.min(c.1), ax.1.max(c.2)));

        self.1 = min_max.0;
        self.2 = min_max.1;
    }
}

/// A simple payload carrying a string and accumulating its hash concatenated
/// with the previous level ones.
#[derive(Serialize, Deserialize, Clone, Debug)]
struct ShaizedString {
    s: String,
    h: String,
}
impl NodePayload for ShaizedString {
    fn aggregate<'a, I: Iterator<Item = Option<Self>>>(&mut self, children: I) {
        let children_hashes = children.into_iter().collect::<Vec<_>>();
        self.h = if children_hashes.iter().all(Option::is_none) {
            sha256::digest(&self.s)
        } else {
            sha256::digest(
                children_hashes
                    .into_iter()
                    .map(|c| c.map(|c| c.h))
                    .map(|h| h.unwrap_or_else(|| sha256::digest("")))
                    .chain(std::iter::once(sha256::digest(&self.s)))
                    .join(""),
            )
        };
    }
}
impl From<String> for ShaizedString {
    fn from(s: String) -> Self {
        Self { s, h: "".into() }
    }
}
impl From<&str> for ShaizedString {
    fn from(s: &str) -> Self {
        Self {
            s: s.to_owned(),
            h: "".into(),
        }
    }
}

#[test]
fn sbbst_storage_in_pgsql() -> Result<()> {
    type V = ShaizedString;
    type TestTree = sbbst::Tree;
    type SqlStorage = PgsqlStorage<TestTree, V>;
    type RamStorage = InMemory<TestTree, V>;

    let mut s_psql = MerkleTreeKvDb::<TestTree, V, SqlStorage>::new(
        InitSettings::Reset(sbbst::Tree::empty()),
        SqlStorageSettings {
            db_url: db_url(),
            table: "simple_sbbst".to_string(),
        },
    )?;

    s_psql.in_transaction(|t| {
        for k in 1..10 {
            t.store(k, format!("Node-{k}").into())?;
        }
        Ok(())
    })?;

    s_psql.in_transaction(|t| {
        t.update(3, "coucou".into())?;
        t.update(8, "cava".into())?;
        t.update(2, "bien".into())
    })?;

    println!("Old one");
    s_psql.print_tree();

    let s2 = MerkleTreeKvDb::<TestTree, V, SqlStorage>::new(
        InitSettings::MustExist,
        SqlStorageSettings {
            db_url: db_url(),
            table: "simple_sbbst".to_string(),
        },
    )?;
    println!("New one");
    s2.print_tree();
    assert_eq!(s_psql.root_data().unwrap().h, s2.root_data().unwrap().h);

    for i in 1..=2 {
        println!("\nEpoch = {i}");
        let ss = s2.view_at(i);
        s2.tree().print(&ss);
        s_psql.diff_at(i).unwrap().print();
    }

    let mut s_ram = MerkleTreeKvDb::<TestTree, V, RamStorage>::new(
        InitSettings::Reset(sbbst::Tree::empty()),
        (),
    )?;
    s_ram.in_transaction(|t| {
        for k in 1..10 {
            t.store(k, format!("Node-{k}").into())?;
        }
        Ok(())
    })?;
    s_ram.in_transaction(|t| {
        t.update(3, "coucou".into())?;
        t.update(8, "cava".into())?;
        t.update(2, "bien".into())
    })?;
    s_ram.print_tree();

    assert_eq!(s2.root_data().unwrap().h, s_ram.root_data().unwrap().h);

    Ok(())
}

fn with_storage<S: TreeTransactionalStorage<String, usize>>(s: &mut S) -> Result<()> {
    s.in_transaction(|t| {
        for k in "les sanglots longs des violons de automne blessent mon coeur langueur monotone"
            .split_whitespace()
        {
            t.store(k.to_string(), k.len())?;
        }
        Ok(())
    })?;

    s.in_transaction(|t| t.remove("blessent".to_string()))?;

    s.in_transaction(|t| t.remove("les".to_string()))?;

    s.in_transaction(|t| t.remove("sanglots".to_string()))?;

    s.in_transaction(|t| {
        t.update("longs".to_string(), 95000)?;
        t.update("des".to_string(), 36000)?;
        t.remove("des".to_string())
    })?;

    s.in_transaction(|t| {
        t.remove("automne".to_string())?;
        t.remove("mon".to_string())?;
        Ok(())
    })?;

    Ok(())
}

#[test]
fn hashes() -> Result<()> {
    type K = i64;
    type V = ShaizedString;

    type Tree = scapegoat::Tree<K>;
    type Storage = InMemory<Tree, V>;

    let mut s = MerkleTreeKvDb::<Tree, V, Storage>::new(
        InitSettings::Reset(scapegoat::Tree::empty(Alpha::fully_balanced())),
        (),
    )?;

    s.in_transaction(|s| {
        s.store(2, "cava".into())?;
        s.store(1, "coucou".into())?;
        s.store(3, "bien".into())
    })?;

    assert_eq!(s.storage.data().fetch(&1).h, sha256::digest("coucou"));
    assert_eq!(
        s.storage.data().fetch(&2).h,
        sha256::digest(
            sha256::digest("coucou") + &sha256::digest("bien") + &sha256::digest("cava")
        )
    );
    assert_eq!(s.storage.data().fetch(&3).h, sha256::digest("bien"));
    Ok(())
}

#[test]
fn sbbst_requires_sequential_keys() -> Result<()> {
    type Tree = sbbst::Tree;
    type V = i64;

    type Storage = InMemory<Tree, V>;

    let mut s = MerkleTreeKvDb::<Tree, V, Storage>::new(
        InitSettings::Reset(sbbst::Tree::with_shift_and_capacity(10, 0)),
        (),
    )?;

    s.start_transaction()?;
    assert!(s.store(2, 2).is_err());
    assert!(s.store(12, 2).is_err());
    assert!(s.store(11, 2).is_ok());
    assert!(s.store(12, 2).is_ok());
    s.commit_transaction()?;

    Ok(())
}

#[test]
fn thousand_rows() -> Result<()> {
    type K = i64;
    type V = usize;
    type Tree = scapegoat::Tree<K>;
    type Storage = PgsqlStorage<Tree, V>;

    let mut s = MerkleTreeKvDb::<Tree, V, Storage>::new(
        InitSettings::Reset(scapegoat::Tree::empty(Alpha::fully_balanced())),
        SqlStorageSettings {
            db_url: db_url(),
            table: "thousand".to_string(),
        },
    )?;

    let mut rng = rand::rngs::StdRng::seed_from_u64(0xc0c0);

    s.in_transaction(|s| {
        for i in 0..1000 {
            s.store(i, (10 * i).try_into().unwrap())?;
        }
        Ok(())
    })?;
    assert_eq!(s.size(), 1000);

    let to_remove = (0..100)
        .map(|_| rng.gen_range(1..=1000))
        .collect::<HashSet<_>>();

    let mt = s.in_transaction(|s| {
        for k in to_remove.iter() {
            s.remove(*k)?;
        }
        Ok(())
    })?;
    mt.print();

    assert_eq!(s.size(), 1000 - to_remove.len());
    for k in to_remove {
        assert!(s.try_fetch(&k).is_none());
    }

    println!("{}", rng.gen::<i32>());

    Ok(())
}

#[test]
fn aggregation_memory() -> Result<()> {
    type Tree = sbbst::Tree;
    type V = MinMaxi64;

    type Storage = InMemory<Tree, V>;

    let mut s =
        MerkleTreeKvDb::<Tree, V, Storage>::new(InitSettings::Reset(sbbst::Tree::empty()), ())?;

    s.in_transaction(|s| {
        for i in 0..30 {
            s.store(
                i + 1,
                MinMaxi64((i + 1).try_into().unwrap(), i as i64, i as i64),
            )?;
        }
        Ok(())
    })?;

    let root_payload = s.fetch(&s.tree().root(&s.storage).unwrap());
    assert_eq!(root_payload.1, 1);
    assert_eq!(root_payload.2, 30);
    Ok(())
}

#[test]
fn aggregation_pgsql() -> Result<()> {
    type Tree = sbbst::Tree;
    type V = MinMaxi64;

    type Storage = PgsqlStorage<Tree, V>;
    let mut s = MerkleTreeKvDb::<Tree, V, Storage>::new(
        InitSettings::Reset(Tree::empty()),
        SqlStorageSettings {
            db_url: db_url(),
            table: "agg".to_string(),
        },
    )?;

    s.in_transaction(|s| {
        for i in 0..30 {
            s.store(
                i + 1,
                MinMaxi64((i + 1).try_into().unwrap(), i as i64, i as i64),
            )?;
        }
        Ok(())
    })?;

    let root_payload = s.fetch(&s.tree().root(&s.storage).unwrap());
    assert_eq!(root_payload.1, 1);
    assert_eq!(root_payload.2, 30);
    Ok(())
}

fn test_rollback<S: EpochKvStorage<i64, MinMaxi64> + TreeTransactionalStorage<i64, MinMaxi64>>(
    s: &mut S,
) {
    for i in 0..3 {
        s.in_transaction(|s| {
            s.store(2 * i, (2 * i).into())?;
            s.store(2 * i + 1, (2 * i + 1).into())?;
            Ok(())
        })
        .unwrap();
    }

    assert_eq!(s.current_epoch(), 3);
    assert_eq!(s.size(), 6);
    for i in 0..=5 {
        assert!(s.contains(&i.into()));
    }

    // Rollback twice to reach epoch 1
    s.rollback_to(1).expect("failed to rollback to 1");
    assert_eq!(s.current_epoch(), 1);
    assert_eq!(s.size(), 2);
    for i in 0..=5 {
        if i <= 1 {
            assert!(s.contains(&i.into()));
        } else {
            assert!(!s.contains(&i.into()));
        }
    }

    // rollback once to reach to epoch 0
    s.rollback().unwrap();
    assert_eq!(s.current_epoch(), 0);
    assert_eq!(s.size(), 0);
    for i in 0..=5 {
        assert!(!s.contains(&i.into()));
    }

    // Can not rollback before epoch 0
    assert!(s.rollback().is_err());
}

#[test]
fn rollback_memory() {
    type K = i64;
    type V = MinMaxi64;
    type Tree = scapegoat::Tree<K>;

    type Storage = InMemory<Tree, V>;
    let mut s = MerkleTreeKvDb::<Tree, V, Storage>::new(
        InitSettings::Reset(Tree::empty(Alpha::new(0.7))),
        (),
    )
    .expect("unable to initialize tree");

    test_rollback(&mut s);
}

#[test]
fn rollback_psql() {
    type K = i64;
    type V = MinMaxi64;
    type Tree = scapegoat::Tree<K>;

    type Storage = PgsqlStorage<Tree, V>;
    let mut s = MerkleTreeKvDb::<Tree, V, Storage>::new(
        InitSettings::Reset(Tree::empty(Alpha::new(0.7))),
        SqlStorageSettings {
            db_url: db_url(),
            table: "rollback".to_string(),
        },
    )
    .expect("unable to initialize tree");

    test_rollback(&mut s);
}
