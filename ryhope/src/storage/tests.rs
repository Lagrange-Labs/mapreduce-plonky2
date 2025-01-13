use anyhow::*;
use bb8_postgres::PostgresConnectionManager;
use futures::FutureExt;
use itertools::Itertools;
use rand::{Rng, SeedableRng};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use tokio_postgres::NoTls;

pub type DBPool = bb8::Pool<PostgresConnectionManager<NoTls>>;

use crate::{
    storage::{
        memory::InMemory,
        pgsql::{PgsqlStorage, SqlServerConnection, SqlStorageSettings},
        EpochKvStorage, EpochMapper, PayloadStorage, RoEpochKvStorage, SqlTreeTransactionalStorage,
        TreeStorage,
    },
    tree::{
        sbbst,
        scapegoat::{self, Alpha},
        PrintableTree, TreeTopology,
    },
    InitSettings, MerkleTreeKvDb, NodePayload, UserEpoch, EPOCH, KEY, VALID_FROM, VALID_UNTIL,
};

use super::TreeTransactionalStorage;

fn db_url() -> String {
    std::env::var("DB_URL").unwrap_or("host=localhost dbname=storage".to_string())
}

impl NodePayload for usize {}
impl NodePayload for String {}
impl NodePayload for i64 {}

async fn _storage_in_memory(initial_epoch: UserEpoch) -> Result<()> {
    type K = String;
    type V = usize;

    type TestTree = scapegoat::Tree<K>;
    type Storage = InMemory<TestTree, V, false>;

    let mut s = MerkleTreeKvDb::<TestTree, V, Storage>::new(
        InitSettings::ResetAt(scapegoat::Tree::empty(Alpha::new(0.8)), initial_epoch),
        (),
    )
    .await?;

    with_storage(&mut s).await?;

    for i in initial_epoch + 1..initial_epoch + 6 {
        println!("\nEpoch = {i}");
        let ss = s.view_at(i);
        s.tree().print(&ss).await;
        s.diff_at(i).await?.unwrap().print();

        match i - initial_epoch {
            1 => {
                assert!(ss.nodes().try_fetch(&"les".to_string()).await?.is_some())
            }
            2 => {
                assert!(ss.nodes().try_fetch(&"les".to_string()).await?.is_some())
            }
            3 => {
                assert!(ss.nodes().try_fetch(&"les".to_string()).await?.is_none())
            }
            4 => {}
            5 => {
                assert!(ss
                    .nodes()
                    .try_fetch(&"automne".to_string())
                    .await?
                    .is_some())
            }
            6 => {
                assert!(ss
                    .nodes()
                    .try_fetch(&"automne".to_string())
                    .await?
                    .is_none())
            }
            _ => {}
        }
    }

    Ok(())
}

#[tokio::test]
async fn storage_in_memory() -> Result<()> {
    _storage_in_memory(0).await
}

#[tokio::test]
async fn shifted_storage_in_memory() -> Result<()> {
    _storage_in_memory(388).await
}

async fn _storage_in_pgsql(initial_epoch: UserEpoch) -> Result<()> {
    type K = String;
    type V = usize;

    type TestTree = scapegoat::Tree<K>;
    type Storage = PgsqlStorage<TestTree, V, false>;
    let table = format!("simple_{}", initial_epoch);

    let mut s = MerkleTreeKvDb::<TestTree, V, Storage>::new(
        InitSettings::ResetAt(scapegoat::Tree::empty(Alpha::new(0.8)), initial_epoch),
        SqlStorageSettings {
            source: SqlServerConnection::NewConnection(db_url()),
            table: table.clone(),
            external_mapper: None,
        },
    )
    .await?;
    with_storage(&mut s).await?;
    println!("Old one");
    s.print_tree().await;

    let s2 = MerkleTreeKvDb::<TestTree, V, Storage>::new(
        InitSettings::MustExist,
        SqlStorageSettings {
            source: SqlServerConnection::NewConnection(db_url()),
            table,
            external_mapper: None,
        },
    )
    .await?;
    println!("New one");
    s2.print_tree().await;

    assert_eq!(s2.root_data().await?, s.root_data().await?);
    assert_eq!(
        s.tree().size(&s2.storage).await?,
        s2.tree().size(&s2.storage).await?
    );

    for i in initial_epoch + 1..=initial_epoch + 6 {
        println!("\nEpoch = {i}");
        let ss = s.view_at(i);
        s.tree().print(&ss).await;
        s.diff_at(i).await?.unwrap().print();

        match i {
            1 => {
                assert!(ss.nodes().try_fetch(&"les".to_string()).await?.is_some())
            }
            2 => {
                assert!(ss.nodes().try_fetch(&"les".to_string()).await?.is_some())
            }
            3 => {
                assert!(ss.nodes().try_fetch(&"les".to_string()).await?.is_none())
            }
            4 => {}
            5 => {
                assert!(ss
                    .nodes()
                    .try_fetch(&"automne".to_string())
                    .await?
                    .is_some())
            }
            6 => {
                assert!(ss
                    .nodes()
                    .try_fetch(&"automne".to_string())
                    .await?
                    .is_none())
            }
            _ => {}
        }
    }

    Ok(())
}

#[tokio::test]
async fn storage_in_pgsql() -> Result<()> {
    _storage_in_pgsql(0).await
}

#[tokio::test]
async fn shifted_storage_in_pgsql() -> Result<()> {
    _storage_in_pgsql(438).await
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
impl From<i32> for MinMaxi64 {
    fn from(x: i32) -> Self {
        let x = x as i64;
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

#[tokio::test]
async fn sbbst_storage_in_pgsql() -> Result<()> {
    type V = ShaizedString;
    type TestTree = sbbst::IncrementalTree;
    type SqlStorage = PgsqlStorage<TestTree, V, false>;
    type RamStorage = InMemory<TestTree, V, false>;

    let mut s_psql = MerkleTreeKvDb::<TestTree, V, SqlStorage>::new(
        InitSettings::Reset(TestTree::empty()),
        SqlStorageSettings {
            source: SqlServerConnection::NewConnection(db_url()),
            table: "simple_sbbst".to_string(),
            external_mapper: None,
        },
    )
    .await?;

    s_psql
        .in_transaction(|t| {
            Box::pin(async {
                for k in 1..10 {
                    t.store(k, format!("Node-{k}").into()).await?;
                }
                Result::Ok(())
            })
        })
        .await?;

    s_psql
        .in_transaction(|t| {
            Box::pin(async {
                t.update(3, "coucou".into()).await.unwrap();
                t.update(8, "cava".into()).await.unwrap();
                t.update(2, "bien".into()).await.unwrap();

                Result::Ok(())
            })
        })
        .await?;

    println!("Old one");
    s_psql.print_tree().await;

    let s2 = MerkleTreeKvDb::<TestTree, V, SqlStorage>::new(
        InitSettings::MustExist,
        SqlStorageSettings {
            source: SqlServerConnection::NewConnection(db_url()),
            table: "simple_sbbst".to_string(),
            external_mapper: None,
        },
    )
    .await?;
    println!("New one");
    s2.print_tree().await;
    let string = s_psql.root_data().await?.unwrap().h;
    println!("Root hash = {string}");
    let string1 = s2.root_data().await?.unwrap().h;
    assert_eq!(string, string1);

    for i in 1..=2 {
        println!("\nEpoch = {i}");
        let ss = s2.view_at(i);
        s2.tree().print(&ss).await;
        s_psql.diff_at(i).await?.unwrap().print();
    }

    let mut s_ram =
        MerkleTreeKvDb::<TestTree, V, RamStorage>::new(InitSettings::Reset(TestTree::empty()), ())
            .await?;
    s_ram
        .in_transaction(|t| {
            Box::pin(async {
                for k in 1..10 {
                    t.store(k, format!("Node-{k}").into()).await?;
                }
                Result::Ok(())
            })
        })
        .await?;
    s_ram
        .in_transaction(|t| {
            Box::pin(async {
                t.update(3, "coucou".into()).await.unwrap();
                t.update(8, "cava".into()).await.unwrap();
                t.update(2, "bien".into()).await.unwrap();

                Result::Ok(())
            })
        })
        .await?;
    s_ram.print_tree().await;

    assert_eq!(
        s2.root_data().await?.unwrap().h,
        s_ram.root_data().await?.unwrap().h
    );

    Ok(())
}

async fn with_storage<S: TreeTransactionalStorage<String, usize> + Send>(s: &mut S) -> Result<()> {
    s.in_transaction(|t| {
        Box::pin(async {
            for k in
                "les sanglots longs des violons de automne blessent mon coeur langueur monotone"
                    .split_whitespace()
            {
                t.store(k.to_string(), k.len()).await.unwrap();
            }
            Result::Ok(())
        })
    })
    .await?;

    s.in_transaction(|t| {
        Box::pin(async {
            t.remove("blessent".to_string()).await.unwrap();
            Result::Ok(())
        })
    })
    .await?;

    s.in_transaction(|t| {
        Box::pin(async {
            t.remove("les".to_string()).await.unwrap();
            Result::Ok(())
        })
    })
    .await?;

    s.in_transaction(|t| {
        Box::pin(async {
            t.remove("sanglots".to_string()).await.unwrap();
            Result::Ok(())
        })
    })
    .await?;

    s.in_transaction(|t| {
        Box::pin(async {
            t.update("longs".to_string(), 95000).await.unwrap();
            t.update("des".to_string(), 36000).await.unwrap();
            t.remove("des".to_string()).await.unwrap();
            Result::Ok(())
        })
    })
    .await?;

    s.in_transaction(|t| {
        Box::pin(async {
            t.remove("automne".to_string()).await.unwrap();
            t.remove("mon".to_string()).await.unwrap();
            Result::Ok(())
        })
    })
    .await?;

    Ok(())
}

#[tokio::test]
async fn hashes() -> Result<()> {
    type K = i64;
    type V = ShaizedString;

    type Tree = scapegoat::Tree<K>;
    type Storage = InMemory<Tree, V, false>;

    let mut s = MerkleTreeKvDb::<Tree, V, Storage>::new(
        InitSettings::ResetAt(Tree::empty(Alpha::fully_balanced()), 392),
        (),
    )
    .await?;

    s.in_transaction(|s| {
        Box::pin(async {
            s.store(2, "cava".into()).await?;
            s.store(1, "coucou".into()).await?;
            s.store(3, "bien".into()).await
        })
    })
    .await?;

    assert_eq!(
        s.storage.data().try_fetch(&1).await?.unwrap().h,
        sha256::digest("coucou")
    );
    assert_eq!(
        s.storage.data().try_fetch(&2).await?.unwrap().h,
        sha256::digest(
            sha256::digest("coucou") + &sha256::digest("bien") + &sha256::digest("cava")
        )
    );
    assert_eq!(
        s.storage.data().try_fetch(&3).await?.unwrap().h,
        sha256::digest("bien")
    );
    Ok(())
}

#[tokio::test]
async fn hashes_pgsql() -> Result<()> {
    type K = i64;
    type V = ShaizedString;

    type Tree = scapegoat::Tree<K>;
    type Storage = PgsqlStorage<Tree, V, false>;

    {
        let mut s = MerkleTreeKvDb::<Tree, V, Storage>::new(
            InitSettings::Reset(Tree::empty(Alpha::fully_balanced())),
            SqlStorageSettings {
                source: SqlServerConnection::NewConnection(db_url()),
                table: "test_hashes".into(),
                external_mapper: None,
            },
        )
        .await?;

        s.in_transaction(|s| {
            Box::pin(async {
                s.store(2, "cava".into()).await?;
                s.store(1, "coucou".into()).await?;
                s.store(3, "bien".into()).await
            })
        })
        .await?;

        assert_eq!(
            s.storage.data().try_fetch(&1).await?.unwrap().h,
            sha256::digest("coucou")
        );
        assert_eq!(
            s.storage.data().try_fetch(&2).await?.unwrap().h,
            sha256::digest(
                sha256::digest("coucou") + &sha256::digest("bien") + &sha256::digest("cava")
            )
        );
        assert_eq!(
            s.storage.data().try_fetch(&3).await?.unwrap().h,
            sha256::digest("bien")
        );
    }

    {
        let mut s = MerkleTreeKvDb::<Tree, V, Storage>::new(
            InitSettings::MustExist,
            SqlStorageSettings {
                source: SqlServerConnection::NewConnection(db_url()),
                table: "test_hashes".into(),
                external_mapper: None,
            },
        )
        .await?;

        s.in_transaction(|s| Box::pin(async { s.update(1, "oucouc".into()).await }))
            .await?;

        assert_eq!(
            s.storage.data().try_fetch(&1).await?.unwrap().h,
            sha256::digest("oucouc")
        );
        assert_eq!(
            s.storage.data().try_fetch(&2).await?.unwrap().h,
            sha256::digest(
                sha256::digest("oucouc") + &sha256::digest("bien") + &sha256::digest("cava")
            )
        );
        assert_eq!(
            s.storage.data().try_fetch(&3).await?.unwrap().h,
            sha256::digest("bien")
        );
    }

    Ok(())
}

#[tokio::test]
async fn incremental_sbbst_requires_sequential_keys() -> Result<()> {
    type Tree = sbbst::IncrementalTree;
    type V = i64;

    type Storage = InMemory<Tree, V, false>;

    let mut s = MerkleTreeKvDb::<Tree, V, Storage>::new(
        InitSettings::Reset(Tree::with_shift_and_capacity(10, 0)),
        (),
    )
    .await?;

    s.start_transaction().await?;
    assert!(s.store(2, 2).await.is_err());
    assert!(s.store(12, 2).await.is_err());
    assert!(s.store(11, 2).await.is_ok());
    assert!(s.store(12, 2).await.is_ok());
    s.commit_transaction().await?;

    Ok(())
}

#[tokio::test]
async fn epoch_sbbst_can_use_non_sequential_keys() -> Result<()> {
    type Tree = sbbst::EpochTree;
    type V = i64;

    type Storage = InMemory<Tree, V, false>;

    let mut s = MerkleTreeKvDb::<Tree, V, Storage>::new(
        InitSettings::Reset(Tree::with_shift_and_capacity(10, 0)),
        (),
    )
    .await?;

    s.start_transaction().await?;
    assert!(s.store(2, 2).await.is_err()); // try insert key smaller than initial shift
    assert!(s.store(12, 2).await.is_ok());
    assert!(s.store(11, 2).await.is_err()); // try insert key smaller than previous one
    assert!(s.store(14, 2).await.is_ok());
    assert!(s.store(15, 2).await.is_ok());
    s.commit_transaction().await?;

    // check that values have been inserted
    assert_eq!(s.try_fetch(&12).await.unwrap(), 2);
    assert_eq!(s.try_fetch(&14).await.unwrap(), 2);
    assert_eq!(s.try_fetch(&15).await.unwrap(), 2);

    // chekc that 11 has not been inserted
    assert!(s.try_fetch(&11).await.is_none());
    Ok(())
}

#[tokio::test]
async fn epoch_sbbst_over_pgsql_with_non_sequential_keys() -> Result<()> {
    type Tree = sbbst::EpochTree;
    type V = i64;

    type Storage = PgsqlStorage<Tree, V, false>;

    let mut s = MerkleTreeKvDb::<Tree, V, Storage>::new(
        InitSettings::Reset(Tree::with_shift_and_capacity(10, 0)),
        SqlStorageSettings {
            table: "epoch_sbbst".to_string(),
            source: SqlServerConnection::NewConnection(db_url()),
            external_mapper: None,
        },
    )
    .await?;

    s.start_transaction().await?;
    assert!(s.store(2, 2).await.is_err()); // try insert key smaller than initial shift
    assert!(s.store(12, 2).await.is_ok());
    assert!(s.store(11, 2).await.is_err()); // try insert key smaller than previous one
    s.commit_transaction().await?;

    // start a new transaction
    s.start_transaction().await?;
    assert!(s.store(14, 2).await.is_ok());
    s.commit_transaction().await?;

    // check that values have been inserted
    assert_eq!(s.try_fetch(&12).await.unwrap(), 2);
    assert_eq!(s.try_fetch(&14).await.unwrap(), 2);

    // check that 11 has not been inserted
    assert!(s.try_fetch(&11).await.is_none());

    assert_eq!(s.storage.epoch_mapper().to_incremental_epoch(12).await, 1);
    assert_eq!(s.storage.epoch_mapper().to_incremental_epoch(14).await, 1);
    assert!(s
        .storage
        .epoch_mapper()
        .try_to_incremental_epoch(11)
        .await
        .is_none());

    Ok(())
}

#[tokio::test]
async fn thousand_rows() -> Result<()> {
    type K = i64;
    type V = usize;
    type Tree = scapegoat::Tree<K>;
    type Storage = PgsqlStorage<Tree, V, false>;

    let mut s = MerkleTreeKvDb::<Tree, V, Storage>::new(
        InitSettings::Reset(Tree::empty(Alpha::fully_balanced())),
        SqlStorageSettings {
            source: SqlServerConnection::NewConnection(db_url()),
            table: "thousand".to_string(),
            external_mapper: None,
        },
    )
    .await?;

    let mut rng = rand::rngs::StdRng::seed_from_u64(0xc0c0);

    s.in_transaction(|s| {
        Box::pin(async {
            for i in 0..1000 {
                s.store(i, (10 * i).try_into().unwrap()).await?;
            }
            Result::Ok(())
        })
    })
    .await?;
    assert_eq!(s.size().await, 1000);

    let to_remove = (0..100)
        .map(|_| rng.gen_range(1..=1000))
        .collect::<HashSet<_>>();

    let to_remove_copy = to_remove.clone();

    let mt = s
        .in_transaction(|s| {
            Box::pin({
                let value = to_remove_copy.clone();
                async move {
                    for k in value.iter() {
                        s.remove(*k).await?;
                    }
                    Result::Ok(())
                }
            })
        })
        .await?;
    mt.print();

    assert_eq!(s.size().await, 1000 - to_remove.len());
    for k in to_remove {
        assert!(s.try_fetch(&k).await?.is_none());
    }

    println!("{}", rng.gen::<i32>());

    Ok(())
}

#[tokio::test]
async fn aggregation_memory() -> Result<()> {
    type Tree = sbbst::IncrementalTree;
    type V = MinMaxi64;

    type Storage = InMemory<Tree, V, false>;

    let mut s =
        MerkleTreeKvDb::<Tree, V, Storage>::new(InitSettings::Reset(Tree::empty()), ()).await?;

    s.in_transaction(|s| {
        Box::pin(async {
            for i in 0..30 {
                s.store(
                    i + 1,
                    MinMaxi64((i + 1).try_into().unwrap(), i as i64, i as i64),
                )
                .await?;
            }
            Result::Ok(())
        })
    })
    .await?;

    let tree = s.tree();
    let root = tree.root(&s.storage).await?.unwrap();
    let root_payload = s.try_fetch(&root).await?.unwrap();
    assert_eq!(root_payload.1, 1);
    assert_eq!(root_payload.2, 30);
    Ok(())
}

#[tokio::test]
async fn aggregation_pgsql() -> Result<()> {
    type Tree = sbbst::IncrementalTree;
    type V = MinMaxi64;

    type Storage = PgsqlStorage<Tree, V, false>;
    let mut s = MerkleTreeKvDb::<Tree, V, Storage>::new(
        InitSettings::ResetAt(Tree::empty(), 32),
        SqlStorageSettings {
            source: SqlServerConnection::NewConnection(db_url()),
            table: "agg".to_string(),
            external_mapper: None,
        },
    )
    .await?;

    s.in_transaction(|s| {
        Box::pin(async {
            for i in 0..30 {
                s.store(
                    i + 1,
                    MinMaxi64((i + 1).try_into().unwrap(), i as i64, i as i64),
                )
                .await?;
            }
            Result::Ok(())
        })
    })
    .await?;

    let root_payload = s
        .try_fetch(&s.tree().root(&s.storage).await?.unwrap())
        .await?
        .unwrap();
    assert_eq!(root_payload.1, 1);
    assert_eq!(root_payload.2, 30);
    Ok(())
}

async fn test_rollback<
    S: EpochKvStorage<i64, MinMaxi64> + TreeTransactionalStorage<i64, MinMaxi64> + Send + Sync,
>(
    s: &mut S,
    initial_epoch: UserEpoch,
) {
    for i in 0..3 {
        s.in_transaction(|s| {
            Box::pin(async move {
                s.store(2 * i, (2 * i).into()).await.unwrap();
                s.store(2 * i + 1, (2 * i + 1).into()).await.unwrap();
                Result::Ok(())
            })
        })
        .await
        .unwrap();
    }

    assert_eq!(s.current_epoch().await.unwrap(), 3 + initial_epoch);
    assert_eq!(s.size().await, 6);
    for i in 0..=5 {
        assert!(s.contains(&i.into()).await.unwrap());
    }

    // Rollback twice to reach epoch 1
    s.rollback_to(1 + initial_epoch)
        .await
        .unwrap_or_else(|_| panic!("failed to rollback to {}", 1 + initial_epoch));
    assert_eq!(s.current_epoch().await.unwrap(), 1 + initial_epoch);
    assert_eq!(s.size().await, 2);
    for i in 0..=5 {
        if i <= 1 {
            assert!(s.contains(&i.into()).await.unwrap());
        } else {
            assert!(!s.contains(&i.into()).await.unwrap());
        }
    }

    // rollback once to reach to epoch 0
    s.rollback().await.unwrap();
    println!("Rollbacked to initial epoch");
    assert_eq!(s.current_epoch().await.unwrap(), initial_epoch);
    assert_eq!(s.size().await, 0);
    for i in 0..=5 {
        assert!(!s.contains(&i.into()).await.unwrap());
    }

    // Can not rollback before epoch 0
    println!("Rolling back before initial epoch");
    assert!(s.rollback().await.is_err());
}

#[tokio::test]
async fn rollback_memory() {
    type K = i64;
    type V = MinMaxi64;
    type Tree = scapegoat::Tree<K>;

    type Storage = InMemory<Tree, V, false>;
    let mut s = MerkleTreeKvDb::<Tree, V, Storage>::new(
        InitSettings::Reset(Tree::empty(Alpha::new(0.7))),
        (),
    )
    .await
    .expect("unable to initialize tree");

    test_rollback(&mut s, 0).await;
}

#[tokio::test]
async fn rollback_memory_at() {
    type K = i64;
    type V = MinMaxi64;
    type Tree = scapegoat::Tree<K>;

    type Storage = InMemory<Tree, V, false>;

    const INITIAL_EPOCH: UserEpoch = 4875;
    let mut s = MerkleTreeKvDb::<Tree, V, Storage>::new(
        InitSettings::ResetAt(Tree::empty(Alpha::new(0.7)), INITIAL_EPOCH),
        (),
    )
    .await
    .expect("unable to initialize tree");

    test_rollback(&mut s, INITIAL_EPOCH).await;
}

#[tokio::test]
async fn rollback_psql() {
    type K = i64;
    type V = MinMaxi64;
    type Tree = scapegoat::Tree<K>;

    type Storage = PgsqlStorage<Tree, V, false>;
    let mut s = MerkleTreeKvDb::<Tree, V, Storage>::new(
        InitSettings::Reset(Tree::empty(Alpha::new(0.7))),
        SqlStorageSettings {
            source: SqlServerConnection::NewConnection(db_url()),
            table: "rollback".to_string(),
            external_mapper: None,
        },
    )
    .await
    .expect("unable to initialize tree");

    test_rollback(&mut s, 0).await;
}

#[tokio::test]
async fn rollback_psql_at() {
    type K = i64;
    type V = MinMaxi64;
    type Tree = scapegoat::Tree<K>;

    const INITIAL_EPOCH: UserEpoch = 4875;
    type Storage = PgsqlStorage<Tree, V, false>;
    let mut s = MerkleTreeKvDb::<Tree, V, Storage>::new(
        InitSettings::ResetAt(Tree::empty(Alpha::new(0.7)), INITIAL_EPOCH),
        SqlStorageSettings {
            source: SqlServerConnection::NewConnection(db_url()),
            table: "rollback_at".to_string(),
            external_mapper: None,
        },
    )
    .await
    .expect("unable to initialize tree");

    test_rollback(&mut s, INITIAL_EPOCH).await;
}

#[tokio::test]
async fn context_at() {
    type Tree = sbbst::IncrementalTree;
    type V = MinMaxi64;
    type Storage = InMemory<Tree, V, false>;
    let mut s = MerkleTreeKvDb::<Tree, V, Storage>::new(InitSettings::Reset(Tree::empty()), ())
        .await
        .unwrap();

    s.in_transaction(|s| {
        Box::pin(async {
            s.store(1, 1i64.into()).await.unwrap();
            Result::Ok(())
        })
    })
    .await
    .unwrap();
    s.in_transaction(|s| {
        Box::pin(async {
            s.store(2, 2i64.into()).await.unwrap();
            Result::Ok(())
        })
    })
    .await
    .unwrap();

    assert_eq!(
        s.fetch_with_context_at(&1, 1)
            .await
            .unwrap()
            .unwrap()
            .0
            .parent,
        None
    );
    assert_eq!(
        s.fetch_with_context_at(&1, 2)
            .await
            .unwrap()
            .unwrap()
            .0
            .parent,
        Some(2)
    );
}

/// Ensure that a tree created will see its state persisted even if it is empty.
#[tokio::test]
async fn initial_state() {
    use crate::storage::EpochStorage;

    type K = i64;
    type V = MinMaxi64;
    type Tree = scapegoat::Tree<K>;
    type Storage = PgsqlStorage<Tree, V, false>;

    // Create an empty tree
    {
        let _ = MerkleTreeKvDb::<Tree, V, Storage>::new(
            InitSettings::Reset(Tree::empty(Alpha::new(0.8))),
            SqlStorageSettings {
                source: SqlServerConnection::NewConnection(db_url()),
                table: "empty_tree".to_string(),
                external_mapper: None,
            },
        )
        .await
        .unwrap();
    }

    {
        let s_init = MerkleTreeKvDb::<Tree, V, Storage>::new(
            InitSettings::MustExist,
            SqlStorageSettings {
                source: SqlServerConnection::NewConnection(db_url()),
                table: "empty_tree".to_string(),
                external_mapper: None,
            },
        )
        .await
        .unwrap();

        let tree_state = s_init.storage.state().fetch().await.unwrap();
        assert_eq!(tree_state.alpha, Alpha::new(0.8));
        assert_eq!(tree_state.node_count, 0);
        println!("Tree alpha is {:?}", tree_state);
    }
}

#[tokio::test]
async fn dirties() {
    type Tree = sbbst::IncrementalTree;
    type V = MinMaxi64;
    type Storage = InMemory<Tree, V, false>;
    let mut s = MerkleTreeKvDb::<Tree, V, Storage>::new(InitSettings::Reset(Tree::empty()), ())
        .await
        .unwrap();

    // Initial tree:
    // (2 (1))
    s.in_transaction(|s| {
        async {
            s.store(1, 1i64.into()).await.unwrap();
            s.store(2, 2i64.into()).await.unwrap();
            Result::Ok(())
        }
        .boxed()
    })
    .await
    .unwrap();

    // Initial tree = (2 (1))
    // New tree = (2 (1 3)) --> dirties = { 2, 3 }
    s.in_transaction(|s| {
        async {
            s.store(3, 2i64.into()).await.unwrap();
            let dirties = s.touched().await;
            assert!(dirties.contains(&2));
            assert!(dirties.contains(&3));
            Result::Ok(())
        }
        .boxed()
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn grouped_txs() -> Result<()> {
    // Create 2 KvDb that will be commited in unison
    let db_manager = PostgresConnectionManager::new_from_stringlike(db_url(), NoTls)
        .with_context(|| format!("while connecting to postgreSQL with `{}`", db_url()))
        .context("failed to connect to PgSQL")?;
    let db_pool = DBPool::builder()
        .build(db_manager)
        .await
        .context("while creating the db_pool")?;

    type K = i64;
    type V = MinMaxi64;

    type SbbstTree = sbbst::EpochTree;
    type SbbstStorage = PgsqlStorage<SbbstTree, V, false>;
    type ScapeTree = scapegoat::Tree<K>;
    type ScapeStorage = PgsqlStorage<ScapeTree, V, true>;

    let mut t1 = MerkleTreeKvDb::<SbbstTree, V, SbbstStorage>::new(
        InitSettings::Reset(SbbstTree::empty()),
        SqlStorageSettings {
            table: "nested_sbbst".into(),
            source: SqlServerConnection::Pool(db_pool.clone()),
            external_mapper: None,
        },
    )
    .await
    .context("while initializing SBBST")?;

    let mut t2 = MerkleTreeKvDb::<ScapeTree, V, ScapeStorage>::new(
        InitSettings::Reset(scapegoat::Tree::empty(Alpha::fully_balanced())),
        SqlStorageSettings {
            table: "nested_scape".into(),
            source: SqlServerConnection::Pool(db_pool.clone()),
            external_mapper: Some("nested_sbbst".into()),
        },
    )
    .await
    .context("while initializing scapegoat")?;

    // First batch - success
    let mut binding = db_pool.get().await?;
    let mut tx = binding.transaction().await?;

    // The genesis root, i.e. None
    let first_root = t1.root().await.unwrap().unwrap();

    t1.start_transaction().await?;
    t2.start_transaction().await?;

    t1.store(1, 456.into()).await?;

    t2.store(8786384, 456.into()).await?;
    t2.store(4, 329.into()).await?;
    t2.store(88, 15.into()).await?;

    // The not-yet-commited root
    let in_flight_root = t1.root().await.unwrap().unwrap();
    assert_ne!(first_root, in_flight_root);
    t1.commit_in(&mut tx).await?;
    t2.commit_in(&mut tx).await?;

    tx.commit().await?;

    t1.commit_success().await;
    t2.commit_success().await;

    // The commited root must be equal to its in-flight snapshot
    let commited_root = t1.root().await.unwrap().unwrap();
    assert_eq!(commited_root, in_flight_root);
    // Sizes must have been commited coorectly
    assert_eq!(t1.size().await, 1);
    assert_eq!(t2.size().await, 3);

    assert!(t2.try_fetch(&4).await.unwrap().is_some());
    assert!(t2.try_fetch(&5).await.unwrap().is_none());

    // Second batch - made to fail
    let mut tx = binding.transaction().await?;
    t1.start_transaction().await?;
    t2.start_transaction().await?;

    t1.store(3, 456.into()).await?;

    t2.store(578943, 542.into()).await?;
    t2.store(943, commited_root.into()).await?;

    t1.commit_in(&mut tx).await?;
    t2.commit_in(&mut tx).await?;

    tx.rollback().await?;
    t1.commit_failed().await;
    t2.commit_failed().await;

    // Size should not have changed
    assert_eq!(t1.size().await, 1);
    assert_eq!(t2.size().await, 3);

    // Old data must still be there
    assert!(t2.try_fetch(&4).await.unwrap().is_some());
    assert!(t2.try_fetch(&5).await.unwrap().is_none());

    // New insertion must have failed
    assert!(t1.try_fetch(&3).await.unwrap().is_none());
    assert!(t1.try_fetch(&4).await.unwrap().is_none());
    assert!(t2.try_fetch(&578943).await.unwrap().is_none());

    Ok(())
}
#[tokio::test]
async fn fetch_many() {
    type K = String;
    type V = usize;
    type Tree = scapegoat::Tree<K>;
    type Storage = PgsqlStorage<Tree, V, false>;

    let mut s = MerkleTreeKvDb::<Tree, V, Storage>::new(
        InitSettings::Reset(Tree::empty(Alpha::never_balanced())),
        SqlStorageSettings {
            source: SqlServerConnection::NewConnection(db_url()),
            table: "many".to_string(),
            external_mapper: None,
        },
    )
    .await
    .unwrap();

    const TEXT1: &str = "au solstice ete comme palais alcine ciel embrasera chateau versailles plus rien restera tu peux lacher bontemps toute sa cohorte que personne ne sorte deja temps";

    const TEXT2: &str = "car je defie astre roi toutes planetes agencer doit titres tetes esope mots allument mon brulot grenouilles jupiter";

    s.in_transaction(|s| {
        Box::pin(async {
            for (i, word) in TEXT1.split(' ').enumerate() {
                s.store(word.to_string(), i).await?;
            }
            Result::Ok(())
        })
    })
    .await
    .unwrap();

    s.in_transaction(|s| {
        Box::pin(async {
            for (i, word) in TEXT2.split(' ').enumerate() {
                s.store(word.to_string(), i).await?;
            }
            Result::Ok(())
        })
    })
    .await
    .unwrap();

    let many = s
        .try_fetch_many_at([
            // OK
            (1i64 as UserEpoch, "restera".to_string()),
            // OK
            (2i64 as UserEpoch, "restera".to_string()),
            // non-existing epoch
            (4i64 as UserEpoch, "restera".to_string()),
            // does not exist yet
            (1i64 as UserEpoch, "car".to_string()),
            // OK
            (2i64 as UserEpoch, "car".to_string()),
            // non-existing key
            (1i64 as UserEpoch, "meumeu".to_string()),
        ])
        .await
        .unwrap()
        .into_iter()
        .map(|(epoch, ctx, v)| (epoch, ctx.node_id, v))
        .collect::<HashSet<_>>();

    // using sets here, for PgSQL does not guarantee ordering
    assert_eq!(
        many,
        [
            (1i64 as UserEpoch, "restera".to_string(), 12),
            (2i64 as UserEpoch, "restera".to_string(), 12),
            (2i64 as UserEpoch, "car".to_string(), 0),
        ]
        .into_iter()
        .collect::<HashSet<_>>()
    )
}

#[tokio::test]
async fn wide_update_trees() {
    type K = String;
    type V = usize;
    type Tree = scapegoat::Tree<K>;
    type Storage = PgsqlStorage<Tree, V, false>;

    let mut s = MerkleTreeKvDb::<Tree, V, Storage>::new(
        InitSettings::Reset(Tree::empty(Alpha::never_balanced())),
        SqlStorageSettings {
            source: SqlServerConnection::NewConnection(db_url()),
            table: "wide".to_string(),
            external_mapper: None,
        },
    )
    .await
    .unwrap();

    const TEXT1: &str = "au solstice ete comme palais alcine ciel embrasera chateau versailles plus rien restera tu peux lacher bontemps toute sa cohorte que personne ne sorte deja temps";

    const TEXT2: &str = "car je defie astre roi toutes planetes agencer doit titres tetes esope mots allument mon brulot grenouilles jupiter";

    s.in_transaction(|s| {
        Box::pin(async {
            for (i, word) in TEXT1.split(' ').enumerate() {
                s.store(word.to_string(), i).await?;
            }
            Result::Ok(())
        })
    })
    .await
    .unwrap();

    s.print_tree().await;

    println!("\n\n\n\n\n");
    s.in_transaction(|s| {
        Box::pin(async {
            for (i, word) in TEXT2.split(' ').enumerate() {
                s.store(word.to_string(), i).await?;
            }
            Result::Ok(())
        })
    })
    .await
    .unwrap();

    s.print_tree().await;

    // Keys are "restera" and "plus"
    let query = format!("
SELECT {KEY}, generate_series(GREATEST(1, {VALID_FROM}), LEAST(2, {VALID_UNTIL})) AS {EPOCH}
FROM wide
WHERE {KEY} = ANY(ARRAY['\\x72657374657261'::bytea,'\\x706c7573'::bytea, '\\x636172']) AND NOT ({VALID_FROM} > 2 OR {VALID_UNTIL} < 1)");

    let trees = s.wide_update_trees_at(2, &query, (1, 2)).await.unwrap();
    for t in trees.iter() {
        println!("{}:", t.epoch());
        t.print();
    }
}

#[tokio::test]
async fn all_pgsql() {
    type K = String;
    type V = usize;
    type Tree = scapegoat::Tree<K>;
    type Storage = PgsqlStorage<Tree, V, false>;

    let mut s = MerkleTreeKvDb::<Tree, V, Storage>::new(
        InitSettings::Reset(Tree::empty(Alpha::never_balanced())),
        SqlStorageSettings {
            source: SqlServerConnection::NewConnection(db_url()),
            table: "fetch_all".to_string(),
            external_mapper: None,
        },
    )
    .await
    .unwrap();

    const TEXT1: &str = "nature berce le il a froid";
    const TEXT2: &str = "dort tranquille deux trous rouges cote";

    s.in_transaction(|s| {
        Box::pin(async {
            for (i, word) in TEXT1.split(' ').enumerate() {
                s.store(word.to_string(), i).await?;
            }
            Result::Ok(())
        })
    })
    .await
    .unwrap();

    s.in_transaction(|s| {
        Box::pin(async {
            s.remove("il".to_string()).await?;
            s.remove("nature".to_string()).await?;
            Result::Ok(())
        })
    })
    .await
    .unwrap();

    s.in_transaction(|s| {
        Box::pin(async {
            for (i, word) in TEXT2.split(' ').enumerate() {
                s.store(word.to_string(), i).await?;
            }
            Result::Ok(())
        })
    })
    .await
    .unwrap();

    let pairs_1 = s.pairs_at(1).await.unwrap();
    let pairs_2 = s.pairs_at(2).await.unwrap();
    let pairs_3 = s.pairs_at(3).await.unwrap();

    assert!(s.pairs_at(0).await.unwrap().is_empty());

    assert!(!pairs_1.contains_key("tranquille"));
    assert!(!pairs_1.contains_key("rouges"));
    assert!(pairs_1.contains_key("nature"));
    assert!(pairs_1.contains_key("froid"));

    assert!(!pairs_2.contains_key("rouges"));
    assert!(!pairs_2.contains_key("nature"));

    assert!(pairs_3.contains_key("tranquille"));
    assert!(pairs_3.contains_key("rouges"));
    assert!(!pairs_3.contains_key("nature"));
    assert!(pairs_3.contains_key("froid"));
}

#[tokio::test]
async fn all_memory() {
    type K = String;
    type V = usize;
    type Tree = scapegoat::Tree<K>;
    type Storage = InMemory<Tree, V, false>;

    let mut s = MerkleTreeKvDb::<Tree, V, Storage>::new(
        InitSettings::Reset(Tree::empty(Alpha::never_balanced())),
        (),
    )
    .await
    .unwrap();

    const TEXT1: &str = "nature berce le il a froid";
    const TEXT2: &str = "dort tranquille deux trous rouges cote";

    s.in_transaction(|s| {
        Box::pin(async {
            for (i, word) in TEXT1.split(' ').enumerate() {
                s.store(word.to_string(), i).await?;
            }
            Result::Ok(())
        })
    })
    .await
    .unwrap();

    s.in_transaction(|s| {
        Box::pin(async {
            s.remove("il".to_string()).await?;
            s.remove("nature".to_string()).await?;
            Result::Ok(())
        })
    })
    .await
    .unwrap();

    s.in_transaction(|s| {
        Box::pin(async {
            for (i, word) in TEXT2.split(' ').enumerate() {
                s.store(word.to_string(), i).await?;
            }
            Result::Ok(())
        })
    })
    .await
    .unwrap();

    let pairs_1 = s.pairs_at(1).await.unwrap();
    let pairs_2 = s.pairs_at(2).await.unwrap();
    let pairs_3 = s.pairs_at(3).await.unwrap();

    assert!(s.pairs_at(0).await.unwrap().is_empty());

    assert!(!pairs_1.contains_key("tranquille"));
    assert!(!pairs_1.contains_key("rouges"));
    assert!(pairs_1.contains_key("nature"));
    assert!(pairs_1.contains_key("froid"));

    assert!(!pairs_2.contains_key("rouges"));
    assert!(!pairs_2.contains_key("nature"));

    assert!(pairs_3.contains_key("tranquille"));
    assert!(pairs_3.contains_key("rouges"));
    assert!(!pairs_3.contains_key("nature"));
    assert!(pairs_3.contains_key("froid"));
}
