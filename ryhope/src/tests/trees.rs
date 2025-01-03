mod sbbst {

    use crate::{
        storage::{memory::InMemory, TransactionalStorage},
        tree::{sbbst, MutableTree, TreeTopology},
    };

    fn sbbst_in_memory(shift: usize, n: usize) -> (sbbst::IncrementalTree, InMemory<sbbst::IncrementalTree, (), false>) {
        (
            sbbst::IncrementalTree::default(),
            InMemory::new_with_epoch(sbbst::IncrementalTree::with_shift_and_capacity(shift, n), 0),
        )
    }

    #[tokio::test]
    async fn degenerated() {
        let (t, s) = sbbst_in_memory(0, 1);
        assert_eq!(t.parent(1, &s).await.unwrap(), None);
    }

    #[tokio::test]
    async fn tiny() {
        let (t, s) = sbbst_in_memory(0, 2);
        assert_eq!(t.parent(1, &s).await.unwrap(), Some(2));
        assert_eq!(t.parent(2, &s).await.unwrap(), None);
    }

    #[tokio::test]
    async fn triangular() {
        let (t, s) = sbbst_in_memory(0, 3);
        assert_eq!(t.parent(1, &s).await.unwrap(), Some(2));
        assert_eq!(t.parent(2, &s).await.unwrap(), None);
        assert_eq!(t.parent(3, &s).await.unwrap(), Some(2));
    }

    #[tokio::test]
    async fn medium() {
        let (t, s) = sbbst_in_memory(0, 6);
        assert_eq!(t.parent(5, &s).await.unwrap(), Some(6));
        assert_eq!(t.parent(6, &s).await.unwrap(), Some(4));
        assert_eq!(t.parent(2, &s).await.unwrap(), Some(4));
        assert_eq!(t.parent(4, &s).await.unwrap(), None);
    }

    #[tokio::test]
    async fn shift() {
        let (mut t, mut s) = sbbst_in_memory(1000, 6);
        assert_eq!(t.size(&s).await.unwrap(), 6);

        s.start_transaction().await.unwrap();
        t.insert(1007, &mut s).await.unwrap();
        s.commit_transaction().await.unwrap();
        assert_eq!(t.size(&s).await.unwrap(), 7);
    }

    #[tokio::test]
    async fn children() {
        let (t, s) = sbbst_in_memory(0, 4);
        assert_eq!(t.children(&4, &s).await.unwrap(), Some((Some(2), None)));

        let (t, s) = sbbst_in_memory(0, 5);
        assert_eq!(t.children(&4, &s).await.unwrap(), Some((Some(2), Some(5))));

        let (t, s) = sbbst_in_memory(0, 9);
        assert_eq!(t.children(&8, &s).await.unwrap(), Some((Some(4), Some(9))));
    }
}

mod scapegoat {
    use anyhow::*;
    use serde::{Deserialize, Serialize};
    use std::hash::Hash;

    use crate::storage::memory::InMemory;
    use crate::storage::{TransactionalStorage, TreeStorage};
    use crate::tree::scapegoat::{self, Alpha};
    use crate::tree::{PrintableTree, TreeTopology};

    fn scapegaot_in_memory<
        K: Eq
            + Hash
            + Ord
            + Default
            + Clone
            + std::fmt::Debug
            + Sync
            + Serialize
            + for<'a> Deserialize<'a>
            + Send,
    >(
        a: Alpha,
    ) -> (scapegoat::Tree<K>, InMemory<scapegoat::Tree<K>, (), false>) {
        (Default::default(), InMemory::new_with_epoch(scapegoat::Tree::empty(a), 0))
    }

    #[tokio::test]
    async fn base() -> Result<()> {
        type K = String;

        let (mut t, mut s) = scapegaot_in_memory::<K>(Alpha::new(0.8));

        assert_eq!(t.size(&s).await.unwrap(), 0);

        s.start_transaction().await?;
        t.insert("adsfda".into(), &mut s).await?;
        assert_eq!(t.size(&s).await.unwrap(), 1);

        t.insert("asdf".into(), &mut s).await?;
        assert!(t.insert("asdf".into(), &mut s).await.is_err());

        t.insert("pipo".into(), &mut s).await.unwrap();
        assert_eq!(t.size(&s).await.unwrap(), 3);

        t.unlink(&"adsfda".into(), &mut s).await.unwrap();
        assert!(t.unlink(&"adsfda".into(), &mut s).await.is_err());
        t.unlink(&"pipo".into(), &mut s).await.unwrap();
        t.unlink(&"asdf".into(), &mut s).await.unwrap();
        s.commit_transaction().await?;

        assert_eq!(t.size(&s).await.unwrap(), 0);

        Ok(())
    }

    #[tokio::test]
    async fn alphas() -> Result<()> {
        type K = u32;

        let (mut bbst, mut bs) = scapegaot_in_memory::<K>(Alpha::fully_balanced());
        let (mut list, mut ls) = scapegaot_in_memory::<K>(Alpha::never_balanced());

        bs.start_transaction().await.unwrap();
        ls.start_transaction().await.unwrap();
        for i in 0..128 {
            bbst.insert(i, &mut bs).await.unwrap();
            list.insert(i, &mut ls).await.unwrap();
        }
        bs.state_mut().commit_transaction().await.unwrap();
        ls.state_mut().commit_transaction().await.unwrap();

        assert_eq!(bbst.depth(&bs).await.unwrap(), 7);
        assert_eq!(list.depth(&ls).await.unwrap(), 127);
        Ok(())
    }

    #[tokio::test]
    async fn unbalanced() -> Result<()> {
        type K = String;

        let (mut t, mut s) = scapegaot_in_memory::<K>(Alpha::new(0.5));

        s.start_transaction().await?;
        for i in 0..20 {
            t.insert("A".repeat(i), &mut s).await.unwrap();
            t.print(&s).await;
            println!("\n\n");
        }
        s.commit_transaction().await?;
        Ok(())
    }
}
