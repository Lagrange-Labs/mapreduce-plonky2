mod sbbst {

    use crate::{
        storage::{memory::InMemory, TransactionalStorage},
        tree::{sbbst, MutableTree, TreeTopology},
    };

    fn sbbst_in_memory(shift: usize, n: usize) -> (sbbst::Tree, InMemory<sbbst::Tree, ()>) {
        (
            sbbst::Tree,
            InMemory::new(sbbst::Tree::with_shift_and_capacity(shift, n)),
        )
    }

    #[test]
    fn degenerated() {
        let (t, s) = sbbst_in_memory(0, 1);
        assert_eq!(t.parent(1, &s), None);
    }

    #[test]
    fn tiny() {
        let (t, s) = sbbst_in_memory(0, 2);
        assert_eq!(t.parent(1, &s), Some(2));
        assert_eq!(t.parent(2, &s), None);
    }

    #[test]
    fn triangular() {
        let (t, s) = sbbst_in_memory(0, 3);
        assert_eq!(t.parent(1, &s), Some(2));
        assert_eq!(t.parent(2, &s), None);
        assert_eq!(t.parent(3, &s), Some(2));
    }

    #[test]
    fn medium() {
        let (t, s) = sbbst_in_memory(0, 6);
        assert_eq!(t.parent(5, &s), Some(6));
        assert_eq!(t.parent(6, &s), Some(4));
        assert_eq!(t.parent(2, &s), Some(4));
        assert_eq!(t.parent(4, &s), None);
    }

    #[test]
    fn shift() {
        let (mut t, mut s) = sbbst_in_memory(1000, 6);
        assert_eq!(t.size(&s), 6);

        s.start_transaction().unwrap();
        t.insert(1007, &mut s).unwrap();
        s.commit_transaction().unwrap();
        assert_eq!(t.size(&s), 7);
    }

    #[test]
    fn children() {
        let (t, s) = sbbst_in_memory(0, 4);
        assert_eq!(t.children(&4, &s), Some((Some(2), None)));

        let (t, s) = sbbst_in_memory(0, 5);
        assert_eq!(t.children(&4, &s), Some((Some(2), Some(5))));

        let (t, s) = sbbst_in_memory(0, 9);
        assert_eq!(t.children(&8, &s), Some((Some(4), Some(9))));
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
            + for<'a> Deserialize<'a>,
    >(
        a: Alpha,
    ) -> (scapegoat::Tree<K>, InMemory<scapegoat::Tree<K>, ()>) {
        (Default::default(), InMemory::new(scapegoat::Tree::empty(a)))
    }

    #[test]
    fn base() -> Result<()> {
        type K = String;

        let (mut t, mut s) = scapegaot_in_memory::<K>(Alpha::new(0.8));

        assert_eq!(t.size(&s), 0);

        s.start_transaction()?;
        t.insert("adsfda".into(), &mut s)?;
        assert_eq!(t.size(&s), 1);

        t.insert("asdf".into(), &mut s)?;
        assert!(t.insert("asdf".into(), &mut s).is_err());

        t.insert("pipo".into(), &mut s).unwrap();
        assert_eq!(t.size(&s), 3);

        t.unlink(&"adsfda".into(), &mut s).unwrap();
        assert!(t.unlink(&"adsfda".into(), &mut s).is_err());
        t.unlink(&"pipo".into(), &mut s).unwrap();
        t.unlink(&"asdf".into(), &mut s).unwrap();
        s.commit_transaction()?;

        assert_eq!(t.size(&s), 0);

        Ok(())
    }

    #[test]
    fn alphas() -> Result<()> {
        type K = u32;

        let (mut bbst, mut bs) = scapegaot_in_memory::<K>(Alpha::fully_balanced());
        let (mut list, mut ls) = scapegaot_in_memory::<K>(Alpha::never_balanced());

        bs.start_transaction().unwrap();
        ls.start_transaction().unwrap();
        for i in 0..128 {
            bbst.insert(i, &mut bs).unwrap();
            list.insert(i, &mut ls).unwrap();
        }
        bs.state_mut().commit_transaction().unwrap();
        ls.state_mut().commit_transaction().unwrap();

        assert_eq!(bbst.depth(&bs), 7);
        assert_eq!(list.depth(&ls), 127);
        Ok(())
    }

    #[test]
    fn unbalanced() -> Result<()> {
        type K = String;

        let (mut t, mut s) = scapegaot_in_memory::<K>(Alpha::new(0.5));

        s.start_transaction()?;
        for i in 0..20 {
            t.insert("A".repeat(i), &mut s).unwrap();
            t.print(&s);
            println!("\n\n");
        }
        s.commit_transaction()?;
        Ok(())
    }
}
