use anyhow::Result;

use crate::storage::Operation;
use crate::storage::{memory::InMemory, RoEpochKvStorage, TreeTransactionalStorage};
use crate::tree::PrintableTree;
use crate::tree::{scapegoat, scapegoat::Alpha};
use crate::{InitSettings, MerkleTreeKvDb};

#[test]
fn run() -> Result<()> {
    println!("Example to create a RowTree backed by memory storage");

    type V = usize;
    type RowTree = scapegoat::Tree<usize>;

    type Storage = InMemory<RowTree, V>;
    let mut tree = MerkleTreeKvDb::<RowTree, V, Storage>::new(
        InitSettings::Reset(scapegoat::Tree::empty(Alpha::new(0.5))),
        (),
    )?;

    println!("Insertion of some (key,value) pairs");
    println!(
        "Current version of the tree before insertion: {}",
        tree.current_epoch()
    );

    let res = tree
        .transaction_from_batch(vec![
            Operation::Insert(1, 1),
            Operation::Insert(2, 2),
            Operation::Insert(3, 3),
        ])
        .expect("this should work");

    let first_stamp = tree.current_epoch();
    println!(
        "Current version of the tree after insertion: {}",
        tree.current_epoch()
    );

    println!("Tree of keys to update:");
    res.print();
    let fetch_key = 1;
    let v = tree.try_fetch(&fetch_key).expect("that should exist");
    assert_eq!(fetch_key, v);
    println!("Fetching value from key {} = {}", fetch_key, v);

    // Now try to add more keys , delete the one just fetched
    let _ = tree
        .transaction_from_batch(vec![
            Operation::Delete(fetch_key),
            Operation::Insert(4, 4),
            Operation::Insert(5, 5),
        ])
        .expect("this should work");

    match tree.try_fetch(&fetch_key) {
        Some(_) => panic!("that should not happen"),
        None => println!("Fetching deleted key {} fails", fetch_key),
    }

    // Now try to fetch from previous version
    match tree.try_fetch_at(&fetch_key, first_stamp) {
        Some(v) => println!(
            "Fetching {} at previous stamp {} works: {}",
            fetch_key, first_stamp, v
        ),
        None => panic!("We should have fetched something for {:?}", fetch_key),
    }

    // Printing the tree at its previous versions
    println!("tree at {} is now:", tree.current_epoch());
    tree.tree().print(&tree.storage);

    println!("tree at epoch {first_stamp} was:");
    let previous_state = tree.view_at(first_stamp);
    tree.tree().print(&previous_state);

    println!(
        "The update tree from {first_stamp} to {} was:",
        first_stamp + 1
    );
    tree.diff_at(first_stamp + 1).unwrap().print();

    println!("The update tree from 0 to 1 was:",);
    tree.diff_at(1).unwrap().print();

    Ok(())
}