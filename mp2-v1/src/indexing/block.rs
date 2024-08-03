//! Module to handle the block number as a primary index
use ryhope::tree::{sbbst, TreeTopology};

/// The index tree when the primary index is the block number of a blockchain is a sbbst since it
/// is a highly optimized tree for monotonically increasing index. It produces very little
/// tree-manipulating operations on update, and therefore, requires the least amount of reproving
/// when adding a new index.
/// NOTE: when dealing with another type of index, i.e. a general index such as what can happen on
/// a result table, then this tree does not work anymore.
pub type BlockTree = sbbst::Tree;
/// The key used to refer to a table where the block number is the primary index.
pub type BlockTreeKey = <BlockTree as TreeTopology>::Key;
/// Just an alias that give more meaning depending on the context
pub type BlockPrimaryIndex = BlockTreeKey;
