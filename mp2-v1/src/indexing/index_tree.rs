use std::iter::once;

use alloy::primitives::U256;
use mp2_common::{
    poseidon::{empty_poseidon_hash, H},
    types::HashOutput,
    utils::ToFields,
    F,
};
use plonky2::{
    field::types::Field,
    hash::hash_types::HashOut,
    plonk::config::{GenericHashOut, Hasher},
};
use ryhope::NodePayload;
use serde::{Deserialize, Serialize};

use super::row_tree::RowTreeKey;

/// Hardcoded to use blocks but the spirit for any primary index is the same
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct IndexNode {
    // information that must be filled manually
    pub identifier: u64,
    pub value: U256,
    pub row_tree_root_key: RowTreeKey,
    pub row_tree_hash: HashOutput,
    pub row_tree_root_primary: U256,
    // information filled during aggregation inside ryhope
    pub node_hash: HashOutput,
    pub min: U256,
    pub max: U256,
}

impl IndexNode {
    pub fn new(
        id: u64,
        value: &[u8],
        row_key: RowTreeKey,
        row_hash: HashOutput,
        primary: &[u8],
    ) -> Self {
        Self {
            identifier: id,
            value: U256::from_be_slice(value),
            row_tree_root_key: row_key,
            row_tree_hash: row_hash,
            row_tree_root_primary: U256::from_be_slice(primary),
            ..Default::default()
        }
    }
}

impl NodePayload for IndexNode {
    fn aggregate<I: Iterator<Item = Option<Self>>>(&mut self, children: I) {
        // curently always return the expected number of children which
        // is two.
        let children = children.into_iter().collect::<Vec<_>>();
        assert_eq!(children.len(), 2);
        let null_hash = empty_poseidon_hash();

        let (left, right) = match [&children[0], &children[1]] {
            // no children
            [None, None] => {
                self.min = self.value;
                self.max = self.value;
                (*null_hash, *null_hash)
            }
            [Some(left), None] => {
                self.min = left.min;
                self.max = self.value;
                (HashOut::from_bytes(&left.node_hash.0), *null_hash)
            }
            [Some(left), Some(right)] => {
                self.min = left.min;
                self.max = right.max;
                (
                    HashOut::from_bytes(&left.node_hash.0),
                    HashOut::from_bytes(&right.node_hash.0),
                )
            }
            [None, Some(_)] => panic!("ryhope sbbst is wrong"),
        };
        let inputs = left
            .to_fields()
            .into_iter()
            .chain(right.to_fields())
            .chain(self.min.to_fields())
            .chain(self.max.to_fields())
            .chain(once(F::from_canonical_u64(self.identifier)))
            .chain(self.value.to_fields())
            .chain(self.row_tree_hash.0.to_fields())
            .collect::<Vec<_>>();
        self.node_hash = HashOutput(H::hash_no_pad(&inputs).to_bytes().try_into().unwrap());
    }
}
