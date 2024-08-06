use plonky2::field::types::Field;
use std::iter::once;

use alloy::primitives::U256;
use derive_more::From;
use mp2_common::{
    poseidon::{empty_poseidon_hash, H},
    serialization::{deserialize, serialize, FromBytes, ToBytes},
    types::HashOutput,
    utils::ToFields,
    F,
};
use plonky2::{
    hash::hash_types::HashOut,
    plonk::config::{GenericHashOut, Hasher},
};
use ryhope::NodePayload;
use serde::{Deserialize, Serialize};

use super::{row::RowTreeKey, ColumnID};

/// Hardcoded to use blocks but the spirit for any primary index is the same
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct IndexNode<PrimaryIndex> {
    // identifier and value are needed to compute the hash
    pub identifier: ColumnID,
    #[serde(serialize_with = "serialize", deserialize_with = "deserialize")]
    pub value: VectorU256,
    pub row_tree_root_key: RowTreeKey,
    pub row_tree_hash: HashOutput,
    pub row_tree_root_primary: PrimaryIndex,
    // information filled during aggregation inside ryhope
    pub node_hash: HashOutput,
    pub min: U256,
    pub max: U256,
}

impl<PrimaryIndex: Default> IndexNode<PrimaryIndex> {
    pub fn new(
        identifier: ColumnID,
        value: U256,
        row_key: RowTreeKey,
        row_hash: HashOutput,
        row_primary: PrimaryIndex,
    ) -> Self {
        Self {
            identifier,
            value: value.into(),
            row_tree_root_key: row_key,
            row_tree_hash: row_hash,
            row_tree_root_primary: row_primary,
            ..Default::default()
        }
    }
}

impl<PrimaryIndex: Default + Clone + Sized + Serialize + for<'a> Deserialize<'a>> NodePayload
    for IndexNode<PrimaryIndex>
{
    fn aggregate<I: Iterator<Item = Option<Self>>>(&mut self, children: I) {
        // curently always return the expected number of children which
        // is two.
        let children = children.into_iter().collect::<Vec<_>>();
        assert_eq!(children.len(), 2);
        let null_hash = empty_poseidon_hash();

        let (left, right) = match [&children[0], &children[1]] {
            // no children
            [None, None] => {
                self.min = self.value.0;
                self.max = self.value.0;
                (*null_hash, *null_hash)
            }
            [Some(left), None] => {
                self.min = left.min;
                self.max = self.value.0;
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
            .chain(self.value.0.to_fields())
            .chain(HashOut::from_bytes(&self.row_tree_hash.0).to_fields())
            .collect::<Vec<_>>();
        self.node_hash = HashOutput(H::hash_no_pad(&inputs).to_bytes().try_into().unwrap());
    }
}

#[derive(Clone, Hash, Debug, PartialOrd, PartialEq, Ord, Eq, Default, From)]
pub struct VectorU256(pub U256);

impl ToBytes for VectorU256 {
    fn to_bytes(&self) -> Vec<u8> {
        self.0.to_be_bytes_trimmed_vec()
    }
}

impl FromBytes for VectorU256 {
    fn from_bytes(
        bytes: &[u8],
    ) -> std::result::Result<Self, mp2_common::serialization::SerializationError> {
        std::result::Result::Ok(VectorU256(U256::from_be_slice(bytes)))
    }
}
