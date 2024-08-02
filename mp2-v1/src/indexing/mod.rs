use alloy::primitives::U256;
use derive_more::{Deref, From};
use mp2_common::serialization::{FromBytes, ToBytes};

pub mod cell_tree;
pub mod index_tree;
pub mod row_tree;

#[derive(Clone, Hash, Debug, PartialOrd, PartialEq, Ord, Eq, Default, From, Deref)]
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
