use plonky2::util::serialization::IoError;
use serde::{de::Error, Deserialize, Serialize};
use std::fmt::Debug;

/// Implement serialization for Plonky2 circuits-related data structures
pub mod circuit_data_serialization;
/// Implement serialization for common Plonky2 targets
pub mod targets_serialization;

/// Provides API to serialize a data structure into a sequence of bytes
pub trait ToBytes {
    /// Convert `self` to a sequence of bytes
    fn to_bytes(&self) -> Vec<u8>;
}

/// Provides API to construct a data structure from a sequence of bytes
pub trait FromBytes: Sized {
    /// Construct an instance of `Self` from a sequence of bytes
    fn from_bytes(bytes: &[u8]) -> Result<Self, SerializationError>;
}
/// Error type for serialization methods implemented in this module
pub struct SerializationError(String);

impl From<IoError> for SerializationError {
    fn from(value: IoError) -> Self {
        Self(format!("{}", value))
    }
}

impl SerializationError {
    /// Conver `SerializationError` to serde deserialization error
    pub fn to_de_error<T: Error>(self) -> T {
        T::custom(self.0)
    }
}

#[derive(Serialize, Deserialize)]
/// Data structure employed to automatically serialize/deserialize a vector of bytes with serde,
/// in turn allowing a straightforward implementation of serde serialize/deserialize for types
/// implementing `ToBytes` and `FromBytes` traits
struct SerializationBytesWrapper(Vec<u8>);

#[derive(Clone, Debug, Eq, PartialEq)]
/// Wrapper type employed to implement serialize and deserialize for several Plonky2 types T
pub struct SerializationWrapper<T>(T);

impl<T: ToBytes> Serialize for SerializationWrapper<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let proof_bytes = SerializationBytesWrapper(self.0.to_bytes());
        proof_bytes.serialize(serializer)
    }
}

impl<'a, T: FromBytes> Deserialize<'a> for SerializationWrapper<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'a>,
    {
        let proof_bytes = SerializationBytesWrapper::deserialize(deserializer)?;
        Ok(Self(
            T::from_bytes(&proof_bytes.0).map_err(SerializationError::to_de_error)?,
        ))
    }
}

impl<T: ToBytes + FromBytes> AsRef<T> for SerializationWrapper<T> {
    fn as_ref(&self) -> &T {
        &self.0
    }
}

impl<T: ToBytes + FromBytes> From<T> for SerializationWrapper<T> {
    fn from(value: T) -> Self {
        Self(value)
    }
}
