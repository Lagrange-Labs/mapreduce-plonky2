use plonky2::util::serialization::IoError;
use serde::{de::Error, Deserialize, Deserializer, Serialize, Serializer};

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

/// `serialize` allows to serialize an element of type `T: ToBytes` employing a serde serializer;
/// Can be employed to derive `Serialize` if `T` does not implement `Serialize` with the `serialize_with` annotation
pub fn serialize<T: ToBytes, S: Serializer>(input: &T, serializer: S) -> Result<S::Ok, S::Error> {
    let input_bytes = input.to_bytes();
    serializer.serialize_bytes(&input_bytes)
}

/// `deserialize` allows to deserialize an element of type `T: FromBytes` employing a serde deserializer;
/// Can be employed to derive `Deserialize` if `T` does not implement `Deserialize` with the `deserialize_with` annotation
pub fn deserialize<'a, T: FromBytes, D: Deserializer<'a>>(deserializer: D) -> Result<T, D::Error> {
    let bytes = Vec::<u8>::deserialize(deserializer)?;
    Ok(T::from_bytes(&bytes).map_err(SerializationError::to_de_error)?)
}

/// `serialize_array` allows to serialize an array with `N` elements of type `T: ToBytes` employing a serde serializer;
/// Can be employed to derive `Serialize` if `T` does not implement `Serialize` with the `serialize_with` annotation
pub fn serialize_array<T: ToBytes, S: Serializer, const N: usize>(
    input: &[T; N],
    serializer: S,
) -> Result<S::Ok, S::Error> {
    let byte_vec = input.iter().map(|inp| inp.to_bytes()).collect::<Vec<_>>();
    Vec::<Vec<u8>>::serialize(&byte_vec, serializer)
}

/// `deserialize_array` allows to deserialize an array with `N` elements of type `T: FromBytes` employing a serde deserializer;
/// Can be employed to derive `Deserialize` if `T` does not implement `Deserialize` with the `deserialize_with` annotation
pub fn deserialize_array<'a, T: FromBytes, D: Deserializer<'a>, const N: usize>(
    deserializer: D,
) -> Result<[T; N], D::Error> {
    deserialize_vec(deserializer)?.try_into().map_err(|_| {
        D::Error::custom(format!(
            "failed to deserialize array: wrong number of items found"
        ))
    })
}

/// `serialize_long_array` overcomes a limitation of serde that cannot derive `Serialize` for arrays
/// of type `T: Serialize` longer than `32` elements; Can be employed to derive `Serialize` for such
/// arrays with the `serialize_with` annotation
pub fn serialize_long_array<T: Serialize + Clone, S: Serializer, const N: usize>(
    input: &[T; N],
    serializer: S,
) -> Result<S::Ok, S::Error> {
    Vec::<T>::serialize(&input.to_vec(), serializer)
}

/// `deserialize_long_array` overcomes a limitation of serde that cannot derive `Deserialize` for arrays
/// of type `T: Deserialize` longer than `32` elements; Can be employed to derive `Deserialize` for such
/// arrays with the `deserialize_with` annotation
pub fn deserialize_long_array<'a, T: Deserialize<'a>, D: Deserializer<'a>, const N: usize>(
    deserializer: D,
) -> Result<[T; N], D::Error> {
    Vec::<T>::deserialize(deserializer)?
        .try_into()
        .map_err(|_| {
            D::Error::custom(format!(
                "failed to deserialize array: wrong number of items found"
            ))
        })
}

/// `serialize_vec` allows to serialize a vector with elements of type `T: ToBytes` employing a serde serializer;
/// Can be employed to derive `Serialize` if `T` does not implement `Serialize` with the `serialize_with` annotation
pub fn serialize_vec<T: ToBytes, S: Serializer>(
    input: &Vec<T>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    let byte_vec = input.iter().map(|inp| inp.to_bytes()).collect::<Vec<_>>();
    Vec::<Vec<u8>>::serialize(&byte_vec, serializer)
}

/// `deserialize_vec` allows to deserialize a vector with elements of type `T: FromBytes` employing a serde deserializer;
/// Can be employed to derive `Deserialize` if `T` does not implement `Deserialize` with the `deserialize_with` annotation
pub fn deserialize_vec<'a, T: FromBytes, D: Deserializer<'a>>(
    deserializer: D,
) -> Result<Vec<T>, D::Error> {
    let byte_vec = Vec::<Vec<u8>>::deserialize(deserializer)?;
    byte_vec
        .into_iter()
        .map(|bytes| T::from_bytes(&bytes).map_err(SerializationError::to_de_error))
        .collect::<Result<_, _>>()
}
