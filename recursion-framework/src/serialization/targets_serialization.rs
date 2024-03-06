use plonky2::{
    hash::{hash_types::MerkleCapTarget, merkle_proofs::MerkleProofTarget},
    iop::target::BoolTarget,
    plonk::{circuit_data::VerifierCircuitTarget, proof::ProofWithPublicInputsTarget},
    util::serialization::{Buffer, Read, Write},
};
use serde::{Deserialize, Serialize};
use std::fmt::Debug;

use super::{FromBytes, SerializationError, SerializationWrapper, ToBytes};

impl<const D: usize> ToBytes for ProofWithPublicInputsTarget<D> {
    fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        buffer
            .write_target_proof_with_public_inputs(&self)
            .expect("Writing to a byte-vector cannot fail.");
        buffer
    }
}

impl<const D: usize> FromBytes for ProofWithPublicInputsTarget<D> {
    fn from_bytes(bytes: &[u8]) -> Result<Self, SerializationError> {
        let mut buffer = Buffer::new(bytes);
        Ok(buffer.read_target_proof_with_public_inputs()?)
    }
}

/// Serializable variant of `ProofWithPublicInputsTarget`
pub type SerializableProofWithPublicInputsTarget<const D: usize> =
    SerializationWrapper<ProofWithPublicInputsTarget<D>>;

impl ToBytes for VerifierCircuitTarget {
    fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        buffer
            .write_target_verifier_circuit(&self)
            .expect("Writing to a byte-vector cannot fail.");
        buffer
    }
}

impl FromBytes for VerifierCircuitTarget {
    fn from_bytes(bytes: &[u8]) -> Result<Self, SerializationError> {
        let mut buffer = Buffer::new(bytes);
        Ok(buffer.read_target_verifier_circuit()?)
    }
}

/// Serializable variant of `VerifierCircuitTarget`
pub type SerializableVerifierCircuitTarget = SerializationWrapper<VerifierCircuitTarget>;

impl ToBytes for MerkleProofTarget {
    fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        buffer
            .write_target_merkle_proof(&self)
            .expect("Writing to a byte-vector cannot fail.");
        buffer
    }
}

impl FromBytes for MerkleProofTarget {
    fn from_bytes(bytes: &[u8]) -> Result<Self, SerializationError> {
        let mut buffer = Buffer::new(bytes);
        Ok(buffer.read_target_merkle_proof()?)
    }
}

/// Serializable variant of `MerkleProofTarget`
pub type SerializableMerkleProofTarget = SerializationWrapper<MerkleProofTarget>;

impl ToBytes for MerkleCapTarget {
    fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        buffer
            .write_target_merkle_cap(&self)
            .expect("Writing to a byte-vector cannot fail.");
        buffer
    }
}

impl FromBytes for MerkleCapTarget {
    fn from_bytes(bytes: &[u8]) -> Result<Self, SerializationError> {
        let mut buffer = Buffer::new(bytes);
        Ok(buffer.read_target_merkle_cap()?)
    }
}

/// Serializable variant of `MerkleCapTarget`
pub type SerializableMerkleCapTarget = SerializationWrapper<MerkleCapTarget>;

impl<T: ToBytes> ToBytes for Vec<T> {
    fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        buffer
            .write_usize(self.len())
            .expect("Writing to a byte-vector cannot fail.");
        for el in self {
            buffer.extend_from_slice(el.to_bytes().as_slice());
        }
        buffer
    }
}

impl FromBytes for Vec<BoolTarget> {
    fn from_bytes(bytes: &[u8]) -> Result<Vec<BoolTarget>, SerializationError> {
        let mut buffer = Buffer::new(bytes);
        Ok(buffer.read_target_bool_vec()?)
    }
}

impl ToBytes for BoolTarget {
    fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        buffer
            .write_target_bool(*self)
            .expect("Writing to a byte-vector cannot fail.");
        buffer
    }
}

/// Data structure to serialize a vector of elements implementing `ToBytes` and `FromBytes`
pub type SerializableVector<T> = SerializationWrapper<Vec<T>>; 

#[derive(Clone, Debug)]
/// Data structure to serialize an array of arbitary size, which is currently unsupported by serde
pub struct SerializableArray<const SIZE: usize, T: Clone + Debug>([T; SIZE]);

impl<const SIZE: usize, T: Serialize + Clone + Debug> Serialize for SerializableArray<SIZE, T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let vector = self.0.to_vec();
        vector.serialize(serializer)
    }
}

impl<'a, const SIZE: usize, T: Clone + Debug + Deserialize<'a>> Deserialize<'a>
    for SerializableArray<SIZE, T>
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'a>,
    {
        let vector = Vec::<T>::deserialize(deserializer)?;
        Ok(Self(vector.try_into().unwrap()))
    }
}

impl<const SIZE: usize, T: Clone + Debug> AsRef<[T; SIZE]> for SerializableArray<SIZE, T> {
    fn as_ref(&self) -> &[T; SIZE] {
        &self.0
    }
}

impl<const SIZE: usize, T: Clone + Debug> From<[T; SIZE]> for SerializableArray<SIZE, T> {
    fn from(value: [T; SIZE]) -> Self {
        Self(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::serialization::circuit_data_serialization::tests::build_test_circuit;
    use plonky2::{
        iop::target::Target,
        plonk::{
            circuit_builder::CircuitBuilder,
            circuit_data::CircuitConfig,
            config::{GenericConfig, PoseidonGoldilocksConfig},
        },
    };
    use rstest::rstest;

    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    #[rstest]
    #[case(2, 4)]
    #[case(0, 3)]
    #[case(3, 0)]
    #[case(0, 0)]
    fn test_targets_serialization(#[case] cap_height: usize, #[case] merkle_proof_height: usize) {
        let cd = build_test_circuit::<F, C, D>().common;
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        let merkle_cap = SerializableMerkleCapTarget::from(builder.add_virtual_cap(cap_height));

        let merkle_proof = SerializableMerkleProofTarget::from(MerkleProofTarget {
            siblings: builder.add_virtual_hashes(merkle_proof_height),
        });

        let proof =
            SerializableProofWithPublicInputsTarget::from(builder.add_virtual_proof_with_pis(&cd));
        let vd = SerializableVerifierCircuitTarget::from(
            builder.add_virtual_verifier_data(cd.config.fri_config.cap_height),
        );

        let short_target_arr = SerializableArray::from(builder.add_virtual_target_arr::<13>());
        let long_target_arr = SerializableArray::from(builder.add_virtual_target_arr::<42>());

        // test `MerkleCapTarget` serialization
        let encoded = bincode::serialize(&merkle_cap).unwrap();
        let decoded: SerializableMerkleCapTarget = bincode::deserialize(&encoded).unwrap();
        assert_eq!(merkle_cap.as_ref(), decoded.as_ref());

        // test `MerkleProofTarget` serialization
        let encoded = bincode::serialize(&merkle_proof).unwrap();
        let decoded: SerializableMerkleProofTarget = bincode::deserialize(&encoded).unwrap();
        assert_eq!(merkle_proof.as_ref(), decoded.as_ref());

        // test `ProofWithPublicInputsTarget` serialization
        let encoded = bincode::serialize(&proof).unwrap();
        let decoded: SerializableProofWithPublicInputsTarget<D> =
            bincode::deserialize(&encoded).unwrap();
        assert_eq!(proof.as_ref(), decoded.as_ref());

        // test `VerifierCircuitTarget` serialization
        let encoded = bincode::serialize(&vd).unwrap();
        let decoded: SerializableVerifierCircuitTarget = bincode::deserialize(&encoded).unwrap();
        assert_eq!(vd.as_ref(), decoded.as_ref());

        // test short target array serialization
        let encoded = bincode::serialize(&short_target_arr).unwrap();
        let decoded: SerializableArray<13, Target> = bincode::deserialize(&encoded).unwrap();
        assert_eq!(short_target_arr.as_ref(), decoded.as_ref());

        // test long target array serialization
        let encoded = bincode::serialize(&long_target_arr).unwrap();
        let decoded: SerializableArray<42, Target> = bincode::deserialize(&encoded).unwrap();
        assert_eq!(long_target_arr.as_ref(), decoded.as_ref());
    }
}
