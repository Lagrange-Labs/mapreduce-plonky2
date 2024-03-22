use plonky2::{
    hash::{
        hash_types::{HashOutTarget, MerkleCapTarget},
        merkle_proofs::MerkleProofTarget,
    },
    iop::target::{BoolTarget, Target},
    plonk::{circuit_data::VerifierCircuitTarget, proof::ProofWithPublicInputsTarget},
    util::serialization::{Buffer, Read, Write},
};

use super::{FromBytes, SerializationError, ToBytes};

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

impl FromBytes for BoolTarget {
    fn from_bytes(bytes: &[u8]) -> Result<Self, SerializationError> {
        let mut buffer = Buffer::new(bytes);
        Ok(buffer.read_target_bool()?)
    }
}

impl ToBytes for Target {
    fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        buffer
            .write_target(*self)
            .expect("Writing to a byte-vector cannot fail.");
        buffer
    }
}

impl FromBytes for Target {
    fn from_bytes(bytes: &[u8]) -> Result<Self, SerializationError> {
        let mut buffer = Buffer::new(bytes);
        Ok(buffer.read_target()?)
    }
}

impl ToBytes for HashOutTarget {
    fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        buffer
            .write_target_hash(self)
            .expect("Writing to a byte-vector cannot fail.");
        buffer
    }
}

impl FromBytes for HashOutTarget {
    fn from_bytes(bytes: &[u8]) -> Result<Self, SerializationError> {
        let mut buffer = Buffer::new(bytes);
        Ok(buffer.read_target_hash()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::serialization::circuit_data_serialization::tests::build_test_circuit;
    use crate::serialization::{
        deserialize, deserialize_array, deserialize_vec, serialize, serialize_array, serialize_vec,
    };
    use plonky2::{
        iop::target::Target,
        plonk::{
            circuit_builder::CircuitBuilder,
            circuit_data::CircuitConfig,
            config::{GenericConfig, PoseidonGoldilocksConfig},
        },
    };
    use rstest::rstest;
    use serde::{Deserialize, Serialize};

    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    #[rstest]
    #[case(2, 4)]
    #[case(0, 3)]
    #[case(3, 0)]
    #[case(0, 0)]
    fn test_targets_serialization(#[case] cap_height: usize, #[case] merkle_proof_height: usize) {
        #[derive(Serialize, Deserialize)]
        struct TestSerialization<T: FromBytes + ToBytes>(
            #[serde(serialize_with = "serialize", deserialize_with = "deserialize")] T,
        );

        let cd = build_test_circuit::<F, C, D>().common;
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        let merkle_cap = TestSerialization::<MerkleCapTarget>(builder.add_virtual_cap(cap_height));

        let merkle_proof = TestSerialization::<MerkleProofTarget>(MerkleProofTarget {
            siblings: builder.add_virtual_hashes(merkle_proof_height),
        });

        let proof = TestSerialization::<ProofWithPublicInputsTarget<D>>(
            builder.add_virtual_proof_with_pis(&cd),
        );
        let vd = TestSerialization::<VerifierCircuitTarget>(
            builder.add_virtual_verifier_data(cd.config.fri_config.cap_height),
        );

        #[derive(Serialize, Deserialize)]
        struct TestArraySerialization<T: ToBytes + FromBytes, const N: usize>(
            #[serde(
                serialize_with = "serialize_array",
                deserialize_with = "deserialize_array"
            )]
            [T; N],
        );

        let short_target_arr = TestArraySerialization(builder.add_virtual_target_arr::<13>());
        let long_target_arr = TestArraySerialization(builder.add_virtual_target_arr::<42>());
        #[derive(Serialize, Deserialize)]
        struct TestVecSerialization<T: ToBytes + FromBytes>(
            #[serde(serialize_with = "serialize_vec", deserialize_with = "deserialize_vec")] Vec<T>,
        );
        let target_vec = TestVecSerialization::<Target>(builder.add_virtual_targets(7));

        // test `MerkleCapTarget` serialization
        let encoded = bincode::serialize(&merkle_cap).unwrap();
        let decoded: TestSerialization<MerkleCapTarget> = bincode::deserialize(&encoded).unwrap();
        assert_eq!(merkle_cap.0, decoded.0);

        // test `MerkleProofTarget` serialization
        let encoded = bincode::serialize(&merkle_proof).unwrap();
        let decoded: TestSerialization<MerkleProofTarget> = bincode::deserialize(&encoded).unwrap();
        assert_eq!(merkle_proof.0, decoded.0);

        // test `ProofWithPublicInputsTarget` serialization
        let encoded = bincode::serialize(&proof).unwrap();
        let decoded: TestSerialization<ProofWithPublicInputsTarget<D>> =
            bincode::deserialize(&encoded).unwrap();
        assert_eq!(proof.0, decoded.0);

        // test `VerifierCircuitTarget` serialization
        let encoded = bincode::serialize(&vd).unwrap();
        let decoded: TestSerialization<VerifierCircuitTarget> =
            bincode::deserialize(&encoded).unwrap();
        assert_eq!(vd.0, decoded.0);

        // test short target array serialization
        let encoded = bincode::serialize(&short_target_arr).unwrap();
        let decoded: TestArraySerialization<Target, 13> = bincode::deserialize(&encoded).unwrap();
        assert_eq!(short_target_arr.0, decoded.0);

        // test long target array serialization
        let encoded = bincode::serialize(&long_target_arr).unwrap();
        let decoded: TestArraySerialization<Target, 42> = bincode::deserialize(&encoded).unwrap();
        assert_eq!(long_target_arr.0, decoded.0);

        // try to deserialize an array with wrong length
        let decoded: Result<TestArraySerialization<Target, 43>, _> = bincode::deserialize(&encoded);
        assert!(decoded.is_err());

        // test vector of targets serialization
        let encoded = bincode::serialize(&target_vec).unwrap();
        let decoded: TestVecSerialization<Target> = bincode::deserialize(&encoded).unwrap();
        assert_eq!(target_vec.0, decoded.0);
    }
}
