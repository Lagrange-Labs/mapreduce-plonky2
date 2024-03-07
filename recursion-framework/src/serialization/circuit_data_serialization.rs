use std::marker::PhantomData;

use plonky2::{
    field::extension::Extendable,
    hash::{hash_types::RichField, merkle_tree::MerkleTree},
    plonk::{
        circuit_data::{CircuitData, CommonCircuitData, VerifierOnlyCircuitData},
        config::{AlgebraicHasher, GenericConfig, Hasher},
    },
    util::serialization::{Buffer, Read, Write},
};
use plonky2_crypto::u32::gates::{HashGateSerializer, HashGeneratorSerializer};

use super::{FromBytes, SerializationError, ToBytes};

impl<F: RichField, H: Hasher<F>> ToBytes for MerkleTree<F, H> {
    fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        buffer
            .write_merkle_tree(&self)
            .expect("Writing to a byte-vector cannot fail.");
        buffer
    }
}

impl<F: RichField, H: Hasher<F>> FromBytes for MerkleTree<F, H> {
    fn from_bytes(bytes: &[u8]) -> Result<Self, SerializationError> {
        let mut buffer = Buffer::new(bytes);
        Ok(buffer.read_merkle_tree()?)
    }
}

impl<C: GenericConfig<D>, const D: usize> ToBytes for VerifierOnlyCircuitData<C, D> {
    fn to_bytes(&self) -> Vec<u8> {
        self.to_bytes()
            .expect("Writing to a byte-vector cannot fail.")
    }
}

impl<C: GenericConfig<D>, const D: usize> FromBytes for VerifierOnlyCircuitData<C, D> {
    fn from_bytes(bytes: &[u8]) -> Result<Self, SerializationError> {
        Ok(Self::from_bytes(bytes.to_vec())?)
    }
}

impl<F: RichField + Extendable<D>, C: GenericConfig<D, F = F> + 'static, const D: usize> ToBytes
    for CircuitData<F, C, D>
where
    C::Hasher: AlgebraicHasher<F>,
{
    fn to_bytes(&self) -> Vec<u8> {
        let generator_serializer = HashGeneratorSerializer::<C, D> {
            _phantom: PhantomData::default(),
        };
        self.to_bytes(&HashGateSerializer, &generator_serializer)
            .expect("Writing to a byte-vector cannot fail.")
    }
}

impl<F: RichField + Extendable<D>, C: GenericConfig<D, F = F> + 'static, const D: usize> FromBytes
    for CircuitData<F, C, D>
where
    C::Hasher: AlgebraicHasher<F>,
{
    fn from_bytes(bytes: &[u8]) -> Result<Self, SerializationError> {
        let generator_serializer = HashGeneratorSerializer::<C, D> {
            _phantom: PhantomData::default(),
        };
        Ok(CircuitData::<F, C, D>::from_bytes(
            bytes,
            &HashGateSerializer,
            &generator_serializer,
        )?)
    }
}

impl<F: RichField + Extendable<D>, const D: usize> ToBytes for CommonCircuitData<F, D> {
    fn to_bytes(&self) -> Vec<u8> {
        self.to_bytes(&HashGateSerializer)
            .expect("Writing to a byte-vector cannot fail.")
    }
}

impl<F: RichField + Extendable<D>, const D: usize> FromBytes for CommonCircuitData<F, D> {
    fn from_bytes(bytes: &[u8]) -> Result<Self, SerializationError> {
        Ok(Self::from_bytes(bytes.to_vec(), &HashGateSerializer)?)
    }
}

#[cfg(test)]
pub(super) mod tests {
    use plonky2::field::types::{Field, Sample};
    use plonky2::{
        gates::noop::NoopGate,
        plonk::{
            circuit_builder::CircuitBuilder, circuit_data::CircuitConfig,
            config::PoseidonGoldilocksConfig,
        },
    };
    use rstest::rstest;
    use serde::{Deserialize, Serialize};

    use crate::serialization::{deserialize, serialize};

    use super::*;

    // build a test circuit to have an instance of `CircuitData` to employ in tests
    pub(crate) fn build_test_circuit<
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F> + 'static,
        const D: usize,
    >() -> CircuitData<F, C, D>
    where
        C::Hasher: AlgebraicHasher<F>,
    {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        _ = builder.add_virtual_public_input_arr::<4>();
        for _ in 0..42 {
            builder.add_gate(NoopGate, vec![]);
        }

        builder.build::<C>()
    }

    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    #[test]
    fn test_circuit_data_serialization() {
        #[derive(Serialize, Deserialize)]
        #[serde(bound = "")]
        struct TestSerialization<
            F: RichField + Extendable<D>,
            C: GenericConfig<D, F = F> + 'static,
            const D: usize,
        >
        where
            C::Hasher: AlgebraicHasher<F>,
        {
            #[serde(serialize_with = "serialize", deserialize_with = "deserialize")]
            cd: CircuitData<F, C, D>,
            #[serde(serialize_with = "serialize", deserialize_with = "deserialize")]
            common: CommonCircuitData<F, D>,
            #[serde(serialize_with = "serialize", deserialize_with = "deserialize")]
            vd: VerifierOnlyCircuitData<C, D>,
        }

        let data = build_test_circuit();

        let vd = data.verifier_only.clone();
        let common = data.common.clone();

        let serialized_struct = TestSerialization::<F, C, D> {
            cd: data,
            common,
            vd,
        };

        let encoded = bincode::serialize(&serialized_struct).unwrap();

        let decoded_data: TestSerialization<F, C, D> = bincode::deserialize(&encoded).unwrap();

        assert_eq!(decoded_data.cd, serialized_struct.cd);

        assert_eq!(decoded_data.common, serialized_struct.common);

        assert_eq!(decoded_data.vd, serialized_struct.vd);
    }

    #[rstest]
    #[case(6, 0)]
    #[case(16, 0)]
    #[case(17, 2)]
    #[case(32, 3)]
    fn test_merkle_tree_serialization(#[case] num_leaves: usize, #[case] cap_height: usize) {
        type H = <C as GenericConfig<D>>::Hasher;
        #[derive(Serialize, Deserialize)]
        struct TestMerkleTreeSerialization(
            #[serde(serialize_with = "serialize", deserialize_with = "deserialize")]
            MerkleTree<F, H>,
        );

        let mut leaves = (0..num_leaves)
            .map(|_| vec![F::rand(); 2])
            .collect::<Vec<_>>();
        let num_leaves_padded: usize = 1 << plonky2::util::log2_ceil(leaves.len());
        leaves.resize_with(num_leaves_padded, || vec![F::ZERO]);

        let mt = TestMerkleTreeSerialization(MerkleTree::new(leaves, cap_height));

        let encoded = bincode::serialize(&mt).unwrap();
        let decoded_mt: TestMerkleTreeSerialization = bincode::deserialize(&encoded).unwrap();

        assert_eq!(decoded_mt.0, mt.0);
    }
}
