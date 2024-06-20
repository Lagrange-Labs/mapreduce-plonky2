use std::marker::PhantomData;

use plonky2::plonk::circuit_data::VerifierCircuitData;
use plonky2::{
    field::extension::Extendable,
    gadgets::{
        arithmetic::EqualityGenerator,
        arithmetic_extension::QuotientGeneratorExtension,
        range_check::LowHighGenerator,
        split_base::BaseSumGenerator,
        split_join::{SplitGenerator, WireSplitGenerator},
    },
    gates::{
        arithmetic_base::{ArithmeticBaseGenerator, ArithmeticGate},
        arithmetic_extension::{ArithmeticExtensionGate, ArithmeticExtensionGenerator},
        base_sum::{BaseSplitGenerator, BaseSumGate},
        constant::ConstantGate,
        coset_interpolation::{CosetInterpolationGate, InterpolationGenerator},
        exponentiation::{ExponentiationGate, ExponentiationGenerator},
        lookup::{LookupGate, LookupGenerator},
        lookup_table::{LookupTableGate, LookupTableGenerator},
        multiplication_extension::{MulExtensionGate, MulExtensionGenerator},
        noop::NoopGate,
        poseidon::{PoseidonGate, PoseidonGenerator},
        poseidon_mds::{PoseidonMdsGate, PoseidonMdsGenerator},
        public_input::PublicInputGate,
        random_access::{RandomAccessGate, RandomAccessGenerator},
        reducing::{ReducingGate, ReducingGenerator},
        reducing_extension::{
            ReducingExtensionGate, ReducingGenerator as ReducingExtensionGenerator,
        },
    },
    get_gate_tag_impl, get_generator_tag_impl,
    hash::{hash_types::RichField, merkle_tree::MerkleTree},
    impl_gate_serializer, impl_generator_serializer,
    iop::generator::{
        ConstantGenerator, CopyGenerator, NonzeroTestGenerator, RandomValueGenerator,
    },
    plonk::{
        circuit_data::{CircuitData, CommonCircuitData, VerifierOnlyCircuitData},
        config::{AlgebraicHasher, GenericConfig, Hasher},
    },
    read_gate_impl, read_generator_impl,
    recursion::dummy_circuit::DummyProofGenerator,
    util::serialization::{Buffer, GateSerializer, Read, WitnessGeneratorSerializer, Write},
};
use plonky2_crypto::{
    biguint::BigUintDivRemGenerator,
    u32::{
        arithmetic_u32::SplitToU32Generator,
        gates::{
            add_many_u32::{U32AddManyGate, U32AddManyGenerator},
            arithmetic_u32::{U32ArithmeticGate, U32ArithmeticGenerator},
            comparison::{ComparisonGate, ComparisonGenerator},
            interleave_u32::{U32InterleaveGate, U32InterleaveGenerator},
            range_check_u32::{U32RangeCheckGate, U32RangeCheckGenerator},
            subtraction_u32::{U32SubtractionGate, U32SubtractionGenerator},
            uninterleave_to_b32::{UninterleaveToB32Gate, UninterleaveToB32Generator},
            uninterleave_to_u32::{UninterleaveToU32Gate, UninterleaveToU32Generator},
        },
    },
};
use plonky2_ecgfp5::{
    curve::base_field::InverseOrZero,
    gadgets::base_field::{QuinticQuotientGenerator, QuinticSqrtGenerator},
};

use crate::u256::UInt256DivGenerator;

use super::{FromBytes, SerializationError, ToBytes};

impl<F: RichField, H: Hasher<F>> ToBytes for MerkleTree<F, H> {
    fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        buffer
            .write_merkle_tree(self)
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

impl<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize> FromBytes
    for VerifierCircuitData<F, C, D>
{
    fn from_bytes(bytes: &[u8]) -> Result<Self, SerializationError> {
        Ok(Self::from_bytes(bytes.to_vec(), &CustomGateSerializer)?)
    }
}

impl<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize> ToBytes
    for VerifierCircuitData<F, C, D>
{
    fn to_bytes(&self) -> Vec<u8> {
        self.to_bytes(&CustomGateSerializer)
            .expect("Writing to a byte-vector cannot fail.")
    }
}

impl<F: SerializableRichField<D>, C: GenericConfig<D, F = F> + 'static, const D: usize> ToBytes
    for CircuitData<F, C, D>
where
    C::Hasher: AlgebraicHasher<F>,
{
    fn to_bytes(&self) -> Vec<u8> {
        let generator_serializer = CustomGeneratorSerializer::<C, D> {
            _phantom: PhantomData,
        };
        self.to_bytes(&CustomGateSerializer, &generator_serializer)
            .expect("Writing to a byte-vector cannot fail.")
    }
}

impl<F: SerializableRichField<D>, C: GenericConfig<D, F = F> + 'static, const D: usize> FromBytes
    for CircuitData<F, C, D>
where
    C::Hasher: AlgebraicHasher<F>,
{
    fn from_bytes(bytes: &[u8]) -> Result<Self, SerializationError> {
        let generator_serializer = CustomGeneratorSerializer::<C, D> {
            _phantom: PhantomData,
        };
        Ok(CircuitData::<F, C, D>::from_bytes(
            bytes,
            &CustomGateSerializer,
            &generator_serializer,
        )?)
    }
}

impl<F: RichField + Extendable<D>, const D: usize> ToBytes for CommonCircuitData<F, D> {
    fn to_bytes(&self) -> Vec<u8> {
        self.to_bytes(&CustomGateSerializer)
            .expect("Writing to a byte-vector cannot fail.")
    }
}

impl<F: RichField + Extendable<D>, const D: usize> FromBytes for CommonCircuitData<F, D> {
    fn from_bytes(bytes: &[u8]) -> Result<Self, SerializationError> {
        Ok(Self::from_bytes(bytes.to_vec(), &CustomGateSerializer)?)
    }
}
/// Trait alias for `RichField` types compatible with the serialization of `CircuitData` provided
/// in this crate
pub trait SerializableRichField<const D: usize>:
    RichField + Extendable<D> + Extendable<5> + InverseOrZero
{
}

impl<const D: usize, T: RichField + Extendable<D> + Extendable<5> + InverseOrZero>
    SerializableRichField<D> for T
{
}
/// Serializer for the set of generators employed in our map-reduce circuits
pub struct CustomGeneratorSerializer<C: GenericConfig<D>, const D: usize> {
    pub _phantom: PhantomData<C>,
}

impl<F, C, const D: usize> WitnessGeneratorSerializer<F, D> for CustomGeneratorSerializer<C, D>
where
    F: SerializableRichField<D>,
    C: GenericConfig<D, F = F> + 'static,
    C::Hasher: AlgebraicHasher<F>,
{
    impl_generator_serializer! {
        DefaultGeneratorSerializer,
        ArithmeticBaseGenerator<F, D>,
        ArithmeticExtensionGenerator<F, D>,
        BaseSplitGenerator<2>,
        BaseSumGenerator<2>,
        BaseSplitGenerator<4>,
        BaseSumGenerator<4>,
        ConstantGenerator<F>,
        CopyGenerator,
        DummyProofGenerator<F, C, D>,
        EqualityGenerator,
        ExponentiationGenerator<F, D>,
        InterpolationGenerator<F, D>,
        LookupGenerator,
        LookupTableGenerator,
        LowHighGenerator,
        MulExtensionGenerator<F, D>,
        NonzeroTestGenerator,
        PoseidonGenerator<F, D>,
        PoseidonMdsGenerator<D>,
        QuotientGeneratorExtension<D>,
        RandomAccessGenerator<F, D>,
        RandomValueGenerator,
        ReducingGenerator<D>,
        ReducingExtensionGenerator<D>,
        SplitGenerator,
        WireSplitGenerator,
        // hash generators added
        BigUintDivRemGenerator<F,D>,
        SplitToU32Generator<F, D>,
        U32AddManyGenerator<F,D>,
        U32ArithmeticGenerator<F,D>,
        ComparisonGenerator<F,D>,
        U32InterleaveGenerator,
        U32RangeCheckGenerator<F,D>,
        U32SubtractionGenerator<F,D>,
        UninterleaveToB32Generator,
        UninterleaveToU32Generator,
        // ecgfp5 generators added
        QuinticQuotientGenerator,
        QuinticSqrtGenerator,
        // uint256 generators added
        UInt256DivGenerator
    }
}

/// Serializer for the set of gates employed in our map-reduce circuits
pub struct CustomGateSerializer;
impl<F: RichField + Extendable<D>, const D: usize> GateSerializer<F, D> for CustomGateSerializer {
    impl_gate_serializer! {
        DefaultGateSerializer,
        ArithmeticGate,
        ArithmeticExtensionGate<D>,
        BaseSumGate<2>,
        BaseSumGate<4>,
        ConstantGate,
        CosetInterpolationGate<F, D>,
        ExponentiationGate<F, D>,
        LookupGate,
        LookupTableGate,
        MulExtensionGate<D>,
        NoopGate,
        PoseidonMdsGate<F, D>,
        PoseidonGate<F, D>,
        PublicInputGate,
        RandomAccessGate<F, D>,
        ReducingExtensionGate<D>,
        ReducingGate<D>,
        //hash gates
        U32AddManyGate<F,D>,
        U32ArithmeticGate<F, D>,
        ComparisonGate<F, D>,
        U32InterleaveGate,
        U32RangeCheckGate<F,D>,
        U32SubtractionGate<F,D>,
        UninterleaveToB32Gate,
        UninterleaveToU32Gate
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
            F: SerializableRichField<D>,
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
