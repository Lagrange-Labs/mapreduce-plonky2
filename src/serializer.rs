use std::marker::PhantomData;

use anyhow::Result;
use plonky2::gadgets::arithmetic::EqualityGenerator;
use plonky2::gadgets::arithmetic_extension::QuotientGeneratorExtension;
use plonky2::gadgets::range_check::LowHighGenerator;
use plonky2::gadgets::split_base::BaseSumGenerator;
use plonky2::gadgets::split_join::{SplitGenerator, WireSplitGenerator};
use plonky2::gates::arithmetic_base::{ArithmeticBaseGenerator, ArithmeticGate};
use plonky2::gates::arithmetic_extension::{ArithmeticExtensionGate, ArithmeticExtensionGenerator};
use plonky2::gates::base_sum::{BaseSplitGenerator, BaseSumGate};
use plonky2::gates::constant::ConstantGate;
use plonky2::gates::coset_interpolation::{CosetInterpolationGate, InterpolationGenerator};
use plonky2::gates::exponentiation::{ExponentiationGate, ExponentiationGenerator};
use plonky2::gates::lookup::{LookupGate, LookupGenerator};
use plonky2::gates::lookup_table::{LookupTableGate, LookupTableGenerator};
use plonky2::gates::multiplication_extension::{MulExtensionGate, MulExtensionGenerator};
use plonky2::gates::noop::NoopGate;
use plonky2::gates::poseidon::{PoseidonGate, PoseidonGenerator};
use plonky2::gates::poseidon_mds::{PoseidonMdsGate, PoseidonMdsGenerator};
use plonky2::gates::public_input::PublicInputGate;
use plonky2::gates::random_access::{RandomAccessGate, RandomAccessGenerator};
use plonky2::gates::reducing::{ReducingGate, ReducingGenerator};
use plonky2::gates::reducing_extension::{
    ReducingExtensionGate, ReducingGenerator as ReducingExtensionGenerator,
};
use plonky2::get_gate_tag_impl;
use plonky2::iop::generator::{
    ConstantGenerator, CopyGenerator, NonzeroTestGenerator, RandomValueGenerator,
};
use plonky2::plonk::circuit_data::{
    ProverOnlyCircuitData, VerifierCircuitData, VerifierOnlyCircuitData,
};
use plonky2::read_gate_impl;
use plonky2::read_generator_impl;
use plonky2::recursion::dummy_circuit::DummyProofGenerator;
use plonky2::util::serialization::GateSerializer as PlonkyGateSerializer;
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    impl_generator_serializer,
    plonk::{
        circuit_data::CommonCircuitData,
        config::{AlgebraicHasher, GenericConfig},
    },
    util::serialization::WitnessGeneratorSerializer,
};
use plonky2::{get_generator_tag_impl, impl_gate_serializer};
use plonky2_bn254::fields::bn254base::Bn254Base;
use plonky2_crypto::biguint::BigUintDivRemGenerator;
use plonky2_crypto::u32::arithmetic_u32::SplitToU32Generator;
use plonky2_crypto::u32::gates::add_many_u32::{U32AddManyGate, U32AddManyGenerator};
use plonky2_crypto::u32::gates::arithmetic_u32::{U32ArithmeticGate, U32ArithmeticGenerator};
use plonky2_crypto::u32::gates::comparison::{ComparisonGate, ComparisonGenerator};
use plonky2_crypto::u32::gates::interleave_u32::{U32InterleaveGate, U32InterleaveGenerator};
use plonky2_crypto::u32::gates::range_check_u32::{U32RangeCheckGate, U32RangeCheckGenerator};
use plonky2_crypto::u32::gates::subtraction_u32::{U32SubtractionGate, U32SubtractionGenerator};
use plonky2_crypto::u32::gates::uninterleave_to_b32::{
    UninterleaveToB32Gate, UninterleaveToB32Generator,
};
use plonky2_crypto::u32::gates::uninterleave_to_u32::{
    UninterleaveToU32Gate, UninterleaveToU32Generator,
};
use plonky2_ecdsa::gadgets::{
    glv::GLVDecompositionGenerator,
    nonnative::{
        NonNativeAdditionGenerator, NonNativeInverseGenerator, NonNativeMultiplicationGenerator,
        NonNativeSubtractionGenerator,
    },
};

pub struct GeneratorSerializer<C: GenericConfig<D>, const D: usize> {
    pub _phantom: PhantomData<C>,
}
impl<C: GenericConfig<D>, const D: usize> GeneratorSerializer<C, D> {
    pub fn new() -> Self {
        Self {
            _phantom: PhantomData,
        }
    }
}

impl<F, C, const D: usize> WitnessGeneratorSerializer<F, D> for GeneratorSerializer<C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    C::Hasher: AlgebraicHasher<F>,
{
    impl_generator_serializer! {
        DefaultGeneratorSerializer,
        ArithmeticBaseGenerator<F, D>,
        ArithmeticExtensionGenerator<F, D>,
        BaseSplitGenerator<2>,
        BaseSumGenerator<2>,
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
        // ecdsa
        GLVDecompositionGenerator<F,D>,
        NonNativeSubtractionGenerator<F,D,Bn254Base>,
        NonNativeInverseGenerator<F,D,Bn254Base>,
        NonNativeMultiplicationGenerator<F,D,Bn254Base>,
        NonNativeAdditionGenerator<F,D,Bn254Base>
    }
}

pub struct GateSerializer;
impl<F: RichField + Extendable<D>, const D: usize> PlonkyGateSerializer<F, D> for GateSerializer {
    impl_gate_serializer! {
        DefaultGateSerializer,
        ArithmeticGate,
        ArithmeticExtensionGate<D>,
        BaseSumGate<2>,
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
