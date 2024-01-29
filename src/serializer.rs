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

#[cfg(test)]
mod test {

    use std::os::unix::thread;

    use anyhow::Result;
    use ark_bn254::G1Affine;
    use ark_std::UniformRand;
    use plonky2::field::types::Field;
    use plonky2::{
        iop::witness::{PartialWitness, WitnessWrite},
        plonk::{
            circuit_builder::CircuitBuilder,
            circuit_data::{CircuitConfig, ProverOnlyCircuitData},
            config::{GenericConfig, PoseidonGoldilocksConfig},
            prover::prove,
        },
        util::timing::TimingTree,
    };
    use plonky2_bn254::curves::g1curve_target::G1Target;
    use plonky2_crypto::hash::keccak256::WitnessHashKeccak;
    use plonky2_crypto::hash::{
        keccak256::{CircuitBuilderHashKeccak, KECCAK256_R},
        CircuitBuilderHash,
    };
    use rand::{thread_rng, Rng};

    use crate::utils::{keccak256, verify_proof_tuple};

    use super::{GateSerializer, GeneratorSerializer};
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;
    #[test]
    fn test_proof_serialization2() -> Result<()> {
        crate::benches::init_logging();
        let config = CircuitConfig::standard_ecc_config();
        let mut builder = CircuitBuilder::new(config);
        let mut pw = PartialWitness::new();
        let hash_input = builder.add_virtual_hash_input_target(1, KECCAK256_R);
        let hash_output = builder.hash_keccak256(&hash_input);
        let a = builder.add_virtual_target();
        let b = builder.add_virtual_target();
        let c = builder.mul(a, b);
        let p1 = G1Target::empty(&mut builder);
        let p2 = G1Target::empty(&mut builder);
        p1.add(&mut builder, &p2);
        builder.register_public_input(c);

        pw.set_target(a, F::from_canonical_u8(2));
        pw.set_target(b, F::from_canonical_u8(3));
        p1.set_witness(&mut pw, &G1Affine::rand(&mut thread_rng()));
        p2.set_witness(&mut pw, &G1Affine::rand(&mut thread_rng()));
        let hin = rand::thread_rng().gen::<[u8; 32]>();
        let hout = keccak256(&hin[..]);
        pw.set_keccak256_input_target(&hash_input, &hin);
        pw.set_keccak256_output_target(&hash_output, &hout);
        let data = builder.build::<C>();
        let proof = data.prove(pw.clone()).unwrap();

        let gate_serializer = GateSerializer {};
        let generator = GeneratorSerializer::<C, D>::new();
        if let Err(e) = data.prover_only.to_bytes(&generator, &data.common) {
            panic!("error: {:?}", e);
        }

        let prover_data_buff = data.prover_only.to_bytes(&generator, &data.common).unwrap();
        let prover_data_exp = ProverOnlyCircuitData::<F, C, D>::from_bytes(
            &prover_data_buff,
            &generator,
            &data.common,
        )
        .unwrap();
        let proof = prove(
            &prover_data_exp,
            &data.common,
            pw,
            &mut TimingTree::default(),
        )
        .unwrap();

        let tuple = (proof, data.verifier_only, data.common);
        verify_proof_tuple(&tuple)?;
        Ok(())
    }
}
