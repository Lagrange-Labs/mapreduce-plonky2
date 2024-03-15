//! Plonky2 documentation
#![warn(missing_docs)]
#![feature(generic_const_exprs)]
#![feature(generic_arg_infer)]
use anyhow::Result;
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    plonk::{
        circuit_data::{CommonCircuitData, VerifierOnlyCircuitData},
        config::GenericConfig,
        proof::{CompressedProofWithPublicInputs, ProofWithPublicInputs},
    },
};
use serde::{Deserialize, Serialize};

mod benches;
pub mod eth;

pub mod api;
mod array;
mod block;
pub(crate) mod circuit;
mod group_hashing;
mod hash;
mod keccak;
mod merkle_tree;
mod mpt_sequential;
mod rlp;
pub mod state;
pub mod storage;
pub mod types;
mod utils;
/// Bundle containing the raw proof, the verification key, and some common data
/// necessary for prover and verifier.
/// TODO: This is a temporary tuple. We need to save the verification key separately.
pub(crate) type ProofTuple<F, C, const D: usize> = (
    ProofWithPublicInputs<F, C, D>,
    VerifierOnlyCircuitData<C, D>,
    CommonCircuitData<F, D>,
);

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ByteProofTuple {
    proof_bytes: Vec<u8>,
    verification_data: Vec<u8>,
    common_data: Vec<u8>,
}

impl ByteProofTuple {
    fn from_proof_tuple<
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F>,
        const D: usize,
    >(
        proof_tuple: ProofTuple<F, C, D>,
    ) -> Result<Vec<u8>> {
        let (proof, vd, cd) = proof_tuple;
        let compressed_proof = proof.compress(&vd.circuit_digest, &cd)?;
        let proof_bytes = compressed_proof.to_bytes();
        let verification_data = vd
            .to_bytes()
            .map_err(|e| anyhow::anyhow!("can't serialize vk: {:?}", e))?;
        //let common_data = bincode::serialize(&cd)?;
        let gate_serializer = plonky2_crypto::u32::gates::HashGateSerializer;
        let common_data = cd
            .to_bytes(&gate_serializer)
            .map_err(|e| anyhow::anyhow!("can't serialize cd: {:?}", e))?; // nikko TODO: this is a hack, we need to serialize the cd properly
        let btp = ByteProofTuple {
            proof_bytes,
            verification_data,
            common_data,
        };
        let buff = bincode::serialize(&btp)?;
        Ok(buff)
    }

    fn into_proof_tuple<
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F>,
        const D: usize,
    >(
        proof_bytes: &[u8],
    ) -> Result<ProofTuple<F, C, D>> {
        let btp: ByteProofTuple = bincode::deserialize(proof_bytes)?;
        let vd = VerifierOnlyCircuitData::from_bytes(btp.verification_data)
            .map_err(|e| anyhow::anyhow!(e))?;
        //let cd: CommonCircuitData<F, D> = bincode::deserialize(&btp.common_data)?;
        let gate_serializer = plonky2_crypto::u32::gates::HashGateSerializer;
        let cd = CommonCircuitData::<F, D>::from_bytes(btp.common_data, &gate_serializer)
            .map_err(|e| anyhow::anyhow!("can't deserialize common data {:?}", e))?;
        let compressed_proof = CompressedProofWithPublicInputs::from_bytes(btp.proof_bytes, &cd)?;
        let proof = compressed_proof.decompress(&vd.circuit_digest, &cd)?;
        Ok((proof, vd, cd))
    }
}

#[cfg(test)]
mod test {
    use anyhow::Result;
    use ethers::utils::keccak256;
    use plonky2::{
        field::types::Field,
        iop::witness::{PartialWitness, WitnessWrite},
        plonk::{
            circuit_builder::CircuitBuilder,
            circuit_data::CircuitConfig,
            config::{GenericConfig, PoseidonGoldilocksConfig},
        },
    };
    use plonky2_crypto::hash::{
        keccak256::{CircuitBuilderHashKeccak, WitnessHashKeccak, KECCAK256_R},
        CircuitBuilderHash,
    };
    use plonky2x::backend::circuit::config::{DefaultParameters, Groth16WrapperParameters};
    use plonky2x::backend::circuit::CircuitBuild;
    use plonky2x::backend::wrapper::wrap::WrappedCircuit;
    use plonky2x::prelude::CircuitBuilder as CBuilder;
    use rand::Rng;

    use crate::{utils::verify_proof_tuple, ByteProofTuple};

    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    #[test]
    fn test_proof_serialization() -> Result<()> {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::new(config);
        let mut pw = PartialWitness::new();
        let hash_input = builder.add_virtual_hash_input_target(1, KECCAK256_R);
        let hash_output = builder.hash_keccak256(&hash_input);
        let a = builder.add_virtual_target();
        let b = builder.add_virtual_target();
        let c = builder.mul(a, b);
        builder.register_public_input(c);
        pw.set_target(a, F::from_canonical_u8(2));
        pw.set_target(b, F::from_canonical_u8(3));
        let hin = rand::thread_rng().gen::<[u8; 32]>();
        let hout = keccak256(&hin[..]);
        pw.set_keccak256_input_target(&hash_input, &hin);
        pw.set_keccak256_output_target(&hash_output, &hout);
        let data = builder.build();
        let proof = data.prove(pw).unwrap();
        let tuple = (proof, data.verifier_only, data.common);
        verify_proof_tuple(&tuple)?;
        let expected = tuple.clone();
        let serialized = ByteProofTuple::from_proof_tuple::<F, C, D>(tuple).unwrap();
        let deserialized = ByteProofTuple::into_proof_tuple::<F, C, D>(&serialized).unwrap();
        assert_eq!(expected, deserialized);
        Ok(())
    }

    #[test]
    fn test_groth16() {
        type L = DefaultParameters;
        let config = CircuitConfig::standard_recursion_config();
        let mut cb = CircuitBuilder::<F, D>::new(config);

        let [a, b] = [0; 2].map(|_| cb.add_virtual_target());
        let c = cb.add(a, b);

        let mut pw = PartialWitness::new();
        pw.set_target(a, F::ZERO);
        pw.set_target(b, F::ONE);
        pw.set_target(c, F::ONE);

        let data = cb.build::<C>();
        let proof = data.prove(pw).unwrap();

        let mut builder = CBuilder::<L, D>::new();
        builder.pre_build();
        let async_hints = CBuilder::<L, D>::async_hint_map(
            data.prover_only.generators.as_slice(),
            builder.async_hints,
        );

        let circuit = CircuitBuild {
            data,
            io: builder.io,
            async_hints,
        };

        let wrapper: WrappedCircuit<_, _, 2> =
            WrappedCircuit::<L, Groth16WrapperParameters, D>::build(circuit);
        let wrapped_proof = wrapper.prove(&proof).unwrap();

        let pi = serde_json::to_string_pretty(&wrapped_proof.proof).unwrap();
        std::fs::write("proof_with_public_inputs.json", pi).unwrap();

        let common = serde_json::to_string_pretty(&wrapped_proof.common_data).unwrap();
        std::fs::write("common_circuit_data.json", common).unwrap();

        let vk = serde_json::to_string_pretty(&wrapped_proof.verifier_data).unwrap();
        std::fs::write("verifier_only_circuit_data.json", vk).unwrap();
    }
}
