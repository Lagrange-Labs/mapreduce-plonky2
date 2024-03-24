//! This module implements the logic of verifying that a Merkle recursive proof
//! over a tree contains the same set of leaves than a MPT recursive proof over
//! a different tree. This is the digest translation mechanism, passing from one
//! tree to another.

use super::{
    length_match::PublicInputs as MPTPublicInputs, lpn::PublicInputs as MerklePublicInputs,
};
use crate::{
    api::{default_config, deserialize_proof, serialize_proof, ProofWithVK},
    array::Array,
    group_hashing::{CircuitBuilderGroupHashing, N},
    keccak::{OutputHash, PACKED_HASH_LEN},
    types::{PackedAddressTarget, PACKED_ADDRESS_LEN},
    utils::{
        convert_point_to_curve_target, convert_slice_to_curve_point, convert_u32_fields_to_u8_vec,
    },
    verifier_gadget::VerifierTarget,
};
use anyhow::Result;
use ethers::types::{H160, H256};
use plonky2::{
    field::goldilocks_field::GoldilocksField,
    hash::hash_types::{HashOutTarget, RichField, NUM_HASH_OUT_ELTS},
    iop::{target::Target, witness::PartialWitness},
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitData, VerifierCircuitData},
        proof::ProofWithPublicInputs,
    },
};
use plonky2_crypto::u32::arithmetic_u32::U32Target;
use plonky2_ecgfp5::gadgets::curve::{CircuitBuilderEcGFp5, CurveTarget};
use recursion_framework::{
    framework::{
        RecursiveCircuits, RecursiveCircuitsVerifierGagdet, RecursiveCircuitsVerifierTarget,
    },
    serialization::{deserialize, serialize},
};
use serde::{Deserialize, Serialize};
use std::array;

/// This is a wrapper around an array of targets set as public inputs of any
/// proof generated in this module. They all share the same structure.
/// `D` Digest of all the values processed
/// `C1` MPT root of blockchain storage trie
/// `C2` Merkle root of LPN’s storage database (merkle tree)
/// `M` Storage slot of the mapping
/// `S` Storage slot of the variable holding the length
#[derive(Clone, Debug)]
pub struct PublicInputs<'a, T: Clone> {
    pub(crate) proof_inputs: &'a [T],
}

impl<'a, F: RichField> PublicInputs<'a, F> {
    /// Get the hash value of storage MPT root (C1).
    pub fn mpt_root_value(&self) -> H256 {
        // The root hash is packed as [u32; 8] in public inputs. This code
        // converts it to [u8; 32] as H256.
        let bytes = convert_u32_fields_to_u8_vec(self.mpt_root_data());

        H256(bytes.try_into().unwrap())
    }
}

impl<'a> PublicInputs<'a, Target> {
    pub fn register(
        cb: &mut CircuitBuilder<GoldilocksField, 2>,
        digest: &CurveTarget,
        mpt_root_hash: &OutputHash,
        merkle_root_hash: &HashOutTarget,
        mapping_slot: Target,
        length_slot: Target,
    ) {
        cb.register_curve_public_input(*digest);
        mpt_root_hash.register_as_public_input(cb);
        cb.register_public_inputs(&merkle_root_hash.elements);
        cb.register_public_input(mapping_slot);
        cb.register_public_input(length_slot);
    }

    /// Return the curve point target of digest defined over the public inputs.
    pub fn digest(&self) -> CurveTarget {
        convert_point_to_curve_target(self.digest_data())
    }

    pub fn mpt_root(&self) -> OutputHash {
        let data = self.mpt_root_data();
        array::from_fn(|i| U32Target(data[i])).into()
    }
}

impl<'a, T: Copy> PublicInputs<'a, T> {
    /// `D` Digest of all the values processed
    /// `C1` MPT root of blockchain storage trie
    /// `C2` Merkle root of LPN’s storage database (merkle tree)
    /// `A` Address of smart contract
    /// `M` Storage slot of the mapping
    /// `S` Storage slot of the variable holding the length
    pub(crate) const D_IDX: usize = 0;
    pub(crate) const C1_IDX: usize = Self::D_IDX + 2 * N + 1; // 2*N+1 for curve target
    pub(crate) const C2_IDX: usize = Self::C1_IDX + PACKED_HASH_LEN;
    pub(crate) const M_IDX: usize = Self::C2_IDX + NUM_HASH_OUT_ELTS;
    pub(crate) const S_IDX: usize = Self::M_IDX + 1;
    pub(crate) const TOTAL_LEN: usize = Self::S_IDX + 1;

    pub fn from(arr: &'a [T]) -> Self {
        Self { proof_inputs: arr }
    }

    /// Transform a list of elements to a curve point.
    pub fn digest_data(&self) -> ([T; 5], [T; 5], T) {
        convert_slice_to_curve_point(&self.proof_inputs[Self::D_IDX..])
    }

    pub fn mpt_root_data(&self) -> &[T] {
        &self.proof_inputs[Self::C1_IDX..Self::C2_IDX]
    }

    pub fn merkle_root_data(&self) -> &[T] {
        &self.proof_inputs[Self::C2_IDX..Self::M_IDX]
    }

    pub fn mapping_slot(&self) -> T {
        self.proof_inputs[Self::M_IDX]
    }

    pub fn length_slot(&self) -> T {
        self.proof_inputs[Self::S_IDX]
    }
}

/// Digest equivalence circuit
#[derive(Clone, Debug)]
struct DigestEqualCircuit;

impl DigestEqualCircuit {
    /// Build for circuit.
    pub fn build(
        cb: &mut CircuitBuilder<GoldilocksField, 2>,
        mpt_pi: &[Target],
        merkle_pi: &[Target],
    ) {
        let mpt_pi = MPTPublicInputs::from(mpt_pi);
        let merkle_pi = MerklePublicInputs::from(merkle_pi);

        // Constrain both digests are equal.
        let mpt_digest = mpt_pi.digest();
        let merkle_digest = merkle_pi.digest();
        cb.connect_curve_points(mpt_digest, merkle_digest);

        // Register the public inputs.
        PublicInputs::register(
            cb,
            &mpt_digest,
            &mpt_pi.root_hash(),
            &merkle_pi.root_hash(),
            mpt_pi.mapping_slot(),
            mpt_pi.length_slot(),
        );
    }
}

type F = crate::api::F;
type C = crate::api::C;
const D: usize = crate::api::D;

#[derive(Serialize, Deserialize)]
pub(crate) struct Parameters {
    #[serde(serialize_with = "serialize", deserialize_with = "deserialize")]
    data: CircuitData<F, C, D>,
    lpn_wires: RecursiveCircuitsVerifierTarget<D>,
    mpt_wires: VerifierTarget<D>,
}

impl Parameters {
    /// Build circuit parameters for digest equal circuit
    pub(crate) fn build(
        lpn_circuit_set: &RecursiveCircuits<F, C, D>,
        mpt_circuit_vd: &VerifierCircuitData<F, C, D>,
    ) -> Self {
        const LPN_PUBLIC_INPUTS: usize = MerklePublicInputs::<Target>::TOTAL_LEN;
        let mut cb = CircuitBuilder::<F, D>::new(default_config());
        let mpt_wires = VerifierTarget::verify_proof(&mut cb, mpt_circuit_vd);
        let verifier_gadget = RecursiveCircuitsVerifierGagdet::<F, C, D, LPN_PUBLIC_INPUTS>::new(
            default_config(),
            lpn_circuit_set,
        );
        let lpn_wires = verifier_gadget.verify_proof_in_circuit_set(&mut cb);
        let mpt_pi = mpt_wires.get_proof().public_inputs.as_slice();
        let lpn_pi = lpn_wires.get_public_input_targets::<F, LPN_PUBLIC_INPUTS>();
        DigestEqualCircuit::build(&mut cb, mpt_pi, lpn_pi);

        let data = cb.build::<C>();

        Self {
            data,
            lpn_wires,
            mpt_wires,
        }
    }
    /// Generate proof for digest equal circuit employiing the circuit parameters found in  `self`
    /// and the necessary inputs values
    pub(crate) fn generate_proof(
        &self,
        lpn_circuit_set: &RecursiveCircuits<F, C, D>,
        lpn_proof: &ProofWithVK,
        mpt_proof: &ProofWithVK,
    ) -> Result<Vec<u8>> {
        let mut pw = PartialWitness::<F>::new();
        let (lpn_proof, lpn_vd) = lpn_proof.into();
        self.lpn_wires
            .set_target(&mut pw, lpn_circuit_set, lpn_proof, lpn_vd)
            .unwrap();
        let (mpt_proof, mpt_vd) = mpt_proof.into();
        self.mpt_wires.set_target(&mut pw, mpt_proof, mpt_vd);
        let proof = self.data.prove(pw)?;
        serialize_proof(&proof)
    }

    /// Get the `CircuitData` of the digest equal circuit
    pub(crate) fn circuit_data(&self) -> &CircuitData<F, C, D> {
        &self.data
    }
}
/// Data structure containing the inputs to be provided to the API in order to
/// generate a proof for the digest equal circuit
pub struct CircuitInput {
    lpn_proof: Vec<u8>,
    mpt_proof: Vec<u8>,
}

impl CircuitInput {
    /// Instantiate `CircuitInput` for digest equal circuit employing a proof for LPN storage circuits
    /// and a proof for the MPT length match circuits
    pub fn new(lpn_proof: Vec<u8>, mpt_proof: Vec<u8>) -> Self {
        Self {
            lpn_proof,
            mpt_proof,
        }
    }
}

impl TryInto<(ProofWithVK, ProofWithPublicInputs<F, C, D>)> for CircuitInput {
    type Error = anyhow::Error;

    fn try_into(
        self,
    ) -> std::prelude::v1::Result<(ProofWithVK, ProofWithPublicInputs<F, C, D>), Self::Error> {
        Ok((
            ProofWithVK::deserialize(&self.lpn_proof)?,
            deserialize_proof(&self.mpt_proof)?,
        ))
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;
    use crate::{
        api::tests::TestDummyCircuit,
        benches::init_logging,
        circuit::{test::run_circuit, UserCircuit},
        eth::{left_pad32, ProofQuery, StorageSlot},
        mpt_sequential::test::generate_random_storage_mpt,
        storage::{self, key::MappingSlot},
        utils::{convert_u8_to_u32_slice, keccak256, test::random_vector},
    };
    use eth_trie::Trie;
    use ethers::{
        providers::{Http, Provider},
        types::{spoof::storage, Address},
    };
    use plonky2::{
        field::types::{Field, Sample},
        hash::keccak,
        iop::witness::{PartialWitness, WitnessWrite},
        plonk::{
            circuit_builder::CircuitBuilder,
            config::{GenericConfig, PoseidonGoldilocksConfig},
        },
    };
    use plonky2::{hash::hash_types::HashOut, plonk::config::GenericHashOut};
    use plonky2_ecgfp5::curve::curve::{Point, WeierstrassPoint};
    use rand::thread_rng;
    use recursion_framework::framework_testing::TestingRecursiveCircuits;
    use serial_test::serial;
    use std::array;

    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    /// Test circuit
    #[derive(Clone, Debug)]
    struct TestCircuit {
        mpt_pi: Vec<F>,
        merkle_pi: Vec<F>,
    }

    impl UserCircuit<F, D> for TestCircuit {
        type Wires = (Vec<Target>, Vec<Target>);

        fn build(cb: &mut CircuitBuilder<F, D>) -> Self::Wires {
            let mpt_pi = cb.add_virtual_targets(MPTPublicInputs::<Target>::TOTAL_LEN);
            let merkle_pi = cb.add_virtual_targets(MerklePublicInputs::<Target>::TOTAL_LEN);

            DigestEqualCircuit::build(cb, &mpt_pi, &merkle_pi);

            (mpt_pi, merkle_pi)
        }

        fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
            pw.set_target_arr(&wires.0, &self.mpt_pi);
            pw.set_target_arr(&wires.1, &self.merkle_pi);
        }
    }

    /// Test the digest-equal circuit with simple random previous public inputs.
    #[test]
    fn test_digest_equal_circuit_simple() {
        init_logging();

        // Generate a random digest.
        let mut rng = thread_rng();
        let digest = Point::sample(&mut rng).to_weierstrass();

        let mpt_pi = generate_mpt_public_inputs(&digest);
        let merkle_pi = generate_merkle_public_inputs(&digest);

        let mpt_pi_wrapper = MPTPublicInputs::<F>::from(&mpt_pi);
        let merkle_pi_wrapper = MerklePublicInputs::<F>::from(merkle_pi.as_slice());

        // Get the expected public inputs.
        let exp_digest = (digest.x.0, digest.y.0, F::from_bool(digest.is_inf));
        let exp_mpt_root = mpt_pi_wrapper.root_hash_data();
        let exp_merkle_root = merkle_pi_wrapper.root_raw();
        let exp_mapping_slot = mpt_pi_wrapper.mapping_slot();
        let exp_length_slot = mpt_pi_wrapper.length_slot();

        let test_circuit = TestCircuit {
            mpt_pi: mpt_pi.clone(),
            merkle_pi: merkle_pi.clone(),
        };
        let proof = run_circuit::<F, D, C, _>(test_circuit);

        // Verify the public inputs.
        let pi = PublicInputs::<F>::from(&proof.public_inputs);
        assert_eq!(pi.digest_data(), exp_digest);
        assert_eq!(pi.mpt_root_data(), exp_mpt_root);
        assert_eq!(pi.merkle_root_data(), exp_merkle_root);
        assert_eq!(pi.mapping_slot(), exp_mapping_slot);
        assert_eq!(pi.length_slot(), exp_length_slot);
    }

    #[test]
    fn test_digest_equal_circuit_parameters() {
        const LPN_PUBLIC_INPUTS: usize = MerklePublicInputs::<'_, Target>::TOTAL_LEN;
        const MPT_PUBLIC_INPUTS: usize = MPTPublicInputs::<'_, Target>::TOTAL_LEN;
        let testing_framework = TestingRecursiveCircuits::<F, C, D, LPN_PUBLIC_INPUTS>::default();
        let mpt_dummy_circuit = TestDummyCircuit::<MPT_PUBLIC_INPUTS>::build();
        let digest_eq_circuit = Parameters::build(
            testing_framework.get_recursive_circuit_set(),
            &mpt_dummy_circuit.circuit_data().verifier_data(),
        );
        // generate inputs
        let mut rng = thread_rng();
        let digest = Point::sample(&mut rng).to_weierstrass();

        let mpt_pi = generate_mpt_public_inputs(&digest);
        let lpn_pi = generate_merkle_public_inputs(&digest);

        // generate input proofs
        let lpn_proof = testing_framework
            .generate_input_proofs::<1>([lpn_pi.try_into().unwrap()])
            .unwrap()[0]
            .clone();
        let mpt_proof = mpt_dummy_circuit
            .generate_proof(mpt_pi.try_into().unwrap())
            .unwrap();

        let lpn_proof = (
            lpn_proof,
            testing_framework.verifier_data_for_input_proofs::<1>()[0].clone(),
        )
            .into();
        let mpt_proof = (
            mpt_proof,
            mpt_dummy_circuit.circuit_data().verifier_only.clone(),
        )
            .into();
        // generate digest equal circuit proof
        let proof = digest_eq_circuit
            .generate_proof(
                testing_framework.get_recursive_circuit_set(),
                &lpn_proof,
                &mpt_proof,
            )
            .unwrap();

        digest_eq_circuit
            .data
            .verify(bincode::deserialize(&proof).unwrap())
            .unwrap();
    }

    fn generate_mpt_public_inputs(digest: &WeierstrassPoint) -> Vec<F> {
        let mut pi: Vec<_> = random_vector::<u32>(MPTPublicInputs::<F>::TOTAL_LEN)
            .into_iter()
            .map(F::from_canonical_u32)
            .collect();

        // Set the digest.
        pi[MPTPublicInputs::<F>::D_IDX..MPTPublicInputs::<F>::D_IDX + N]
            .copy_from_slice(&digest.x.0);
        pi[MPTPublicInputs::<F>::D_IDX + N..MPTPublicInputs::<F>::D_IDX + 2 * N]
            .copy_from_slice(&digest.y.0);
        pi[MPTPublicInputs::<F>::D_IDX + 2 * N] = F::from_bool(digest.is_inf);

        pi
    }

    fn generate_merkle_public_inputs(digest: &WeierstrassPoint) -> Vec<F> {
        let mut pi: Vec<_> = random_vector::<u32>(MerklePublicInputs::<F>::TOTAL_LEN)
            .into_iter()
            .map(F::from_canonical_u32)
            .collect();

        // Set the digest.
        pi[MerklePublicInputs::<F>::D_IDX..MerklePublicInputs::<F>::D_IDX + N]
            .copy_from_slice(&digest.x.0);
        pi[MerklePublicInputs::<F>::D_IDX + N..MerklePublicInputs::<F>::D_IDX + 2 * N]
            .copy_from_slice(&digest.y.0);
        pi[MerklePublicInputs::<F>::D_IDX + 2 * N] = F::from_bool(digest.is_inf);

        pi
    }
    use anyhow::Result;
    use storage::lpn::{leaf_digest_for_mapping, leaf_hash_for_mapping};
    #[tokio::test]
    #[serial]
    async fn test_mapping_extraction_equivalence_pudgy() -> Result<()> {
        // first pinguin holder https://dune.com/queries/2450476/4027653
        // holder: 0x188b264aa1456b869c3a92eeed32117ebb835f47
        // NFT id https://opensea.io/assets/ethereum/0xbd3531da5cf5857e7cfaa92426877b022e612cf8/1116
        let mapping_value =
            Address::from_str("0x188B264AA1456B869C3a92eeeD32117EbB835f47").unwrap();
        let nft_id: u32 = 1116;
        let mapping_key = left_pad32(&nft_id.to_be_bytes());
        let url = "https://eth.llamarpc.com";
        let provider =
            Provider::<Http>::try_from(url).expect("could not instantiate HTTP Provider");

        // extracting from
        // https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/token/ERC721/ERC721.sol
        // assuming it's using ERC731Enumerable that inherits ERC721
        let mapping_slot = 2;
        // pudgy pinguins
        let pudgy_address = Address::from_str("0xBd3531dA5CF5857e7CfAA92426877b022e612cf8")?;
        let query = ProofQuery::new_mapping_slot(pudgy_address, mapping_slot, mapping_key.to_vec());
        let res = query.query_mpt_proof(&provider, None).await?;
        let raw_address = ProofQuery::verify_storage_proof(&res)?;
        // the value is actually RLP encoded !
        let decoded_address: Vec<u8> = rlp::decode(&raw_address).unwrap();
        // this is read in the same order
        let found_address = Address::from_slice(&decoded_address.into_iter().collect::<Vec<u8>>());
        assert_eq!(found_address, mapping_value);
        let slot = MappingSlot::new(mapping_slot as u8, mapping_key.to_vec());

        let leaf_node = res.storage_proof[0].proof.last().unwrap();
        let mpt_circuit = storage::mapping::leaf::LeafCircuit::<80> {
            node: leaf_node.to_vec(),
            slot,
        };
        let mpt_proof = run_circuit::<F, D, C, _>(mpt_circuit);
        let mpt_pi = storage::mapping::PublicInputs::from(&mpt_proof.public_inputs);
        // Check hash
        let computed_hash = mpt_pi.root_hash();
        assert_eq!(
            convert_u8_to_u32_slice(&keccak256(leaf_node)),
            computed_hash
        );
        // Check the digest
        let expected_digest = leaf_digest_for_mapping(&mapping_key, mapping_value.as_bytes());
        let circuit_digest = mpt_pi.accumulator();
        println!("left_pad32(mapping_key) = \t{:?}", left_pad32(&mapping_key));

        assert_eq!(expected_digest.to_weierstrass(), circuit_digest);

        let exp_hash = HashOut::from_bytes(&leaf_hash_for_mapping(
            &mapping_key,
            mapping_value.as_bytes(),
        ));
        // use the _same_ inputs to the lpn leaf circuit
        let lpn_circuit = storage::lpn::leaf::LeafCircuit {
            mapping_key,
            mapping_value: left_pad32(mapping_value.as_bytes()),
        };
        let lpn_proof = run_circuit::<F, D, C, _>(lpn_circuit);
        let lpn_pi = storage::lpn::PublicInputs::from(lpn_proof.public_inputs.as_slice());
        assert_eq!(expected_digest.to_weierstrass(), lpn_pi.digest());
        assert_eq!(&exp_hash, &lpn_pi.root_hash());
        Ok(())
    }
}
