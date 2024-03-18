use super::extension::ExtensionNodeCircuit;
use super::extension::ExtensionWires;
use super::leaf::LeafCircuit;
use super::leaf::LeafWires;
use super::leaf::StorageLeafWire;
use super::PublicInputs;
use crate::api::ProofWithVK;
use crate::mpt_sequential::PAD_LEN;
use crate::storage::key::MappingSlot;
use crate::storage::mapping::branch::BranchCircuit;
use crate::storage::mapping::branch::BranchWires;
use crate::storage::MAX_BRANCH_NODE_LEN;
use crate::storage::MAX_LEAF_NODE_LEN;
use anyhow::bail;
use anyhow::Result;
use log::debug;
use paste::paste;
use plonky2::field::extension::quadratic::QuadraticExtension;
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::field::types::PrimeField64;
use plonky2::hash::hash_types::HashOut;
use plonky2::hash::poseidon::{PoseidonHash, PoseidonPermutation};
use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::circuit_data::CircuitData;
use plonky2::plonk::circuit_data::CommonCircuitData;
use plonky2::plonk::circuit_data::VerifierOnlyCircuitData;
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2x::backend::circuit::config::{DefaultParameters, Groth16WrapperParameters};
use plonky2x::backend::circuit::CircuitBuild;
use plonky2x::backend::wrapper::wrap::WrappedCircuit;
use plonky2x::prelude::CircuitBuilder as CBuilder;
use recursion_framework::circuit_builder::CircuitWithUniversalVerifier;
use recursion_framework::circuit_builder::CircuitWithUniversalVerifierBuilder;
use recursion_framework::framework::RecursiveCircuitInfo;
use recursion_framework::framework::RecursiveCircuits;
use recursion_framework::framework_testing::new_universal_circuit_builder_for_testing;
use recursion_framework::framework_testing::TestingRecursiveCircuits;
use recursion_framework::serialization::deserialize;
use recursion_framework::serialization::serialize;
use serde::Deserialize;
use serde::Serialize;
use std::array::from_fn as create_array;
use crate::groth16_tests::gen_groth16_proof;

const D: usize = 2;
type C = PoseidonGoldilocksConfig;
type F = <C as GenericConfig<D>>::F;

/// number of circuits in the set
/// 1 leaf, 1 ext, 16 branches * 2 because we split the node len in half
#[cfg(not(test))]
const MAPPING_CIRCUIT_SET_SIZE: usize = 34;
#[cfg(test)]
const MAPPING_CIRCUIT_SET_SIZE: usize = 6; // 1leaf, 1ext, 2 branches * 2

#[derive(Serialize, Deserialize)]
/// CircuitType is a wrapper around the different specialized circuits that can be used to prove a MPT node recursively
/// NOTE: Right now these circuits are specialized to prove inclusion of a single mapping slot.
pub enum CircuitInput {
    Leaf(LeafCircuit<MAX_LEAF_NODE_LEN>),
    Extension(ExtensionInput),
    Branch(BranchInput),
}

impl CircuitInput {
    /// Returns a circuit input for proving a leaf MPT node
    pub fn new_leaf(node: Vec<u8>, slot: usize, mapping_key: Vec<u8>) -> Self {
        CircuitInput::Leaf(LeafCircuit {
            node,
            slot: MappingSlot::new(slot as u8, mapping_key),
        })
    }
    /// Returns a circuit input for proving an extension MPT node
    pub fn new_extension(node: Vec<u8>, child_proof: Vec<u8>) -> Self {
        CircuitInput::Extension(ExtensionInput {
            input: InputNode { node },
            serialized_child_proofs: vec![child_proof],
        })
    }
    /// Returns a circuit input for proving an branch MPT node
    pub fn new_branch(node: Vec<u8>, child_proofs: Vec<Vec<u8>>) -> Self {
        CircuitInput::Branch(ProofInputSerialized {
            input: InputNode { node },
            serialized_child_proofs: child_proofs,
        })
    }
}

#[derive(Serialize, Deserialize, Eq, PartialEq)]
/// Main struct holding the different circuit parameters for each of the MPT circuits defined here.
/// Most notably, it holds them in a way to use the recursion framework allowing us to specialize
/// circuits according to the situation.
pub struct PublicParameters {
    leaf_circuit: CircuitWithUniversalVerifier<F, C, D, 0, StorageLeafWire>,
    set: RecursiveCircuits<F, C, D>,
}
/// Public API employed to build the MPT circuits, which are returned in serialized form
pub fn build_circuits_params() -> PublicParameters {
    PublicParameters::build()
}

/// Public API employed to generate a proof for the circuit specified by `CircuitType`,
/// employing the `circuit_params` generated with the `build_circuits_params` API
pub fn generate_proof(
    circuit_params: PublicParameters,
    circuit_type: CircuitInput,
) -> Result<Vec<u8>> {
    circuit_params.generate_proof(circuit_type)?.serialize()
}
#[derive(Serialize, Deserialize)]
/// This data structure allows to specify the inputs for a circuit that needs to recursively verify
/// proofs; the generic type `T` allows to specify the specific inputs of each circuits besides the
/// proofs that need to be recursively verified, while the proofs are serialized in byte format
struct ProofInputSerialized<T> {
    input: T,
    serialized_child_proofs: Vec<Vec<u8>>,
}

impl<T> ProofInputSerialized<T> {
    /// Deserialize child proofs and return the set of deserialized 'MTPProof`s
    fn get_child_proofs(&self) -> Result<Vec<ProofWithVK>> {
        self.serialized_child_proofs
            .iter()
            .map(|proof| ProofWithVK::deserialize(proof))
            .collect::<Result<Vec<_>, _>>()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
/// Struct containing the expected input MPT Extension/Branch node.
struct InputNode {
    node: Vec<u8>,
}

type ExtensionInput = ProofInputSerialized<InputNode>;

type BranchInput = ProofInputSerialized<InputNode>;

const NUM_IO: usize = PublicInputs::<F>::TOTAL_LEN;
/// generate a macro filling the BranchCircuit structs manually
macro_rules! impl_branch_circuits {
    ($struct_name:ty, $($i:expr),*) => {
        paste! {
        #[derive(Debug, Serialize, Deserialize, Eq, PartialEq)]
        pub struct [< $struct_name GenericNodeLen>]<const NODE_LEN: usize>
        where
            [(); PAD_LEN(NODE_LEN)]:,
            [(); PAD_LEN(NODE_LEN/2)]:,
        {
            $(
                [< b $i >]: CircuitWithUniversalVerifier<F, C, D, $i, BranchWires<NODE_LEN>>,
                [< b $i _over_2 >]: CircuitWithUniversalVerifier<F, C, D, $i, BranchWires<{NODE_LEN/2}>>,
            )+
        }
        #[doc = stringify!($struct_name)]
        #[doc = "holds the logic to create the different circuits for handling a branch node.
        In particular, it generates specific circuits for each number of child proofs, as well as
        in combination with the node input length."]
        pub type $struct_name =  [< $struct_name GenericNodeLen>]<MAX_BRANCH_NODE_LEN>;

        impl $struct_name {
            fn new(builder: &CircuitWithUniversalVerifierBuilder<F, D, NUM_IO>) -> Self {
                $struct_name {
                    $(
                        // generate one circuit with full node len
                        [< b $i >]:  builder.build_circuit::<C, $i, BranchWires<MAX_BRANCH_NODE_LEN>>(()),
                        // generate one circuit with half node len
                        [< b $i _over_2>]:  builder.build_circuit::<C, $i, BranchWires<{MAX_BRANCH_NODE_LEN/2}>>(()),

                    )+
                }
            }
            /// Returns the set of circuits to be fed to the recursive framework
            fn circuit_set(&self) -> Vec<HashOut<F>> {
                let mut arr = Vec::new();
                $(
                    arr.push(self.[< b $i >].circuit_data().verifier_only.circuit_digest);
                    arr.push(self.[< b $i _over_2 >].circuit_data().verifier_only.circuit_digest);
                )+
                arr
            }

            /// generates a proof from the inputs stored in `branch`. Depending on the size of the node,
            /// and the number of children proofs, it selects the right specialized circuit to generate the proof.
            fn generate_proof(
                &self,
                set: &RecursiveCircuits<F, C, D>,
                branch_node: InputNode,
                child_proofs: Vec<ProofWithVK>,
            ) -> Result<ProofWithVK> {
                // first, determine manually the common prefix, the ptr and the mapping slot
                // from the public inputs of the children proofs.
                // Note this is done outside circuits, more as a sanity check. The circuits is enforcing
                // this condition.
                let valid_inputs = child_proofs
                    .windows(2)
                    .all(|arr| {
                        if arr.len() == 1 {
                            true
                        } else {
                            let pi1 = PublicInputs::<F>::from(&arr[0].proof.public_inputs);
                            let (k1, p1) = pi1.mpt_key_info();
                            let pi2 = PublicInputs::<F>::from(&arr[1].proof.public_inputs);
                            let (k2, p2) = pi2.mpt_key_info();
                            let up1 = p1.to_canonical_u64() as usize;
                            let up2 = p2.to_canonical_u64() as usize;
                            up1 < k1.len() && up2 < k2.len() && p1 == p2 && k1[..up1] == k2[..up2]
                        }
                    });
                if !valid_inputs {
                    bail!("proofs don't match on the key and/or pointers");
                }
                if child_proofs.is_empty() || child_proofs.len() > 16 {
                    bail!("No child proofs or too many child proofs");
                }
                if branch_node.node.len() > MAX_BRANCH_NODE_LEN {
                    bail!("Branch node too long");
                }

                // we just take the first one,it doesn't matter which one we take as long
                // as all prefixes and pointers are equal.
                let pi = PublicInputs::<F>::from(&child_proofs[0].proof.public_inputs);
                let (key, ptr) = pi.mpt_key_info();
                let mapping_slot = pi.mapping_slot().to_canonical_u64() as usize;
                let common_prefix = key
                    .iter()
                    .map(|nib| nib.to_canonical_u64() as u8)
                    .collect::<Vec<_>>();
                // -1 because it's the expected pointer _after_ advancing the
                // pointer by one in the branch circuit.
                // TODO: refactor circuit to only advance the pointer by one _after_
                // the comparison, so we don't need to do this?
                let pointer = ptr.to_canonical_u64() as usize - 1;
                let proofs = child_proofs
                    .iter()
                    // TODO: didn't find a way to get rid of the useless clone - it's either on the vk or on the proof
                    .map(|p| p.proof.clone())
                    .collect::<Vec<_>>();
                let min_range = MAX_BRANCH_NODE_LEN / 2;
                 match child_proofs.len() {
                     $($i if branch_node.node.len() > min_range => {
                         set.generate_proof(
                             &self.[< b $i >],
                             proofs.try_into().unwrap(),
                             create_array(|i| &child_proofs[i].vk),
                             BranchCircuit {
                                 node: branch_node.node,
                                 common_prefix,
                                 expected_pointer: pointer,
                                 mapping_slot,
                             }
                         ).map(|p| (p, self.[< b $i >].get_verifier_data().clone()).into())
                     },
                         $i if branch_node.node.len() <= min_range => {
                         set.generate_proof(
                             &self.[< b $i _over_2 >],
                             proofs.try_into().unwrap(),
                             create_array(|i| &child_proofs[i].vk),
                             BranchCircuit {
                                 node: branch_node.node,
                                 common_prefix,
                                 expected_pointer: pointer,
                                 mapping_slot,
                             }
                         ).map(|p| (p, self.[< b $i _over_2>].get_verifier_data().clone()).into())
                     }
                 )+
                     _ => bail!("invalid child proof len"),
                 }
                }
            }
}
    }
}

impl_branch_circuits!(
    BranchCircuits,
    1,
    2,
    3,
    4,
    5,
    6,
    7,
    8,
    9,
    10,
    11,
    12,
    13,
    14,
    15,
    16
);
#[cfg(test)]
impl_branch_circuits!(TestBranchCircuits, 1, 2);

impl PublicParameters {
    /// Generates the circuit parameters for the MPT circuits.
    fn build() -> Self {
        let config = CircuitConfig::standard_recursion_config();
        let circuit_builder = CircuitWithUniversalVerifierBuilder::<F, D, NUM_IO>::new::<C>(
            config,
            MAPPING_CIRCUIT_SET_SIZE,
        );

        debug!("Building leaf circuit");
        let leaf_circuit = circuit_builder.build_circuit::<C, 0, LeafWires<MAX_LEAF_NODE_LEN>>(());
        let mut circuits_set = vec![leaf_circuit.get_verifier_data().circuit_digest];

        PublicParameters {
            leaf_circuit,
            set: RecursiveCircuits::new_from_circuit_digests(circuits_set),
        }
    }

    fn generate_proof(mut self, circuit_type: CircuitInput) -> Result<ProofWithVK> {
        let set = &self.set;
        match circuit_type {
            CircuitInput::Leaf(leaf) => {
                let proof: ProofWithVK = set
                    .generate_proof(&self.leaf_circuit, [], [], leaf)
                    .map(|p| (p, self.leaf_circuit.get_verifier_data().clone()).into())
                    .unwrap();

                // Dump the proof, common-circuit-data and verifier-only-data for Groth16 test.
                {
                    type L = DefaultParameters;

                    // TRICKY: get the circuit-data to build WrappedCircuit of plonkyx.
                    let circuit_data = self.leaf_circuit.wrap_circuit.circuit_data.pop().unwrap();

                    // TODO: Not work for now, since the public inputs must be bytes.
                    gen_groth16_proof(circuit_data, &proof.proof);
                }

                Ok(proof)
            }
            _ => panic!("Not support"),
        }
    }
}

#[cfg(test)]
mod test {
    use eth_trie::{EthTrie, MemoryDB, Trie};
    use plonky2::field::types::Field;
    use rand::{thread_rng, Rng};
    use serial_test::serial;

    use super::*;
    use crate::{
        eth::StorageSlot,
        mpt_sequential::{bytes_to_nibbles, test::generate_random_storage_mpt},
        storage::key::MappingSlot,
        utils::test::random_vector,
    };

    struct TestData {
        trie: EthTrie<MemoryDB>,
        key: Vec<u8>,
        mpt_key1: Vec<u8>,
        mpt_key2: Vec<u8>,
    }

    fn generate_storage_trie_and_keys(slot: usize) -> TestData {
        let (mut trie, _) = generate_random_storage_mpt::<3, 32>();
        // insert two keys that share the same prefix
        let key = random_vector(20); // like address
        let mpt1 = StorageSlot::Mapping(key.clone(), slot).mpt_key();
        let mut mpt2 = mpt1.clone();
        let last_byte = mpt2[mpt1.len() - 1];
        let first_nibble = last_byte & 0xF0;
        // only change the last nibble
        while mpt2 == mpt1 {
            mpt2[mpt1.len() - 1] = first_nibble + (thread_rng().gen::<u8>() & 0x0F);
        }
        println!(
            "key1: {:?}, key2: {:?}",
            hex::encode(&mpt1),
            hex::encode(&mpt2)
        );
        let v = random_vector(32);
        trie.insert(&mpt1, &v).unwrap();
        trie.insert(&mpt2, &v).unwrap();
        trie.root_hash().unwrap();

        TestData {
            trie,
            key,
            mpt_key1: mpt1,
            mpt_key2: mpt2,
        }
    }

    #[test]
    #[serial]
    fn test_serialization() {
        let params = PublicParameters::build();

        let encoded = bincode::serialize(&params).unwrap();
        let decoded_params: PublicParameters = bincode::deserialize(&encoded).unwrap();

        assert!(decoded_params == params);

        let slot = 3;
        let mut test_data = generate_storage_trie_and_keys(slot);
        let p1 = test_data.trie.get_proof(&test_data.mpt_key1).unwrap();
        let l1 = CircuitInput::Leaf(LeafCircuit {
            node: p1.last().unwrap().to_vec(),
            slot: MappingSlot::new(slot as u8, test_data.key.clone()),
        });

        let encoded = bincode::serialize(&l1).unwrap();
        let decoded_input: CircuitInput = bincode::deserialize(&encoded).unwrap();

        // we test serialization of `CircuitType::Leaf` by employing the deserialized input to
        // generate the proof
        let leaf_proof = params.generate_proof(decoded_input).unwrap();
    }
}
