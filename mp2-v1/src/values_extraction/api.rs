//! Values extraction APIs

use super::{
    branch::{BranchCircuit, BranchWires},
    extension::{ExtensionNodeCircuit, ExtensionNodeWires},
    leaf_mapping::{LeafMappingCircuit, LeafMappingWires},
    leaf_single::{LeafSingleCircuit, LeafSingleWires},
    public_inputs::PublicInputs,
};
use crate::{api::InputNode, MAX_BRANCH_NODE_LEN, MAX_LEAF_NODE_LEN};
use anyhow::{bail, ensure, Result};
use log::debug;
use mp2_common::{
    default_config,
    mpt_sequential::PAD_LEN,
    proof::{ProofInputSerialized, ProofWithVK},
    storage_key::{MappingSlot, SimpleSlot},
    C, D, F,
};
use paste::paste;
use plonky2::{field::types::PrimeField64, hash::hash_types::HashOut};
#[cfg(test)]
use recursion_framework::framework_testing::{
    new_universal_circuit_builder_for_testing, TestingRecursiveCircuits,
};
use recursion_framework::{
    circuit_builder::{CircuitWithUniversalVerifier, CircuitWithUniversalVerifierBuilder},
    framework::{RecursiveCircuitInfo, RecursiveCircuits},
};
use serde::{Deserialize, Serialize};
use std::array;

type LeafSingleWire = LeafSingleWires<MAX_LEAF_NODE_LEN>;
type LeafMappingWire = LeafMappingWires<MAX_LEAF_NODE_LEN>;
type ExtensionInput = ProofInputSerialized<InputNode>;
type BranchInput = ProofInputSerialized<InputNode>;

const NUM_IO: usize = PublicInputs::<F>::TOTAL_LEN;

/// CircuitInput is a wrapper around the different specialized circuits that can
/// be used to prove a MPT node recursively.
#[derive(Serialize, Deserialize)]
pub enum CircuitInput {
    LeafSingle(LeafSingleCircuit<MAX_LEAF_NODE_LEN>),
    LeafMapping(LeafMappingCircuit<MAX_LEAF_NODE_LEN>),
    Extension(ExtensionInput),
    BranchSingle(BranchInput),
    BranchMapping(BranchInput),
}

impl CircuitInput {
    /// Create a circuit input for proving a leaf MPT node of single variable.
    pub fn new_single_variable_leaf(node: Vec<u8>, slot: u8, column_id: u64) -> Self {
        CircuitInput::LeafSingle(LeafSingleCircuit {
            node,
            slot: SimpleSlot::new(slot),
            id: column_id,
        })
    }

    /// Create a circuit input for proving a leaf MPT node of mapping variable.
    pub fn new_mapping_variable_leaf(
        node: Vec<u8>,
        slot: u8,
        mapping_key: Vec<u8>,
        key_id: u64,
        value_id: u64,
    ) -> Self {
        CircuitInput::LeafMapping(LeafMappingCircuit {
            node,
            slot: MappingSlot::new(slot, mapping_key),
            key_id,
            value_id,
        })
    }

    /// Create a circuit input for proving an extension MPT node.
    pub fn new_extension(node: Vec<u8>, child_proof: Vec<u8>) -> Self {
        CircuitInput::Extension(ExtensionInput {
            input: InputNode { node },
            serialized_child_proofs: vec![child_proof],
        })
    }

    /// Create a circuit input for proving a branch MPT node of single variable.
    pub fn new_single_variable_branch(node: Vec<u8>, child_proofs: Vec<Vec<u8>>) -> Self {
        CircuitInput::BranchSingle(ProofInputSerialized {
            input: InputNode { node },
            serialized_child_proofs: child_proofs,
        })
    }

    /// Create a circuit input for proving a branch MPT node of mapping variable.
    pub fn new_mapping_variable_branch(node: Vec<u8>, child_proofs: Vec<Vec<u8>>) -> Self {
        CircuitInput::BranchMapping(ProofInputSerialized {
            input: InputNode { node },
            serialized_child_proofs: child_proofs,
        })
    }
}

/// Main struct holding the different circuit parameters for each of the MPT
/// circuits defined here.
/// Most notably, it holds them in a way to use the recursion framework allowing
/// us to specialize circuits according to the situation.
#[derive(Eq, PartialEq, Serialize, Deserialize)]
pub struct PublicParameters {
    leaf_single: CircuitWithUniversalVerifier<F, C, D, 0, LeafSingleWire>,
    leaf_mapping: CircuitWithUniversalVerifier<F, C, D, 0, LeafMappingWire>,
    extension: CircuitWithUniversalVerifier<F, C, D, 1, ExtensionNodeWires>,
    #[cfg(not(test))]
    branches: BranchCircuits,
    #[cfg(test)]
    branches: TestBranchCircuits,
    #[cfg(not(test))]
    set: RecursiveCircuits<F, C, D>,
    #[cfg(test)]
    set: TestingRecursiveCircuits<F, C, D, NUM_IO>,
}

/// Public API employed to build the MPT circuits, which are returned in
/// serialized form.
pub fn build_circuits_params() -> PublicParameters {
    PublicParameters::build()
}

/// Public API employed to generate a proof for the circuit specified by
/// `CircuitInput`, employing the `circuit_params` generated with the
/// `build_circuits_params` API.
pub fn generate_proof(
    circuit_params: &PublicParameters,
    circuit_type: CircuitInput,
) -> Result<Vec<u8>> {
    circuit_params.generate_proof(circuit_type)?.serialize()
}

/// generate a macro filling the BranchCircuit structs manually
macro_rules! impl_branch_circuits {
    ($struct_name:ty, $($i:expr),*) => {
        paste! {
        #[derive(Debug, Serialize, Deserialize, Eq, PartialEq)]
        pub struct [< $struct_name GenericNodeLen>]<const NODE_LEN: usize>
        where
            [(); PAD_LEN(NODE_LEN)]:,
        {
            $(
                [< b $i >]: CircuitWithUniversalVerifier<F, C, D, $i, BranchWires<NODE_LEN>>,
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
                    )+
                }
            }
            /// Returns the set of circuits to be fed to the recursive framework
            fn circuit_set(&self) -> Vec<HashOut<F>> {
                let mut arr = Vec::new();
                $(
                    arr.push(self.[< b $i >].circuit_data().verifier_only.circuit_digest);
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
                is_simple_aggregation: bool,
            ) -> Result<ProofWithVK> {
                // first, determine manually the common prefix, the ptr and the mapping slot
                // from the public inputs of the children proofs.
                // Note this is done outside circuits, more as a sanity check. The circuits is enforcing
                // this condition.
                for arr in child_proofs.windows(2) {
                    if arr.len() > 1 {
                        let pi1 = PublicInputs::<F>::new(&arr[0].proof().public_inputs);
                        let (k1, p1) = pi1.mpt_key_info();
                        let pi2 = PublicInputs::<F>::new(&arr[1].proof().public_inputs);
                        let (k2, p2) = pi2.mpt_key_info();
                        let up1 = p1.to_canonical_u64() as usize;
                        let up2 = p2.to_canonical_u64() as usize;

                        ensure!(up1 < k1.len(), "up1 ({}) >= |k1| ({})", up1, k1.len());
                        ensure!(up2 < k2.len(), "up2 ({}) >= |k2| ({})", up2, k2.len());
                        ensure!(p1 == p2, "p1 ({p1}) != p2 ({p2})");
                        ensure!(k1[..up1] == k2[..up1], "k1[..up1] ({:?}) != k[2..up2] ({:?})", &k1[..up1], &k2[..up2]);
                    }

                }
                ensure!(!child_proofs.is_empty(), "empty child_proofs");
                ensure!(child_proofs.len() <= 16, "too many child proofs found: {}", child_proofs.len());
                ensure!(branch_node.node.len() <= MAX_BRANCH_NODE_LEN, "branch_node too long: {}", branch_node.node.len());

                // We just take the first one, it doesn't matter which one we
                // take as long as all prefixes and pointers are equal.
                let pi = PublicInputs::<F>::new(&child_proofs[0].proof().public_inputs);
                let (key, ptr) = pi.mpt_key_info();
                let common_prefix = key
                    .iter()
                    .map(|nib| nib.to_canonical_u64() as u8)
                    .collect::<Vec<_>>();
                let pointer = ptr.to_canonical_u64() as usize;
                let (mut proofs, vks): (Vec<_>, Vec<_>) = child_proofs
                    .iter()
                    // TODO: didn't find a way to get rid of the useless clone - it's either on the vk or on the proof
                    .map(|p| {
                        let (proof, vk) = p.into();
                        (proof.clone(), vk)
                    })
                    .unzip();
                 match child_proofs.len() {
                     $(_ if $i == child_proofs.len() => {
                         set.generate_proof(
                             &self.[< b $i >],
                             proofs.try_into().unwrap(),
                             array::from_fn(|i| vks[i]),
                             BranchCircuit {
                                 node: branch_node.node,
                                 common_prefix,
                                 expected_pointer: pointer,
                                 n_proof_valid: $i,
                                 is_simple_aggregation,
                             }
                         ).map(|p| (p, self.[< b $i >].get_verifier_data().clone()).into())
                     },
                     _ if $i > child_proofs.len()  => {
                         // This should match for number of real proofs
                         // between the previous $i passed to the macro and
                         // current $i, since `match` greedily matches arms.
                         let num_real_proofs = child_proofs.len();
                         // we pad the number of proofs to $i by repeating the
                         // first proof
                         for _ in 0..($i - num_real_proofs) {
                             proofs.push(proofs.first().unwrap().clone());
                         }
                         println!("Generating proof with {} proofs over branch circuit {}", proofs.len(), $i);
                         set.generate_proof(
                             &self.[< b $i>],
                             proofs.try_into().unwrap(),
                             array::from_fn(|i| if i < num_real_proofs { vks[i] } else { vks[0] }),
                             BranchCircuit {
                                 node: branch_node.node,
                                 common_prefix,
                                 expected_pointer: pointer,
                                 n_proof_valid: num_real_proofs,
                                 is_simple_aggregation,
                             },
                         ).map(|p| (p, self.[< b $i>].get_verifier_data().clone()).into())
                     }
                 )+
                         _ => bail!("invalid child proof len: {}", child_proofs.len()),
                 }
            }
        }}
    }
}

impl_branch_circuits!(BranchCircuits, 2, 9, 16);
#[cfg(test)]
impl_branch_circuits!(TestBranchCircuits, 1, 4, 9);

/// Number of circuits in the set
/// 3 branch circuits + 1 extension + 1 leaf single + 1 leaf mapping
const MAPPING_CIRCUIT_SET_SIZE: usize = 6;

impl PublicParameters {
    /// Generates the circuit parameters for the MPT circuits.
    fn build() -> Self {
        let config = default_config();
        #[cfg(not(test))]
        let circuit_builder = CircuitWithUniversalVerifierBuilder::<F, D, NUM_IO>::new::<C>(
            config,
            MAPPING_CIRCUIT_SET_SIZE,
        );
        #[cfg(test)]
        let circuit_builder = new_universal_circuit_builder_for_testing::<F, C, D, NUM_IO>(
            config,
            MAPPING_CIRCUIT_SET_SIZE,
        );

        debug!("Building leaf single circuit");
        let leaf_single =
            circuit_builder.build_circuit::<C, 0, LeafSingleWires<MAX_LEAF_NODE_LEN>>(());

        debug!("Building leaf mapping circuit");
        let leaf_mapping =
            circuit_builder.build_circuit::<C, 0, LeafMappingWires<MAX_LEAF_NODE_LEN>>(());

        debug!("Building extension circuit");
        let extension = circuit_builder.build_circuit::<C, 1, ExtensionNodeWires>(());

        debug!("Building branch circuits");
        #[cfg(not(test))]
        let branches = BranchCircuits::new(&circuit_builder);
        #[cfg(test)]
        let branches = TestBranchCircuits::new(&circuit_builder);
        let mut circuits_set = vec![
            leaf_single.get_verifier_data().circuit_digest,
            leaf_mapping.get_verifier_data().circuit_digest,
            extension.get_verifier_data().circuit_digest,
        ];
        circuits_set.extend(branches.circuit_set());
        assert_eq!(circuits_set.len(), MAPPING_CIRCUIT_SET_SIZE);

        PublicParameters {
            leaf_single,
            leaf_mapping,
            extension,
            branches,
            #[cfg(not(test))]
            set: RecursiveCircuits::new_from_circuit_digests(circuits_set),
            #[cfg(test)]
            set: TestingRecursiveCircuits::new_from_circuit_digests(&circuit_builder, circuits_set),
        }
    }

    fn generate_proof(&self, circuit_type: CircuitInput) -> Result<ProofWithVK> {
        let set = &self.get_circuit_set();
        match circuit_type {
            CircuitInput::LeafSingle(leaf) => set
                .generate_proof(&self.leaf_single, [], [], leaf)
                .map(|p| (p, self.leaf_single.get_verifier_data().clone()).into()),
            CircuitInput::LeafMapping(leaf) => set
                .generate_proof(&self.leaf_mapping, [], [], leaf)
                .map(|p| (p, self.leaf_mapping.get_verifier_data().clone()).into()),
            CircuitInput::Extension(ext) => {
                let mut child_proofs = ext.get_child_proofs()?;
                let (child_proof, child_vk) = child_proofs
                    .pop()
                    .ok_or(anyhow::Error::msg(
                        "No proof found in input for extension node",
                    ))?
                    .into();
                set.generate_proof(
                    &self.extension,
                    [child_proof],
                    [&child_vk],
                    ExtensionNodeCircuit {
                        node: ext.input.node,
                    },
                )
                .map(|p| (p, self.extension.get_verifier_data().clone()).into())
            }
            CircuitInput::BranchSingle(branch) => {
                let child_proofs = branch.get_child_proofs()?;
                self.branches
                    .generate_proof(set, branch.input, child_proofs, true)
            }
            CircuitInput::BranchMapping(branch) => {
                let child_proofs = branch.get_child_proofs()?;
                self.branches
                    .generate_proof(set, branch.input, child_proofs, false)
            }
        }
    }

    pub(crate) fn get_circuit_set(&self) -> &RecursiveCircuits<F, C, D> {
        #[cfg(not(test))]
        let set = &self.set;
        #[cfg(test)]
        let set = self.set.get_recursive_circuit_set();

        set
    }
}

#[cfg(test)]
mod tests {

    use super::{
        super::{
            compute_leaf_mapping_metadata_digest, compute_leaf_mapping_values_digest,
            compute_leaf_single_metadata_digest, compute_leaf_single_values_digest,
            identifier_for_mapping_key_column, identifier_for_mapping_value_column,
            identifier_single_var_column, public_inputs,
        },
        *,
    };
    use alloy::primitives::Address;
    use eth_trie::{EthTrie, MemoryDB, Trie};
    use mp2_common::{
        eth::StorageSlot,
        mpt_sequential::utils::bytes_to_nibbles,
        types::{GFp, ADDRESS_LEN},
    };
    use mp2_test::{mpt_sequential::generate_random_storage_mpt, utils::random_vector};
    use plonky2::field::types::Field;
    use plonky2_ecgfp5::curve::curve::Point;
    use serial_test::serial;
    use std::{str::FromStr, sync::Arc};

    const TEST_SLOT: u8 = 10;
    const TEST_CONTRACT_ADDRESS: &str = "0xd6a2bfb7f76caa64dad0d13ed8a9efb73398f39e";

    #[derive(Debug)]
    struct TestData {
        trie: EthTrie<MemoryDB>,
        mpt_keys: Vec<Vec<u8>>,
        /// Key of mapping slot, or none for simple slot
        mapping_key: Option<Vec<u8>>,
    }

    impl TestData {
        fn is_simple_slot(&self) -> bool {
            self.mapping_key.is_none()
        }
    }

    #[test]
    fn test_values_extraction_single_variable_apis() {
        test_apis(true);
    }

    #[test]
    fn test_values_extraction_mapping_variable_apis() {
        test_apis(false);
    }

    #[test]
    #[serial]
    fn test_values_extraction_single_variable_circuits() {
        test_circuits(true, 6);
    }

    #[test]
    #[serial]
    fn test_values_extraction_mapping_variable_circuits() {
        test_circuits(false, 6);
    }

    #[test]
    #[serial]
    fn test_values_extraction_api_serialization() {
        let contract_address = Address::from_str(TEST_CONTRACT_ADDRESS).unwrap();
        let chain_id = 10;

        // Test serialization for public parameters.
        let params = PublicParameters::build();
        let encoded = bincode::serialize(&params).unwrap();
        let decoded_params: PublicParameters = bincode::deserialize(&encoded).unwrap();
        assert!(decoded_params == params);

        let test_circuit_input = |input: CircuitInput| {
            // Test circuit input serialization.
            let encoded_input = bincode::serialize(&input).unwrap();
            let decoded_input: CircuitInput = bincode::deserialize(&encoded_input).unwrap();

            // Test proof serialization.
            let proof = params.generate_proof(decoded_input).unwrap();
            let encoded_proof = bincode::serialize(&proof).unwrap();
            let decoded_proof: ProofWithVK = bincode::deserialize(&encoded_proof).unwrap();
            assert_eq!(proof, decoded_proof);

            encoded_proof
        };

        // Test for leaf single variable circuit.
        let mut test_data = generate_storage_trie_and_keys(true, TEST_SLOT, 2);
        let proof = test_data.trie.get_proof(&test_data.mpt_keys[0]).unwrap();
        test_circuit_input(CircuitInput::LeafSingle(LeafSingleCircuit {
            node: proof.last().unwrap().to_vec(),
            slot: SimpleSlot::new(TEST_SLOT),
            id: identifier_single_var_column(TEST_SLOT, &contract_address, chain_id, vec![]),
        }));

        // Test for leaf mapping variable circuit.
        let mut test_data = generate_storage_trie_and_keys(false, TEST_SLOT, 2);
        let proof = test_data.trie.get_proof(&test_data.mpt_keys[0]).unwrap();
        let encoded = test_circuit_input(CircuitInput::LeafMapping(LeafMappingCircuit {
            node: proof.last().unwrap().to_vec(),
            slot: MappingSlot::new(TEST_SLOT, test_data.mapping_key.unwrap().clone()),
            key_id: identifier_for_mapping_key_column(
                TEST_SLOT,
                &contract_address,
                chain_id,
                vec![],
            ),
            value_id: identifier_for_mapping_value_column(
                TEST_SLOT,
                &contract_address,
                chain_id,
                vec![],
            ),
        }));

        // Test for branch circuit.
        let branch_node = proof[proof.len() - 2].to_vec();
        test_circuit_input(CircuitInput::BranchMapping(BranchInput {
            input: InputNode {
                node: branch_node.clone(),
            },
            serialized_child_proofs: vec![encoded],
        }));
    }

    fn generate_storage_trie_and_keys(
        is_simple_aggregation: bool,
        slot: u8,
        num_children: usize,
    ) -> TestData {
        let (mut trie, _) = generate_random_storage_mpt::<3, 32>();
        let (mapping_key, slot) = if is_simple_aggregation {
            (None, StorageSlot::Simple(slot as usize))
        } else {
            let mapping_key = random_vector(20);
            (
                Some(mapping_key.clone()),
                StorageSlot::Mapping(mapping_key, slot as usize),
            )
        };
        let mut mpt = slot.mpt_key_vec();
        let mpt_len = mpt.len();
        let last_byte = mpt[mpt_len - 1];
        let first_nibble = last_byte & 0xF0;
        let second_nibble = last_byte & 0x0F;
        println!(
            "key: {}, last: {}, first: {}, second: {}",
            hex::encode(&mpt),
            last_byte,
            first_nibble,
            second_nibble
        );
        let mut mpt_keys = Vec::new();
        // only change the last nibble
        for i in 0..num_children {
            mpt[mpt_len - 1] = first_nibble + ((second_nibble + i as u8) & 0x0F);
            mpt_keys.push(mpt.clone());
        }
        println!(
            "key1: {:?}, key2: {:?}",
            hex::encode(&mpt_keys[0]),
            hex::encode(&mpt_keys[1])
        );
        let v: Vec<u8> = rlp::encode(&random_vector(32)).to_vec();
        mpt_keys
            .iter()
            .for_each(|mpt| trie.insert(mpt, &v).unwrap());
        trie.root_hash().unwrap();

        TestData {
            trie,
            mapping_key,
            mpt_keys,
        }
    }

    fn test_apis(is_simple_aggregation: bool) {
        let contract_address = Address::from_str(TEST_CONTRACT_ADDRESS).unwrap();
        let chain_id = 10;

        let memdb = Arc::new(MemoryDB::new(true));
        let mut trie = EthTrie::new(memdb.clone());

        let key1 = [1u8; 4];
        let val1 = [2u8; ADDRESS_LEN];
        let slot1 = if is_simple_aggregation {
            StorageSlot::Simple(TEST_SLOT as usize)
        } else {
            StorageSlot::Mapping(key1.to_vec(), TEST_SLOT as usize)
        };
        let mpt_key1 = slot1.mpt_key();

        let key2 = [3u8; 4];
        let val2 = [4u8; ADDRESS_LEN];
        let slot2 = if is_simple_aggregation {
            // Must be a different slot value for single variables.
            StorageSlot::Simple(TEST_SLOT as usize + 1)
        } else {
            // Must be the same slot value for mapping variables.
            StorageSlot::Mapping(key2.to_vec(), TEST_SLOT as usize)
        };
        let mpt_key2 = slot2.mpt_key();

        trie.insert(&mpt_key1, &rlp::encode(&val1.as_slice()))
            .unwrap();
        trie.insert(&mpt_key2, &rlp::encode(&val2.as_slice()))
            .unwrap();
        trie.root_hash().unwrap();

        let proof1 = trie.get_proof(&mpt_key1).unwrap();
        let proof2 = trie.get_proof(&mpt_key2).unwrap();
        assert_eq!(proof1[0], proof2[0]);

        // Make sure node above is really a branch node.
        assert!(rlp::decode_list::<Vec<u8>>(&proof1[0]).len() == 17);
        println!("Generating params...");
        let params = build_circuits_params();

        println!("Proving leaf 1...");
        let leaf_input1 = if is_simple_aggregation {
            let column_id =
                identifier_single_var_column(TEST_SLOT, &contract_address, chain_id, vec![]);
            CircuitInput::new_single_variable_leaf(proof1[1].clone(), TEST_SLOT, column_id)
        } else {
            let key_id =
                identifier_for_mapping_key_column(TEST_SLOT, &contract_address, chain_id, vec![]);
            let value_id =
                identifier_for_mapping_value_column(TEST_SLOT, &contract_address, chain_id, vec![]);

            CircuitInput::new_mapping_variable_leaf(
                proof1[1].clone(),
                TEST_SLOT,
                key1.to_vec(),
                key_id,
                value_id,
            )
        };
        let now = std::time::Instant::now();
        let leaf_proof1 = generate_proof(&params, leaf_input1).unwrap();
        {
            let lp = ProofWithVK::deserialize(&leaf_proof1).unwrap();
            let pub1 = PublicInputs::new(&lp.proof.public_inputs);
            let (_, ptr) = pub1.mpt_key_info();
            assert_eq!(ptr, GFp::ZERO);
        }
        println!(
            "Proof for leaf 1 generated in {} ms",
            now.elapsed().as_millis()
        );

        println!("Proving leaf 2...");
        let leaf_input2 = if is_simple_aggregation {
            let column_id =
                identifier_single_var_column(TEST_SLOT + 1, &contract_address, chain_id, vec![]);
            CircuitInput::new_single_variable_leaf(proof2[1].clone(), TEST_SLOT + 1, column_id)
        } else {
            let key_id =
                identifier_for_mapping_key_column(TEST_SLOT, &contract_address, chain_id, vec![]);
            let value_id =
                identifier_for_mapping_value_column(TEST_SLOT, &contract_address, chain_id, vec![]);
            CircuitInput::new_mapping_variable_leaf(
                proof2[1].clone(),
                TEST_SLOT,
                key2.to_vec(),
                key_id,
                value_id,
            )
        };
        let now = std::time::Instant::now();
        let leaf_proof2 = generate_proof(&params, leaf_input2).unwrap();
        println!(
            "Proof for leaf 2 generated in {} ms",
            now.elapsed().as_millis()
        );

        println!("Proving branch...");
        let branch_input = if is_simple_aggregation {
            CircuitInput::new_single_variable_branch(
                proof1[0].clone(),
                vec![leaf_proof1, leaf_proof2],
            )
        } else {
            CircuitInput::new_mapping_variable_branch(
                proof1[0].clone(),
                vec![leaf_proof1, leaf_proof2],
            )
        };
        let now = std::time::Instant::now();
        generate_proof(&params, branch_input).unwrap();
        println!(
            "Proof for branch node generated in {} ms",
            now.elapsed().as_millis()
        );
    }

    fn test_circuits(is_simple_aggregation: bool, num_children: usize) {
        let contract_address = Address::from_str(TEST_CONTRACT_ADDRESS).unwrap();
        let chain_id = 10;
        let id = identifier_single_var_column(TEST_SLOT, &contract_address, chain_id, vec![]);
        let key_id =
            identifier_for_mapping_key_column(TEST_SLOT, &contract_address, chain_id, vec![]);
        let value_id =
            identifier_for_mapping_value_column(TEST_SLOT, &contract_address, chain_id, vec![]);

        let params = PublicParameters::build();
        let mut test_data =
            generate_storage_trie_and_keys(is_simple_aggregation, TEST_SLOT, num_children);

        let trie = &mut test_data.trie;
        let mpt1 = test_data.mpt_keys[0].as_slice();
        let mpt2 = test_data.mpt_keys[1].as_slice();
        let p1 = trie.get_proof(mpt1).unwrap();
        let p2 = trie.get_proof(mpt2).unwrap();

        // They should share the same branch node.
        assert_eq!(p1.len(), p2.len());
        assert_eq!(p1[p1.len() - 2], p2[p2.len() - 2]);

        let l1_inputs = if is_simple_aggregation {
            let column_id =
                identifier_single_var_column(TEST_SLOT, &contract_address, chain_id, vec![]);
            CircuitInput::new_single_variable_leaf(
                p1.last().unwrap().to_vec(),
                TEST_SLOT,
                column_id,
            )
        } else {
            let key_id =
                identifier_for_mapping_key_column(TEST_SLOT, &contract_address, chain_id, vec![]);
            let value_id =
                identifier_for_mapping_value_column(TEST_SLOT, &contract_address, chain_id, vec![]);
            CircuitInput::new_mapping_variable_leaf(
                p1.last().unwrap().to_vec(),
                TEST_SLOT,
                test_data.mapping_key.clone().unwrap(),
                key_id,
                value_id,
            )
        };

        // Generate a leaf then a branch proof with only this leaf.
        println!("[+] Generating leaf proof 1...");
        let leaf1_proof_buff = generate_proof(&params, l1_inputs).unwrap();
        let leaf1_proof = ProofWithVK::deserialize(&leaf1_proof_buff).unwrap();
        let pub1 = leaf1_proof.proof.public_inputs[..NUM_IO].to_vec();
        let pi1 = PublicInputs::new(&pub1);
        assert_eq!(pi1.proof_inputs.len(), NUM_IO);
        let (_, comp_ptr) = pi1.mpt_key_info();
        assert_eq!(comp_ptr, F::from_canonical_usize(63));

        let branch_node = p1[p1.len() - 2].to_vec();
        println!("[+] Generating branch proof 1...");
        let branch_inputs = if is_simple_aggregation {
            CircuitInput::new_single_variable_branch(branch_node.clone(), vec![leaf1_proof_buff])
        } else {
            CircuitInput::new_mapping_variable_branch(branch_node.clone(), vec![leaf1_proof_buff])
        };
        let branch1_buff = generate_proof(&params, branch_inputs).unwrap();
        let branch1 = ProofWithVK::deserialize(&branch1_buff).unwrap();
        let exp_vk = params.branches.b1.get_verifier_data();
        assert_eq!(branch1.verifier_data(), exp_vk);

        // Generate a fake proof to test branch circuit.
        let gen_fake_proof = |mpt| {
            let mut pub2 = pub1.clone();
            assert_eq!(pub2.len(), NUM_IO);
            pub2[public_inputs::K_RANGE].copy_from_slice(
                &bytes_to_nibbles(mpt)
                    .into_iter()
                    .map(F::from_canonical_u8)
                    .collect::<Vec<_>>(),
            );
            assert_eq!(pub2.len(), pub1.len());

            let pi2 = PublicInputs::new(&pub2);
            {
                let (k1, p1) = pi1.mpt_key_info();
                let (k2, p2) = pi2.mpt_key_info();
                let (pt1, pt2) = (
                    p1.to_canonical_u64() as usize,
                    p2.to_canonical_u64() as usize,
                );
                assert!(pt1 < k1.len() && pt2 < k2.len());
                assert!(p1 == p2);
                assert!(k1[..pt1] == k2[..pt2]);
            }
            let fake_proof = params
                .set
                .generate_input_proofs([pub2.clone().try_into().unwrap()])
                .unwrap();
            let vk = params.set.verifier_data_for_input_proofs::<1>()[0].clone();
            ProofWithVK::from((fake_proof[0].clone(), vk))
        };

        // Check validity of public input of `branch2` proof.
        let check_public_input = |num_children, proof: &ProofWithVK| {
            let branch_pub = PublicInputs::new(&proof.proof().public_inputs[..NUM_IO]);

            let value: Vec<u8> = rlp::decode(&trie.get(mpt1).unwrap().unwrap()).unwrap();
            let [leaf_values_digest, leaf_metadata_digest] = if is_simple_aggregation {
                let dv = compute_leaf_single_values_digest(id, &value);
                let dm = compute_leaf_single_metadata_digest(id, TEST_SLOT);

                [dv, dm]
            } else {
                let dv = compute_leaf_mapping_values_digest(
                    key_id,
                    value_id,
                    &test_data.mapping_key.clone().unwrap(),
                    &value,
                );
                let dm = compute_leaf_mapping_metadata_digest(key_id, value_id, TEST_SLOT);

                [dv, dm]
            };

            let values_digest =
                (0..num_children).fold(Point::NEUTRAL, |acc, _| acc + leaf_values_digest);
            let metadata_digest = if is_simple_aggregation {
                (0..num_children).fold(Point::NEUTRAL, |acc, _| acc + leaf_metadata_digest)
            } else {
                leaf_metadata_digest
            };
            assert_eq!(branch_pub.values_digest(), values_digest.to_weierstrass());
            assert_eq!(
                branch_pub.metadata_digest(),
                metadata_digest.to_weierstrass()
            );
            assert_eq!(branch_pub.n(), F::from_canonical_usize(num_children));

            let (k1, p1) = pi1.mpt_key_info();
            let (kb, pb) = branch_pub.mpt_key_info();
            let p1 = p1.to_canonical_u64() as usize;
            let pb = pb.to_canonical_u64() as usize;
            assert_eq!(p1 - 1, pb);
            assert_eq!(k1[..pb], kb[..pb]);
        };

        // Generate a branch proof with two leafs inputs now but using the
        // testing framework. We simulate another leaf at the right key, so we
        // just modify the nibble at the pointer.
        // Generate fake dummy proofs but with expected public inputs.
        println!("[+] Generating leaf proof 2...");
        let leaf2_proof = gen_fake_proof(mpt2);

        println!("[+] Generating branch proof 2...");
        let branch_input = BranchInput {
            input: InputNode {
                node: branch_node.clone(),
            },
            serialized_child_proofs: vec![
                bincode::serialize(&leaf1_proof).unwrap(),
                bincode::serialize(&leaf2_proof).unwrap(),
            ],
        };
        let branch_input = if is_simple_aggregation {
            CircuitInput::BranchSingle(branch_input)
        } else {
            CircuitInput::BranchMapping(branch_input)
        };
        let branch2 = params.generate_proof(branch_input).unwrap();
        let exp_vk = params.branches.b4.get_verifier_data().clone();
        assert_eq!(branch2.verifier_data(), &exp_vk);
        check_public_input(2, &branch2);

        // Generate num_children-2 fake proofs to test branch circuit with
        // num_children proofs.
        let mut serialized_child_proofs = vec![
            bincode::serialize(&leaf1_proof).unwrap(),
            bincode::serialize(&leaf2_proof).unwrap(),
        ];
        for i in 2..num_children {
            serialized_child_proofs.push(
                bincode::serialize(&gen_fake_proof(test_data.mpt_keys[i].as_slice())).unwrap(),
            )
        }
        println!("[+] Generating branch proof {}...", num_children);
        let branch_input = BranchInput {
            input: InputNode {
                node: branch_node.clone(),
            },
            serialized_child_proofs,
        };
        let branch_input = if is_simple_aggregation {
            CircuitInput::BranchSingle(branch_input)
        } else {
            CircuitInput::BranchMapping(branch_input)
        };
        let branch_proof = params.generate_proof(branch_input).unwrap();
        let exp_vk = params.branches.b9.get_verifier_data().clone();
        assert_eq!(branch_proof.verifier_data(), &exp_vk);
        check_public_input(num_children, &branch_proof);
    }
}
