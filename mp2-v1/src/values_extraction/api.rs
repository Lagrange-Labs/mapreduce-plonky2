//! Values extraction APIs

use super::{
    branch::{BranchCircuit, BranchWires},
    extension::{ExtensionNodeCircuit, ExtensionNodeWires},
    gadgets::{column_info::ColumnInfo, metadata_gadget::MetadataGadget},
    leaf_mapping::{LeafMappingCircuit, LeafMappingWires},
    leaf_mapping_of_mappings::{LeafMappingOfMappingsCircuit, LeafMappingOfMappingsWires},
    leaf_single::{LeafSingleCircuit, LeafSingleWires},
    public_inputs::PublicInputs,
};
use crate::{api::InputNode, MAX_BRANCH_NODE_LEN};
use anyhow::{bail, Result};
use log::debug;
use mp2_common::{
    default_config,
    mpt_sequential::PAD_LEN,
    poseidon::H,
    proof::{ProofInputSerialized, ProofWithVK},
    storage_key::{MappingSlot, SimpleSlot},
    C, D, F,
};
use paste::paste;
use plonky2::{field::types::PrimeField64, hash::hash_types::HashOut, plonk::config::Hasher};
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

type ExtensionInput = ProofInputSerialized<InputNode>;
type BranchInput = ProofInputSerialized<InputNode>;
const NUM_IO: usize = PublicInputs::<F>::TOTAL_LEN;

/// CircuitInput is a wrapper around the different specialized circuits that can
/// be used to prove a MPT node recursively.
#[derive(Serialize, Deserialize)]
pub enum CircuitInput<
    const NODE_LEN: usize,
    const MAX_COLUMNS: usize,
    const MAX_FIELD_PER_EVM: usize,
> where
    [(); PAD_LEN(NODE_LEN)]:,
{
    LeafSingle(LeafSingleCircuit<NODE_LEN, MAX_COLUMNS, MAX_FIELD_PER_EVM>),
    LeafMapping(LeafMappingCircuit<NODE_LEN, MAX_COLUMNS, MAX_FIELD_PER_EVM>),
    LeafMappingOfMappings(LeafMappingOfMappingsCircuit<NODE_LEN, MAX_COLUMNS, MAX_FIELD_PER_EVM>),
    Extension(ExtensionInput),
    Branch(BranchInput),
}

impl<const NODE_LEN: usize, const MAX_COLUMNS: usize, const MAX_FIELD_PER_EVM: usize>
    CircuitInput<NODE_LEN, MAX_COLUMNS, MAX_FIELD_PER_EVM>
where
    [(); PAD_LEN(NODE_LEN)]:,
{
    /// Create a circuit input for proving a leaf MPT node of single variable.
    pub fn new_single_variable_leaf(
        node: Vec<u8>,
        slot: u8,
        evm_word: u32,
        extracted_column_identifiers: &[F],
        table_info: Vec<ColumnInfo>,
    ) -> Self {
        let slot = SimpleSlot::new(slot);
        let metadata = MetadataGadget::new(table_info, extracted_column_identifiers, evm_word);

        CircuitInput::LeafSingle(LeafSingleCircuit {
            node,
            slot,
            metadata,
        })
    }

    /// Create a circuit input for proving a leaf MPT node of mapping variable.
    pub fn new_mapping_variable_leaf(
        node: Vec<u8>,
        slot: u8,
        mapping_key: Vec<u8>,
        key_id: F,
        evm_word: u32,
        extracted_column_identifiers: &[F],
        table_info: Vec<ColumnInfo>,
    ) -> Self {
        let slot = MappingSlot::new(slot, mapping_key);
        let metadata = MetadataGadget::new(table_info, extracted_column_identifiers, evm_word);

        CircuitInput::LeafMapping(LeafMappingCircuit {
            node,
            slot,
            key_id,
            metadata,
        })
    }

    /// Create a circuit input for proving a leaf MPT node of mappings where the
    /// value stored in a mapping entry is another mapping.
    pub fn new_mapping_of_mappings_leaf(
        node: Vec<u8>,
        slot: u8,
        outer_key: Vec<u8>,
        inner_key: Vec<u8>,
        outer_key_id: F,
        inner_key_id: F,
        evm_word: u32,
        extracted_column_identifiers: &[F],
        table_info: Vec<ColumnInfo>,
    ) -> Self {
        let slot = MappingSlot::new(slot, outer_key);
        let metadata = MetadataGadget::new(table_info, extracted_column_identifiers, evm_word);

        CircuitInput::LeafMappingOfMappings(LeafMappingOfMappingsCircuit {
            node,
            slot,
            inner_key,
            outer_key_id,
            inner_key_id,
            metadata,
        })
    }

    /// Create a circuit input for proving an extension MPT node.
    pub fn new_extension(node: Vec<u8>, child_proof: Vec<u8>) -> Self {
        CircuitInput::Extension(ExtensionInput {
            input: InputNode { node },
            serialized_child_proofs: vec![child_proof],
        })
    }

    /// Create a circuit input for proving a branch MPT node.
    pub fn new_branch(node: Vec<u8>, child_proofs: Vec<Vec<u8>>) -> Self {
        CircuitInput::Branch(ProofInputSerialized {
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
pub struct PublicParameters<
    const NODE_LEN: usize,
    const MAX_COLUMNS: usize,
    const MAX_FIELD_PER_EVM: usize,
> where
    [(); PAD_LEN(NODE_LEN)]:,
{
    leaf_single: CircuitWithUniversalVerifier<
        F,
        C,
        D,
        0,
        LeafSingleWires<NODE_LEN, MAX_COLUMNS, MAX_FIELD_PER_EVM>,
    >,
    leaf_mapping: CircuitWithUniversalVerifier<
        F,
        C,
        D,
        0,
        LeafMappingWires<NODE_LEN, MAX_COLUMNS, MAX_FIELD_PER_EVM>,
    >,
    leaf_mapping_of_mappings: CircuitWithUniversalVerifier<
        F,
        C,
        D,
        0,
        LeafMappingOfMappingsWires<NODE_LEN, MAX_COLUMNS, MAX_FIELD_PER_EVM>,
    >,
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
pub fn build_circuits_params<
    const NODE_LEN: usize,
    const MAX_COLUMNS: usize,
    const MAX_FIELD_PER_EVM: usize,
>() -> PublicParameters<NODE_LEN, MAX_COLUMNS, MAX_FIELD_PER_EVM>
where
    [(); PAD_LEN(NODE_LEN)]:,
{
    PublicParameters::build()
}

/// Public API employed to generate a proof for the circuit specified by
/// `CircuitInput`, employing the `circuit_params` generated with the
/// `build_circuits_params` API.
pub fn generate_proof<
    const NODE_LEN: usize,
    const MAX_COLUMNS: usize,
    const MAX_FIELD_PER_EVM: usize,
>(
    circuit_params: &PublicParameters<NODE_LEN, MAX_COLUMNS, MAX_FIELD_PER_EVM>,
    circuit_type: CircuitInput<NODE_LEN, MAX_COLUMNS, MAX_FIELD_PER_EVM>,
) -> Result<Vec<u8>>
where
    [(); PAD_LEN(NODE_LEN)]:,
{
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
                            let pi1 = PublicInputs::<F>::new(&arr[0].proof().public_inputs);
                            let (k1, p1) = pi1.mpt_key_info();
                            let pi2 = PublicInputs::<F>::new(&arr[1].proof().public_inputs);
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
                             },
                         ).map(|p| (p, self.[< b $i>].get_verifier_data().clone()).into())
                     }
                 )+
                     _ => bail!("invalid child proof len"),
                 }
            }
        }}
    }
}

impl_branch_circuits!(BranchCircuits, 2, 9, 16);
#[cfg(test)]
impl_branch_circuits!(TestBranchCircuits, 1, 4, 9);

/// Number of circuits in the set
/// 3 branch circuits + 1 extension + 1 leaf single + 1 leaf mapping + 1 leaf mapping of mappings
const MAPPING_CIRCUIT_SET_SIZE: usize = 7;

impl<const NODE_LEN: usize, const MAX_COLUMNS: usize, const MAX_FIELD_PER_EVM: usize>
    PublicParameters<NODE_LEN, MAX_COLUMNS, MAX_FIELD_PER_EVM>
where
    [(); PAD_LEN(NODE_LEN)]:,
    [(); <H as Hasher<F>>::HASH_SIZE]:,
{
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
        let leaf_single = circuit_builder
            .build_circuit::<C, 0, LeafSingleWires<NODE_LEN, MAX_COLUMNS, MAX_FIELD_PER_EVM>>(());

        debug!("Building leaf mapping circuit");
        let leaf_mapping = circuit_builder.build_circuit::<C, 0, LeafMappingWires<
            NODE_LEN,
            MAX_COLUMNS,
            MAX_FIELD_PER_EVM,
        >>(());

        debug!("Building leaf mapping of mappings circuit");
        let leaf_mapping_of_mappings =
                        circuit_builder.build_circuit::<C, 0,
                LeafMappingOfMappingsWires<NODE_LEN, MAX_COLUMNS, MAX_FIELD_PER_EVM>
                        >(());

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
            leaf_mapping_of_mappings.get_verifier_data().circuit_digest,
            extension.get_verifier_data().circuit_digest,
        ];
        circuits_set.extend(branches.circuit_set());
        assert_eq!(circuits_set.len(), MAPPING_CIRCUIT_SET_SIZE);

        PublicParameters {
            leaf_single,
            leaf_mapping,
            leaf_mapping_of_mappings,
            extension,
            branches,
            #[cfg(not(test))]
            set: RecursiveCircuits::new_from_circuit_digests(circuits_set),
            #[cfg(test)]
            set: TestingRecursiveCircuits::new_from_circuit_digests(&circuit_builder, circuits_set),
        }
    }

    fn generate_proof(
        &self,
        circuit_type: CircuitInput<NODE_LEN, MAX_COLUMNS, MAX_FIELD_PER_EVM>,
    ) -> Result<ProofWithVK> {
        let set = &self.get_circuit_set();
        match circuit_type {
            CircuitInput::LeafSingle(leaf) => set
                .generate_proof(&self.leaf_single, [], [], leaf)
                .map(|p| (p, self.leaf_single.get_verifier_data().clone()).into()),
            CircuitInput::LeafMapping(leaf) => set
                .generate_proof(&self.leaf_mapping, [], [], leaf)
                .map(|p| (p, self.leaf_mapping.get_verifier_data().clone()).into()),
            CircuitInput::LeafMappingOfMappings(leaf) => set
                .generate_proof(&self.leaf_mapping_of_mappings, [], [], leaf)
                .map(|p| (p, self.leaf_mapping_of_mappings.get_verifier_data().clone()).into()),
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
            CircuitInput::Branch(branch) => {
                let child_proofs = branch.get_child_proofs()?;
                self.branches
                    .generate_proof(set, branch.input, child_proofs)
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
    use super::{super::public_inputs, *};
    use crate::{
        tests::{TEST_MAX_COLUMNS, TEST_MAX_FIELD_PER_EVM},
        values_extraction::{
            compute_leaf_mapping_metadata_digest, compute_leaf_mapping_of_mappings_metadata_digest,
            compute_leaf_single_metadata_digest,
        },
        MAX_LEAF_NODE_LEN,
    };
    use eth_trie::{EthTrie, MemoryDB, Trie};
    use itertools::Itertools;
    use log::info;
    use mp2_common::{
        array::ToField,
        eth::{StorageSlot, StorageSlotNode},
        group_hashing::weierstrass_to_point,
        mpt_sequential::utils::bytes_to_nibbles,
        types::MAPPING_LEAF_VALUE_LEN,
    };
    use mp2_test::{mpt_sequential::generate_random_storage_mpt, utils::random_vector};
    use plonky2::field::types::{Field, Sample};
    use plonky2_ecgfp5::curve::curve::Point;
    use std::{slice, sync::Arc};

    type StorageSlotInfo = super::super::StorageSlotInfo<TEST_MAX_COLUMNS, TEST_MAX_FIELD_PER_EVM>;
    type CircuitInput =
        super::CircuitInput<MAX_LEAF_NODE_LEN, TEST_MAX_COLUMNS, TEST_MAX_FIELD_PER_EVM>;
    type PublicParameters =
        super::PublicParameters<MAX_LEAF_NODE_LEN, TEST_MAX_COLUMNS, TEST_MAX_FIELD_PER_EVM>;

    #[derive(Debug)]
    struct TestEthTrie {
        trie: EthTrie<MemoryDB>,
        mpt_keys: Vec<Vec<u8>>,
    }

    #[test]
    fn test_values_extraction_api_single_variable() {
        const TEST_SLOTS: [u8; 2] = [5, 10];

        let _ = env_logger::try_init();

        let storage_slot1 = StorageSlot::Simple(TEST_SLOTS[0] as usize);
        let storage_slot2 = StorageSlot::Simple(TEST_SLOTS[1] as usize);

        let mut metadata1 = MetadataGadget::sample(TEST_SLOTS[0], 0);
        // We only extract the first column for simple slot.
        metadata1.num_extracted_columns = 1;
        // Set the second test slot and EVM word.
        metadata1.table_info[1].slot = TEST_SLOTS[1].to_field();
        metadata1.table_info[1].evm_word = F::ZERO;
        // Initialize the second metadata with second column identifier.
        let metadata2 = MetadataGadget::new(
            metadata1.table_info[..metadata1.num_actual_columns].to_vec(),
            slice::from_ref(&metadata1.table_info[1].identifier),
            0,
        );

        let test_slots = [
            StorageSlotInfo::new(storage_slot1, metadata1, None, None),
            StorageSlotInfo::new(storage_slot2, metadata2, None, None),
        ];

        test_api(test_slots);
    }

    #[test]
    fn test_values_extraction_api_single_struct() {
        const TEST_SLOT: u8 = 2;
        const TEST_EVM_WORDS: [u32; 2] = [10, 20];

        let _ = env_logger::try_init();

        let parent_slot = StorageSlot::Simple(TEST_SLOT as usize);
        let storage_slot1 = StorageSlot::Node(StorageSlotNode::new_struct(
            parent_slot.clone(),
            TEST_EVM_WORDS[0],
        ));
        let storage_slot2 =
            StorageSlot::Node(StorageSlotNode::new_struct(parent_slot, TEST_EVM_WORDS[1]));

        let mut metadata1 = MetadataGadget::sample(TEST_SLOT, TEST_EVM_WORDS[0]);
        // We only extract the first column for simple slot.
        metadata1.num_extracted_columns = 1;
        // Set the second test slot and EVM word.
        metadata1.table_info[1].slot = TEST_SLOT.to_field();
        metadata1.table_info[1].evm_word = TEST_EVM_WORDS[1].to_field();
        // Initialize the second metadata with second column identifier.
        let metadata2 = MetadataGadget::new(
            metadata1.table_info[..metadata1.num_actual_columns].to_vec(),
            slice::from_ref(&metadata1.table_info[1].identifier),
            TEST_EVM_WORDS[1],
        );

        let test_slots = [
            StorageSlotInfo::new(storage_slot1, metadata1, None, None),
            StorageSlotInfo::new(storage_slot2, metadata2, None, None),
        ];

        test_api(test_slots);
    }

    #[test]
    fn test_values_extraction_api_mapping_variable() {
        const TEST_SLOT: u8 = 2;

        let _ = env_logger::try_init();

        let mapping_key1 = vec![10];
        let mapping_key2 = vec![20];
        let storage_slot1 = StorageSlot::Mapping(mapping_key1, TEST_SLOT as usize);
        let storage_slot2 = StorageSlot::Mapping(mapping_key2, TEST_SLOT as usize);

        let mut metadata1 = MetadataGadget::sample(TEST_SLOT, 0);
        // We only extract the first column for simple slot.
        metadata1.num_extracted_columns = 1;
        // Set the second test slot and EVM word.
        metadata1.table_info[1].slot = TEST_SLOT.to_field();
        metadata1.table_info[1].evm_word = F::ZERO;
        // The first and second column infos are same (only for testing).
        let metadata2 = metadata1.clone();

        let key_id = Some(F::rand());
        let test_slots = [
            StorageSlotInfo::new(storage_slot1, metadata1, key_id, None),
            StorageSlotInfo::new(storage_slot2, metadata2, key_id, None),
        ];

        test_api(test_slots);
    }

    #[test]
    fn test_values_extraction_api_mapping_struct() {
        const TEST_SLOT: u8 = 2;
        const TEST_EVM_WORDS: [u32; 2] = [10, 20];

        let _ = env_logger::try_init();

        let parent_slot = StorageSlot::Mapping(vec![10, 20], TEST_SLOT as usize);
        let storage_slot1 = StorageSlot::Node(StorageSlotNode::new_struct(
            parent_slot.clone(),
            TEST_EVM_WORDS[0],
        ));
        let storage_slot2 =
            StorageSlot::Node(StorageSlotNode::new_struct(parent_slot, TEST_EVM_WORDS[1]));

        let mut metadata1 = MetadataGadget::sample(TEST_SLOT, TEST_EVM_WORDS[0]);
        // We only extract the first column for simple slot.
        metadata1.num_extracted_columns = 1;
        // Set the second test slot and EVM word.
        metadata1.table_info[1].slot = TEST_SLOT.to_field();
        metadata1.table_info[1].evm_word = TEST_EVM_WORDS[1].to_field();
        // Initialize the second metadata with second column identifier.
        let metadata2 = MetadataGadget::new(
            metadata1.table_info[..metadata1.num_actual_columns].to_vec(),
            slice::from_ref(&metadata1.table_info[1].identifier),
            TEST_EVM_WORDS[1],
        );

        let key_id = Some(F::rand());
        let test_slots = [
            StorageSlotInfo::new(storage_slot1, metadata1, key_id, None),
            StorageSlotInfo::new(storage_slot2, metadata2, key_id, None),
        ];

        test_api(test_slots);
    }

    #[test]
    fn test_values_extraction_api_mapping_of_mappings() {
        const TEST_SLOT: u8 = 2;
        const TEST_EVM_WORDS: [u32; 2] = [10, 20];

        let _ = env_logger::try_init();

        let grand_slot = StorageSlot::Mapping(vec![10, 20], TEST_SLOT as usize);
        let parent_slot =
            StorageSlot::Node(StorageSlotNode::new_mapping(grand_slot, vec![30, 40]).unwrap());
        let storage_slot1 = StorageSlot::Node(StorageSlotNode::new_struct(
            parent_slot.clone(),
            TEST_EVM_WORDS[0],
        ));
        let storage_slot2 =
            StorageSlot::Node(StorageSlotNode::new_struct(parent_slot, TEST_EVM_WORDS[1]));

        let mut metadata1 = MetadataGadget::sample(TEST_SLOT, TEST_EVM_WORDS[0]);
        // We only extract the first column for simple slot.
        metadata1.num_extracted_columns = 1;
        // Set the second test slot and EVM word.
        metadata1.table_info[1].slot = TEST_SLOT.to_field();
        metadata1.table_info[1].evm_word = TEST_EVM_WORDS[1].to_field();
        let mut metadata2 = metadata1.clone();
        metadata2.evm_word = TEST_EVM_WORDS[1];
        // Swap the column infos of the two test slots.
        metadata2.table_info[0] = metadata1.table_info[1].clone();
        metadata2.table_info[1] = metadata1.table_info[0].clone();

        let outer_key_id = Some(F::rand());
        let inner_key_id = Some(F::rand());
        let test_slots = [
            StorageSlotInfo::new(storage_slot1, metadata1, outer_key_id, inner_key_id),
            StorageSlotInfo::new(storage_slot2, metadata2, outer_key_id, inner_key_id),
        ];

        test_api(test_slots);
    }

    #[test]
    fn test_values_extraction_api_branch_with_multiple_children() {
        const TEST_SLOT: u8 = 2;
        const NUM_CHILDREN: usize = 6;

        let _ = env_logger::try_init();

        let storage_slot = StorageSlot::Simple(TEST_SLOT as usize);
        let metadata = MetadataGadget::sample(TEST_SLOT, 0);
        let test_slot = StorageSlotInfo::new(storage_slot, metadata, None, None);

        test_branch_with_multiple_children(NUM_CHILDREN, test_slot);
    }

    #[test]
    fn test_values_extraction_api_serialization() {
        const TEST_SLOT: u8 = 10;
        const TEST_EVM_WORD: u32 = 5;
        const TEST_OUTER_KEY: [u8; 2] = [10, 20];
        const TEST_INNER_KEY: [u8; 3] = [30, 40, 50];

        let _ = env_logger::try_init();

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

        // Test for single variable leaf.
        let parent_slot = StorageSlot::Simple(TEST_SLOT as usize);
        let storage_slot = StorageSlot::Node(StorageSlotNode::new_struct(
            parent_slot.clone(),
            TEST_EVM_WORD,
        ));
        let mut metadata = MetadataGadget::sample(TEST_SLOT, 0);
        // We only extract the first column for simple slot.
        metadata.num_extracted_columns = 1;
        let table_info = metadata.table_info.to_vec();
        let column_identifier = table_info[0].identifier;
        let test_slot = StorageSlotInfo::new(storage_slot, metadata, None, None);
        let mut test_trie = generate_test_trie(1, &test_slot);
        let proof = test_trie.trie.get_proof(&test_trie.mpt_keys[0]).unwrap();
        test_circuit_input(CircuitInput::new_single_variable_leaf(
            proof.last().unwrap().to_vec(),
            TEST_SLOT,
            0,
            slice::from_ref(&column_identifier),
            table_info,
        ));

        // Test for mapping variable leaf.
        let parent_slot = StorageSlot::Mapping(TEST_OUTER_KEY.to_vec(), TEST_SLOT as usize);
        let storage_slot = StorageSlot::Node(StorageSlotNode::new_struct(
            parent_slot.clone(),
            TEST_EVM_WORD,
        ));
        let mut metadata = MetadataGadget::sample(TEST_SLOT, TEST_EVM_WORD);
        // We only extract the first column.
        metadata.num_extracted_columns = 1;
        let table_info = metadata.table_info.to_vec();
        let column_identifier = table_info[0].identifier;
        let key_id = F::rand();
        let test_slot = StorageSlotInfo::new(storage_slot, metadata, Some(key_id), None);
        let mut test_trie = generate_test_trie(1, &test_slot);
        let proof = test_trie.trie.get_proof(&test_trie.mpt_keys[0]).unwrap();
        test_circuit_input(CircuitInput::new_mapping_variable_leaf(
            proof.last().unwrap().to_vec(),
            TEST_SLOT,
            TEST_OUTER_KEY.to_vec(),
            key_id,
            TEST_EVM_WORD,
            slice::from_ref(&column_identifier),
            table_info,
        ));

        // Test for mapping of mappings leaf.
        let grand_slot = StorageSlot::Mapping(TEST_OUTER_KEY.to_vec(), TEST_SLOT as usize);
        let parent_slot = StorageSlot::Node(
            StorageSlotNode::new_mapping(grand_slot, TEST_INNER_KEY.to_vec()).unwrap(),
        );
        let storage_slot =
            StorageSlot::Node(StorageSlotNode::new_struct(parent_slot, TEST_EVM_WORD));
        let mut metadata = MetadataGadget::sample(TEST_SLOT, TEST_EVM_WORD);
        // We only extract the first column.
        metadata.num_extracted_columns = 1;
        let table_info = metadata.table_info.to_vec();
        let column_identifier = table_info[0].identifier;
        let outer_key_id = F::rand();
        let inner_key_id = F::rand();
        let test_slot = StorageSlotInfo::new(
            storage_slot,
            metadata,
            Some(outer_key_id),
            Some(inner_key_id),
        );
        let mut test_trie = generate_test_trie(2, &test_slot);
        let proof = test_trie.trie.get_proof(&test_trie.mpt_keys[0]).unwrap();
        let encoded = test_circuit_input(CircuitInput::new_mapping_of_mappings_leaf(
            proof.last().unwrap().to_vec(),
            TEST_SLOT,
            TEST_OUTER_KEY.to_vec(),
            TEST_INNER_KEY.to_vec(),
            outer_key_id,
            inner_key_id,
            TEST_EVM_WORD,
            slice::from_ref(&column_identifier),
            table_info,
        ));

        // Test for branch.
        let branch_node = proof[proof.len() - 2].to_vec();
        test_circuit_input(CircuitInput::Branch(BranchInput {
            input: InputNode {
                node: branch_node.clone(),
            },
            serialized_child_proofs: vec![encoded],
        }));
    }

    fn test_api(test_slots: [StorageSlotInfo; 2]) {
        info!("Generating MPT proofs");
        let memdb = Arc::new(MemoryDB::new(true));
        let mut trie = EthTrie::new(memdb.clone());
        let mpt_keys = test_slots
            .iter()
            .map(|test_slot| {
                let mpt_key = test_slot.slot.mpt_key();
                let value = random_vector(MAPPING_LEAF_VALUE_LEN);
                trie.insert(&mpt_key, &rlp::encode(&value)).unwrap();
                mpt_key
            })
            .collect_vec();
        trie.root_hash().unwrap();
        let mpt_proofs = mpt_keys
            .into_iter()
            .map(|key| trie.get_proof(&key).unwrap())
            .collect_vec();
        // Get the branch node.
        let node_len = mpt_proofs[0].len();
        // Ensure both are located in the same branch.
        assert_eq!(node_len, mpt_proofs[1].len());
        let branch_node = mpt_proofs[0][node_len - 2].clone();
        assert_eq!(branch_node, mpt_proofs[1][node_len - 2]);

        info!("Generating parameters");
        let params = build_circuits_params();

        let leaf_proofs = test_slots
            .into_iter()
            .zip_eq(mpt_proofs)
            .enumerate()
            .map(|(i, (test_slot, mut leaf_proof))| {
                info!("Proving leaf {i}");
                prove_leaf(&params, leaf_proof.pop().unwrap(), test_slot)
            })
            .collect();

        info!("Proving branch");
        let _branch_proof = prove_branch(&params, branch_node, leaf_proofs);
    }

    /// Generate a branch proof.
    fn prove_branch(
        params: &PublicParameters,
        node: Vec<u8>,
        leaf_proofs: Vec<Vec<u8>>,
    ) -> Vec<u8> {
        let input = CircuitInput::new_branch(node, leaf_proofs);
        generate_proof(params, input).unwrap()
    }

    /// Generate a leaf proof.
    fn prove_leaf(params: &PublicParameters, node: Vec<u8>, test_slot: StorageSlotInfo) -> Vec<u8> {
        let metadata = test_slot.metadata();
        let evm_word = metadata.evm_word;
        let table_info = metadata.table_info[..metadata.num_actual_columns].to_vec();
        let extracted_column_identifiers = table_info[..metadata.num_extracted_columns]
            .iter()
            .map(|column_info| column_info.identifier)
            .collect_vec();

        let (expected_metadata_digest, circuit_input) = match test_slot.slot {
            // Simple variable slot
            StorageSlot::Simple(slot) => {
                let metadata_digest = compute_leaf_single_metadata_digest::<
                    TEST_MAX_COLUMNS,
                    TEST_MAX_FIELD_PER_EVM,
                >(
                    table_info.clone(), &extracted_column_identifiers, evm_word
                );

                let circuit_input = CircuitInput::new_single_variable_leaf(
                    node,
                    slot as u8,
                    evm_word,
                    &extracted_column_identifiers,
                    table_info,
                );

                (metadata_digest, circuit_input)
            }
            // Mapping variable
            StorageSlot::Mapping(mapping_key, slot) => {
                let metadata_digest = compute_leaf_mapping_metadata_digest::<
                    TEST_MAX_COLUMNS,
                    TEST_MAX_FIELD_PER_EVM,
                >(
                    table_info.clone(),
                    &extracted_column_identifiers,
                    evm_word,
                    slot as u8,
                    test_slot.outer_key_id,
                );

                let circuit_input = CircuitInput::new_mapping_variable_leaf(
                    node,
                    slot as u8,
                    mapping_key,
                    test_slot.outer_key_id,
                    evm_word,
                    &extracted_column_identifiers,
                    table_info,
                );

                (metadata_digest, circuit_input)
            }
            StorageSlot::Node(StorageSlotNode::Struct(parent, evm_word)) => match *parent {
                // Simple Struct
                StorageSlot::Simple(slot) => {
                    let metadata_digest =
                        compute_leaf_single_metadata_digest::<
                            TEST_MAX_COLUMNS,
                            TEST_MAX_FIELD_PER_EVM,
                        >(
                            table_info.clone(), &extracted_column_identifiers, evm_word
                        );

                    let circuit_input = CircuitInput::new_single_variable_leaf(
                        node,
                        slot as u8,
                        evm_word,
                        &extracted_column_identifiers,
                        table_info,
                    );

                    (metadata_digest, circuit_input)
                }
                // Mapping Struct
                StorageSlot::Mapping(mapping_key, slot) => {
                    let metadata_digest = compute_leaf_mapping_metadata_digest::<
                        TEST_MAX_COLUMNS,
                        TEST_MAX_FIELD_PER_EVM,
                    >(
                        table_info.clone(),
                        &extracted_column_identifiers,
                        evm_word,
                        slot as u8,
                        test_slot.outer_key_id,
                    );

                    let circuit_input = CircuitInput::new_mapping_variable_leaf(
                        node,
                        slot as u8,
                        mapping_key,
                        test_slot.outer_key_id,
                        evm_word,
                        &extracted_column_identifiers,
                        table_info,
                    );

                    (metadata_digest, circuit_input)
                }
                // Mapping of mappings Struct
                StorageSlot::Node(StorageSlotNode::Mapping(grand, inner_mapping_key)) => {
                    match *grand {
                        StorageSlot::Mapping(outer_mapping_key, slot) => {
                            let metadata_digest = compute_leaf_mapping_of_mappings_metadata_digest::<
                                TEST_MAX_COLUMNS,
                                TEST_MAX_FIELD_PER_EVM,
                            >(
                                table_info.clone(),
                                &extracted_column_identifiers,
                                evm_word,
                                slot as u8,
                                test_slot.outer_key_id,
                                test_slot.inner_key_id,
                            );

                            let circuit_input = CircuitInput::new_mapping_of_mappings_leaf(
                                node,
                                slot as u8,
                                outer_mapping_key,
                                inner_mapping_key,
                                test_slot.outer_key_id,
                                test_slot.inner_key_id,
                                evm_word,
                                &extracted_column_identifiers,
                                table_info,
                            );

                            (metadata_digest, circuit_input)
                        }
                        _ => unreachable!(),
                    }
                }
                _ => unreachable!(),
            },
            _ => unreachable!(),
        };

        let proof = generate_proof(params, circuit_input).unwrap();

        // Check the metadata digest of public inputs.
        let decoded_proof = ProofWithVK::deserialize(&proof).unwrap();
        let pi = PublicInputs::new(&decoded_proof.proof.public_inputs);
        assert_eq!(
            pi.metadata_digest(),
            expected_metadata_digest.to_weierstrass()
        );

        proof
    }

    /// Generate a MPT trie with sepcified number of children.
    fn generate_test_trie(num_children: usize, storage_slot: &StorageSlotInfo) -> TestEthTrie {
        let (mut trie, _) = generate_random_storage_mpt::<3, 32>();

        let mut mpt_key = storage_slot.slot.mpt_key_vec();
        let mpt_len = mpt_key.len();
        let last_byte = mpt_key[mpt_len - 1];
        let first_nibble = last_byte & 0xF0;
        let second_nibble = last_byte & 0x0F;

        // Generate the test MPT keys.
        let mut mpt_keys = Vec::new();
        for i in 0..num_children {
            // Only change the last nibble.
            mpt_key[mpt_len - 1] = first_nibble + ((second_nibble + i as u8) & 0x0F);
            mpt_keys.push(mpt_key.clone());
        }

        // Add the MPT keys to the trie.
        let value = rlp::encode(&random_vector(32)).to_vec();
        mpt_keys
            .iter()
            .for_each(|key| trie.insert(key, &value).unwrap());
        trie.root_hash().unwrap();

        TestEthTrie { trie, mpt_keys }
    }

    /// Test the proof generation of one branch with the specified number of children.
    fn test_branch_with_multiple_children(num_children: usize, test_slot: StorageSlotInfo) {
        info!("Generating test trie");
        let mut test_trie = generate_test_trie(num_children, &test_slot);

        let mpt_key1 = test_trie.mpt_keys[0].as_slice();
        let mpt_key2 = test_trie.mpt_keys[1].as_slice();
        let proof1 = test_trie.trie.get_proof(mpt_key1).unwrap();
        let proof2 = test_trie.trie.get_proof(mpt_key2).unwrap();
        let node_len = proof1.len();
        // Get the branch node.
        let branch_node = proof1[node_len - 2].clone();
        // Ensure both are located in the same branch.
        assert_eq!(node_len, proof2.len());
        assert_eq!(branch_node, proof2[node_len - 2]);

        info!("Generating parameters");
        let params = build_circuits_params();

        // Generate the branch proof with one leaf.
        println!("Generating leaf proof");
        let leaf_proof_buf1 = prove_leaf(&params, proof1[node_len - 1].clone(), test_slot);
        let leaf_proof1 = ProofWithVK::deserialize(&leaf_proof_buf1).unwrap();
        let pub1 = leaf_proof1.proof.public_inputs[..NUM_IO].to_vec();
        let pi1 = PublicInputs::new(&pub1);
        assert_eq!(pi1.proof_inputs.len(), NUM_IO);
        let (_, comp_ptr) = pi1.mpt_key_info();
        assert_eq!(comp_ptr, F::from_canonical_usize(63));
        println!("Generating branch proof with one leaf");
        let branch_proof =
            prove_branch(&params, branch_node.clone(), vec![leaf_proof_buf1.clone()]);
        let branch_proof = ProofWithVK::deserialize(&branch_proof).unwrap();
        let exp_vk = params.branches.b1.get_verifier_data();
        assert_eq!(branch_proof.verifier_data(), exp_vk);

        // Generate a fake proof for testing branch circuit.
        let gen_fake_proof = |mpt_key| {
            let mut pub2 = pub1.clone();
            assert_eq!(pub2.len(), NUM_IO);
            pub2[public_inputs::K_RANGE].copy_from_slice(
                &bytes_to_nibbles(mpt_key)
                    .into_iter()
                    .map(F::from_canonical_u8)
                    .collect_vec(),
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
                .serialize()
                .unwrap()
        };

        // Check the public input of branch proof.
        let check_branch_public_inputs = |num_children, branch_proof: &ProofWithVK| {
            let [leaf_pi, branch_pi] = [&leaf_proof1, branch_proof]
                .map(|proof| PublicInputs::new(&proof.proof().public_inputs[..NUM_IO]));

            let leaf_metadata_digest = leaf_pi.metadata_digest();
            let leaf_values_digest = weierstrass_to_point(&leaf_pi.values_digest());
            let branch_values_digest =
                (0..num_children).fold(Point::NEUTRAL, |acc, _| acc + leaf_values_digest);
            assert_eq!(branch_pi.metadata_digest(), leaf_metadata_digest);
            assert_eq!(
                branch_pi.values_digest(),
                branch_values_digest.to_weierstrass()
            );
            assert_eq!(branch_pi.n(), F::from_canonical_usize(num_children));
        };

        info!("Generating branch with two leaves");
        let leaf_proof_buf2 = gen_fake_proof(mpt_key2);
        let branch_proof = prove_branch(
            &params,
            branch_node.clone(),
            vec![leaf_proof_buf1.clone(), leaf_proof_buf2.clone()],
        );
        let branch_proof = ProofWithVK::deserialize(&branch_proof).unwrap();
        let exp_vk = params.branches.b4.get_verifier_data().clone();
        assert_eq!(branch_proof.verifier_data(), &exp_vk);
        check_branch_public_inputs(2, &branch_proof);

        // Generate `num_children - 2`` fake proofs.
        let mut leaf_proofs = vec![leaf_proof_buf1, leaf_proof_buf2];
        for i in 2..num_children {
            let leaf_proof = gen_fake_proof(test_trie.mpt_keys[i].as_slice());
            leaf_proofs.push(leaf_proof);
        }
        info!("Generating branch proof with {num_children} leaves");
        let branch_proof = prove_branch(&params, branch_node, leaf_proofs);
        let branch_proof = ProofWithVK::deserialize(&branch_proof).unwrap();
        let exp_vk = params.branches.b9.get_verifier_data().clone();
        assert_eq!(branch_proof.verifier_data(), &exp_vk);
        check_branch_public_inputs(num_children, &branch_proof);
    }
}
