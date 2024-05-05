//! Values extraction APIs

use super::{
    branch::{BranchCircuit, BranchWires},
    extension::{ExtensionNodeCircuit, ExtensionNodeWires},
    key::{MappingSlot, SimpleSlot},
    leaf_mapping::{LeafMappingCircuit, LeafMappingWires},
    leaf_single::{LeafSingleCircuit, LeafSingleWires},
    public_inputs::PublicInputs,
    MAX_BRANCH_NODE_LEN, MAX_LEAF_NODE_LEN,
};
use crate::api::{default_config, ProofWithVK};
use anyhow::{bail, Result};
use log::debug;
use mp2_common::{mpt_sequential::PAD_LEN, C, D, F};
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

/// CircuitType is a wrapper around the different specialized circuits that can
/// be used to prove a MPT node recursively.
#[derive(Serialize, Deserialize)]
pub enum CircuitInput {
    LeafSingle(LeafSingleCircuit<MAX_LEAF_NODE_LEN>),
    LeafMapping(LeafMappingCircuit<MAX_LEAF_NODE_LEN>),
    Extension(ExtensionInput),
    Branch(BranchInput),
}

impl CircuitInput {
    /// Create a circuit input for proving a leaf MPT node of single variable.
    pub fn new_single_variable_leaf(node: Vec<u8>, slot: u8) -> Self {
        CircuitInput::LeafSingle(LeafSingleCircuit {
            node,
            slot: SimpleSlot::new(slot),
        })
    }

    /// Create a circuit input for proving a leaf MPT node of mapping variable.
    pub fn new_mapping_variable_leaf(node: Vec<u8>, slot: u8, mapping_key: Vec<u8>) -> Self {
        CircuitInput::LeafMapping(LeafMappingCircuit {
            node,
            slot: MappingSlot::new(slot, mapping_key),
        })
    }

    /// Create a circuit input for proving an extension MPT node.
    pub fn new_extension(node: Vec<u8>, child_proof: Vec<u8>) -> Self {
        CircuitInput::Extension(ExtensionInput {
            input: InputNode {
                node,
                // The `is_simple_slot` flag is useless for an extension node.
                is_simple_slot: false,
            },
            serialized_child_proofs: vec![child_proof],
        })
    }

    /// Create a circuit input for proving an branch MPT node.
    pub fn new_branch(node: Vec<u8>, child_proofs: Vec<Vec<u8>>, is_simple_slot: bool) -> Self {
        CircuitInput::Branch(ProofInputSerialized {
            input: InputNode {
                node,
                is_simple_slot,
            },
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
    branchs: BranchCircuits,
    #[cfg(test)]
    branchs: TestBranchCircuits,
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
/// `CircuitType`, employing the `circuit_params` generated with the
/// `build_circuits_params` API.
pub fn generate_proof(
    circuit_params: &PublicParameters,
    circuit_type: CircuitInput,
) -> Result<Vec<u8>> {
    circuit_params.generate_proof(circuit_type)?.serialize()
}

/// This data structure allows to specify the inputs for a circuit that needs to
/// recursively verify proofs; the generic type `T` allows to specify the
/// specific inputs of each circuits besides the proofs that need to be
/// recursively verified, while the proofs are serialized in byte format.
#[derive(Serialize, Deserialize)]
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

/// Struct containing the expected input MPT Extension/Branch node.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct InputNode {
    node: Vec<u8>,
    /// The flag to identify if the storage slot is a simple slot or mapping slot
    is_simple_slot: bool,
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
                                 is_simple_aggregation: branch_node.is_simple_slot,
                             }
                         ).map(|p| (p, self.[< b $i >].get_verifier_data().clone()).into())
                     },
                     _ if $i > child_proofs.len()  => {
                         type C = mp2_common::C;
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
                                 is_simple_aggregation: branch_node.is_simple_slot,
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

/// number of circuits in the set
#[cfg(not(test))]
const MAPPING_CIRCUIT_SET_SIZE: usize = 3 + 2; // 3 branch circuits + 1 ext + 1 leaf
#[cfg(test)]
const MAPPING_CIRCUIT_SET_SIZE: usize = 3 + 2; // 3 branch + 1 ext + 1 leaf

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
        let branch_circuits = BranchCircuits::new(&circuit_builder);
        #[cfg(test)]
        let branch_circuits = TestBranchCircuits::new(&circuit_builder);
        let mut circuits_set = vec![
            leaf_single.get_verifier_data().circuit_digest,
            leaf_mapping.get_verifier_data().circuit_digest,
            extension.get_verifier_data().circuit_digest,
        ];
        circuits_set.extend(branch_circuits.circuit_set());
        // gupeng
        assert_eq!(circuits_set.len(), MAPPING_CIRCUIT_SET_SIZE);

        PublicParameters {
            leaf_single,
            leaf_mapping,
            extension,
            branchs: branch_circuits,
            #[cfg(not(test))]
            set: RecursiveCircuits::new_from_circuit_digests(circuits_set),
            #[cfg(test)]
            set: TestingRecursiveCircuits::new_from_circuit_digests(&circuit_builder, circuits_set),
        }
    }

    fn generate_proof(&self, circuit_type: CircuitInput) -> Result<ProofWithVK> {
        #[cfg(not(test))]
        let set = &self.set;
        #[cfg(test)]
        let set = &self.set.get_recursive_circuit_set();
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
            CircuitInput::Branch(branch) => {
                let child_proofs = branch.get_child_proofs()?;
                self.branchs.generate_proof(set, branch.input, child_proofs)
            }
        }
    }

    pub(crate) fn get_mapping_circuit_set(&self) -> &RecursiveCircuits<F, C, D> {
        #[cfg(not(test))]
        let set = &self.set;
        #[cfg(test)]
        let set = self.set.get_recursive_circuit_set();

        set
    }
}
