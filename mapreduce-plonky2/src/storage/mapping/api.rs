use super::extension::ExtensionNodeCircuit;
use super::extension::ExtensionWires;
use super::leaf::LeafCircuit;
use super::leaf::LeafWires;
use super::leaf::MAX_LEAF_NODE_LEN;
use super::PublicInputs;
use crate::storage::mapping::branch::BranchCircuit;
use crate::storage::mapping::branch::BranchWires;
use crate::storage::mapping::branch::MAX_BRANCH_NODE_LEN;
use anyhow::bail;
use anyhow::Result;
use paste::paste;
use plonky2::field::types::PrimeField64;
use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::circuit_data::VerifierOnlyCircuitData;
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
use plonky2::plonk::proof::ProofWithPublicInputs;
use recursion_framework::circuit_builder::CircuitWithUniversalVerifier;
use recursion_framework::circuit_builder::CircuitWithUniversalVerifierBuilder;
use recursion_framework::framework::prepare_recursive_circuit_for_circuit_set as p;
use recursion_framework::framework::RecursiveCircuits;
use std::array::from_fn as create_array;

const D: usize = 2;
type C = PoseidonGoldilocksConfig;
type F = <C as GenericConfig<D>>::F;

const MAPPING_CIRCUIT_SET_SIZE: usize = 3;
pub enum CircuitType {
    Leaf(LeafCircuit<MAX_LEAF_NODE_LEN>),
    Extension(ExtensionProofInput),
    Branch(BranchProofInput),
}

pub struct ExtensionProofInput {
    node: Vec<u8>,
    child_proof: MPTProof,
}

/// This struct holds the basic information necessary to prove a branch node. It
/// selects the right specialized circuits according to its inputs. For example,
/// if only one child proof is present, it uses the branch_1 circuit.
pub struct BranchProofInput {
    node: Vec<u8>,
    child_proofs: Vec<MPTProof>,
}

pub struct MPTProof {
    proof: ProofWithPublicInputs<F, C, D>,
    vk: VerifierOnlyCircuitData<C, D>,
}
struct MPTCircuitsParams {
    leaf_circuit: CircuitWithUniversalVerifier<F, C, D, 0, LeafWires<MAX_LEAF_NODE_LEN>>,
    ext_circuit: CircuitWithUniversalVerifier<F, C, D, 1, ExtensionWires>,
    branchs: BranchCircuits,
    set: RecursiveCircuits<F, C, D>,
}
/// generate a macro filling the BranchCircuit structs manually
macro_rules! define_branch_circuits {
    ($($i:expr),*) => {
        paste! {
        pub struct BranchCircuits {
            $(
                [< b $i >]: CircuitWithUniversalVerifier<F, C, D, $i, BranchWires<MAX_BRANCH_NODE_LEN>>,
            )+
        }
        }
    }
}
define_branch_circuits!(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16);

impl MPTCircuitsParams {
    fn new() -> Self {
        let config = CircuitConfig::standard_recursion_config();
        const NUM_IO: usize = PublicInputs::<F>::TOTAL_LEN;
        let circuit_builder = CircuitWithUniversalVerifierBuilder::<F, D, NUM_IO>::new::<C>(
            config,
            MAPPING_CIRCUIT_SET_SIZE,
        );

        let leaf_circuit = circuit_builder.build_circuit::<C, 0, LeafWires<MAX_LEAF_NODE_LEN>>(());
        let ext_circuit = circuit_builder.build_circuit::<C, 1, ExtensionWires>(());
        macro_rules! fill_branch_circuits {
            ($($i:expr),*) => {
                {
                    let mut arr = Vec::new();
                    paste! {
                    (BranchCircuits {
                        $(
                            [< b $i >]: {
                                let c = circuit_builder.build_circuit::<C, $i, BranchWires<MAX_BRANCH_NODE_LEN>>(());
                                arr.push(p(&c));
                                c
                            },
                        )+
                    },arr)
                }
            }
            }
        }
        let (branch_circuits, set) =
            fill_branch_circuits!(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16);
        let mut circuits = vec![p(&leaf_circuit), p(&ext_circuit)];
        circuits.extend(set);
        let recursive_framework = RecursiveCircuits::new(circuits);

        MPTCircuitsParams {
            leaf_circuit,
            ext_circuit,
            branchs: branch_circuits,
            set: recursive_framework,
        }
    }

    fn generate_proof(&self, circuit_type: CircuitType) -> Result<ProofWithPublicInputs<F, C, D>> {
        match circuit_type {
            CircuitType::Leaf(leaf) => self.set.generate_proof(&self.leaf_circuit, [], [], leaf),
            CircuitType::Extension(ext) => self.set.generate_proof(
                &self.ext_circuit,
                [ext.child_proof.proof],
                [&ext.child_proof.vk],
                ExtensionNodeCircuit { node: ext.node },
            ),
            CircuitType::Branch(branch) => self.handle_branch_proof(branch),
        }
    }

    fn handle_branch_proof(
        &self,
        branch: BranchProofInput,
    ) -> Result<ProofWithPublicInputs<F, C, D>> {
        // first, determine manually the common prefix, the ptr and the mapping slot
        // from the public inputs of the children proofs.
        // Note this is done outside circuits, more as a sanity check. The circuits is enforcing
        // this condition.
        let valid_inputs = branch
            .child_proofs
            .iter()
            .map(|child_proof| {
                let pi = PublicInputs::<F>::from(&child_proof.proof.public_inputs);
                let (key, ptr) = pi.mpt_key_info();
                (key, ptr)
            })
            .collect::<Vec<_>>()
            .windows(2)
            .all(|[(k1, p1), (k2, p2)]| {
                let up1 = p1.to_canonical_u64() as usize;
                let up2 = p2.to_canonical_u64() as usize;
                up1 < k1.len() && up2 < k2.len() && p1 == p2 && k1[..up1] == k2[..up2]
            });
        if !valid_inputs {
            bail!("proofs don't match on the key and/or pointers");
        }
        if branch.child_proofs.is_empty() || branch.child_proofs.len() > 16 {
            bail!("No child proofs or too many child proofs");
        }

        let pi = PublicInputs::<F>::from(&branch.child_proofs[0].proof.public_inputs);
        let (key, ptr) = pi.mpt_key_info();
        let mapping_slot = pi.mapping_slot().to_canonical_u64() as usize;
        let common_prefix = key
            .iter()
            .map(|nib| nib.to_canonical_u64() as u8)
            .collect::<Vec<_>>();
        let pointer = ptr.to_canonical_u64() as usize;

        macro_rules! handle_branch_proof {
           ($($i:expr),*) => {
                    paste! {
                        match branch.child_proofs.len() {
                            $($i => {
                                self.set.generate_proof(
                                    &self.branchs.[< b $i >],
                                    create_array(|i| branch.child_proofs[i].proof),
                                    create_array(|i| &branch.child_proofs[i].vk),
                                    BranchCircuit {
                                        node: branch.node,
                                        common_prefix,
                                        expected_pointer: pointer,
                                        mapping_slot,
                                    }
                                )
                            })+
                        }
                    }
            }
        }
        let proof = handle_branch_proof!(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16);
        proof
    }
}
