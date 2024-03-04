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
use recursion_framework::framework::RecursiveCircuitInfo;
use recursion_framework::framework::RecursiveCircuits;
use std::array::from_fn as create_array;

const D: usize = 2;
type C = PoseidonGoldilocksConfig;
type F = <C as GenericConfig<D>>::F;

const MAPPING_CIRCUIT_SET_SIZE: usize = 3;

/// CircuitType is a wrapper around the different specialized circuits that can be used to prove a MPT node recursively
/// NOTE: Right now these circuits are specialized to prove inclusion of a single mapping slot.
pub enum CircuitType {
    Leaf(LeafCircuit<MAX_LEAF_NODE_LEN>),
    Extension(ExtensionProofInput),
    Branch(BranchProofInput),
}

/// MPTProof is a generic struct holding a child proof and its associated verification key.
#[derive(Clone, Debug)]
pub struct MPTProof {
    proof: ProofWithPublicInputs<F, C, D>,
    vk: VerifierOnlyCircuitData<C, D>,
}

impl
    From<(
        ProofWithPublicInputs<F, C, D>,
        VerifierOnlyCircuitData<C, D>,
    )> for MPTProof
{
    fn from(
        (proof, vk): (
            ProofWithPublicInputs<F, C, D>,
            VerifierOnlyCircuitData<C, D>,
        ),
    ) -> Self {
        MPTProof { proof, vk }
    }
}
/// Struct containing the expected inputs to prove an extension node.
pub struct ExtensionProofInput {
    node: Vec<u8>,
    child_proof: MPTProof,
}

/// This struct holds the basic information necessary to prove a branch node. It
/// selects the right specialized circuits according to its inputs. For example,
/// if only one child proof is present, it uses the b_1 or b_1_over_2 circuit.
pub struct BranchProofInput {
    node: Vec<u8>,
    child_proofs: Vec<MPTProof>,
}

/// Main struct holding the different circuit parameters for each of the MPT circuits defined here.
/// Most notably, it holds them in a way to use the recursion framework allowing us to specialize
/// circuits according to the situation.
struct MPTCircuitsParams {
    leaf_circuit: CircuitWithUniversalVerifier<F, C, D, 0, LeafWires<MAX_LEAF_NODE_LEN>>,
    ext_circuit: CircuitWithUniversalVerifier<F, C, D, 1, ExtensionWires>,
    #[cfg(not(test))]
    branchs: BranchCircuits,
    #[cfg(test)]
    branchs: TestBranchCircuits,
    set: RecursiveCircuits<F, C, D>,
}

const NUM_IO: usize = PublicInputs::<F>::TOTAL_LEN;
/// generate a macro filling the BranchCircuit structs manually
macro_rules! impl_branch_circuits {
    ($struct_name:ty, $($i:expr),*) => {
        paste! {
        /// BranchCircuits holds the logic to create the different circuits for handling a branch node.
        /// In particular, it generates specific circuits for each number of child proofs, as well as
        /// in combination with the node input length.
        pub struct $struct_name {
            $(
                [< b $i >]: CircuitWithUniversalVerifier<F, C, D, $i, BranchWires<MAX_BRANCH_NODE_LEN>>,
                [< b $i _over_2 >]: CircuitWithUniversalVerifier<F, C, D, $i, BranchWires<{MAX_BRANCH_NODE_LEN/2}>>,
            )+
        }
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
            fn circuit_set(&self) -> Vec<Box<dyn RecursiveCircuitInfo<F, C, D> + '_>> {
                let mut arr = Vec::new();
                $(
                    arr.push(p(&self.[< b $i >]));
                    arr.push(p(&self.[< b $i _over_2 >]));
                )+
                arr
            }
            /// generates a proof from the inputs stored in `branch`. Depending on the size of the node,
            /// and the number of children proofs, it selects the right specialized circuit to generate the proof.
            fn generate_proof(
                &self,
                set: &RecursiveCircuits<F, C, D>,
                branch: BranchProofInput,
            ) -> Result<MPTProof> {
                // first, determine manually the common prefix, the ptr and the mapping slot
                // from the public inputs of the children proofs.
                // Note this is done outside circuits, more as a sanity check. The circuits is enforcing
                // this condition.
                let valid_inputs = branch
                    .child_proofs
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
                if branch.child_proofs.is_empty() || branch.child_proofs.len() > 16 {
                    bail!("No child proofs or too many child proofs");
                }
                if branch.node.len() > MAX_BRANCH_NODE_LEN {
                    bail!("Branch node too long");
                }

                let pi = PublicInputs::<F>::from(&branch.child_proofs[0].proof.public_inputs);
                let (key, ptr) = pi.mpt_key_info();
                let mapping_slot = pi.mapping_slot().to_canonical_u64() as usize;
                let common_prefix = key
                    .iter()
                    .map(|nib| nib.to_canonical_u64() as u8)
                    .collect::<Vec<_>>();
                let pointer = ptr.to_canonical_u64() as usize;
                let proofs = branch
                    .child_proofs
                    .iter()
                    // TODO: didn't find a way to get rid of the useless clone - it's either on the vk or on the proof
                    .map(|p| p.proof.clone())
                    .collect::<Vec<_>>();
                let min_range = MAX_BRANCH_NODE_LEN / 2;
                 match branch.child_proofs.len() {
                     $($i if branch.node.len() > min_range => {
                         set.generate_proof(
                             &self.[< b $i >],
                             proofs.try_into().unwrap(),
                             create_array(|i| &branch.child_proofs[i].vk),
                             BranchCircuit {
                                 node: branch.node,
                                 common_prefix,
                                 expected_pointer: pointer,
                                 mapping_slot,
                             }
                         ).map(|p| (p, self.[< b $i >].get_verifier_data().clone()).into())
                     },
                         $i if branch.node.len() <= min_range => {
                         set.generate_proof(
                             &self.[< b $i _over_2 >],
                             proofs.try_into().unwrap(),
                             create_array(|i| &branch.child_proofs[i].vk),
                             BranchCircuit {
                                 node: branch.node,
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

impl MPTCircuitsParams {
    /// Generates the circuit parameters for the MPT circuits.
    fn build() -> Self {
        let config = CircuitConfig::standard_recursion_config();
        let circuit_builder = CircuitWithUniversalVerifierBuilder::<F, D, NUM_IO>::new::<C>(
            config,
            MAPPING_CIRCUIT_SET_SIZE,
        );

        let leaf_circuit = circuit_builder.build_circuit::<C, 0, LeafWires<MAX_LEAF_NODE_LEN>>(());
        let ext_circuit = circuit_builder.build_circuit::<C, 1, ExtensionWires>(());
        #[cfg(not(test))]
        let branch_circuits = BranchCircuits::new(&circuit_builder);
        #[cfg(test)]
        let branch_circuits = TestBranchCircuits::new(&circuit_builder);
        let mut circuits = vec![p(&leaf_circuit), p(&ext_circuit)];
        circuits.extend(branch_circuits.circuit_set());
        let recursive_framework = RecursiveCircuits::new(circuits);

        MPTCircuitsParams {
            leaf_circuit,
            ext_circuit,
            branchs: branch_circuits,
            set: recursive_framework,
        }
    }

    fn generate_proof(&self, circuit_type: CircuitType) -> Result<MPTProof> {
        match circuit_type {
            CircuitType::Leaf(leaf) => self
                .set
                .generate_proof(&self.leaf_circuit, [], [], leaf)
                .map(|p| (p, self.leaf_circuit.get_verifier_data().clone()).into()),
            CircuitType::Extension(ext) => self
                .set
                .generate_proof(
                    &self.ext_circuit,
                    [ext.child_proof.proof],
                    [&ext.child_proof.vk],
                    ExtensionNodeCircuit { node: ext.node },
                )
                .map(|p| (p, self.ext_circuit.get_verifier_data().clone()).into()),
            CircuitType::Branch(branch) => self.branchs.generate_proof(&self.set, branch),
        }
    }
}

#[cfg(test)]
mod test {
    use eth_trie::Trie;
    use rand::{random, thread_rng, Rng};

    use crate::{
        mpt_sequential::test::generate_random_storage_mpt, storage::key::MappingSlot,
        utils::test::random_vector,
    };

    /// test if the selection of the circuits is correct
    #[test]
    fn test_branch_logic() {
        use super::*;
        let params = MPTCircuitsParams::build();
        let (mut trie, _) = generate_random_storage_mpt::<3, 32>();
        // insert two keys that share the same prefix
        let key1 = random_vector(32);
        let mut key2 = key1.clone();
        key2[key1.len() - 1] = thread_rng().gen();
        let v = random_vector(32);
        trie.insert(&key1, &v).unwrap();
        trie.insert(&key2, &v).unwrap();
        trie.root_hash().unwrap();
        let p1 = trie.get_proof(&key1.clone()).unwrap();
        let p2 = trie.get_proof(&key2.clone()).unwrap();
        // they should share the same branch node
        assert_eq!(p1.len(), p2.len());
        assert_eq!(p1[p1.len() - 2], p2[p2.len() - 2]);
        let slot = MappingSlot::new(1, vec![1, 2, 3, 4]);
        let l1 = LeafCircuit {
            node: p1.last().unwrap().to_vec(),
            slot: slot.clone(),
        };
        // generate a leaf then a branch proof with only this leaf
        let leaf1 = params.generate_proof(CircuitType::Leaf(l1)).unwrap();
        let branch_node = p1[p1.len() - 2].to_vec();
        let branch_inputs = CircuitType::Branch(BranchProofInput {
            node: branch_node.clone(),
            child_proofs: vec![leaf1.clone()],
        });
        let branch1 = params.generate_proof(branch_inputs).unwrap();
        let exp_vk = if branch_node.len() < MAX_BRANCH_NODE_LEN / 2 {
            params.branchs.b1_over_2.get_verifier_data().clone()
        } else {
            params.branchs.b1.get_verifier_data().clone()
        };
        assert_eq!(branch1.vk, exp_vk);

        // generate  a branch proof with two leafs inputs now
        //let l2 = LeafCircuit {
        //    node: p2.last().unwrap().to_vec(),
        //    slot: slot.clone(),
        //};
        //let leaf2 = params.generate_proof(CircuitType::Leaf(l2)).unwrap();
        //let branch_inputs = CircuitType::Branch(BranchProofInput {
        //    node: branch_node.clone(),
        //    child_proofs: vec![leaf1, leaf2],
        //});
        //let branch2 = params.generate_proof(branch_inputs).unwrap();
        //let exp_vk = if branch_node.len() < MAX_BRANCH_NODE_LEN / 2 {
        //    params.branchs.b2_over_2.get_verifier_data().clone()
        //} else {
        //    params.branchs.b2.get_verifier_data().clone()
        //};
        //assert_eq!(branch2.vk, exp_vk);
    }
}
