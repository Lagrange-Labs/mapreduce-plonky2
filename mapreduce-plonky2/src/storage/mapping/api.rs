use crate::circuit;
use crate::mpt_sequential::Circuit;
use crate::storage::mapping::branch::BranchWires;
use crate::storage::mapping::branch::MAX_BRANCH_NODE_LEN;

use super::extension::ExtensionNodeCircuit;
use super::extension::ExtensionWires;
use super::leaf::LeafCircuit;
use super::leaf::LeafWires;
use super::leaf::MAX_LEAF_NODE_LEN;
use super::PublicInputs;
use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
use recursion_framework::circuit_builder::CircuitWithUniversalVerifier;
use recursion_framework::circuit_builder::CircuitWithUniversalVerifierBuilder;
use recursion_framework::framework::prepare_recursive_circuit_for_circuit_set as p;
use recursion_framework::framework::RecursiveCircuits;

const D: usize = 2;
type C = PoseidonGoldilocksConfig;
type F = <C as GenericConfig<D>>::F;

const MAPPING_CIRCUIT_SET_SIZE: usize = 3;
pub enum CircuitType {
    Leaf(LeafCircuit<MAX_LEAF_NODE_LEN>),
    Extension(ExtensionNodeCircuit),
    Branch(GenericBranchCircuit),
}

/// This struct holds the basic information necessary to prove a branch node. It 
/// selects the right specialized circuits according to its inputs. For example,
/// if only one child proof is present, it uses the branch_1 circuit.
struct GenericBranchCircuit {
    node: Vec<u8>
}
struct MPTCircuitsParams {
    leaf_circuit: CircuitWithUniversalVerifier<F, C, D, 0, LeafWires<MAX_LEAF_NODE_LEN>>,
    ext_circuit: CircuitWithUniversalVerifier<F, C, D, 1, ExtensionWires>,
    branch_1: CircuitWithUniversalVerifier<F, C, D, 1, BranchWires<MAX_BRANCH_NODE_LEN>>,
    branch_2: CircuitWithUniversalVerifier<F, C, D, 2, BranchWires<MAX_BRANCH_NODE_LEN>>,
    set: RecursiveCircuits<F, C, D>,
}
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
        let branch_1 = circuit_builder.build_circuit::<C, 1, BranchWires<MAX_BRANCH_NODE_LEN>>(());
        let branch_2 = circuit_builder.build_circuit::<C, 2, BranchWires<MAX_BRANCH_NODE_LEN>>(());
        let circuits = vec![
            p(&leaf_circuit),
            p(&ext_circuit),
            p(&branch_1),
            p(&branch_2),
        ];
        let recursive_framework = RecursiveCircuits::new(circuits);

        MPTCircuitsParams {
            leaf_circuit,
            ext_circuit,
            branch_1,
            branch_2,
            set: recursive_framework,
        }
    }
}
