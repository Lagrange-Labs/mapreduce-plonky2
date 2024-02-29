use crate::circuit;

use super::extension::ExtensionWires;
use super::leaf::LeafWires;
use super::leaf::MAX_LEAF_NODE_LEN;
use super::PublicInputs;
use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
use recursion_framework::circuit_builder::CircuitWithUniversalVerifier;
use recursion_framework::circuit_builder::CircuitWithUniversalVerifierBuilder;

const D: usize = 2;
type C = PoseidonGoldilocksConfig;
type F = <C as GenericConfig<D>>::F;

const MAPPING_CIRCUIT_SET_SIZE: usize = 3;

struct MPTCircuitsParams {
    leaf_circuit: CircuitWithUniversalVerifier<F, C, D, 0, LeafWires<MAX_LEAF_NODE_LEN>>,
    ext_circuit: CircuitWithUniversalVerifier<F, C, D, 1, ExtensionWires>,
}
fn generate_params_for_mpt_mapping() -> MPTCircuitsParams {
    let config = CircuitConfig::standard_recursion_config();
    const NUM_IO: usize = PublicInputs::<F>::TOTAL_LEN;
    let circuit_builder = CircuitWithUniversalVerifierBuilder::<F, D, NUM_IO>::new::<C>(
        config,
        MAPPING_CIRCUIT_SET_SIZE,
    );

    let leaf_circuit = circuit_builder.build_circuit::<C, 0, LeafWires<MAX_LEAF_NODE_LEN>>(());
    let ext_circuit = circuit_builder.build_circuit::<C, 1, ExtensionWires>(());
    MPTCircuitsParams {
        leaf_circuit,
        ext_circuit,
    }
}
