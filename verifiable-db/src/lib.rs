// Add this to allow generic const expressions, e.g. `PAD_LEN(NODE_LEN)`.
#![feature(generic_const_exprs)]
/// Module for circuits for simple queries
pub mod simple_query_circuits;

use anyhow::Result;
use plonky2::{
    field::types::Field,
    iop::witness::{PartialWitness, WitnessWrite},
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::CircuitConfig,
        config::{GenericConfig, PoseidonGoldilocksConfig},
    },
};

pub mod api;
pub mod block_tree;
pub mod cells_tree;
pub mod extraction;
pub mod ivc;
pub mod row_tree;

/// An example of using Plonky2 to prove a statement of the form
/// "I know two know numbers A and B such that A + B = C"
fn add_circuit() -> Result<()> {
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    // The arithmetic circuit.
    let input_a_target = builder.add_virtual_target();
    let input_b_target = builder.add_virtual_target();

    let input_c_target = builder.add(input_a_target, input_b_target);

    // Public inputs are the initial value (provided below) and the result (which is generated).
    builder.register_public_input(input_c_target);

    let mut pw = PartialWitness::new();
    pw.set_target(input_a_target, F::ONE);
    pw.set_target(input_b_target, F::ONE);

    let data = builder.build::<C>();
    let proof = data.prove(pw)?;

    println!("Sum of two numbers: {}", proof.public_inputs[0]);

    data.verify(proof)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[ignore]
    #[test]
    fn it_works_plonky2() {
        let result = add_circuit();
        assert!(result.is_ok());
    }
}
