use plonky2::{field::extension::Extendable, gates::noop::NoopGate, hash::hash_types::RichField, plonk::{circuit_builder::CircuitBuilder, 
    circuit_data::{CircuitConfig, CircuitData, CommonCircuitData}, config::{AlgebraicHasher, GenericConfig, Hasher}}};

use self::{circuit_set::num_targets_for_circuit_set, wrap_circuit::WrapCircuit};

mod circuit_set;
pub(crate) mod wrap_circuit;
pub(crate) mod verifier_gadget;

pub(crate) use circuit_set::{CircuitSet, CircuitSetTarget};
pub use circuit_set::CircuitSetDigest;

// cap height for the Merkle-tree employed to represent the set of circuits that can be aggregated with
// `MergeCircuit`; it is now set to 0 for simplicity, which is equivalent to a traditional
// Merkle-tree with a single root.
//ToDo: evaluate if changing the value depending on the number of circuits in the set
const CIRCUIT_SET_CAP_HEIGHT: usize = 0;

pub(crate) const RECURSION_THRESHOLD: usize = 12;

// degree bits of a base circuit guaranteeing that 2 wrap steps are necessary to shrink a proof
// generated for such a circuit up to the recursion threshold
const SHRINK_LIMIT: usize = 15;

fn dummy_circuit<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>(
    config: CircuitConfig,
    num_gates: usize,
    num_public_inputs: usize,
) -> CircuitData<F, C, D>
{
    let mut builder = CircuitBuilder::new(config);
    for _ in 0..num_public_inputs {
        let target = builder.add_virtual_target();
        builder.register_public_input(target);
    }
    // pad the number of gates of the circuit up to `num_gates` with noop operations
    let num_padding_gates = num_gates - builder.num_gates();
    for _ in 0..num_padding_gates {
        builder.add_gate(NoopGate, vec![]);
    }

    builder.build::<C>()
}

pub(crate) fn build_data_for_recursive_aggregation<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
>(
    config: CircuitConfig,
    num_public_inputs: usize,
) -> CommonCircuitData<F, D>
where
    C::Hasher: AlgebraicHasher<F>,
    [(); C::Hasher::HASH_SIZE]:,
{
    let num_public_inputs = num_public_inputs + num_targets_for_circuit_set::<F, D>(config.clone());
    let circuit_data =
        dummy_circuit::<F, C, D>(config.clone(), 1 << SHRINK_LIMIT, num_public_inputs);

    let wrap_circuit = WrapCircuit::<F, C, D>::build_wrap_circuit(
        &circuit_data.verifier_only,
        &circuit_data.common,
        &config,
    );

    wrap_circuit.final_proof_circuit_data().common.clone()
}

#[cfg(test)]
mod tests {
    use plonky2::plonk::{circuit_data::CircuitConfig, config::{GenericConfig, PoseidonGoldilocksConfig}};

    use super::{build_data_for_recursive_aggregation, RECURSION_THRESHOLD};


    #[test]
    fn test_common_data_for_recursion() {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let cd = build_data_for_recursive_aggregation::<F, C, D>(
            CircuitConfig::standard_recursion_config(),
            3,
        );

        assert_eq!(dbg!(cd).degree_bits(), RECURSION_THRESHOLD);
    }
}
