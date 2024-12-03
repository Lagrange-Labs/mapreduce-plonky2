use anyhow::Result;
use mp2_common::{C, D, F};
use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::witness::PartialWitness,
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitData, VerifierCircuitData},
        config::GenericConfig,
    },
};
use recursion_framework::{
    circuit_builder::CircuitLogicWires, framework_testing::DummyCircuitWires,
};
use std::fmt::Debug;

/// Circuit that does nothing but can be passed as a children proof to some circuit when testing the aggregation
/// logic.
pub struct TestDummyCircuit<const NUM_PUBLIC_INPUTS: usize> {
    data: CircuitData<F, C, D>,
    wires: DummyCircuitWires<NUM_PUBLIC_INPUTS>,
}

impl<const NUM_PUBLIC_INPUTS: usize> TestDummyCircuit<NUM_PUBLIC_INPUTS> {
    pub fn build() -> Self {
        let config = CircuitConfig::standard_recursion_config();
        let mut cb = CircuitBuilder::<F, D>::new(config);
        let wires = DummyCircuitWires::circuit_logic(&mut cb, [], ());
        let data = cb.build::<C>();
        Self { data, wires }
    }

    pub fn generate_proof(
        &self,
        public_inputs: [F; NUM_PUBLIC_INPUTS],
    ) -> Result<ProofWithPublicInputs<F, C, D>> {
        let mut pw = PartialWitness::<F>::new();
        <DummyCircuitWires<NUM_PUBLIC_INPUTS> as CircuitLogicWires<F, D, 0>>::assign_input(
            &self.wires,
            public_inputs,
            &mut pw,
        )?;
        self.data.prove(pw)
    }

    pub fn circuit_data(&self) -> &CircuitData<F, C, D> {
        &self.data
    }
}

/// Simple trait defining the main utilities method to define circuits almost
/// as gadgets / library calls.
pub trait UserCircuit<F, const D: usize>: Clone
where
    F: RichField + Extendable<D>,
{
    /// The wires related to this circuit that need assignement during
    /// the proving phase.
    type Wires;

    /// Method is called once to build the circuit shape.
    fn build(c: &mut CircuitBuilder<F, D>) -> Self::Wires;

    /// Create a proof, giving the wires already generated at the first step.
    fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires);
}

/// Setup the circuit to be proven via an instance.
pub fn setup_circuit<
    F: RichField + Extendable<D>,
    const D: usize,
    C: GenericConfig<D, F = F>,
    U: UserCircuit<F, D> + Debug,
>() -> (U::Wires, CircuitData<F, C, D>, VerifierCircuitData<F, C, D>) {
    let mut b = CircuitBuilder::new(CircuitConfig::standard_recursion_config());
    let now = std::time::Instant::now();
    let wires = U::build(&mut b);
    let circuit_data = b.build::<C>();
    let vcd = VerifierCircuitData {
        verifier_only: circuit_data.verifier_only.clone(),
        common: circuit_data.common.clone(),
    };

    println!("[+] Circuit data built in {:?}s", now.elapsed().as_secs());
    println!("FRI config: {:?}", circuit_data.common.fri_params);
    (wires, circuit_data, vcd)
}

/// Prove and verify a circuit instance with a previously generated setup.
pub fn prove_circuit<
    F: RichField + Extendable<D>,
    const D: usize,
    C: GenericConfig<D, F = F>,
    U: UserCircuit<F, D> + Debug,
>(
    setup: &(U::Wires, CircuitData<F, C, D>, VerifierCircuitData<F, C, D>),
    u: &U,
) -> ProofWithPublicInputs<F, C, D> {
    let mut pw = PartialWitness::new();

    println!("[+] Generating a proof ... ");
    let now = std::time::Instant::now();
    u.prove(&mut pw, &setup.0);
    let proof = setup.1.prove(pw).expect("invalid proof");

    println!("[+] Proof generated in {:?}ms", now.elapsed().as_millis());
    setup
        .2
        .verify(proof.clone())
        .expect("failed to verify proof");

    proof
}

/// Proves and verifies the provided circuit instance.
pub fn run_circuit<
    F: RichField + Extendable<D>,
    const D: usize,
    C: GenericConfig<D, F = F>,
    U: UserCircuit<F, D> + Debug,
>(
    u: U,
) -> ProofWithPublicInputs<F, C, D> {
    let setup = setup_circuit::<F, D, C, U>();

    println!(
        "setup.verifierdata hash {:?}",
        setup.2.verifier_only.circuit_digest
    );

    prove_circuit(&setup, &u)
}

/// Given a `PartitionWitness` that has only inputs set, populates the rest of the witness using the
/// given set of generators.
pub fn debug_generate_partial_witness<
    'a,
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
>(
    inputs: PartialWitness<F>,
    prover_data: &'a plonky2::plonk::circuit_data::ProverOnlyCircuitData<F, C, D>,
    common_data: &'a plonky2::plonk::circuit_data::CommonCircuitData<F, D>,
) -> plonky2::iop::witness::PartitionWitness<'a, F> {
    use plonky2::iop::witness::WitnessWrite;

    let config = &common_data.config;
    let generators = &prover_data.generators;
    let generator_indices_by_watches = &prover_data.generator_indices_by_watches;

    let mut witness = plonky2::iop::witness::PartitionWitness::new(
        config.num_wires,
        common_data.degree(),
        &prover_data.representative_map,
    );

    for (t, v) in inputs.target_values.into_iter() {
        witness.set_target(t, v);
    }

    // Build a list of "pending" generators which are queued to be run. Initially, all generators
    // are queued.
    let mut pending_generator_indices: Vec<_> = (0..generators.len()).collect();

    // We also track a list of "expired" generators which have already returned false.
    let mut generator_is_expired = vec![false; generators.len()];
    let mut remaining_generators = generators.len();

    let mut buffer = plonky2::iop::generator::GeneratedValues::empty();

    // Keep running generators until we fail to make progress.
    while !pending_generator_indices.is_empty() {
        let mut next_pending_generator_indices = Vec::new();

        for &generator_idx in &pending_generator_indices {
            if generator_is_expired[generator_idx] {
                continue;
            }

            let finished = generators[generator_idx].0.run(&witness, &mut buffer);
            if finished {
                generator_is_expired[generator_idx] = true;
                remaining_generators -= 1;
            }

            // Merge any generated values into our witness, and get a list of newly-populated
            // targets' representatives.
            let new_target_reps = buffer
                .target_values
                .drain(..)
                .flat_map(|(t, v)| witness.set_target_returning_rep(t, v));

            // Enqueue unfinished generators that were watching one of the newly populated targets.
            for watch in new_target_reps {
                let opt_watchers = generator_indices_by_watches.get(&watch);
                if let Some(watchers) = opt_watchers {
                    for &watching_generator_idx in watchers {
                        if !generator_is_expired[watching_generator_idx] {
                            next_pending_generator_indices.push(watching_generator_idx);
                        }
                    }
                }
            }
        }

        pending_generator_indices = next_pending_generator_indices;
    }
    if remaining_generators != 0 {
        println!("{} generators weren't run", remaining_generators);

        let filtered = generator_is_expired
            .iter()
            .enumerate()
            .filter_map(|(index, flag)| if !flag { Some(index) } else { None })
            .min();

        if let Some(min_val) = filtered {
            println!("generator at index: {} is the first to not run", min_val);
            println!("This has ID: {}", generators[min_val].0.id());

            for watch in generators[min_val].0.watch_list().iter() {
                println!("watching: {:?}", watch);
            }
        }
    }

    witness
}
