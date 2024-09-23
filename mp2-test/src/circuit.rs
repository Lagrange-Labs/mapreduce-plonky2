use anyhow::Result;
use mp2_common::{C, D, F};
use plonky2::iop::target::BoolTarget;
use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget};
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::witness::PartialWitness,
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{
            CircuitData, CommonCircuitData, VerifierCircuitData, VerifierOnlyCircuitData,
        },
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

    prove_circuit(&setup, &u)
}
