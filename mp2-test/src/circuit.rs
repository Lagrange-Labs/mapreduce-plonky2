use anyhow::Result;
use hashbrown::HashMap;
use log::{debug, info};
use plonky2::gates::noop::NoopGate;
use plonky2::iop::target::BoolTarget;
use plonky2::iop::witness::WitnessWrite;
use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget};
use plonky2::recursion::cyclic_recursion::check_cyclic_proof_verifier_data;
use plonky2::recursion::dummy_circuit::cyclic_base_proof;
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::witness::PartialWitness,
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{
            CircuitData, CommonCircuitData, VerifierCircuitData, VerifierCircuitTarget,
            VerifierOnlyCircuitData,
        },
        config::{AlgebraicHasher, GenericConfig},
    },
};
use std::fmt::Debug;

/// Bundle containing the raw proof, the verification key, and some common data
/// necessary for prover and verifier.
/// TODO: This is a temporary tuple. We need to save the verification key separately.
type ProofTuple<F, C, const D: usize> = (
    ProofWithPublicInputs<F, C, D>,
    VerifierOnlyCircuitData<C, D>,
    CommonCircuitData<F, D>,
);

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

/// Extension to the `UserCircuit` trait that allows a circuit to be used in a
/// recursive context. ARITY is the number of proofs being verified at each
/// steps (see `CyclicCircuit` for more info).
pub trait PCDCircuit<F, const D: usize, const ARITY: usize>: UserCircuit<F, D>
where
    F: RichField + Extendable<D>,
{
    /// Build takes in addition an array
    fn build_recursive(
        b: &mut CircuitBuilder<F, D>,
        p: &[ProofOrDummyTarget<D>; ARITY],
    ) -> Self::Wires;
    fn base_inputs(&self) -> Vec<F>;
    fn num_io() -> usize;
}

/// Utility struct to work with proofs that can either be a dummy proof
/// or a real proof to verify in circuit, denoted by a boolean target.
#[derive(Debug, Clone)]
pub struct ProofOrDummyTarget<'a, const D: usize> {
    pub p: &'a ProofWithPublicInputsTarget<D>,
    b: &'a BoolTarget,
}

impl<'a, const D: usize> ProofOrDummyTarget<'a, D> {
    pub fn new(p: &'a ProofWithPublicInputsTarget<D>, real: &'a BoolTarget) -> Self {
        Self { p, b: real }
    }
    /// Assert that `check` is true if and only if the proof is present, i.e.
    /// it is not a dummy proof. Otherwise, just assert true = true.
    pub fn conditionally_true<F: RichField + Extendable<D>>(
        &self,
        c: &mut CircuitBuilder<F, D>,
        check: BoolTarget,
    ) {
        let t = c._true();
        let out = c._if(*self.b, check.target, t.target);
        c.connect(out, t.target);
    }
}
/// Circuit that can recursively verify itself. It is generic over
///  * the number of recursive proofs: If ARITY == 1, then it is an IVC chain,
/// if ARITY > 1, then it becomes a PCD graph.
///  * The circuit being executed at each step. It is a UserCircuit with some
/// additional required functionality to make it work in the cyclic case.
///
/// The circuit is able to verify either a real proof OR a dummy proof for each
/// of the ARITY expected proofs during recursion. A boolean array is used to denote
/// wether a real proof should be verified or a dummy one.
///
/// NOTE: due to how Plonky2 API / recursion works, there needs to be some manual
/// work for the initialization phase. In particular, cyclic first base proof,
/// i.e. the proof to verify at the first step, is a dummy proof that needs to
/// have relatively the same shape as the normal recursive proof (the proofs
/// generated after the first step). This shape is influenced by padding and type
/// of gates used in the circuit. For this reason, the initialization function takes
/// a Padder function to be able to accomodate to any use cases.
pub struct CyclicCircuit<F, CC, const D: usize, U, const ARITY: usize>
where
    F: RichField + Extendable<D>,
    U: PCDCircuit<F, D, ARITY>,
    CC: GenericConfig<D, F = F>,
    CC::Hasher: AlgebraicHasher<F>,
{
    /// Denotes if circuit verifies a real proof (true) or dummy proof (false)
    present_proofs: [BoolTarget; ARITY],
    /// Verifier data necessary to verify proofs generated by this circuit
    verifier_data: VerifierCircuitTarget,
    /// Wires related to the proofs
    proofs: [ProofWithPublicInputsTarget<D>; ARITY],
    /// Wires related to the generic circuit
    user_wires: U::Wires,
    /// Circuit data related to the first dummy cyclic proof generated
    base_common: CommonCircuitData<F, D>,
    /// CircuitData of this circuit
    circuit_data: CircuitData<F, CC, D>,
    pub num_gates: usize,
}

/// The number of elements added to public inputs list when adding a verifier data as public
/// input.
const NUM_ELEM_VERIFIER_DATA_PUBLIC_INPUTS: usize = 68;
/// Responsible for inserting the right gates inside the dummy circuit creation and to
/// pad accordingly. The reason it is a closure is because these things depend on the
/// whole circuit being proven, not only on small pieces like Keccak or Poseidon.
/// The implementer of the whole circuit needs to give the right padder otherwise building
/// the circuit data will fail.
pub type Padder<F, const D: usize> = fn(&mut CircuitBuilder<F, D>) -> usize;

impl<F, CC, const D: usize, U, const ARITY: usize> CyclicCircuit<F, CC, D, U, ARITY>
where
    F: RichField + Extendable<D>,
    U: PCDCircuit<F, D, ARITY>,
    CC: GenericConfig<D, F = F> + 'static,
    CC::Hasher: AlgebraicHasher<F>,
{
    pub fn new(padder: Padder<F, D>) -> Self {
        debug!("Building first base circuit");
        let mut cd = Self::build_first_proof(padder);
        let mut b = CircuitBuilder::new(CircuitConfig::standard_recursion_config());
        let conditions_t: [BoolTarget; ARITY] =
            Vec::from_iter((0..ARITY).map(|_| b.add_virtual_bool_target_safe()))
                .try_into()
                .unwrap();
        // expectation is that verifier data is last on public inputs so we must know
        // how much public input should the virtual proof will have before calling it,
        // so we can pass it to the user circuit.
        let num_user_io = U::num_io();
        // the only thing that the proof requires is the number of public inputs
        cd.num_public_inputs = NUM_ELEM_VERIFIER_DATA_PUBLIC_INPUTS + num_user_io;
        let proofs_t: [ProofWithPublicInputsTarget<D>; ARITY] = (0..ARITY)
            .map(|_| b.add_virtual_proof_with_pis(&cd))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap(); // safe because it has N elements guaranteed
        let tuples = proofs_t
            .iter()
            .zip(conditions_t.iter())
            .map(|(p, c)| ProofOrDummyTarget::new(p, c))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap(); // safe because it has N elements guaranteed
        let wires = U::build_recursive(&mut b, &tuples);
        // this call adds 68 public input elements
        let verifier_t = b.add_verifier_data_public_inputs();
        let (dummy_p, dummy_vd) = b.dummy_proof_and_vk::<CC>(&cd).unwrap();
        for (proof_t, present) in proofs_t.iter().zip(conditions_t.iter()) {
            b.conditionally_verify_cyclic_proof::<CC>(*present, proof_t, &dummy_p, &dummy_vd, &cd)
                .expect("this should not panic");
        }
        debug!(" ---- Building cyclic circuit data ---");
        b.print_gate_counts(1);
        let num_gates = b.num_gates();
        info!("[+] Final cyclic circuit has {} gates", num_gates);
        let cyclic_data = b.build::<CC>();
        Self {
            present_proofs: conditions_t,
            verifier_data: verifier_t,
            proofs: proofs_t,
            user_wires: wires,
            base_common: cd,
            circuit_data: cyclic_data,
            num_gates,
        }
    }
    // first time it is false since it's dummy proof - then it's set to true
    pub fn prove_init(&self, circuit: U) -> Result<ProofTuple<F, CC, D>> {
        self.prove_internal(circuit, true, None)
    }
    pub fn prove_step(
        &self,
        circuit: U,
        last_proofs: &[Option<ProofWithPublicInputs<F, CC, D>>; ARITY],
    ) -> Result<ProofTuple<F, CC, D>> {
        self.prove_internal(circuit, false, Some(last_proofs))
    }

    fn prove_internal(
        &self,
        circuit: U,
        init: bool,
        last_proofs: Option<&[Option<ProofWithPublicInputs<F, CC, D>>; ARITY]>,
    ) -> Result<ProofTuple<F, CC, D>> {
        debug!("Setting witness");
        let mut pw = PartialWitness::new();
        circuit.prove(&mut pw, &self.user_wires);
        let mut inputs_map: HashMap<usize, F> = HashMap::new();
        for (i, v) in circuit.base_inputs().iter().enumerate() {
            inputs_map.insert(i, *v);
        }
        let dummy_proof = cyclic_base_proof(
            &self.base_common,
            &self.circuit_data.verifier_only,
            inputs_map,
        );
        if init {
            for i in 0..ARITY {
                pw.set_bool_target(self.present_proofs[i], false);
            }

            // we verify ARITY out of them anyway right now. This would change depending on the shape
            // of the graph ?
            for target in self.proofs.iter() {
                pw.set_proof_with_pis_target::<CC, D>(target, &dummy_proof);
            }
        } else {
            let last_proofs =
                last_proofs.ok_or(anyhow::anyhow!("no last proof given for non base step"))?;
            for (i, (target, proof_o)) in self.proofs.iter().zip(last_proofs.iter()).enumerate() {
                if let Some(proof) = proof_o {
                    pw.set_bool_target(self.present_proofs[i], true);
                    pw.set_proof_with_pis_target::<CC, D>(target, proof);
                } else {
                    pw.set_bool_target(self.present_proofs[i], false);
                    pw.set_proof_with_pis_target::<CC, D>(target, &dummy_proof);
                }
            }
        }

        pw.set_verifier_data_target(&self.verifier_data, &self.circuit_data.verifier_only);
        debug!("Proving proof");
        let proof = self.circuit_data.prove(pw)?;
        Ok((
            proof,
            self.circuit_data.verifier_only.clone(),
            self.circuit_data.common.clone(),
        ))
    }
    pub fn verify_proof(&self, proof: ProofWithPublicInputs<F, CC, D>) -> Result<()> {
        debug!("[+] Verifying cyclic verifier data");
        check_cyclic_proof_verifier_data(
            &proof,
            &self.circuit_data.verifier_only.clone(),
            &self.circuit_data.common.clone(),
        )?;
        debug!("[+] Verifying proof");
        let vcd = VerifierCircuitData {
            verifier_only: self.circuit_data.verifier_only.clone(),
            common: self.circuit_data.common.clone(),
        };
        vcd.verify(proof.clone())
    }
    fn build_first_proof(padder: Padder<F, D>) -> CommonCircuitData<F, D> {
        let config = CircuitConfig::standard_recursion_config();
        let builder = CircuitBuilder::<F, D>::new(config.clone());
        let data = builder.build::<CC>();
        let mut builder = CircuitBuilder::<F, D>::new(config.clone());
        let proof = builder.add_virtual_proof_with_pis(&data.common);
        let verifier_data =
            builder.add_virtual_verifier_data(data.common.config.fri_config.cap_height);
        builder.verify_proof::<CC>(&proof, &verifier_data, &data.common);
        let data = builder.build::<CC>();

        let mut builder = CircuitBuilder::<F, D>::new(config);
        let to_pad = padder(&mut builder);
        let proof = builder.add_virtual_proof_with_pis(&data.common);
        let verifier_data =
            builder.add_virtual_verifier_data(data.common.config.fri_config.cap_height);
        builder.verify_proof::<CC>(&proof, &verifier_data, &data.common);
        // It panics without it
        while builder.num_gates() < 1 << to_pad {
            builder.add_gate(NoopGate, vec![]);
        }
        #[cfg(test)]
        {
            debug!("--- BEFORE GATE COUNT FOR DUMMY CIRCUIT --- ");
            builder.print_gate_counts(0);
        }
        builder.build::<CC>().common
    }
    pub fn circuit_data(&self) -> &CircuitData<F, CC, D> {
        &self.circuit_data
    }
}
#[derive(Clone, Debug)]
pub struct NoopCircuit {}
impl NoopCircuit {
    pub fn new() -> Self {
        Self {}
    }
}
impl<F, const D: usize> UserCircuit<F, D> for NoopCircuit
where
    F: RichField + Extendable<D>,
{
    type Wires = ();
    fn build(_: &mut CircuitBuilder<F, D>) -> Self::Wires {}
    fn prove(&self, _: &mut PartialWitness<F>, _: &Self::Wires) {}
}

impl<F, const D: usize, const N: usize> PCDCircuit<F, D, N> for NoopCircuit
where
    F: RichField + Extendable<D>,
{
    fn build_recursive(b: &mut CircuitBuilder<F, D>, _: &[ProofOrDummyTarget<D>; N]) {
        <Self as UserCircuit<F, D>>::build(b)
    }
    fn base_inputs(&self) -> Vec<F> {
        vec![]
    }
    fn num_io() -> usize {
        0
    }
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
    let mut b = CircuitBuilder::new(CircuitConfig::standard_recursion_config());
    let mut pw = PartialWitness::new();
    // small hack to print the name of the circuit being generated
    println!(
        "[+] Building circuit data with circuit {:?}...",
        &format!("{:?}", u)[0..20]
    );
    let now = std::time::Instant::now();
    let wires = U::build(&mut b);
    let circuit_data = b.build::<C>();
    println!("[+] Circuit data built in {:?}s", now.elapsed().as_secs());
    println!("[+] Generating a proof ... ");
    let now = std::time::Instant::now();
    u.prove(&mut pw, &wires);
    let proof = circuit_data.prove(pw).expect("invalid proof");
    println!("[+] Proof generated in {:?}s", now.elapsed().as_secs());
    let vcd = VerifierCircuitData {
        verifier_only: circuit_data.verifier_only,
        common: circuit_data.common,
    };
    vcd.verify(proof.clone()).expect("failed to verify proof");

    proof
}