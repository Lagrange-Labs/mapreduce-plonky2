use crate::circuit::{NoopCircuit, ProofOrDummyTarget};
use itertools::Itertools;
use log::info;
use plonky2::field::types::Sample;
use plonky2::hash::poseidon::Poseidon;
use plonky2::{
    field::extension::Extendable,
    hash::{
        hash_types::{HashOutTarget, RichField, NUM_HASH_OUT_ELTS},
        hashing::hash_n_to_hash_no_pad,
        poseidon::{PoseidonHash, PoseidonPermutation},
    },
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::CircuitConfig,
        config::{AlgebraicHasher, GenericConfig, GenericHashOut, PoseidonGoldilocksConfig},
        proof::ProofWithPublicInputs,
    },
};
use serde::Serialize;

use super::init_logging;
use crate::circuit::{PCDCircuit, Padder, UserCircuit};
use crate::{circuit::CyclicCircuit, utils::verify_proof_tuple};
use std::{iter, time};

/// Circuit hashing ELEMS field elements into a standard Poseidon 256 bit output
/// (containing NUM_HASH_OUT_ELTS).
/// NOTE: this is an implementation for the sake of benchmarking. It takes
/// several deliberate decisions such as registering the output as public inputs,
/// fixing the length of the output, creating new targets for the inputs, etc.
/// Given Poseidon is already quite API-zed, it is not necessary to expose it at
/// the moment, because it wouldn't offer a fully customizable experience to all
/// the potential use cases.
#[derive(Clone, Debug)]
struct PoseidonCircuit<F, const ELEMS: usize> {
    inputs: [F; ELEMS],
}
#[derive(Debug)]
struct PoseidonWires<const ELEMS: usize> {
    /// Input is kept as wires because prover need to assign the concrete
    /// values to it
    inputs: [Target; ELEMS],
    outputs: HashOutTarget,
}

impl<F, const ELEMS: usize> PoseidonCircuit<F, ELEMS> {
    fn new(inputs: [F; ELEMS]) -> Self {
        Self { inputs }
    }
}
impl<F, const D: usize, const ELEMS: usize, const ARITY: usize> PCDCircuit<F, D, ARITY>
    for PoseidonCircuit<F, ELEMS>
where
    F: RichField + Extendable<D>,
{
    fn build_recursive(
        b: &mut CircuitBuilder<F, D>,
        _: &[ProofOrDummyTarget<D>; ARITY],
    ) -> Self::Wires {
        let w = <Self as UserCircuit<F, D>>::build(b);
        b.register_public_inputs(&w.outputs.elements);
        // TODO: check the proof public input match what is expected
        w
    }
    fn base_inputs(&self) -> Vec<F> {
        F::rand_vec(NUM_HASH_OUT_ELTS)
    }
    fn num_io() -> usize {
        NUM_HASH_OUT_ELTS
    }
}

impl<F, const D: usize, const N: usize> UserCircuit<F, D> for PoseidonCircuit<F, N>
where
    F: RichField + Extendable<D>,
{
    type Wires = PoseidonWires<N>;
    fn build(b: &mut CircuitBuilder<F, D>) -> Self::Wires {
        let inputs = b.add_virtual_target_arr::<N>();
        let outputs = b.hash_n_to_hash_no_pad::<PoseidonHash>(inputs.to_vec());
        PoseidonWires { inputs, outputs }
    }
    fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
        pw.set_target_arr(&wires.inputs, &self.inputs);
        let output = hash_n_to_hash_no_pad::<F, PoseidonPermutation<F>>(&self.inputs);
        pw.set_hash_target(wires.outputs, output);
    }
}

macro_rules! timeit {
    ($a:expr) => {{
        let now = time::Instant::now();
        $a;
        now.elapsed()
    }};
}

const D: usize = 2;
type C = PoseidonGoldilocksConfig;
type F = <C as GenericConfig<D>>::F;

#[test]
fn bench_recursion_noop() {
    #[cfg(not(ci))]
    init_logging();
    let tname = |i| format!("pcd_recursion_noop");
    macro_rules! bench_pcd {
            ($( $a:expr),+) => { {
                let mut fns : Vec<Box<dyn FnOnce() -> BenchResult>> = vec![];
                let step_fn = || NoopCircuit::new();
                $(
                    let padder = |b: &mut CircuitBuilder<F,D>| {
                        match $a {
                            1 => 12,
                            2 => 13,
                            4 => 14,
                            8 => 15,
                            16 => 16,
                            _ => panic!("unrecognozed size"),
                        }
                    };
                    fns.push(Box::new(move || {
                        // arity changing but with same number of work at each step
                        bench_pcd_circuit::<F, C, D, $a, _>(tname($a), $a, step_fn,padder)
                    }));
                )+
                fns
            }
            };
        }
    // test for IVC and binary PCD case
    let trials = bench_pcd!(1, 2);
    run_benchs("bench_recursion_noop.csv".to_string(), trials);
}

#[test]
fn test_simple_poseidon() {
    #[cfg(not(ci))]
    init_logging();
    const NB_ELEM: usize = 5;
    let circuit = PoseidonCircuit::<F, NB_ELEM>::new(F::rand_vec(NB_ELEM).try_into().unwrap());
    bench_simple_circuit::<F, D, C, _>("simple_poseidon".to_string(), circuit);
}

/// ELEMS : how many elements are you hashing at each poseidon call
/// N : how many iteration of the poseidon call you are doing
#[derive(Clone, Debug)]
struct RepeatedPoseidon<F, const ELEMS: usize, const N: usize> {
    circuits: [PoseidonCircuit<F, ELEMS>; N],
}

impl<F, const D: usize, const ELEMS: usize, const N: usize> UserCircuit<F, D>
    for RepeatedPoseidon<F, ELEMS, N>
where
    F: RichField + Extendable<D>,
{
    type Wires = [PoseidonWires<ELEMS>; N];
    fn build(c: &mut CircuitBuilder<F, D>) -> Self::Wires {
        (0..N)
            .map(|_| PoseidonCircuit::<F, ELEMS>::build(c))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap()
    }
    fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
        for (c, w) in self.circuits.iter().zip(wires.iter()) {
            c.prove(pw, w)
        }
    }
}
impl<F, const E: usize, const N: usize> Benchable for RepeatedPoseidon<F, E, N> {
    fn n(&self) -> usize {
        N
    }
}

#[test]
fn bench_simple_repeated_poseidon() {
    #[cfg(not(ci))]
    init_logging();
    const NB_ELEM: usize = 4;
    //const N : usize = 4096 * 27; // 2^12 * 27
    const N: usize = 2;
    let individual_circuits = (0..N)
        .map(|_| PoseidonCircuit::<F, NB_ELEM>::new(F::rand_vec(NB_ELEM).try_into().unwrap()))
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();

    let circuit = RepeatedPoseidon::<F, NB_ELEM, N> {
        circuits: individual_circuits,
    };
    bench_simple_circuit::<F, D, C, _>("simple_repeated_poseidon".to_string(), circuit);
}

#[derive(Serialize, Clone, Debug)]
struct BenchResult {
    circuit: String,
    // n is circuit dependent
    n: usize,
    // arity is 0 when it's not recursive, 1 when ivc and more for PCD
    arity: usize,
    gate_count: usize,
    building: u64,
    proving: u64,
    lde: usize,
    verifying: u64,
}

fn run_benchs(fname: String, benches: Vec<Box<dyn FnOnce() -> BenchResult>>) {
    let mut writer = csv::Writer::from_path(fname).unwrap();
    for bench in benches {
        let result = bench();
        writer.serialize(result).unwrap();
        writer.flush().unwrap();
    }
}

pub trait Benchable {
    // returns the relevant information depending on the circuit being benchmarked
    // i.e. n can be the number of times we hash some fixed length data
    fn n(&self) -> usize {
        0
    }
}
impl Benchable for NoopCircuit {}
impl<F, const ELEMS: usize> Benchable for PoseidonCircuit<F, ELEMS> {
    fn n(&self) -> usize {
        ELEMS
    }
}
fn bench_simple_circuit<
    F,
    const D: usize,
    C: GenericConfig<D, F = F>,
    U: UserCircuit<F, D> + Benchable,
>(
    tname: String,
    u: U,
) -> BenchResult
where
    F: RichField + Extendable<D>,
{
    let mut b = CircuitBuilder::new(CircuitConfig::standard_recursion_config());
    let mut pw = PartialWitness::new();
    let now = time::Instant::now();
    let wires = U::build(&mut b);
    let gate_count = b.num_gates();
    let circuit_data = b.build::<C>();
    let building_time = now.elapsed();
    let now = time::Instant::now();
    u.prove(&mut pw, &wires);
    let proof = circuit_data.prove(pw).expect("invalid proof");
    let proving_time = now.elapsed();
    let lde = circuit_data.common.lde_size();
    let verifying_time =
        timeit!(
            verify_proof_tuple(&(proof, circuit_data.verifier_only, circuit_data.common)).unwrap()
        );
    BenchResult {
        circuit: tname,
        gate_count,
        n: u.n(),
        arity: 0,
        lde,
        building: building_time.as_millis() as u64,
        proving: proving_time.as_millis() as u64,
        verifying: verifying_time.as_millis() as u64,
    }
}

fn bench_pcd_circuit<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    const D: usize,
    const ARITY: usize,
    U: PCDCircuit<F, D, ARITY> + Benchable,
>(
    tname: String,
    n_leaves: usize,
    step_fn: impl Fn() -> U,
    padder: Padder<F, D>,
) -> BenchResult
where
    C::Hasher: AlgebraicHasher<F>,
{
    let now = time::Instant::now();
    let circuit = CyclicCircuit::<F, C, D, U, ARITY>::new(padder);
    let building_time = now.elapsed().as_millis() as u64;
    let mut last_proofs = iter::repeat(circuit.prove_init(step_fn()).expect("base step failed").0)
        .take(n_leaves)
        .collect::<Vec<_>>();
    let mut n_prove = 0;
    let mut proving_time = 0;
    let mut verifying_time = 0;
    // either we are in the PCD case, so the condition to stop is to reduce all the proofs
    // together until there is only one left. Or we are in the IVC case where we just
    // want to run one piece of the step function to get some benchmark data.
    while last_proofs.len() > 1 || (n_leaves == 1 && n_prove == 0) {
        last_proofs = last_proofs
            .iter()
            .chunks(ARITY)
            .into_iter()
            .map(|children_proofs| {
                let children_vec = children_proofs.cloned().collect::<Vec<_>>();
                let n_dummy = ARITY - children_vec.len();
                let children_array: [Option<ProofWithPublicInputs<F, C, D>>; ARITY] = children_vec
                    .into_iter()
                    .map(Some)
                    .chain(std::iter::repeat(None).take(n_dummy))
                    .collect::<Vec<_>>()
                    .try_into()
                    .unwrap();
                let now = time::Instant::now();
                let node_proof = circuit
                    .prove_step(step_fn(), &children_array)
                    .expect("invalid step proof")
                    .0;
                proving_time += now.elapsed().as_millis();
                n_prove += 1;
                let now = time::Instant::now();
                circuit
                    .verify_proof(node_proof.clone())
                    .expect("failed verification of base step");
                verifying_time += now.elapsed().as_millis();
                node_proof
            })
            .collect();
    }
    info!(
        "PCD circuit digest: {}",
        hex::encode(
            circuit
                .circuit_data()
                .verifier_only
                .circuit_digest
                .to_bytes()
        )
    );
    BenchResult {
        circuit: tname,
        n: step_fn().n(),
        gate_count: circuit.num_gates,
        arity: ARITY,
        lde: circuit.circuit_data().common.lde_size(),
        building: building_time,
        proving: (proving_time / n_prove) as u64,
        verifying: (verifying_time / n_prove) as u64,
    }
}
