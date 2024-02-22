use crate::benches::test::{bench_simple_circuit, run_benchs, BenchResult};
use crate::circuit::{NoopCircuit, ProofOrDummyTarget};
use crate::keccak::{self, KeccakWires};
use itertools::Itertools;
use log::info;
use plonky2::field::types::Sample;
use plonky2::gates::exponentiation::ExponentiationGate;
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
        config::{AlgebraicHasher, GenericConfig, GenericHashOut, PoseidonGoldilocksConfig},
        proof::ProofWithPublicInputs,
    },
};
use rand::Rng;
use std::array::from_fn as create_array;

use super::init_logging;
use super::test::Benchable;
use crate::circuit::CyclicCircuit;
use crate::circuit::{PCDCircuit, Padder, UserCircuit};
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
impl Benchable for NoopCircuit {}
impl<F, const ELEMS: usize> Benchable for PoseidonCircuit<F, ELEMS> {
    fn n(&self) -> usize {
        ELEMS
    }
}

const D: usize = 2;
type C = PoseidonGoldilocksConfig;
type F = <C as GenericConfig<D>>::F;

#[test]
fn bench_recursion_noop() {
    #[cfg(not(ci))]
    init_logging();
    let tname = |_| format!("pcd_recursion_noop");
    macro_rules! bench_pcd {
            ($( $a:expr),+) => { {
                let mut fns : Vec<Box<dyn FnOnce() -> BenchResult>> = vec![];
                let step_fn = || NoopCircuit::new();
                $(
                    let padder = |_: &mut CircuitBuilder<F,D>| {
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
    run_benchs(
        "simple_repeated_poseidon.csv".to_string(),
        vec![Box::new(|| {
            bench_simple_circuit::<F, D, C, _>(
                format!("repeated_poseidon_n{}", N).to_string(),
                circuit,
            )
        })],
    );
}

fn rand_arr(size: usize) -> Vec<u8> {
    (0..size)
        .map(|_| rand::thread_rng().gen())
        .collect::<Vec<u8>>()
}

use crate::keccak::KeccakCircuit;
impl<const BYTES: usize> Benchable for KeccakCircuit<BYTES> {
    fn n(&self) -> usize {
        BYTES
    }
}
#[derive(Clone, Debug)]
struct RepeatedKeccak<const BYTES: usize, const N: usize> {
    circuits: [KeccakCircuit<BYTES>; N],
}

impl<const BYTES: usize, const N: usize> Benchable for RepeatedKeccak<BYTES, N> {
    fn n(&self) -> usize {
        N
    }
}
impl<F, const D: usize, const BYTES: usize, const N: usize> UserCircuit<F, D>
    for RepeatedKeccak<BYTES, N>
where
    F: RichField + Extendable<D>,
    [(); BYTES / 4]:,
{
    type Wires = [KeccakWires<BYTES>; N];
    fn build(c: &mut CircuitBuilder<F, D>) -> Self::Wires {
        (0..N)
            .map(|_| KeccakCircuit::<BYTES>::build(c))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap()
    }

    fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
        for (i, circuit) in self.circuits.iter().enumerate() {
            circuit.prove(pw, &wires[i]);
        }
    }
}

// D = comes from plonky2
// ARITY = of the PCD graph
// BYTES = number of bytes hashed
// N = number of times we repeat the hashing in circuit
impl<F, const D: usize, const ARITY: usize, const N: usize, const BYTES: usize>
    PCDCircuit<F, D, ARITY> for RepeatedKeccak<BYTES, N>
where
    F: RichField + Extendable<D>,
    [(); BYTES / 4]:,
{
    // TODO: remove  assumption about public inputs, in this case we don't
    // need to expose as pub inputs all the intermediate hashing
    fn base_inputs(&self) -> Vec<F> {
        (0..N).flat_map(|_| F::rand_vec(8)).collect()
    }
    fn build_recursive(
        b: &mut CircuitBuilder<F, D>,
        p: &[ProofOrDummyTarget<D>; ARITY],
    ) -> Self::Wires {
        let mut wires = vec![];
        for _ in 0..N {
            wires.push(KeccakCircuit::<BYTES>::build_recursive(b, p));
        }
        wires.try_into().unwrap()
    }
    fn num_io() -> usize {
        let one = <KeccakCircuit<BYTES> as PCDCircuit<F, D, ARITY>>::num_io();
        one * N
    }
}

/// This creates a different circuits that hash some data, different number
/// of times. This is to emulate verifying a MPT proof, where one needs
/// to consecutively hash nodes on the path from leaf to the root.
#[test]
fn bench_keccak_repeated() {
    const DATA_LEN: usize = 544;
    const BYTES: usize = keccak::compute_size_with_padding(DATA_LEN);
    // the whole reason we need these macros is to be able to declare "like at runtime"
    // an array of things with different constants inside. We can't have "const" value
    // on iteration so we have to use macro to avoid hardcoding them one by one.
    macro_rules! keccak_circuit {
        ($( $a:expr),+) => {
            {
            let tname = |i| format!("repeated-keccak-n{}-b{}", i, BYTES);
            let single_circuit = KeccakCircuit::<BYTES>::new(rand_arr(DATA_LEN)).unwrap();
            let mut fns : Vec<Box<dyn FnOnce() -> BenchResult>> = vec![];
            $(
                let name = tname($a);
                let circuit = single_circuit.clone();
                fns.push(Box::new(move || {
                    bench_simple_circuit::<F, D, C, _>(
                        name,
                        RepeatedKeccak::<BYTES,$a> {
                            circuits: create_array(|i| circuit.clone()),
                        },
                    )
                    }));
            )+
            fns
            }
        }
    }
    let fns2 = keccak_circuit!(2, 3);
    run_benchs("bench_keccak_repeated.csv".to_string(), fns2);
}

/// Launch a benchmark that runs an unified circuit that does:
/// 1. Keccak256() of some fixed data
/// 2. Verify N proofs where N varies in the experiments
/// This is to simulate the case where we want to have one unified circuit during
/// our recursion.
#[test]
fn bench_recursion_single_circuit() {
    const DATA_LEN: usize = 544;
    const BYTES: usize = keccak::compute_size_with_padding(DATA_LEN);
    init_logging();
    let tname = |_| format!("pcd_single_circuit_keccak");
    macro_rules! bench_pcd {
            ($( $a:expr),+) => { {
                let mut fns : Vec<Box<dyn FnOnce() -> BenchResult>> = vec![];
                let step_fn = || KeccakCircuit::<BYTES>::new(rand_arr(DATA_LEN)).unwrap();
                $(
                    let padder = |b: &mut CircuitBuilder<F,D>| {
                        KeccakCircuit::<200>::build(b);
                        match $a {
                            1 | 2 => 15,
                            4 => 15,
                            8 => 16,
                            12 => 16,
                            16 => {
                                b.add_gate(ExponentiationGate::new(66), vec![]);
                                17
                            }
                            _ => panic!("unrecognozed size"),
                        }};
                    fns.push(Box::new(move || {
                        // arity changing but with same number of work at each step
                        bench_pcd_circuit::<F, C, D, $a, _>(tname($a), $a-1, step_fn,padder)
                    }));
                )+
                fns
            }
            };
        }
    let trials = bench_pcd!(2);
    run_benchs("bench_recursion_single_circuit.csv".to_string(), trials);
}

/// Bench a circuit that does:
/// 1. Verify a proof recursively
/// 2. Make N consecutive hashing of fixed length
/// This is to emulate the cirucit where we can prove the update of a leaf
/// of a leaf in the merkle tree. So N must be dividable by 2, so length of
/// a proof, is N/2.
#[test]
fn bench_recursive_update_keccak() {
    const DATA_LEN: usize = 544;
    const BYTES: usize = keccak::compute_size_with_padding(DATA_LEN);
    init_logging();
    let tname = |_| format!("pcd_single_circuit_keccak");
    let single_circuit = KeccakCircuit::<BYTES>::new(rand_arr(DATA_LEN)).unwrap();
    macro_rules! bench_pcd {
            ($( $a:expr),+) => { {
                let mut fns : Vec<Box<dyn FnOnce() -> BenchResult>> = vec![];
                $(
                    let padder = |b: &mut CircuitBuilder<F,D>|{
                        KeccakCircuit::<200>::build(b);
                        match $a {
                            1 => 15,
                            2 => 16,
                            4 => {
                                b.add_gate(ExponentiationGate::new(66), vec![]);
                                17
                            },
                            8..=14 => {
                                b.add_gate(ExponentiationGate::new(66), vec![]);
                                18
                            },
                            _ => panic!("unrecognized size - fill manually"),
                        }
                    };
                    let circuit = single_circuit.clone();
                    fns.push(Box::new(move || {
                        // always 1 arity because we only verify one proof
                        // but verify multiple hashes
                        bench_pcd_circuit::<F, C, D, 1, _>(tname($a), 1, || RepeatedKeccak::<BYTES,$a> {
                            circuits: create_array(|_| circuit.clone()),
                        },padder)
                    }));
                )+
                fns
            }
            };
        }
    let trials = bench_pcd!(1, 2);
    run_benchs("bench_recursive_update_keccak.csv".to_string(), trials);
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
    let mut last_proofs = iter::repeat({
        println!("[+] Proving leaf proof");
        let proof = circuit.prove_init(step_fn()).expect("base step failed").0;
        circuit
            .verify_proof(proof.clone())
            .expect("failed verification of intermediate step");
        proof
    })
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
                let child_len = children_vec.len();
                let n_dummy = ARITY - children_vec.len();
                let children_array: [Option<ProofWithPublicInputs<F, C, D>>; ARITY] = children_vec
                    .into_iter()
                    .map(Some)
                    .chain(std::iter::repeat(None).take(n_dummy))
                    .collect::<Vec<_>>()
                    .try_into()
                    .unwrap();
                let now = time::Instant::now();
                println!(
                    "[+] Proving steps with {} / {} children proofs",
                    child_len, ARITY
                );
                let node_proof = circuit
                    .prove_step(step_fn(), &children_array)
                    .expect("invalid step proof")
                    .0;
                proving_time += now.elapsed().as_millis();
                n_prove += 1;
                let now = time::Instant::now();
                circuit
                    .verify_proof(node_proof.clone())
                    .expect("failed verification of intermediate step");
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
