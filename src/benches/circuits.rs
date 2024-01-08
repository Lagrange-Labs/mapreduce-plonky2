use anyhow::{ensure, Result};
use hashbrown::HashMap;
use plonky2::gates::exponentiation::ExponentiationGate;
use plonky2::gates::noop::NoopGate;
use plonky2::hash::hash_types::{HashOutTarget, NUM_HASH_OUT_ELTS};
use plonky2::hash::hashing::hash_n_to_hash_no_pad;
use plonky2::hash::poseidon::{PoseidonHash, PoseidonPermutation};
use plonky2::iop::target::{BoolTarget, Target};
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
        circuit_data::{CircuitData, CommonCircuitData, VerifierCircuitTarget},
        config::{AlgebraicHasher, GenericConfig},
    },
};
use plonky2_crypto::biguint::BigUintTarget;
use plonky2_crypto::hash::keccak256::{CircuitBuilderHashKeccak, KECCAK256_R};
use plonky2_crypto::hash::HashInputTarget;
use plonky2_crypto::u32::arithmetic_u32::U32Target;

use crate::hash::HashGadget;
use crate::utils::{convert_u8_to_u32, less_than, verify_proof_tuple, IntTargetWriter};
use crate::ProofTuple;

struct CyclicCircuit<F, CC, const D: usize, U, const ARITY: usize>
where
    F: RichField + Extendable<D>,
    U: PCDCircuit<F, D, ARITY>,
    CC: GenericConfig<D, F = F>,
    CC::Hasher: AlgebraicHasher<F>,
{
    present_proofs: [BoolTarget; ARITY],
    verifier_data: VerifierCircuitTarget,
    proofs: [ProofWithPublicInputsTarget<D>; ARITY],
    user_wires: U::Wires,
    base_common: CommonCircuitData<F, D>,
    circuit_data: CircuitData<F, CC, D>,
    #[cfg(test)]
    num_gates: usize,
}

trait UserCircuit<F, const D: usize>: Clone
where
    F: RichField + Extendable<D>,
{
    type Wires;
    fn build(c: &mut CircuitBuilder<F, D>) -> Self::Wires;
    fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires);
}

trait PCDCircuit<F, const D: usize, const ARITY: usize>: UserCircuit<F, D>
where
    F: RichField + Extendable<D>,
{
    fn build_recursive(
        b: &mut CircuitBuilder<F, D>,
        p: &[ProofWithPublicInputsTarget<D>; ARITY],
    ) -> Self::Wires;
    fn base_inputs(&self) -> Vec<F>;
    fn num_io() -> usize;
}

/// The number of elements added to public inputs list when adding a verifier data as public
/// input.
const NUM_ELEM_VERIFIER_DATA_PUBLIC_INPUTS: usize = 68;
/// Responsible for inserting the right gates inside the dummy circuit creation and to
/// pad accordingly. The reason it is a closure is because these things depend on the
/// whole circuit being proven, not only on small pieces like Keccak or Poseidon.
/// The implementer of the whole circuit needs to give the right padder otherwise building
/// the circuit data will fail.
type Padder<F, const D: usize> = fn(&mut CircuitBuilder<F, D>) -> usize;

impl<F, CC, const D: usize, U, const ARITY: usize> CyclicCircuit<F, CC, D, U, ARITY>
where
    F: RichField + Extendable<D>,
    U: PCDCircuit<F, D, ARITY>,
    CC: GenericConfig<D, F = F> + 'static,
    CC::Hasher: AlgebraicHasher<F>,
{
    fn new(padder: Padder<F, D>) -> Self {
        println!("[+] Building first base circuit");
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
        let proofs_t = (0..ARITY)
            .map(|_| b.add_virtual_proof_with_pis(&cd))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap(); // safe because it has N elements guaranteed
        let wires = U::build_recursive(&mut b, &proofs_t);
        // this call adds 68 public input elements
        let verifier_t = b.add_verifier_data_public_inputs();
        let (dummy_p, dummy_vd) = b.dummy_proof_and_vk::<CC>(&cd).unwrap();
        for (proof_t, present) in proofs_t.iter().zip(conditions_t.iter()) {
            b.conditionally_verify_cyclic_proof::<CC>(*present, proof_t, &dummy_p, &dummy_vd, &cd)
                .expect("this should not panic");
        }
        println!("[+] Building cyclic circuit data");
        b.print_gate_counts(1);
        let num_gates = b.num_gates();
        println!(" ---> {} num gates", num_gates);
        let cyclic_data = b.build::<CC>();
        Self {
            present_proofs: conditions_t,
            verifier_data: verifier_t,
            proofs: proofs_t,
            user_wires: wires,
            base_common: cd,
            circuit_data: cyclic_data,
            #[cfg(test)]
            num_gates,
        }
    }
    // first time it is false since it's dummy proof - then it's set to true
    fn prove_init(&self, circuit: U) -> Result<ProofTuple<F, CC, D>> {
        self.prove_internal(circuit, true, None)
    }
    fn prove_step(
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
        println!("[+] Setting witness");
        let mut pw = PartialWitness::new();
        circuit.prove(&mut pw, &self.user_wires);
        if init {
            for i in 0..ARITY {
                pw.set_bool_target(self.present_proofs[i], false);
            }
            let mut inputs_map: HashMap<usize, F> = HashMap::new();
            for (i, v) in circuit.base_inputs().iter().enumerate() {
                inputs_map.insert(i, *v);
            }
            let proof = cyclic_base_proof(
                &self.base_common,
                &self.circuit_data.verifier_only,
                inputs_map,
            );
            // we verify ARITY out of them anyway right now. This would change depending on the shape
            // of the graph ?
            for target in self.proofs.iter() {
                pw.set_proof_with_pis_target::<CC, D>(target, &proof);
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
                }
            }
        }

        pw.set_verifier_data_target(&self.verifier_data, &self.circuit_data.verifier_only);
        println!("[+] Proving proof");
        let proof = self.circuit_data.prove(pw)?;
        Ok((
            proof,
            self.circuit_data.verifier_only.clone(),
            self.circuit_data.common.clone(),
        ))
    }
    fn verify_proof(&self, proof: ProofWithPublicInputs<F, CC, D>) -> Result<()> {
        println!("[+] Verifying cyclic verifier data");
        check_cyclic_proof_verifier_data(
            &proof,
            &self.circuit_data.verifier_only.clone(),
            &self.circuit_data.common.clone(),
        )?;
        println!("[+] Verifying proof");
        verify_proof_tuple(&(
            proof.clone(),
            self.circuit_data.verifier_only.clone(),
            self.circuit_data.common.clone(),
        ))
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
        println!("--- BEFORE GATE COUNT FOR DUMMY CIRCUIT --- ");
        builder.print_gate_counts(0);
        builder.build::<CC>().common
    }
}
#[derive(Clone, Debug)]
struct NoopCircuit {}
impl NoopCircuit {
    fn new() -> Self {
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
    fn build_recursive(b: &mut CircuitBuilder<F, D>, _: &[ProofWithPublicInputsTarget<D>; N]) {
        <Self as UserCircuit<F, D>>::build(b)
    }
    fn base_inputs(&self) -> Vec<F> {
        vec![]
    }
    fn num_io() -> usize {
        0
    }
}

#[derive(Clone, Copy, Debug)]
struct KeccakCircuit<const N: usize> {
    data: [u8; N],
    unpadded_len: usize,
}
#[derive(Clone, Debug)]
struct KeccakWires<const N: usize> {
    input_array: ArrayWire<N>,
    diff: Target,
    // 256/u32 = 8
    output_array: [Target; 8],
}

#[derive(Debug, Clone)]
struct ArrayWire<const N: usize> {
    arr: [Target; N],
    real_len: Target,
}
impl<const N: usize> KeccakCircuit<N> {
    fn new(mut data: Vec<u8>) -> Result<Self> {
        let total = HashGadget::compute_size_with_padding(data.len());
        ensure!(total <= N, "{}bytes can't fit in {} with padding", total, N);
        // NOTE we don't pad anymore because we enforce that the resulting length is already a multiple
        // of 4 so it will fit the conversion to u32 and circuit vk would stay the same for different
        // data length
        ensure!(
            N % 4 == 0,
            "Fixed array size must be 0 mod 4 for conversion with u32"
        );

        let unpadded_len = data.len();
        data.resize(N, 0);
        Ok(Self {
            data: data.try_into().unwrap(),
            unpadded_len,
        })
    }

    fn build_from_array<F: RichField + Extendable<D>, const D: usize>(
        b: &mut CircuitBuilder<F, D>,
        a: &ArrayWire<N>,
    ) -> <Self as UserCircuit<F, D>>::Wires {
        let diff_target = b.add_virtual_target();
        let end_padding = b.add(a.real_len, diff_target);
        let one = b.one();
        let end_padding = b.sub(end_padding, one); // inclusive range
                                                   // little endian so we start padding from the end of the byte
        let single_pad = b.constant(F::from_canonical_usize(0x81)); // 1000 0001
        let begin_pad = b.constant(F::from_canonical_usize(0x01)); // 0000 0001
        let end_pad = b.constant(F::from_canonical_usize(0x80)); // 1000 0000
                                                                 // TODO : make that const generic
        let padded_node = a
            .arr
            .iter()
            .enumerate()
            .map(|(i, byte)| {
                let i_target = b.constant(F::from_canonical_usize(i));
                // condition if we are within the data range ==> i < length
                let is_data = less_than(b, i_target, a.real_len, 32);
                // condition if we start the padding ==> i == length
                let is_start_padding = b.is_equal(i_target, a.real_len);
                // condition if we are done with the padding ==> i == length + diff - 1
                let is_end_padding = b.is_equal(i_target, end_padding);
                // condition if we only need to add one byte 1000 0001 to pad
                // because we work on u8 data, we know we're at least adding 1 byte and in
                // this case it's 0x81 = 1000 0001
                // i == length == diff - 1
                let is_start_and_end = b.and(is_start_padding, is_end_padding);

                // nikko XXX: Is this sound ? I think so but not 100% sure.
                // I think it's ok to not use `quin_selector` or `b.random_acess` because
                // if the prover gives another byte target, then the resulting hash would be invalid,
                let item_data = b.mul(is_data.target, *byte);
                let item_start_padding = b.mul(is_start_padding.target, begin_pad);
                let item_end_padding = b.mul(is_end_padding.target, end_pad);
                let item_start_and_end = b.mul(is_start_and_end.target, single_pad);
                // if all of these conditions are false, then item will be 0x00,i.e. the padding
                let mut item = item_data;
                item = b.add(item, item_start_padding);
                item = b.add(item, item_end_padding);
                item = b.add(item, item_start_and_end);
                item
            })
            .collect::<Vec<_>>();

        // convert padded node to u32
        let node_u32_target: Vec<U32Target> = convert_u8_to_u32(b, &padded_node);

        // fixed size block delimitation: this is where we tell the hash function gadget
        // to only look at a certain portion of our data, each bool says if the hash function
        // will update its state for this block or not.
        let rate_bytes = b.constant(F::from_canonical_usize(KECCAK256_R / 8));
        let end_padding_offset = b.add(end_padding, one);
        let nb_blocks = b.div(end_padding_offset, rate_bytes);
        // - 1 because keccak always take first block so we don't count it
        let nb_actual_blocks = b.sub(nb_blocks, one);
        let total_num_blocks = N / (KECCAK256_R / 8) - 1;
        let blocks = (0..total_num_blocks)
            .map(|i| {
                let i_target = b.constant(F::from_canonical_usize(i));
                less_than(b, i_target, nb_actual_blocks, 8)
            })
            .collect::<Vec<_>>();

        let hash_target = HashInputTarget {
            input: BigUintTarget {
                limbs: node_u32_target,
            },
            input_bits: 0,
            blocks,
        };

        let hash_output = b.hash_keccak256(&hash_target);
        let output_array: [Target; 8] = hash_output
            .limbs
            .iter()
            .map(|limb| limb.0)
            .collect::<Vec<_>>()
            .try_into()
            .expect("keccak256 should have 8 u32 limbs");
        KeccakWires {
            input_array: a.clone(),
            diff: diff_target,
            output_array,
        }
    }
    fn prove_from_array<F: RichField>(
        pw: &mut PartialWitness<F>,
        wires: &KeccakWires<N>,
        unpadded_len: usize,
    ) {
        let diff = HashGadget::compute_padding_size(unpadded_len);
        pw.set_target(wires.diff, F::from_canonical_usize(diff));
    }
}

impl<F, const D: usize, const N: usize> UserCircuit<F, D> for KeccakCircuit<N>
where
    F: RichField + Extendable<D>,
{
    type Wires = KeccakWires<N>;

    fn build(b: &mut CircuitBuilder<F, D>) -> Self::Wires {
        let real_len = b.add_virtual_target();
        let array = b.add_virtual_target_arr::<N>();
        let wires = Self::build_from_array(
            b,
            &ArrayWire {
                arr: array,
                real_len,
            },
        );
        b.register_public_inputs(&wires.output_array);
        wires
    }

    fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
        pw.set_int_targets(&wires.input_array.arr, &self.data);
        pw.set_target(
            wires.input_array.real_len,
            F::from_canonical_usize(self.unpadded_len),
        );
        Self::prove_from_array(pw, wires, self.unpadded_len);
    }
}
impl<F, const D: usize, const BYTES: usize, const ARITY: usize> PCDCircuit<F, D, ARITY>
    for KeccakCircuit<BYTES>
where
    F: RichField + Extendable<D>,
{
    fn build_recursive(
        b: &mut CircuitBuilder<F, D>,
        _: &[ProofWithPublicInputsTarget<D>; ARITY],
    ) -> Self::Wires {
        <Self as UserCircuit<F, D>>::build(b)
        // TODO: check the proof public input match what is in the hash node for example for MPT
    }
    fn base_inputs(&self) -> Vec<F> {
        // since we don't care about the public inputs of the first
        // proof (since we're not reading them , because we take array
        // to hash as witness)
        // 8 * u32 = 256 bits
        F::rand_vec(8)
    }
    fn num_io() -> usize {
        8
    }
}

#[derive(Clone)]
struct PoseidonCircuit<F, const N: usize> {
    inputs: [F; N],
}
struct PoseidonWires<const N: usize> {
    inputs: [Target; N],
    outputs: HashOutTarget,
}

impl<F, const N: usize> PoseidonCircuit<F, N> {
    fn new(inputs: [F; N]) -> Self {
        Self { inputs }
    }
}
impl<F, const D: usize, const N: usize, const ARITY: usize> PCDCircuit<F, D, ARITY>
    for PoseidonCircuit<F, N>
where
    F: RichField + Extendable<D>,
{
    fn build_recursive(
        b: &mut CircuitBuilder<F, D>,
        _: &[ProofWithPublicInputsTarget<D>; ARITY],
    ) -> Self::Wires {
        <Self as UserCircuit<F, D>>::build(b)
        // TODO: check the proof public input match what is expected
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
        b.register_public_inputs(&outputs.elements);
        PoseidonWires { inputs, outputs }
    }
    fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
        pw.set_target_arr(&wires.inputs, &self.inputs);
        let output = hash_n_to_hash_no_pad::<F, PoseidonPermutation<F>>(&self.inputs);
        pw.set_hash_target(wires.outputs, output);
    }
}

mod benchmark {
    use crate::benches::circuits::NoopCircuit;
    use itertools::Itertools;
    use plonky2::gates::exponentiation::ExponentiationGate;
    use plonky2::{
        field::extension::Extendable,
        hash::hash_types::RichField,
        iop::witness::PartialWitness,
        plonk::{
            circuit_builder::CircuitBuilder,
            circuit_data::CircuitConfig,
            config::{AlgebraicHasher, GenericConfig, GenericHashOut, PoseidonGoldilocksConfig},
            proof::ProofWithPublicInputs,
        },
    };
    use rand::Rng;
    use serde::Serialize;

    use super::{PCDCircuit, Padder, UserCircuit};
    use crate::{
        benches::{
            circuits::{CyclicCircuit, KeccakCircuit, KeccakWires},
            test::init_logging,
        },
        hash::HashGadget,
        utils::verify_proof_tuple,
    };
    use std::{iter, time};

    /// Maximum length in bytes that a MPT branch node can take.
    const DATA_LEN: usize = 544;
    /// Actual padded length for Keccak256
    const BYTES: usize = HashGadget::compute_size_with_padding(DATA_LEN);
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

    /// This creates a different circuits that hash some data, different number
    /// of times. This is to emulate verifying a MPT proof, where one needs
    /// to consecutively hash nodes on the path from leaf to the root.
    #[test]
    fn bench_keccak_repeated() {
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
                        RepeatedKeccak {
                            circuits: [circuit; $a],
                        },
                    )
                    }));
            )+
            fns
            }
        }
    }
        let fns2 = keccak_circuit!(2, 4, 6, 8, 10, 12, 14);
        run_benchs("bench_keccak_repeated.csv".to_string(), fns2);
    }

    /// Launch a benchmark that runs an unified circuit that does:
    /// 1. Keccak256() of some fixed data
    /// 2. Verify N proofs where N varies in the experiments
    /// This is to simulate the case where we want to have one unified circuit during
    /// our recursion.
    #[test]
    fn bench_recursion_single_circuit() {
        init_logging();
        let tname = |i| format!("pcd_single_circuit_keccak");
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
                        bench_pcd_circuit::<F, C, D, $a, _>(tname($a), $a, step_fn,padder)
                    }));
                )+
                fns
            }
            };
        }
        let trials = bench_pcd!(1, 2, 4, 8, 16);
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
        init_logging();
        let tname = |i| format!("pcd_single_circuit_keccak");
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
                    fns.push(Box::new(move || {
                        // always 1 arity because we only verify one proof
                        // but verify multiple hashes
                        bench_pcd_circuit::<F, C, D, 1, _>(tname($a), 1, || RepeatedKeccak::<BYTES,$a> {
                            circuits: [single_circuit; $a]
                        },padder)
                    }));
                )+
                fns
            }
            };
        }
        let trials = bench_pcd!(1, 2, 4, 8, 10, 14);
        run_benchs("bench_recursive_update_keccak.csv".to_string(), trials);
    }

    #[test]
    fn bench_recursion_noop() {
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
        let trials = bench_pcd!(1, 2, 4, 8, 16);
        run_benchs("bench_recursion_noop.csv".to_string(), trials);
    }
    #[derive(Clone, Debug)]
    struct RepeatedKeccak<const BYTES: usize, const N: usize> {
        circuits: [KeccakCircuit<BYTES>; N],
    }
    impl<F, const D: usize, const BYTES: usize, const N: usize> UserCircuit<F, D>
        for RepeatedKeccak<BYTES, N>
    where
        F: RichField + Extendable<D>,
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
    impl<F, const D: usize, const ARITY: usize, const N: usize> PCDCircuit<F, D, ARITY>
        for RepeatedKeccak<BYTES, N>
    where
        F: RichField + Extendable<D>,
    {
        // TODO: remove  assumption about public inputs, in this case we don't
        // need to expose as pub inputs all the intermediate hashing
        fn base_inputs(&self) -> Vec<F> {
            (0..N).flat_map(|_| F::rand_vec(8)).collect()
        }
        fn build_recursive(
            b: &mut CircuitBuilder<F, D>,
            p: &[plonky2::plonk::proof::ProofWithPublicInputsTarget<D>; ARITY],
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

    fn rand_arr(size: usize) -> Vec<u8> {
        (0..size)
            .map(|_| rand::thread_rng().gen())
            .collect::<Vec<u8>>()
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
    impl<const BYTES: usize, const N: usize> Benchable for RepeatedKeccak<BYTES, N> {
        fn n(&self) -> usize {
            // number of times we repeat the hashing in the circuit
            N
        }
    }
    impl<const BYTES: usize> Benchable for KeccakCircuit<BYTES> {
        fn n(&self) -> usize {
            BYTES
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
        init_logging();
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
                verify_proof_tuple(&(proof, circuit_data.verifier_only, circuit_data.common))
                    .unwrap()
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
        let mut last_proofs =
            iter::repeat(circuit.prove_init(step_fn()).expect("base step failed").0)
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
                    let children_array: [Option<ProofWithPublicInputs<F, C, D>>; ARITY] =
                        children_vec
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
        println!(
            "[+] PCD circuit digest: {}",
            hex::encode(circuit.circuit_data.verifier_only.circuit_digest.to_bytes())
        );
        BenchResult {
            circuit: tname,
            n: step_fn().n(),
            gate_count: circuit.num_gates,
            arity: ARITY,
            lde: circuit.circuit_data.common.lde_size(),
            building: building_time,
            proving: (proving_time / n_prove) as u64,
            verifying: (verifying_time / n_prove) as u64,
        }
    }
}
