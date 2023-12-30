use anyhow::{ensure, Result};
use hashbrown::HashMap;
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
    /// returns the number of gates the circuit should have at the
    /// end of the first circuit creation. It must be in log2 base
    /// as it is being used in the following way
    /// ```
    ///     while builder.num_gates() < 1 << gates {
    ///         builder.add_gate(NoopGate, vec![]);
    ///     }
    /// ```
    /// Implementers can add any custom gates for example as well
    /// so the first basic proof has the same shape than the following
    /// ones.
    fn dummy_circuit(builder: &mut CircuitBuilder<F, D>) -> usize;
    fn base_inputs(&self) -> Vec<F>;
    fn num_io() -> usize;
}

/// The number of elements added to public inputs list when adding a verifier data as public
/// input.
const NUM_ELEM_VERIFIER_DATA_PUBLIC_INPUTS: usize = 68;
impl<F, CC, const D: usize, U, const ARITY: usize> CyclicCircuit<F, CC, D, U, ARITY>
where
    F: RichField + Extendable<D>,
    U: PCDCircuit<F, D, ARITY>,
    CC: GenericConfig<D, F = F> + 'static,
    CC::Hasher: AlgebraicHasher<F>,
{
    fn new() -> Self {
        println!("[+] Building cyclic circuit");
        //let mut cd = prepare_common_data_step0v2::<F, CC, D>();
        let mut cd = Self::build_first_proof();
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
        b.print_gate_counts(0);
        println!(" ---> {} num gates", b.num_gates());
        let cyclic_data = b.build::<CC>();
        Self {
            present_proofs: conditions_t,
            verifier_data: verifier_t,
            proofs: proofs_t,
            user_wires: wires,
            base_common: cd,
            circuit_data: cyclic_data,
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
    fn build_first_proof() -> CommonCircuitData<F, D> {
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
        let to_pad = U::dummy_circuit(&mut builder);
        let proof = builder.add_virtual_proof_with_pis(&data.common);
        let verifier_data =
            builder.add_virtual_verifier_data(data.common.config.fri_config.cap_height);
        builder.verify_proof::<CC>(&proof, &verifier_data, &data.common);
        builder.print_gate_counts(0);
        // It panics without it
        while builder.num_gates() < 1 << to_pad {
            builder.add_gate(NoopGate, vec![]);
        }
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
    fn dummy_circuit(_: &mut CircuitBuilder<F, D>) -> usize {
        12
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
impl<F, const D: usize, const N: usize, const ARITY: usize> PCDCircuit<F, D, ARITY>
    for KeccakCircuit<N>
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
    fn dummy_circuit(builder: &mut CircuitBuilder<F, D>) -> usize {
        KeccakCircuit::<200>::build(builder);
        15
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
    fn dummy_circuit(_: &mut CircuitBuilder<F, D>) -> usize {
        match ARITY {
            16 => 16,
            2 => 13,
            _ => 12,
        }
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
    use itertools::Itertools;
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

    use super::{PCDCircuit, UserCircuit};
    use crate::{
        benches::{
            circuits::{CyclicCircuit, KeccakCircuit, KeccakWires, NoopCircuit},
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
        let fns2 = keccak_circuit!(2, 3, 4);
        run_benchs("keccak_repeated.csv".to_string(), fns2);
    }

    /// Launch a benchmark that runs an unified circuit that does:
    /// 1. Keccak256() of some fixed data
    /// 2. Verify N proofs where N varies in the experiments
    /// This is to simulate the case where we want to have one unified circuit during
    /// our recursion.
    #[test]
    fn bench_recursion_single_circuit() {
        let tname = |i| format!("pcd_single_circuit_keccak");
        macro_rules! bench_pcd {
            ($( $a:expr),+) => { {
                let mut fns : Vec<Box<dyn FnOnce() -> BenchResult>> = vec![];
                let step_fn = || KeccakCircuit::<BYTES>::new(rand_arr(DATA_LEN)).unwrap();
                $(
                    fns.push(Box::new(move || {
                        bench_pcd_circuit::<F, C, D, $a, _>(tname($a), $a, step_fn)
                    }));
                )+
                fns
            }
            };
        }
        let trials = bench_pcd!(1, 2, 4);
        run_benchs("pcd_1circuit_keccak.csv".to_string(), trials);
    }

    /// Bench a circuit that does:
    /// 1. Verify a proof recursively
    /// 2. Make N consecutive hashing of fixed length
    /// This is to emulate the cirucit where we can prove the update of a leaf
    /// of a leaf in the merkle tree. So N must be dividable by 2, so length of
    /// a proof, is N/2.
    #[test]
    fn bench_recursive_update_keccak() {
        let tname = |i| format!("pcd_single_circuit_keccak");
        let single_circuit = KeccakCircuit::<BYTES>::new(rand_arr(DATA_LEN)).unwrap();
        macro_rules! bench_pcd {
            ($( $a:expr),+) => { {
                let mut fns : Vec<Box<dyn FnOnce() -> BenchResult>> = vec![];
                $(
                    fns.push(Box::new(move || {
                        bench_pcd_circuit::<F, C, D, $a, _>(tname($a), $a, || RepeatedKeccak::<BYTES,$a> {
                            circuits: [single_circuit; $a]
                        })
                    }));
                )+
                fns
            }
            };
        }
        let trials = bench_pcd!(1, 2, 4);
        run_benchs("pcd_recursive_update_keccak.csv".to_string(), trials);
    }

    #[derive(Copy, Clone, Debug)]
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
        fn dummy_circuit(builder: &mut CircuitBuilder<F, D>) -> usize {
            <KeccakCircuit<BYTES> as PCDCircuit<F, D, ARITY>>::dummy_circuit(builder);
            // trial and error
            match N {
                1 => 15,
                2 => 16,
                3..=6 => 17,
                _ => 18,
            }
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
        }
        writer.flush().unwrap();
    }

    pub trait Benchable {
        fn n(&self) -> usize;
    }
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
    ) -> BenchResult
    where
        C::Hasher: AlgebraicHasher<F>,
    {
        let now = time::Instant::now();
        let circuit = CyclicCircuit::<F, C, D, U, ARITY>::new();
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
            arity: ARITY,
            lde: circuit.circuit_data.common.lde_size(),
            building: building_time,
            proving: (proving_time / n_prove) as u64,
            verifying: (verifying_time / n_prove) as u64,
        }
    }
}

#[cfg(test)]
mod test {
    use std::iter;

    use itertools::Itertools;
    use plonky2::field::types::Sample;
    use plonky2::{
        iop::witness::PartialWitness,
        plonk::{
            circuit_builder::CircuitBuilder,
            circuit_data::CircuitConfig,
            config::{GenericConfig, GenericHashOut, PoseidonGoldilocksConfig},
            proof::ProofWithPublicInputs,
        },
    };
    use rand::Rng;

    use crate::{
        benches::{
            circuits::{KeccakCircuit, PoseidonCircuit},
            test::init_logging,
        },
        hash::HashGadget,
    };
    use anyhow::Result;

    use super::{CyclicCircuit, NoopCircuit, PCDCircuit, UserCircuit};

    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    fn rand_arr(size: usize) -> Vec<u8> {
        (0..size)
            .map(|_| rand::thread_rng().gen())
            .collect::<Vec<u8>>()
    }
    #[test]
    fn test_pcd_circuit_poseidon() {
        init_logging();
        // the arity of the circuit
        const ARITY: usize = 3;
        // The actuanl number of proofs we have
        const N_LEAVES: usize = 1;
        const NB_ELEM: usize = 4;
        let step_fn =
            || PoseidonCircuit::<F, NB_ELEM>::new(F::rand_vec(NB_ELEM).try_into().unwrap());
        test_pcd_circuit::<ARITY, _>(N_LEAVES, step_fn);
    }

    #[test]
    fn test_pcd_circuit_keccak() {
        init_logging();
        // the arity of the circuit
        const ARITY: usize = 2;
        // The actuanl number of proofs we have
        const N_LEAVES: usize = 1;
        const DATA_LEN: usize = 544;
        const BYTES: usize = HashGadget::compute_size_with_padding(DATA_LEN);
        let step_fn = || KeccakCircuit::<BYTES>::new(rand_arr(DATA_LEN)).unwrap();
        test_pcd_circuit::<ARITY, KeccakCircuit<BYTES>>(N_LEAVES, step_fn);
    }
    #[test]
    fn test_cyclic_circuit_basic() {
        test_cyclic_circuit((0..4).map(|_| NoopCircuit::new()).collect::<Vec<_>>());
    }

    #[test]
    fn test_cyclic_circuit_keccak256() {
        init_logging();
        let n = 3;
        const DATA_LEN: usize = 544;
        const MAX_LEN: usize = HashGadget::compute_size_with_padding(DATA_LEN);
        let circuits = (0..n)
            .map(|_| KeccakCircuit::<MAX_LEN>::new(rand_arr(DATA_LEN)))
            .collect::<Result<Vec<_>>>()
            .expect("can't create hash circuits");
        test_cyclic_circuit(circuits)
    }
    #[test]
    fn test_cyclic_circuit_poseidon() {
        init_logging();
        let n = 5;
        const NB_ELEM: usize = 4;
        let circuits = (0..n)
            .map(|_| PoseidonCircuit::<F, NB_ELEM>::new(F::rand_vec(NB_ELEM).try_into().unwrap()))
            .collect::<Vec<_>>();
        test_cyclic_circuit(circuits)
    }

    #[test]
    fn test_simple_circuit_poseidon() {
        const NB_ELEM: usize = 4;
        let circuit = PoseidonCircuit::<F, NB_ELEM>::new(F::rand_vec(NB_ELEM).try_into().unwrap());
        test_simple_circuit(circuit);
    }
    #[test]
    fn test_simple_circuit_keccak256() {
        const DATA_LEN: usize = 544;
        const MAX_LEN: usize = HashGadget::compute_size_with_padding(DATA_LEN);
        let circuit =
            KeccakCircuit::<MAX_LEN>::new(rand_arr(DATA_LEN)).expect("to create keccak circuit");
        test_simple_circuit(circuit)
    }

    fn test_simple_circuit<U: UserCircuit<F, D>>(u: U) {
        init_logging();
        let mut b = CircuitBuilder::new(CircuitConfig::standard_recursion_config());
        let mut pw = PartialWitness::new();
        let wires = U::build(&mut b);
        let circuit_data = b.build::<C>();
        u.prove(&mut pw, &wires);
        circuit_data.prove(pw).expect("invalid proof");
    }
    // IVC : only one proof per step being verified
    fn test_cyclic_circuit<U: PCDCircuit<F, D, 1>>(steps: Vec<U>) {
        let circuit = CyclicCircuit::<F, C, D, U, 1>::new();
        let mut last_proof = circuit
            .prove_init(steps[0].clone())
            .expect("base step failed")
            .0;
        for step in steps.into_iter().skip(1) {
            last_proof = circuit
                .prove_step(step, &vec![Some(last_proof)].try_into().unwrap())
                .expect("invalid step proof")
                .0;
            circuit
                .verify_proof(last_proof.clone())
                .expect("failed verification of base step");
        }
    }
    // IVC : only one proof per step being verified
    fn test_pcd_circuit<const ARITY: usize, U: PCDCircuit<F, D, ARITY>>(
        n_leaves: usize,
        step_fn: impl Fn() -> U,
    ) {
        let circuit = CyclicCircuit::<F, C, D, U, ARITY>::new();
        let mut last_proofs =
            iter::repeat(circuit.prove_init(step_fn()).expect("base step failed").0)
                .take(n_leaves)
                .collect::<Vec<_>>();
        while last_proofs.len() > 1 {
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
                    let node_proof = circuit
                        .prove_step(step_fn(), &children_array)
                        .expect("invalid step proof")
                        .0;
                    circuit
                        .verify_proof(node_proof.clone())
                        .expect("failed verification of base step");
                    node_proof
                })
                .collect();
        }
        println!(
            "[+] PCD circuit digest: {}",
            hex::encode(circuit.circuit_data.verifier_only.circuit_digest.to_bytes())
        );
    }
}
