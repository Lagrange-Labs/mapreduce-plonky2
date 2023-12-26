#[cfg(test)]
mod test {
    use anyhow::anyhow;
    use anyhow::ensure;
    use anyhow::Result;
    use hashbrown::HashMap;
    use plonky2::field::types::Field;
    use plonky2::field::types::Sample;
    use plonky2::gates::noop::NoopGate;
    use plonky2::hash::hash_types::HashOutTarget;
    use plonky2::hash::hash_types::NUM_HASH_OUT_ELTS;
    use plonky2::hash::hashing::hash_n_to_hash_no_pad;
    use plonky2::hash::poseidon::PoseidonHash;
    use plonky2::hash::poseidon::PoseidonPermutation;
    use plonky2::iop::target::BoolTarget;
    use plonky2::iop::target::Target;
    use plonky2::plonk::circuit_data::VerifierCircuitTarget;
    use plonky2::plonk::proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget};
    use plonky2::recursion::cyclic_recursion::check_cyclic_proof_verifier_data;
    use plonky2::{
        field::extension::Extendable,
        hash::hash_types::RichField,
        iop::witness::{PartialWitness, WitnessWrite},
        plonk::{
            circuit_builder::CircuitBuilder,
            circuit_data::{CircuitConfig, CircuitData, CommonCircuitData},
            config::{AlgebraicHasher, GenericConfig, GenericHashOut, PoseidonGoldilocksConfig},
        },
        recursion::dummy_circuit::cyclic_base_proof,
    };
    use plonky2_crypto::biguint::BigUintTarget;
    use plonky2_crypto::hash::keccak256::CircuitBuilderHashKeccak;
    use plonky2_crypto::hash::keccak256::KECCAK256_R;
    use plonky2_crypto::hash::HashInputTarget;
    use plonky2_crypto::u32::arithmetic_u32::U32Target;
    use rand::Rng;
    use serde::Serialize;
    use std::sync::Arc;
    use std::time::Instant;

    use crate::utils::convert_u8_to_u32;
    use crate::utils::less_than;
    use crate::{
        benches::test::init_logging,
        hash::{hash_array, HashGadget},
        utils::{verify_proof_tuple, IntTargetWriter},
        ProofTuple,
    };
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    fn rand_arr(size: usize) -> Vec<u8> {
        (0..size)
            .map(|_| rand::thread_rng().gen())
            .collect::<Vec<u8>>()
    }

    fn hash_circuit<F: RichField + Extendable<D>, const D: usize>(
        mut builder: CircuitBuilder<F, D>,
        mut pw: PartialWitness<F>,
        mut arr: Vec<u8>,
    ) -> (CircuitBuilder<F, D>, PartialWitness<F>) {
        let length = arr.len();
        let padded_len = HashGadget::compute_size_with_padding(length);
        arr.resize(padded_len, 0);
        let arr_tgt = builder.add_virtual_targets(arr.len());
        pw.set_int_targets(&arr_tgt, &arr);
        let length_tgt = builder.add_virtual_target();
        pw.set_target(length_tgt, F::from_canonical_usize(length));
        let output = hash_array(&mut builder, &mut pw, &arr_tgt, length_tgt, length);
        builder.register_public_inputs(&output);
        (builder, pw)
    }

    fn recurse_circuit<
        F: RichField + Extendable<D>,
        InnerC: GenericConfig<D, F = F>,
        C: GenericConfig<D, F = F>,
        const D: usize,
    >(
        mut builder: CircuitBuilder<F, D>,
        mut pw: PartialWitness<F>,
        inners: &[ProofTuple<F, InnerC, D>],
    ) -> (CircuitBuilder<F, D>, PartialWitness<F>)
    where
        InnerC::Hasher: AlgebraicHasher<F>,
        C::Hasher: AlgebraicHasher<F>,
    {
        for iproof in inners {
            let (inner_proof, inner_vd, inner_cd) = iproof;
            let pt = builder.add_virtual_proof_with_pis(inner_cd);
            pw.set_proof_with_pis_target(&pt, inner_proof);
            let idata = builder.add_virtual_verifier_data(inner_cd.config.fri_config.cap_height);
            pw.set_verifier_data_target(&idata, inner_vd);
            builder.verify_proof::<C>(&pt, &idata, inner_cd);
        }
        (builder, pw)
    }

    #[derive(Serialize, Debug)]
    enum ProofType {
        Hashing,
        RecursionLeaf,
        // recurse over a recursive leaf proof
        RecursiveSquare,
        RecursionDummy,
    }

    #[derive(Debug, Serialize)]
    struct BenchResult {
        proof_type: ProofType,
        n: usize,
        building: u128,
        proving: u128,
        lde_size: usize,
        degree: usize,
        gate_constraints: usize,
    }

    fn run_proof<P>(n: usize, proof_type: ProofType, f: P) -> (BenchResult, ProofTuple<F, C, D>)
    where
        P: FnOnce(
            CircuitBuilder<F, D>,
            PartialWitness<F>,
        ) -> (CircuitBuilder<F, D>, PartialWitness<F>),
    {
        println!("[+] Starting benchmark {:?} : n = {}", proof_type, n);
        let config = CircuitConfig::standard_recursion_config();
        let builder = CircuitBuilder::new(config);
        let pw = PartialWitness::new();
        let (builder, pw) = f(builder, pw);
        builder.print_gate_counts(0);
        let start = Instant::now();
        let data: CircuitData<F, C, D> = builder.build();
        let time_building = start.elapsed();

        let start = Instant::now();
        let proof = data.prove(pw).unwrap();
        let time_proving = start.elapsed();
        let lde = data.common.lde_size();
        let degree = data.common.constraint_degree();
        let gate_constraints = data
            .common
            .gates
            .iter()
            .map(|g| g.0.num_constraints())
            .sum();
        verify_proof_tuple(&(
            proof.clone(),
            data.verifier_only.clone(),
            data.common.clone(),
        ))
        .expect("invalid proof");
        (
            BenchResult {
                n,
                proof_type,
                building: time_building.as_millis(),
                proving: time_proving.as_millis(),
                lde_size: lde,
                degree,
                gate_constraints,
            },
            (proof, data.verifier_only, data.common),
        )
    }

    #[test]
    fn compare_recursion_vs_hashing() {
        init_logging();
        let len = 600;
        let arr = rand_arr(len);
        let (_, tuple) = run_proof(len, ProofType::Hashing, |b, pw| {
            hash_circuit::<F, D>(b, pw, arr.clone())
        });

        let (_, recurse_tuple) = run_proof(1, ProofType::RecursionLeaf, |b, pw| {
            recurse_circuit::<F, C, C, D>(b, pw, &[tuple.clone()])
        });

        let mut wtr = csv::Writer::from_path("bench_plonky2.csv").expect("can't write csv");
        for n in [64, 128, 256, 512, 1024] {
            let arr = rand_arr(n);
            let hashing = move |b, pw| hash_circuit::<F, D>(b, pw, arr);
            let (res, _) = run_proof(n, ProofType::Hashing, hashing);
            wtr.serialize(res).unwrap();
        }
        // recursion of simple leafs
        for n in [1, 2, 4, 8, 16] {
            let tuples = (0..n).map(|_| tuple.clone()).collect::<Vec<_>>();
            let (res, _) = run_proof(n, ProofType::RecursionLeaf, |b, pw| {
                recurse_circuit::<F, C, C, D>(b, pw, &tuples)
            });
            wtr.serialize(res).unwrap();
        }
        // recursion of recursive proofs
        for n in [1, 2, 4, 8, 16] {
            let tuples = (0..n).map(|_| recurse_tuple.clone()).collect::<Vec<_>>();
            let (res, _) = run_proof(n, ProofType::RecursiveSquare, |b, pw| {
                recurse_circuit::<F, C, C, D>(b, pw, &tuples)
            });
            wtr.serialize(res).unwrap();
        }
        wtr.flush().unwrap();
    }

    #[test]
    fn compare_recursion_vk() {
        let (_, hash_proof) = run_proof(600, ProofType::Hashing, |b, pw| {
            hash_circuit::<F, D>(b, pw, rand_arr(600))
        });
        println!(
            "[+] Hash proof vk {:?}",
            hex::encode(hash_proof.1.circuit_digest.to_bytes())
        );

        let mut last_proof = hash_proof;
        for i in 0..4 {
            let (_, p) = run_proof(1, ProofType::RecursionLeaf, |b, pw| {
                recurse_circuit::<F, C, C, D>(b, pw, &[last_proof.clone()])
            });
            println!(
                "[+] Level {} recursive proof vk {:?}",
                i + 1,
                hex::encode(p.1.circuit_digest.to_bytes())
            );
            last_proof = p;
        }
    }

    fn prepare_common_data_step0v1<
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F>,
        const D: usize,
    >() -> CommonCircuitData<F, D> {
        let b = CircuitBuilder::new(CircuitConfig::standard_recursion_config());
        b.build::<C>().common
    }
    fn prepare_common_data_step0v2<
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F>,
        const D: usize,
    >() -> CommonCircuitData<F, D>
    where
        C::Hasher: AlgebraicHasher<F>,
    {
        let config = CircuitConfig::standard_recursion_config();
        let builder = CircuitBuilder::<F, D>::new(config.clone());
        let data = builder.build::<C>();
        let mut builder = CircuitBuilder::<F, D>::new(config.clone());
        let proof = builder.add_virtual_proof_with_pis(&data.common);
        let verifier_data =
            builder.add_virtual_verifier_data(data.common.config.fri_config.cap_height);
        builder.verify_proof::<C>(&proof, &verifier_data, &data.common);
        let data = builder.build::<C>();

        let mut builder = CircuitBuilder::<F, D>::new(config);
        KeccakCircuit::<200>::build(&mut builder);
        let proof = builder.add_virtual_proof_with_pis(&data.common);
        let verifier_data =
            builder.add_virtual_verifier_data(data.common.config.fri_config.cap_height);
        builder.verify_proof::<C>(&proof, &verifier_data, &data.common);
        builder.print_gate_counts(0);
        // It panics without it
        while builder.num_gates() < 1 << 15 {
            builder.add_gate(NoopGate, vec![]);
        }
        //let min_degree_bits = 14;
        //let min_gates = (1 << (min_degree_bits - 1)) + 1;
        //for _ in builder.num_gates()..min_gates {
        //    builder.add_gate(NoopGate, vec![]);
        //}
        builder.build::<C>().common
    }

    struct CyclicCircuit<F, CC, const D: usize, U>
    where
        F: RichField + Extendable<D>,
        U: IVCCircuit<F, D>,
        CC: GenericConfig<D, F = F>,
        CC::Hasher: AlgebraicHasher<F>,
    {
        step_condition: BoolTarget,
        verifier_data: VerifierCircuitTarget,
        proof: ProofWithPublicInputsTarget<D>,
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

    trait IVCCircuit<F, const D: usize>: UserCircuit<F, D>
    where
        F: RichField + Extendable<D>,
    {
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
    }

    impl<F, CC, const D: usize, U> CyclicCircuit<F, CC, D, U>
    where
        F: RichField + Extendable<D>,
        U: IVCCircuit<F, D>,
        CC: GenericConfig<D, F = F> + 'static,
        CC::Hasher: AlgebraicHasher<F>,
    {
        fn new() -> Self {
            println!("[+] Building cyclic circuit");
            //let mut cd = prepare_common_data_step0v2::<F, CC, D>();
            let mut cd = Self::build_first_proof();
            let mut b = CircuitBuilder::new(CircuitConfig::standard_recursion_config());
            let wires = U::build(&mut b);
            // verify 1 proof: either dummy one or real one
            let condition_t = b.add_virtual_bool_target_safe();
            let verifier_t = b.add_verifier_data_public_inputs();
            // needs to make this cheat so the first dummy common data
            cd.num_public_inputs = b.num_public_inputs();
            let proof_t = b.add_virtual_proof_with_pis(&cd);
            b.conditionally_verify_cyclic_proof_or_dummy::<CC>(condition_t, &proof_t, &cd)
                .expect("this should not panic");

            println!("[+] Building cyclic circuit data");
            b.print_gate_counts(0);
            println!(" ---> {} num gates", b.num_gates());
            let cyclic_data = b.build::<CC>();
            Self {
                step_condition: condition_t,
                verifier_data: verifier_t,
                proof: proof_t,
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
            last_proof: ProofWithPublicInputs<F, CC, D>,
        ) -> Result<ProofTuple<F, CC, D>> {
            self.prove_internal(circuit, false, Some(last_proof))
        }

        fn prove_internal(
            &self,
            circuit: U,
            init: bool,
            last_proof: Option<ProofWithPublicInputs<F, CC, D>>,
        ) -> Result<ProofTuple<F, CC, D>> {
            println!("[+] Setting witness");
            let mut pw = PartialWitness::new();
            circuit.prove(&mut pw, &self.user_wires);
            // step_condition must be true to verify the real proof. If false, it verifies
            // the dummy first proof
            pw.set_bool_target(self.step_condition, !init);
            let last_proof = if init {
                let mut inputs_map: HashMap<usize, F> = HashMap::new();
                for (i, v) in circuit.base_inputs().iter().enumerate() {
                    inputs_map.insert(i, *v);
                }
                cyclic_base_proof(
                    &self.base_common,
                    &self.circuit_data.verifier_only,
                    inputs_map,
                )
            } else {
                last_proof.ok_or(anyhow::anyhow!("no last proof given for non base step"))?
            };
            pw.set_proof_with_pis_target::<CC, D>(&self.proof, &last_proof);
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
        fn build(c: &mut CircuitBuilder<F, D>) -> Self::Wires {}
        fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {}
    }

    impl<F, const D: usize> IVCCircuit<F, D> for NoopCircuit
    where
        F: RichField + Extendable<D>,
    {
        fn base_inputs(&self) -> Vec<F> {
            vec![]
        }
        fn dummy_circuit(builder: &mut CircuitBuilder<F, D>) -> usize {
            12
        }
    }

    #[derive(Clone, Debug)]
    struct KeccakCircuit<const N: usize> {
        data: [u8; N],
        unpadded_len: usize,
    }
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
    impl<const N: usize> IVCCircuit<F, D> for KeccakCircuit<N>
    where
        F: RichField + Extendable<D>,
    {
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
    impl<const N: usize> IVCCircuit<F, D> for PoseidonCircuit<F, N>
    where
        F: RichField + Extendable<D>,
    {
        fn base_inputs(&self) -> Vec<F> {
            F::rand_vec(NUM_HASH_OUT_ELTS)
        }
        fn dummy_circuit(builder: &mut CircuitBuilder<F, D>) -> usize {
            12
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
    fn test_cyclic_circuit<U: IVCCircuit<F, D>>(steps: Vec<U>) {
        let circuit = CyclicCircuit::<F, C, D, U>::new();
        let mut last_proof = circuit
            .prove_init(steps[0].clone())
            .expect("base step failed")
            .0;
        for step in steps.into_iter().skip(1) {
            last_proof = circuit
                .prove_step(step, last_proof)
                .expect("invalid step proof")
                .0;
            circuit
                .verify_proof(last_proof.clone())
                .expect("failed verification of base step");
        }
    }
    #[test]
    fn bench_unified_circuit() {
        println!("[+] Prepare common data step 0");
        // ?? why v1 is not working
        let leaf_cd = prepare_common_data_step0v2::<F, C, D>();
        let inputs = F::rand_vec(4);
        let mut cd = leaf_cd;

        println!("[+] Creating circuit");
        let mut b = CircuitBuilder::new(CircuitConfig::standard_recursion_config());
        let mut pw = PartialWitness::new();
        // verify 1 proof: either dummy one or real one
        let condition_t = b.add_virtual_bool_target_safe();
        let inputs_t = b.add_virtual_public_input_arr::<4>();
        let verifier_t = b.add_verifier_data_public_inputs();
        // needs to make this cheat so the first dummy common data
        cd.num_public_inputs = b.num_public_inputs();
        let proof_t = b.add_virtual_proof_with_pis(&cd);
        println!("[+] Circuit verify cyclic proof");
        b.conditionally_verify_cyclic_proof_or_dummy::<C>(condition_t, &proof_t, &cd)
            .expect("this should not panic");

        // build and set expected proofs
        println!("[+] Building proof");
        let cyclic_data = b.build::<C>();
        println!("[+] Setting witness");
        pw.set_target_arr(&inputs_t, &inputs);
        // first time it is false since it's dummy proof - then it's set to true
        pw.set_bool_target(condition_t, false);
        let mut inputs_map = HashMap::new();
        //for (i, v) in inputs.iter().enumerate() {
        //    inputs_map.insert(i, *v);
        //}
        pw.set_proof_with_pis_target::<C, D>(
            &proof_t,
            &cyclic_base_proof(&cd, &cyclic_data.verifier_only, inputs_map),
        );
        pw.set_verifier_data_target(&verifier_t, &cyclic_data.verifier_only);
        println!("[+] Proving proof");
        let proof = cyclic_data.prove(pw).expect("proof should pass");
        println!("[+] Verifying cyclic verifier data");
        check_cyclic_proof_verifier_data(&proof, &cyclic_data.verifier_only, &cyclic_data.common)
            .expect("unverified vk");
        println!("[+] Verifying proof");
        verify_proof_tuple(&(proof.clone(), cyclic_data.verifier_only, cyclic_data.common))
            .expect("invalid proof");
    }
}
