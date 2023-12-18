#[cfg(test)]
mod test {
    use std::time::Instant;

    use plonky2::{
        field::extension::Extendable,
        hash::hash_types::RichField,
        iop::witness::{PartialWitness, WitnessWrite},
        plonk::{
            circuit_builder::CircuitBuilder,
            circuit_data::{CircuitConfig, CircuitData},
            config::{AlgebraicHasher, GenericConfig, PoseidonGoldilocksConfig},
        },
    };
    use rand::Rng;
    use serde::Serialize;

    use crate::{
        hash::hash_array,
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
        mut arr: Vec<u8>,
    ) -> (CircuitBuilder<F, D>, PartialWitness<F>) {
        let length = arr.len();
        assert!(length < 816);
        arr.resize(816, 0);
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::new(config);
        let mut pw = PartialWitness::new();
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
        inners: &[ProofTuple<F, InnerC, D>],
    ) -> (CircuitBuilder<F, D>, PartialWitness<F>)
    where
        InnerC::Hasher: AlgebraicHasher<F>,
        C::Hasher: AlgebraicHasher<F>,
    {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::new(config);
        let mut pw = PartialWitness::new();
        for iproof in inners {
            let (inner_proof, inner_vd, inner_cd) = iproof;
            let pt = builder.add_virtual_proof_with_pis(inner_cd);
            pw.set_proof_with_pis_target(&pt, inner_proof);
            let idata = builder.add_virtual_verifier_data(inner_cd.config.fri_config.cap_height);
            pw.set_verifier_data_target(&idata, inner_vd);
            builder.verify_proof::<C>(&pt, &idata, &inner_cd);
        }
        (builder, pw)
    }

    #[test]
    fn compare_recursion_vs_hashing() {
        let len = 600;
        let arr = rand_arr(len);
        let (b, pw) = hash_circuit(arr.clone());
        let data: CircuitData<F, C, D> = b.build();
        let proof = data.prove(pw).unwrap();
        let tuple = (proof, data.verifier_only, data.common);

        let mut wtr = csv::Writer::from_path("bench_plonky2.csv").expect("can't write csv");
        for n in [64, 128, 256, 512] {
            let arr = rand_arr(n);
            let hashing = move || hash_circuit::<F, D>(arr);
            let res = run_proof(n, ProofType::Hashing, hashing);
            wtr.serialize(res).unwrap();
        }
        // recursion
        for n in [1, 2, 4, 8] {
            let tuples = (0..n).map(|_| tuple.clone()).collect::<Vec<_>>();
            let res = run_proof(n, ProofType::Recursion, || {
                recurse_circuit::<F, C, C, D>(&tuples)
            });
            wtr.serialize(res).unwrap();
        }
        wtr.flush().unwrap();
    }

    #[derive(Serialize, Debug)]
    enum ProofType {
        Hashing,
        Recursion,
    }
    #[derive(Debug, Serialize)]
    struct BenchResult {
        proof_type: ProofType,
        n: usize,
        building: u128,
        proving: u128,
        lde_size: usize,
        degree: usize,
    }

    fn run_proof<P>(n: usize, proof_type: ProofType, f: P) -> BenchResult
    where
        P: FnOnce() -> (CircuitBuilder<F, D>, PartialWitness<F>),
    {
        println!("[+] Starting benchmark {:?} : n = {}", proof_type, n);
        let (b, pw) = f();
        let start = Instant::now();
        let data: CircuitData<F, C, D> = b.build();
        let time_building = start.elapsed();

        let start = Instant::now();
        let proof = data.prove(pw).unwrap();
        let time_proving = start.elapsed();
        let lde = data.common.lde_size();
        let degree = data.common.constraint_degree();
        verify_proof_tuple(&(proof, data.verifier_only, data.common)).expect("invalid proof");
        BenchResult {
            n,
            proof_type,
            building: time_building.as_millis(),
            proving: time_proving.as_millis(),
            lde_size: lde,
            degree,
        }
    }
}
