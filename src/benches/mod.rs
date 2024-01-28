use log::{log_enabled, Level, LevelFilter};
use std::env;
use std::io::Write;
mod array_access;
#[cfg(test)]
mod recursion;

/// Sets RUST_LOG=debug and initializes the logger
/// if it hasn't been enabled already.
pub(crate) fn init_logging() {
    if !log_enabled!(Level::Debug) {
        env::set_var("RUST_LOG", "debug");
        let _ = env_logger::builder()
            .format(|buf, record| writeln!(buf, "    {}", record.args()))
            .try_init();
        log::set_max_level(LevelFilter::Debug);
    }
}

#[cfg(test)]
mod test {
    use plonky2::{
        field::extension::Extendable,
        hash::hash_types::RichField,
        iop::witness::PartialWitness,
        plonk::{
            circuit_builder::CircuitBuilder,
            circuit_data::CircuitConfig,
            config::{AlgebraicHasher, GenericConfig},
        },
    };
    use serde::Serialize;
    use std::time;

    use crate::{
        circuit::UserCircuit,
        serializer::{GateSerializer, GeneratorSerializer},
        utils::verify_proof_tuple,
    };

    #[derive(Serialize, Clone, Debug, Default)]
    pub(crate) struct BenchResult {
        pub circuit: String,
        // n is circuit dependent
        pub n: usize,
        // arity is 0 when it's not recursive, 1 when ivc and more for PCD
        pub arity: usize,
        pub gate_count: usize,
        pub building: u64,
        pub proving: u64,
        pub lde: usize,
        pub verifying: u64,
        pub prover_data_size: usize,
        pub verifier_data_size: usize,
        pub common_data_size: usize,
    }

    pub fn run_benchs(fname: String, benches: Vec<Box<dyn FnOnce() -> BenchResult>>) {
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

    // TODO refactor with bench_Simple_circuit to avoid code repetition
    pub fn bench_simple_setup<
        F,
        const D: usize,
        C: GenericConfig<D, F = F> + 'static,
        U: UserCircuit<F, D> + Benchable,
    >(
        tname: String,
        u: U,
    ) -> BenchResult
    where
        F: RichField + Extendable<D>,
        C::Hasher: AlgebraicHasher<F>,
    {
        let mut b = CircuitBuilder::new(CircuitConfig::standard_ecc_config());
        let now = time::Instant::now();
        let wires = U::build(&mut b);
        let gate_count = b.num_gates();
        let circuit_data = b.build::<C>();
        let building_time = now.elapsed();
        let gen = GeneratorSerializer::<C, D>::new();
        let prover_data_size = circuit_data
            .prover_only
            .to_bytes(&gen, &circuit_data.common)
            .unwrap()
            .len();
        let verifier_data_size = circuit_data.verifier_only.to_bytes().unwrap().len();
        let common_data_size = circuit_data
            .common
            .to_bytes(&GateSerializer {})
            .unwrap()
            .len();
        BenchResult {
            building: building_time.as_millis() as u64,
            verifier_data_size,
            prover_data_size,
            common_data_size,
            ..BenchResult::default()
        }
    }
    pub fn bench_simple_circuit<
        F,
        const D: usize,
        C: GenericConfig<D, F = F> + 'static,
        U: UserCircuit<F, D> + Benchable,
    >(
        tname: String,
        u: U,
    ) -> BenchResult
    where
        F: RichField + Extendable<D>,
        C::Hasher: AlgebraicHasher<F>,
    {
        let mut b = CircuitBuilder::new(CircuitConfig::standard_ecc_config());
        let mut pw = PartialWitness::new();
        let now = time::Instant::now();
        let wires = U::build(&mut b);
        let gate_count = b.num_gates();
        let circuit_data = b.build::<C>();
        let building_time = now.elapsed();
        let prover_data_size = circuit_data
            .prover_only
            .to_bytes(&GeneratorSerializer::<C, D>::new(), &circuit_data.common)
            .unwrap()
            .len();
        let verifier_data_size = circuit_data.verifier_only.to_bytes().unwrap().len();
        let common_data_size = circuit_data
            .common
            .to_bytes(&GateSerializer {})
            .unwrap()
            .len();
        let now = time::Instant::now();
        u.prove(&mut pw, &wires);
        let proof = circuit_data.prove(pw).expect("invalid proof");
        let proving_time = now.elapsed();
        let lde = circuit_data.common.lde_size();
        let now = time::Instant::now();
        verify_proof_tuple(&(proof, circuit_data.verifier_only, circuit_data.common)).unwrap();
        let verifying_time = now.elapsed();
        BenchResult {
            circuit: tname,
            gate_count,
            n: u.n(),
            arity: 0,
            lde,
            building: building_time.as_millis() as u64,
            proving: proving_time.as_millis() as u64,
            verifying: verifying_time.as_millis() as u64,
            verifier_data_size,
            common_data_size,
            prover_data_size,
        }
    }
}
