use log::{log_enabled, Level, LevelFilter};
use std::env;
use std::io::Write;

mod array_access;
#[cfg(test)]
mod merkle_tree;
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
            circuit_builder::CircuitBuilder, circuit_data::CircuitConfig, config::GenericConfig,
        },
    };
    use serde::Serialize;
    use std::time;

    use crate::{circuit::UserCircuit, utils::verify_proof_tuple};

    #[derive(Serialize, Clone, Debug)]
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

    pub fn bench_simple_circuit<
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
        }
    }
}
