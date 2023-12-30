#[cfg(test)]
mod circuits;
#[cfg(test)]
mod random_access;
#[cfg(test)]
mod recursion;

/// Sets RUST_LOG=debug and initializes the logger
/// if it hasn't been enabled already.
#[cfg(test)]
pub(crate) mod test {
    use anyhow::Result;
    use plonky2::iop::witness::PartialWitness;
    use plonky2::plonk::{
        circuit_builder::CircuitBuilder, circuit_data::CircuitConfig, config::GenericConfig,
    };
    use std::io::Write;
    use std::time::Instant;

    pub(crate) fn init_logging() {
        use std::env;

        use log::{log_enabled, Level, LevelFilter};

        if !log_enabled!(Level::Debug) {
            env::set_var("RUST_LOG", "debug");
            env_logger::builder()
                .format(|buf, record| writeln!(buf, "    {}", record.args()))
                .init();
            log::set_max_level(LevelFilter::Debug);
        }
    }

    /// Compares the gate counts, LDE size, build time, proving time, and verification time
    /// of two circuits. Accepts two closures `v1` and `v2` which are the only places where
    /// the two circuits are allowed to add different gates to the circuit. The `after` closure
    /// can be used to add identical gates after the differences.
    pub(crate) fn compare<C, const D: usize>(
        config: CircuitConfig,
        (v1, v1_name): (impl Fn(&mut CircuitBuilder<C::F, D>), &str),
        (v2, v2_name): (impl Fn(&mut CircuitBuilder<C::F, D>), &str),
        after: impl Fn(&mut CircuitBuilder<C::F, D>),
    ) -> Result<()>
    where
        C: GenericConfig<D>,
    {
        // turn on logging and force DEBUG level logs
        // to be printed to the screen

        init_logging();

        let end = |builder: CircuitBuilder<C::F, D>| {
            // print gate information from the DEBUG log level
            builder.print_gate_counts(0);

            // time the build process
            print!("    Building....");
            let now = Instant::now();
            let data = builder.build::<C>();
            println!("{:.2?}", now.elapsed());

            // time the proving process
            print!("    Proving.....");
            let pw = PartialWitness::new();
            let now = Instant::now();
            let proof = data.prove(pw)?;
            println!("{:.2?}", now.elapsed());

            // time the verification process
            print!("    Verifying...");
            let now = Instant::now();
            let res = data.verify(proof);
            println!("{:.2?}", now.elapsed());

            println!("    LDE size: {}", data.common.lde_size());

            res
        };

        let mut builder1 = CircuitBuilder::<C::F, D>::new(config.clone());
        println!("\n{}", v1_name);
        v1(&mut builder1);
        after(&mut builder1);
        let verified1 = end(builder1);

        let mut builder2 = CircuitBuilder::<C::F, D>::new(config);
        println!("\n{}", v2_name);
        v2(&mut builder2);
        after(&mut builder2);
        let verified2 = end(builder2);

        assert!(verified1.is_ok());
        assert!(verified2.is_ok());
        verified1.and(verified2)
    }
}
