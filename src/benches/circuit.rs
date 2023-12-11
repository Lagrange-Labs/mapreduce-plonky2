#[cfg(test)]
mod tests {
    use std::env;
    use std::time::Instant;
    use log::LevelFilter;
    use anyhow::Result;
    use plonky2::field::types::Field;
    use plonky2::iop::target::Target;
    use plonky2::iop::witness::PartialWitness;
    use plonky2::plonk::circuit_builder::CircuitBuilder;
    use plonky2::plonk::circuit_data::CircuitConfig;
    use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};

    #[test]
    fn compare_quin_random_access() -> Result<()> {
        use crate::rlp::quin_selector;
        use rand::Rng;

        // common to both circuits
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        // both versions of the circuit need to capture this information
        let bits_of_length: usize = 6;
        let byte_arr: Vec<u8> = (0..1<<bits_of_length).map(|_i| rand::thread_rng().gen()).collect();
        println!("Array length: {}", byte_arr.len());
        let rand_index: usize = rand::thread_rng().gen_range(0..1<<bits_of_length);

        let config = CircuitConfig::standard_recursion_config();

        let quin_version = |builder: &mut CircuitBuilder<F, D>| {
            println!("QUIN VERSION");        
            let arr_target: Vec<Target> = byte_arr
                .iter()
                .map(|x| builder.constant(F::from_canonical_u8(*x)))
                .collect();
            let n: Target = builder.constant(F::from_canonical_usize(rand_index));
            let element = arr_target[rand_index];
            
            let ret_element = quin_selector( builder, &arr_target, n);
            
            builder.connect(element, ret_element);
            builder.register_public_input(ret_element);
            builder.register_public_inputs(&arr_target);
        };

        let random_access_version = |builder: &mut CircuitBuilder<F, D>| {
            println!("RANDOM ACCESS VERSION");
            let arr_target: Vec<Target> = byte_arr
                .iter()
                .map(|x| builder.constant(F::from_canonical_u8(*x)))
                .collect();
            let n: Target = builder.constant(F::from_canonical_usize(rand_index));
            let element = arr_target[rand_index];

            let ret_element = builder.random_access(n,arr_target.clone());

            builder.connect(element, ret_element);
            builder.register_public_input(ret_element);
            builder.register_public_inputs(&arr_target);
        };

        // in this case there is nothing to do to the circuit
        // after each version so we pass the identity function
        compare::<C, D>(
            config,
            quin_version,
            random_access_version,
            |_| {}, // identity function
        )
    }    

    /// Sets RUST_LOG=debug and initializes the logger
    fn init_logging() {
        env::set_var("RUST_LOG", "debug");
        env_logger::init();
        log::set_max_level(LevelFilter::Debug);
    }

    /// Compares the gate counts, LDE size, build time, proving time, and verification time
    /// of two circuits. Accepts two closures `v1` and `v2` which are the only places where
    /// the two circuits are allowed to add different gates to the circuit. The `after` closure
    /// can be used to add identical gates after the differences.
    fn compare<C, const D: usize>(
        config: CircuitConfig,
        v1: impl Fn(&mut CircuitBuilder<C::F, D>),
        v2: impl Fn(&mut CircuitBuilder<C::F, D>),
        after: impl Fn(&mut CircuitBuilder<C::F, D>),
    ) -> Result<()>
    where
        C: GenericConfig<D>,
    {
        // turn on logging and force DEBUG level logs
        // to be printed to the screen
        init_logging();

        // 
        let end = |builder: CircuitBuilder<C::F, D>| {
            // print gate information from the DEBUG log level
            builder.print_gate_counts(0);

            print!("Building....");
            let now = Instant::now();
            let data = builder.build::<C>();
            println!("{:.2?}", now.elapsed());

            print!("Proving.....");         
            let pw = PartialWitness::new();
            let now = Instant::now();
            let proof = data.prove(pw)?;
            println!("{:.2?}", now.elapsed());

            print!("Verifying...");
            let now = Instant::now();
            let res = data.verify(proof);
            println!("{:.2?}", now.elapsed());

            println!("LDE size: {}",data.common.lde_size());

            res
        };

        let mut builder1 = CircuitBuilder::<C::F, D>::new(config.clone());
        v1(&mut builder1);
        after(&mut builder1);
        let verified1 = end(builder1);

        let mut builder2 = CircuitBuilder::<C::F, D>::new(config);
        v2(&mut builder2);
        after(&mut builder2);
        let verified2 = end(builder2);
        
        assert!(verified1.is_ok());
        assert!(verified2.is_ok());
        verified1.and(verified2)
    }
}