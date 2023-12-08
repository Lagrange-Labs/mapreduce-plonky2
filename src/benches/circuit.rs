#[cfg(test)]
mod tests {
    use std::env;
    use log::{LevelFilter, debug};
    use anyhow::Result;
    use plonky2::field::types::Field;
    use plonky2::iop::target::Target;
    use plonky2::iop::witness::PartialWitness;
    use plonky2::plonk::circuit_builder::CircuitBuilder;
    use plonky2::plonk::circuit_data::CircuitConfig;
    use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};

    // sets RUST_LOG=debug and initializes the logger
    // call init() at the top of every comparison test
    fn init() {
        env::set_var("RUST_LOG", "debug");
        env_logger::init();
        log::set_max_level(LevelFilter::Debug);
    }

    #[test]
    fn compare_quin_random_access() -> Result<()> {
        use crate::rlp::quin_selector;
        use rand::Rng;
        init();
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        let config = CircuitConfig::standard_recursion_config();
        let bits_of_length: usize = 6;
        let byte_arr: Vec<u8> = (0..1<<bits_of_length).map(|_i| rand::thread_rng().gen()).collect();
        println!("byte_arr length: {}", byte_arr.len());
        let rand_index: usize = rand::thread_rng().gen_range(0..1<<bits_of_length);

        // quin version
        debug!("QUIN VERSION");
        let pw = PartialWitness::new();
        let mut builder = CircuitBuilder::<F, D>::new(config.clone());

        let arr_target: Vec<Target> = byte_arr
            .iter()
            .map(|x| builder.constant(F::from_canonical_u8(*x)))
            .collect();

        let n: Target = builder.constant(F::from_canonical_usize(rand_index));

        let element = arr_target[rand_index];
        let ret_element = quin_selector(&mut builder, &arr_target, n);

        builder.connect(element, ret_element);
        builder.register_public_inputs(&arr_target);
        builder.register_public_input(ret_element);
        builder.print_gate_counts(0);

        let data = builder.build::<C>();
        debug!("lde size: {}",data.common.lde_size());
        let proof = data.prove(pw)?;
        assert!(data.verify(proof).is_ok());

        // random access version
        debug!("RANDOM ACCESS VERSION");
        let pw = PartialWitness::new();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let arr_target: Vec<Target> = byte_arr
            .iter()
            .map(|x| builder.constant(F::from_canonical_u8(*x)))
            .collect();

        let n: Target = builder.constant(F::from_canonical_usize(rand_index));

        let element = arr_target[rand_index];
        let ret_element = builder.random_access(n,arr_target.clone());

        builder.connect(element, ret_element);
        builder.register_public_inputs(&arr_target);
        builder.register_public_input(ret_element);
        builder.print_gate_counts(0);

        let data = builder.build::<C>();
        debug!("lde size: {}",data.common.lde_size());
        let proof = data.prove(pw)?;
        data.verify(proof)
    }
    
}