#[cfg(test)]
mod tests {
    use anyhow::Result;
    use plonky2::field::types::Field;
    use plonky2::iop::target::Target;
    use plonky2::iop::witness::PartialWitness;
    use plonky2::plonk::circuit_builder::CircuitBuilder;
    use plonky2::plonk::circuit_data::CircuitConfig;
    use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
    use std::time::Instant;

    use crate::benches::init_logging;

    #[test]
    fn compare_quin_random_access() -> Result<()> {
        use crate::rlp::quin_selector;
        use rand::Rng;

        // if this is `k` then the array will have 2^k elements
        let array_bits_of_length_max: usize = 6;

        let comparison = |k: usize| {
            // common to both circuits
            const D: usize = 2;
            type C = PoseidonGoldilocksConfig;
            type F = <C as GenericConfig<D>>::F;

            // both versions of the circuit need to capture this information
            let bits_of_length: usize = k;
            let byte_arr: Vec<u8> = (0..1 << bits_of_length)
                .map(|_i| rand::thread_rng().gen())
                .collect();
            println!("\nArray length: {}", byte_arr.len());
            let rand_index: usize = rand::thread_rng().gen_range(0..1 << bits_of_length);

            let config = CircuitConfig::standard_recursion_config();

            let quin_version = |builder: &mut CircuitBuilder<F, D>| {
                let arr_target: Vec<Target> = byte_arr
                    .iter()
                    .map(|x| builder.constant(F::from_canonical_u8(*x)))
                    .collect();
                let n: Target = builder.constant(F::from_canonical_usize(rand_index));
                let element = arr_target[rand_index];

                let ret_element = quin_selector(builder, &arr_target, n);

                builder.connect(element, ret_element);
                builder.register_public_input(ret_element);
                builder.register_public_inputs(&arr_target);
            };

            let random_access_version = |builder: &mut CircuitBuilder<F, D>| {
                let arr_target: Vec<Target> = byte_arr
                    .iter()
                    .map(|x| builder.constant(F::from_canonical_u8(*x)))
                    .collect();
                let n: Target = builder.constant(F::from_canonical_usize(rand_index));
                let element = arr_target[rand_index];

                let ret_element = builder.random_access(n, arr_target.clone());

                builder.connect(element, ret_element);
                builder.register_public_input(ret_element);
                builder.register_public_inputs(&arr_target);
            };

            // in this case there is nothing to do to the circuit
            // after each version so we pass the identity function
            compare::<C, D>(
                config,
                (quin_version, "QUIN VERSION"),
                (random_access_version, "RANDOM ACCESS VERSION"),
                |_| {}, // identity function
            )
        };

        (0..(array_bits_of_length_max + 1))
            .map(comparison)
            .try_fold((), |acc, item| Ok(acc).and(item))
    }

    /// Compares the gate counts, LDE size, build time, proving time, and verification time
    /// of two circuits. Accepts two closures `v1` and `v2` which are the only places where
    /// the two circuits are allowed to add different gates to the circuit. The `after` closure
    /// can be used to add identical gates after the differences.
    fn compare<C, const D: usize>(
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

/*

Bench results with array lengths from 2^0 to 2^6

`random_access` fails for arrays longer than 2^6
because it packs a random access gate into a single row
which has 64 wires in the standard configuration

running 1 test

Array length: 1

QUIN VERSION
    2 gates to root
    Total gate counts:
    - 2 instances of ArithmeticGate { num_ops: 20 }
    Degree before blinding & padding: 6
    Degree after blinding & padding: 8
    Building circuit took 0.043633606s
    Building....43.70ms
    Proving.....2.02s
    Verifying...93.23ms
    LDE size: 64

RANDOM ACCESS VERSION
    0 gates to root
    Total gate counts:
    Degree before blinding & padding: 3
    Degree after blinding & padding: 4
    Building circuit took 0.0190342s
    Building....19.13ms
    Proving.....786.01ms
    Verifying...93.12ms
    LDE size: 32

Array length: 2

QUIN VERSION
    3 gates to root
    Total gate counts:
    - 3 instances of ArithmeticGate { num_ops: 20 }
    Degree before blinding & padding: 7
    Degree after blinding & padding: 8
    Building circuit took 0.06195052s
    Building....62.48ms
    Proving.....607.86ms
    Verifying...110.70ms
    LDE size: 64

RANDOM ACCESS VERSION
    1 gates to root
    Total gate counts:
    - 1 instances of RandomAccessGate { bits: 1, num_copies: 20, num_extra_constants: 0, _phantom: PhantomData<plonky2_field::goldilocks_field::GoldilocksField> }<D=2>
    Degree before blinding & padding: 5
    Degree after blinding & padding: 8
    Building circuit took 0.02839202s
    Building....28.44ms
    Proving.....1.91s
    Verifying...96.69ms
    LDE size: 64

Array length: 4

QUIN VERSION
    3 gates to root
    Total gate counts:
    - 3 instances of ArithmeticGate { num_ops: 20 }
    Degree before blinding & padding: 10
    Degree after blinding & padding: 16
    Building circuit took 0.06623432s
    Building....66.30ms
    Proving.....520.85ms
    Verifying...103.93ms
    LDE size: 128

RANDOM ACCESS VERSION
    1 gates to root
    Total gate counts:
    - 1 instances of RandomAccessGate { bits: 2, num_copies: 13, num_extra_constants: 2, _phantom: PhantomData<plonky2_field::goldilocks_field::GoldilocksField> }<D=2>
    Degree before blinding & padding: 5
    Degree after blinding & padding: 8
    Building circuit took 0.04746539s
    Building....47.53ms
    Proving.....848.61ms
    Verifying...92.31ms
    LDE size: 64

Array length: 8

QUIN VERSION
    3 gates to root
    Total gate counts:
    - 3 instances of ArithmeticGate { num_ops: 20 }
    Degree before blinding & padding: 16
    Degree after blinding & padding: 16
    Building circuit took 0.07234759s
    Building....72.44ms
    Proving.....572.17ms
    Verifying...94.25ms
    LDE size: 128

RANDOM ACCESS VERSION
    1 gates to root
    Total gate counts:
    - 1 instances of RandomAccessGate { bits: 3, num_copies: 8, num_extra_constants: 0, _phantom: PhantomData<plonky2_field::goldilocks_field::GoldilocksField> }<D=2>
    Degree before blinding & padding: 9
    Degree after blinding & padding: 16
    Building circuit took 0.076199085s
    Building....76.26ms
    Proving.....664.78ms
    Verifying...95.64ms
    LDE size: 128

Array length: 16

QUIN VERSION
    6 gates to root
    Total gate counts:
    - 6 instances of ArithmeticGate { num_ops: 20 }
    Degree before blinding & padding: 26
    Degree after blinding & padding: 32
    Building circuit took 0.1314385s
    Building....131.55ms
    Proving.....1.55s
    Verifying...104.35ms
    LDE size: 256

RANDOM ACCESS VERSION
    1 gates to root
    Total gate counts:
    - 1 instances of RandomAccessGate { bits: 4, num_copies: 4, num_extra_constants: 2, _phantom: PhantomData<plonky2_field::goldilocks_field::GoldilocksField> }<D=2>
    Degree before blinding & padding: 13
    Degree after blinding & padding: 16
    Building circuit took 0.07145585s
    Building....71.51ms
    Proving.....516.23ms
    Verifying...104.20ms
    LDE size: 128

Array length: 32

QUIN VERSION
    11 gates to root
    Total gate counts:
    - 11 instances of ArithmeticGate { num_ops: 20 }
    Degree before blinding & padding: 57
    Degree after blinding & padding: 64
    Building circuit took 0.21333219s
    Building....213.50ms
    Proving.....4.38s
    Verifying...120.49ms
    LDE size: 512

RANDOM ACCESS VERSION
    1 gates to root
    Total gate counts:
    - 1 instances of RandomAccessGate { bits: 5, num_copies: 2, num_extra_constants: 2, _phantom: PhantomData<plonky2_field::goldilocks_field::GoldilocksField> }<D=2>
    Degree before blinding & padding: 23
    Degree after blinding & padding: 32
    Building circuit took 0.1523578s
    Building....152.82ms
    Proving.....604.20ms
    Verifying...125.65ms
    LDE size: 256

Array length: 64

QUIN VERSION
    21 gates to root
    Total gate counts:
    - 21 instances of ArithmeticGate { num_ops: 20 }
    Degree before blinding & padding: 107
    Degree after blinding & padding: 128
    Building circuit took 0.3929123s
    Building....393.29ms
    Proving.....1.54s
    Verifying...130.57ms
    LDE size: 1024

RANDOM ACCESS VERSION
    1 gates to root
    Total gate counts:
    - 1 instances of RandomAccessGate { bits: 6, num_copies: 1, num_extra_constants: 2, _phantom: PhantomData<plonky2_field::goldilocks_field::GoldilocksField> }<D=2>
    Degree before blinding & padding: 39
    Degree after blinding & padding: 64
    Building circuit took 0.21680678s
    Building....216.89ms
    Proving.....1.62s
    Verifying...138.10ms
    LDE size: 512
test benches::circuit::tests::compare_quin_random_access ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 18 filtered out; finished in 21.25s

*/
