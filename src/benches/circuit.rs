#[cfg(test)]
mod tests {
    use anyhow::Result;
    use log::{log_enabled, Level, LevelFilter};
    use plonky2::field::extension::Extendable;
    use plonky2::field::types::Field;
    use plonky2::gadgets::arithmetic_extension::PowersTarget;
    use plonky2::hash::hash_types::RichField;
    use plonky2::iop::target::Target;
    use plonky2::iop::witness::PartialWitness;
    use plonky2::plonk::circuit_builder::CircuitBuilder;
    use plonky2::plonk::circuit_data::CircuitConfig;
    use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
    use std::env;
    use std::io::Write;
    use std::time::Instant;


    fn rotation_setup<F: RichField + Extendable<D>, const D: usize>(
        b: &mut CircuitBuilder<F, D>,
        arr: &[Target],
    ) -> Target {

        let gen = F::MULTIPLICATIVE_GROUP_GENERATOR;
        let power: u64 = (F::ORDER - 1) / 544;
        let gen_order_544 = gen.exp_u64(power);
        let powers = F::cyclic_subgroup_known_order(gen_order_544, 544);

        let terms: Vec<Target> = arr.iter().zip(powers).map(|(x, c)| 
            b.mul_const(c, *x)
        ).collect();

        b.add_many(terms)
    }

    fn rotation_access<F: RichField + Extendable<D>, const D: usize>(
        b: &mut CircuitBuilder<F, D>,
        arr: Target,
        index: Target,
        element: Target,
    ) {

        let gen = F::MULTIPLICATIVE_GROUP_GENERATOR;
        let power: u64 = (F::ORDER - 1) / 544;
        let r_inverse = gen.inverse().exp_u64(power);

        let bits_of_index = b.split_le(index, 10);
        let r_inverse_to_index = b.exp_from_bits_const_base(r_inverse, bits_of_index);
        let shifted_arr = b.mul(r_inverse_to_index, arr);
        let tail_times_r = b.sub(shifted_arr, element);
        let tail = b.mul_const(r_inverse, tail_times_r);

    }

    fn vanishing_poly_setup<F: RichField + Extendable<D>, const D: usize>(
        b: &mut CircuitBuilder<F, D>,
        arr: &[Target],
    ) -> Vec<Target> {
        // separator is 2^8 since array elements are less than 2^8
                
        // preprocess the elements of the array
        // cost: l constraints
        arr.into_iter().enumerate().map(|(i, el)| {
            // separator is 2^8 since array elements are less than 2^8
            let i_target = F::from_canonical_usize(i*256);

            // out = separator * i_target + a
            b.add_const( *el, i_target)
        }).collect()
    }

    fn vanishing_poly_access<F: RichField + Extendable<D>, const D: usize>(
        b: &mut CircuitBuilder<F, D>,
        indexed_elements: &[Target],
        n: Target,
        element: Target,
    ){
        // separator is 2^8 since array elements are less than 2^8
        let separator = F::from_canonical_u64(256);
        
        let claimed_pair = b.mul_const_add(separator, n, element);

        // index into the array at n by computing the vanishing polynomial
        let diffs: Vec<Target> = indexed_elements.into_iter().map(|el|
            b.sub(*el, claimed_pair)
        ).collect();

        let zero = b.zero();
        let product = b.mul_many(diffs);
        b.connect(product, zero);
    }

    #[test]
    fn compare_quin_vanishing_poly() -> Result<()> {
        use crate::rlp::quin_selector;
        use rand::Rng;

        // (l, n) = (length of array, number of array lookups)
        let comparison = |n: usize| {
            // common to both circuits
            const D: usize = 2;
            type C = PoseidonGoldilocksConfig;
            type F = <C as GenericConfig<D>>::F;

            let byte_arr = [
            185, 4, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
            22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43,
            44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65,
            66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87,
            88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107,
            108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124,
            125, 126, 127, 128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141,
            142, 143, 144, 145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155, 156, 157, 158,
            159, 160, 161, 162, 163, 164, 165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175,
            176, 177, 178, 179, 180, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191, 192,
            193, 194, 195, 196, 197, 198, 199, 200, 201, 202, 203, 204, 205, 206, 207, 208, 209,
            210, 211, 212, 213, 214, 215, 216, 217, 218, 219, 220, 221, 222, 223, 224, 225, 226,
            227, 228, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238, 239, 240, 241, 242, 243,
            244, 245, 246, 247, 248, 249, 250, 251, 252, 253, 254, 255, 0, 1, 2, 3, 4, 5, 6, 7, 8,
            9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30,
            31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52,
            53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74,
            75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96,
            97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114,
            115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131,
            132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148,
            149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164, 165,
            166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 179, 180, 181, 182,
            183, 184, 185, 186, 187, 188, 189, 190, 191, 192, 193, 194, 195, 196, 197, 198, 199,
            200, 201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211, 212, 213, 214, 215, 216,
            217, 218, 219, 220, 221, 222, 223, 224, 225, 226, 227, 228, 229, 230, 231, 232, 233,
            234, 235, 236, 237, 238, 239, 240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250,
            234, 235, 236, 237, 238, 239, 240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250,
            234, 235, 236, 237, 238, 239, 240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250,
            1,
        ];

            println!("\nArray length: {}", byte_arr.len());

            let rand_indices: Vec<usize> = (0..n).map(|_| rand::thread_rng().gen_range(0..byte_arr.len())).collect();

            let config = CircuitConfig::standard_recursion_config();

            let quin_version = |builder: &mut CircuitBuilder<F, D>| {
                let arr_target: Vec<Target> = byte_arr
                    .iter()
                    .map(|x| builder.constant(F::from_canonical_u8(*x)))
                    .collect();
                
                for rand_index in &rand_indices {
                    let n: Target = builder.constant(F::from_canonical_usize(*rand_index));
                    let ret_element = quin_selector(builder, &arr_target, n);
                }
            };

            let vanishing_poly_version = |builder: &mut CircuitBuilder<F, D>| {
                let arr_target: Vec<Target> = byte_arr
                    .iter()
                    .map(|x| builder.constant(F::from_canonical_u8(*x)))
                    .collect();
                let indexed_elements = vanishing_poly_setup(builder, &arr_target);

                for rand_index in &rand_indices {
                    let n: Target = builder.constant(F::from_canonical_usize(*rand_index));
                    let element = arr_target[*rand_index];
                    vanishing_poly_access(builder, &indexed_elements, n, element);
                }
            };

            // in this case there is nothing to do to the circuit
            // after each version so we pass the identity function
            compare::<C, D>(
                config,
                (quin_version, "QUIN VERSION"),
                (vanishing_poly_version, "VANISHING POLY VERSION"),
                |_| {}, // identity function
            )
        };

        comparison(32)
    }

    #[test]
    fn arrays_by_vanishing_poly() -> Result<()> {
        use rand::Rng;
        init_logging();

        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        let config = CircuitConfig::standard_recursion_config();
        let pw = PartialWitness::new();
        let mut builder = CircuitBuilder::<F, D>::new(config);


        let bits_of_length: usize = 6;
        let byte_arr: Vec<u8> = (0..1 << bits_of_length)
            .map(|_i| rand::thread_rng().gen())
            .collect();
        println!("\nArray length: {}", byte_arr.len());
        let rand_index: usize = rand::thread_rng().gen_range(0..1 << bits_of_length);

        let arr_target: Vec<Target> = byte_arr
            .iter()
            .map(|x| builder.constant(F::from_canonical_u8(*x)))
            .collect();
        let n: Target = builder.constant(F::from_canonical_usize(rand_index));
        let element = arr_target[rand_index];

        // separator is 2^8 since array elements are less than 2^8
        let separator = F::from_canonical_u64(256);

        // preprocess the elements of the array
        // cost: l constraints
        let indexed_elements: Vec<Target> = arr_target.into_iter().enumerate().map(|(i, el)| {
            let i_target = builder.constant(F::from_canonical_usize(i));

            // out = separator * i_target + a
            builder.mul_const_add(separator, i_target, el)
        }).collect();

        let claimed_pair = builder.mul_const_add(separator, n, element);

        // index into the array at n by computing the vanishing polynomial
        let one = builder.one();
        let product = indexed_elements.into_iter().fold(one, |acc, el| {
            let diff = builder.sub(el, claimed_pair);
            builder.mul(acc, diff)
        });

        let zero = builder.zero();
        builder.connect(product, zero);      

        builder.print_gate_counts(0);
        let data = builder.build::<C>();
        let proof = data.prove(pw)?;
        let res = data.verify(proof);
        println!("    LDE size: {}", data.common.lde_size());

        res
    }

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
            .fold(Ok(()), |r, state| state.and(r))
    }

    /// Sets RUST_LOG=debug and initializes the logger
    /// if it hasn't been enabled already.
    fn init_logging() {
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
