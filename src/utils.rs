use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2_crypto::hash::HashOutputTarget;
use plonky2_crypto::u32::arithmetic_u32::U32Target;
use itertools::Itertools;

pub(crate) const TWO_POWER_8: usize = 256;
pub(crate) const TWO_POWER_16: usize = 65536;
pub(crate) const TWO_POWER_24: usize = 16777216;

/// Useful to convert between u32 representation and u8 representation in circuit. 
/// For example hash output is using u32 representations.
pub fn array_u8_to_u32<F: RichField + Extendable<D>, const D: usize>(
    b: &mut CircuitBuilder<F, D>,
    arr: &[Target; 32], // each target represents a single byte
) -> [U32Target; 8] {
    // constants to convert [u8; 4] to u32
    // u32 = u8[0] + u8[1] * 2^8 + u8[2] * 2^16 + u8[3] * 2^24
    let two_power_8: Target = b.constant(F::from_canonical_usize(TWO_POWER_8));
    let two_power_16: Target = b.constant(F::from_canonical_usize(TWO_POWER_16));
    let two_power_24: Target = b.constant(F::from_canonical_usize(TWO_POWER_24));

    let mut u32_array = [U32Target(b.zero()); 8];
    (0..arr.len()).step_by(4).for_each(|i| {
        // u8[0]
        let mut x = arr[i];

        // u8[1]
        let mut y = arr[i + 1];
        // u8[1] * 2^8
        y = b.mul(y, two_power_8);

        // u8[0] + u8[1] * 2^8
        x = b.add(x, y);

        // u8[2]
        y = arr[i + 2];
        // u8[2] * 2^16
        y = b.mul(y, two_power_16);

        // u8[0] + u8[1] * 2^8 + u8[2] * 2^16
        x = b.add(x, y);

        // u8[3]
        y = arr[i + 3];
        // u8[3] * 2^24
        y = b.mul(y, two_power_24);

        // u8[0] + u8[1] * 2^8 + u8[2] * 2^16 + u8[3] * 2^24
        x = b.add(x, y);

        u32_array[i / 4] = U32Target(x);
    });
    u32_array
}

pub fn num_to_bits<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    n: usize,
    x: Target,
) -> Vec<BoolTarget> {
    builder.range_check(x, n);
    builder.split_le(x, n)
}

pub fn bits_to_num<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    bits: &[BoolTarget],
) -> Target {
    let mut res = builder.zero();
    let mut e2 = builder.one();
    for bit in bits {
        res = builder.mul_add(e2, bit.target, res);
        e2 = builder.add(e2, e2);
    }
    res
}

pub fn less_than<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    a: Target,
    b: Target,
    n: usize,
) -> BoolTarget {
    assert!(n < 64);

    let power_of_two = builder.constant(F::from_canonical_u64(1 << n));
    let mut lin_pol = builder.add(a, power_of_two);
    // 2^n + a - b
    lin_pol = builder.sub(lin_pol, b);

    let binary = num_to_bits(builder, n + 1, lin_pol);
    // bin(2^n + a - b)[n] == false is correct only when a < b otherwise
    // 2^n + a - b > 2^n so binary[n] will be set
    builder.not(binary[n])
}

pub fn greater_than<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    a: Target,
    b: Target,
    n: usize,
) -> BoolTarget {
    less_than(builder, b, a, n)
}

pub fn less_than_or_equal_to<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    a: Target,
    b: Target,
    n: usize,
) -> BoolTarget {
    let one = builder.one();
    let b_plus_1 = builder.add(b, one);
    less_than(builder, a, b_plus_1, n)
}

pub fn greater_than_or_equal_to<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    a: Target,
    b: Target,
    n: usize,
) -> BoolTarget {
    let one = builder.one();
    let a_plus_1 = builder.add(a, one);
    less_than(builder, b, a_plus_1, n)
}

// Returns the shifted bits as a num
pub fn right_shift<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    n: usize,
    x: Target,
    shift: usize,
) -> Target {
    // nikko: Is this legit ? an IF depending on the witness seems
    // wrong, because then the circuit is not the same depending
    // on the value of the witness...
    let bits = num_to_bits(builder, n, x);
    if bits.is_empty() || shift >= bits.len() {
        return builder.zero();
    }
    // Remove the least significant bits according to the shift value
    let shifted_bits = &bits[shift..];

    // Convert the shifted bits back to a number
    bits_to_num(builder, shifted_bits)
}

#[cfg(test)]
mod test {
    use crate::utils::{
        bits_to_num, greater_than, greater_than_or_equal_to, less_than, less_than_or_equal_to,
        num_to_bits, right_shift,
    };
    use anyhow::Result;
    use plonky2::field::types::Field;
    use plonky2::iop::target::Target;
    use plonky2::iop::witness::PartialWitness;
    use plonky2::plonk::circuit_builder::CircuitBuilder;
    use plonky2::plonk::circuit_data::CircuitConfig;
    use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};

    #[test]
    fn test_right_shift() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        let config = CircuitConfig::standard_recursion_config();
        let pw = PartialWitness::new();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let a = builder.constant(F::from_canonical_u64(121u64));
        let b = builder.constant(F::from_canonical_u64(15u64));
        let res = right_shift(&mut builder, 64, a, 3);

        builder.connect(res, b);

        builder.register_public_input(a);
        builder.register_public_input(b);
        builder.register_public_input(res);

        let data = builder.build::<C>();
        let proof = data.prove(pw)?;
        data.verify(proof)
    }

    #[test]
    fn test_bits_to_num() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        let config = CircuitConfig::standard_recursion_config();
        let pw = PartialWitness::new();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let number = builder.constant(F::from_canonical_usize(1986));
        let t = builder._true();
        let f = builder._false();

        let bits_array = [f, t, f, f, f, f, t, t, t, t, t];
        let one = builder.one();
        let zero = builder.zero();

        let public_input_array = [zero, one, zero, zero, zero, zero, one, one, one, one, one];

        let nums = bits_to_num(&mut builder, &bits_array);

        builder.connect(number, nums);
        builder.register_public_input(number);
        builder.register_public_inputs(&public_input_array);

        let data = builder.build::<C>();
        let proof = data.prove(pw)?;
        data.verify(proof)
    }

    #[test]
    fn test_num_to_bits_valid() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        let config = CircuitConfig::standard_recursion_config();
        let pw = PartialWitness::new();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let x = F::from_canonical_usize(0b110100000); // 416 = 1532 in base 6.
        let xt = builder.constant(x);

        let mut bits = [1, 1, 0, 1, 0, 0, 0, 0, 0];
        bits.reverse();
        let mut bits_target_input: Vec<Target> = vec![];

        let bits_target = num_to_bits(&mut builder, 9, xt);

        for i in 0..bits_target.len() {
            bits_target_input.push(builder.constant(F::from_canonical_u64(bits[i])));
            builder.connect(bits_target_input[i], bits_target[i].target);
        }

        builder.register_public_input(xt);
        builder.register_public_inputs(&bits_target_input);

        let data = builder.build::<C>();
        let proof = data.prove(pw)?;
        data.verify(proof)
    }

    #[test]
    fn test_less_than() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        let config = CircuitConfig::standard_recursion_config();
        let pw = PartialWitness::new();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let a = builder.constant(F::from_canonical_u64(5u64));
        let b = builder.constant(F::from_canonical_u64(10u64));
        let n = 4;

        let result = less_than(&mut builder, a, b, n);
        let one = builder.one();
        builder.connect(result.target, one);

        builder.register_public_input(a);
        builder.register_public_input(b);
        builder.register_public_input(result.target);

        let data = builder.build::<C>();
        let proof = data.prove(pw)?;
        data.verify(proof)
    }

    #[test]
    fn test_greater_than() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        let config = CircuitConfig::standard_recursion_config();
        let pw = PartialWitness::new();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let a = builder.constant(F::from_canonical_u64(10u64));
        let b = builder.constant(F::from_canonical_u64(5u64));
        let n = 4;

        let result = greater_than(&mut builder, a, b, n);
        let one = builder.one();
        builder.connect(result.target, one);

        builder.register_public_input(a);
        builder.register_public_input(b);
        builder.register_public_input(result.target);

        let data = builder.build::<C>();
        let proof = data.prove(pw)?;
        data.verify(proof)
    }

    #[test]
    fn test_less_than_or_equal_to() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        let config = CircuitConfig::standard_recursion_config();
        let pw = PartialWitness::new();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let a = builder.constant(F::from_canonical_u64(10u64));
        let b = builder.constant(F::from_canonical_u64(10u64));
        let n = 4;

        let result = less_than_or_equal_to(&mut builder, a, b, n);
        let one = builder.one();
        builder.connect(result.target, one);

        builder.register_public_input(a);
        builder.register_public_input(b);
        builder.register_public_input(result.target);

        let data = builder.build::<C>();
        let proof = data.prove(pw)?;
        data.verify(proof)
    }

    #[test]
    fn test_greater_than_or_equal_to() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        let config = CircuitConfig::standard_recursion_config();
        let pw = PartialWitness::new();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let a = builder.constant(F::from_canonical_u64(10u64));
        let b = builder.constant(F::from_canonical_u64(10u64));
        let n = 4;

        let result = greater_than_or_equal_to(&mut builder, a, b, n);
        let one = builder.one();
        builder.connect(result.target, one);

        builder.register_public_input(a);
        builder.register_public_input(b);
        builder.register_public_input(result.target);

        let data = builder.build::<C>();
        let proof = data.prove(pw)?;
        data.verify(proof)
    }
}
