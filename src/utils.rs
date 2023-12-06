use anyhow::Result;
use itertools::Itertools;
use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::VerifierCircuitData;
use plonky2::plonk::config::GenericConfig;
use plonky2_crypto::u32::arithmetic_u32::U32Target;
use sha3::Digest;
use sha3::Keccak256;

use crate::ProofTuple;

pub(crate) fn verify_proof_tuple<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
>(
    proof: &ProofTuple<F, C, D>,
) -> Result<()> {
    let vcd = VerifierCircuitData {
        verifier_only: proof.1.clone(),
        common: proof.2.clone(),
    };
    vcd.verify(proof.0.clone())
}

/// Allows to write directly a vector of integers into a partial witness
pub trait IntTargetWriter {
    fn set_int_targets<T: Into<u32> + Clone>(&mut self, t: &[Target], v: &[T]);
}
impl<F: RichField> IntTargetWriter for PartialWitness<F> {
    fn set_int_targets<T: Into<u32> + Clone>(&mut self, t: &[Target], v: &[T]) {
        assert_eq!(t.len(), v.len());
        for i in 0..t.len() {
            self.set_target(t[i], F::from_canonical_u32(v[i].clone().into()));
        }
    }
}

// Returns the index where the subvector starts in v, if any.
pub(crate) fn find_index_subvector(v: &[u8], sub: &[u8]) -> Option<usize> {
    (0..(v.len() - sub.len())).find(|&i| &v[i..i + sub.len()] == sub)
}

/// Compute the keccak256 hash of the given data.
/// NOTE: probably should have two modules for circuit related stuff and non-circuit related stuff
pub(crate) fn keccak256(data: &[u8]) -> Vec<u8> {
    let mut hasher = Keccak256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}
pub(crate) fn convert_u8_to_u32<F: RichField + Extendable<D>, const D: usize>(
    b: &mut CircuitBuilder<F, D>,
    data: &[Target],
) -> Vec<U32Target> {
    assert!(data.len() % 4 == 0);
    const TWO_POWER_8: usize = 256;
    const TWO_POWER_16: usize = 65536;
    const TWO_POWER_24: usize = 16777216;
    let padded = data;

    // constants to convert [u8; 4] to u32
    // u32 = u8[0] + u8[1] * 2^8 + u8[2] * 2^16 + u8[3] * 2^24
    let two_power_8: Target = b.constant(F::from_canonical_usize(TWO_POWER_8));
    let two_power_16: Target = b.constant(F::from_canonical_usize(TWO_POWER_16));
    let two_power_24: Target = b.constant(F::from_canonical_usize(TWO_POWER_24));

    // convert padded node to u32
    (0..padded.len())
        .step_by(4)
        .map(|i| {
            // u8[0]
            let mut x = padded[i];
            // u8[1]
            let mut y = padded[i + 1];
            // u8[1] * 2^8
            y = b.mul(y, two_power_8);
            // u8[0] + u8[1] * 2^8
            x = b.add(x, y);
            // u8[2]
            y = padded[i + 2];
            // u8[2] * 2^16
            y = b.mul(y, two_power_16);
            // u8[0] + u8[1] * 2^8 + u8[2] * 2^16
            x = b.add(x, y);
            // u8[3]
            y = padded[i + 3];
            // u8[3] * 2^24
            y = b.mul(y, two_power_24);
            // u8[0] + u8[1] * 2^8 + u8[2] * 2^16 + u8[3] * 2^24
            x = b.add(x, y);

            U32Target(x)
        })
        .collect_vec()
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
pub(crate) fn hash_to_fields<F: RichField>(expected: &[u8]) -> Vec<F> {
    let iter_u32 = expected.iter().chunks(4);
    iter_u32
        .into_iter()
        .map(|chunk| {
            let chunk_buff = chunk.copied().collect::<Vec<u8>>();
            let u32_num = read_le_u32(&mut chunk_buff.as_slice());
            F::from_canonical_u32(u32_num)
        })
        .collect::<Vec<_>>()
}

// taken from rust doc https://doc.rust-lang.org/std/primitive.u32.html#method.from_be_bytes
pub(crate) fn read_le_u32(input: &mut &[u8]) -> u32 {
    let (int_bytes, rest) = input.split_at(std::mem::size_of::<u32>());
    *input = rest;
    u32::from_le_bytes(int_bytes.try_into().unwrap())
}

#[cfg(test)]
pub(crate) mod test {
    use crate::utils::{
        bits_to_num, greater_than, greater_than_or_equal_to, less_than, less_than_or_equal_to,
        num_to_bits,
    };
    use anyhow::Result;
    use itertools::Itertools;
    use plonky2::field::extension::Extendable;
    use plonky2::field::types::Field;
    use plonky2::hash::hash_types::RichField;
    use plonky2::iop::target::Target;
    use plonky2::iop::witness::{PartialWitness, WitnessWrite};
    use plonky2::plonk::circuit_builder::CircuitBuilder;
    use plonky2::plonk::circuit_data::CircuitConfig;
    use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};

    use super::read_le_u32;

    pub(crate) fn hash_output_to_field<F: RichField>(expected: &[u8]) -> Vec<F> {
        let iter_u32 = expected.iter().chunks(4);
        iter_u32
            .into_iter()
            .map(|chunk| {
                let chunk_buff = chunk.copied().collect::<Vec<u8>>();
                let u32_num = read_le_u32(&mut chunk_buff.as_slice());
                F::from_canonical_u32(u32_num)
            })
            .collect::<Vec<_>>()
    }

    pub(crate) fn connect<F: RichField + Extendable<D>, const D: usize, I: Into<u32>>(
        b: &mut CircuitBuilder<F, D>,
        pw: &mut PartialWitness<F>,
        a: Target,
        v: I,
    ) {
        let t = b.add_virtual_target();
        pw.set_target(t, F::from_canonical_u32(v.into()));
        b.connect(a, t);
    }

    pub(crate) fn data_to_constant_targets<F: RichField + Extendable<D>, const D: usize>(
        b: &mut CircuitBuilder<F, D>,
        d: &[u8],
    ) -> Vec<Target> {
        d.iter()
            .map(|x| b.constant(F::from_canonical_u8(*x)))
            .collect()
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
