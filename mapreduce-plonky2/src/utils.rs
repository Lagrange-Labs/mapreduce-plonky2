use anyhow::Result;
use itertools::Itertools;
use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::{HashOut, RichField};
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::VerifierCircuitData;
use plonky2::plonk::config::{GenericConfig, GenericHashOut, Hasher};
use plonky2_crypto::u32::arithmetic_u32::U32Target;
use plonky2_ecgfp5::curve::curve::WeierstrassPoint;
use plonky2_ecgfp5::gadgets::{base_field::QuinticExtensionTarget, curve::CurveTarget};
use sha3::Digest;
use sha3::Keccak256;

use crate::{group_hashing::N, types::HashOutput, ProofTuple};

const TWO_POWER_8: usize = 256;
const TWO_POWER_16: usize = 65536;
const TWO_POWER_24: usize = 16777216;

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
    v.windows(sub.len()).position(|s| s == sub)
}

/// Compute the keccak256 hash of the given data.
/// NOTE: probably should have two modules for circuit related stuff and non-circuit related stuff
pub(crate) fn keccak256(data: &[u8]) -> Vec<u8> {
    let mut hasher = Keccak256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

/// Convert an u8 slice to an u32-field vector.
pub(crate) fn convert_u8_slice_to_u32_fields<F: RichField>(values: &[u8]) -> Vec<F> {
    assert!(values.len() % 4 == 0);

    values
        .chunks(4)
        .into_iter()
        .map(|mut chunk| {
            let u32_num = read_le_u32(&mut chunk);
            F::from_canonical_u32(u32_num)
        })
        .collect()
}

/// Convert an u32-field slice to an u8 vector.
pub(crate) fn convert_u32_fields_to_u8_vec<F: RichField>(fields: &[F]) -> Vec<u8> {
    fields
        .iter()
        .flat_map(|f| (f.to_canonical_u64() as u32).to_le_bytes())
        .collect()
}

pub(crate) fn convert_u8_values_to_u32<F: RichField>(values: &[F]) -> Vec<F> {
    assert!(values.len() % 4 == 0);

    let two_power_8 = F::from_canonical_usize(TWO_POWER_8);
    let two_power_16 = F::from_canonical_usize(TWO_POWER_16);
    let two_power_24 = F::from_canonical_usize(TWO_POWER_24);

    (0..values.len())
        .step_by(4)
        .map(|i| {
            values[i]
                + values[i + 1] * two_power_8
                + values[i + 2] * two_power_16
                + values[i + 3] * two_power_24
        })
        .collect()
}

pub(crate) fn convert_u8_targets_to_u32<F: RichField + Extendable<D>, const D: usize>(
    b: &mut CircuitBuilder<F, D>,
    data: &[Target],
) -> Vec<U32Target> {
    assert!(data.len() % 4 == 0);
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
            // u8[0] + u8[1] * 2^8
            x = b.mul_add(y, two_power_8, x);
            // u8[2]
            y = padded[i + 2];
            // u8[0] + u8[1] * 2^8 + u8[2] * 2^16
            x = b.mul_add(y, two_power_16, x);
            // u8[3]
            y = padded[i + 3];
            // u8[0] + u8[1] * 2^8 + u8[2] * 2^16 + u8[3] * 2^24
            x = b.mul_add(y, two_power_24, x);

            U32Target(x)
        })
        .collect_vec()
}

/// Returns the bits of the given number.
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

/// Returns true if a < b in the first n bits. False otherwise.
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

/// Resize the input vector if needed
pub(crate) fn convert_u8_to_u32_slice(data: &[u8]) -> Vec<u32> {
    let mut d = data.to_vec();
    if data.len() % 4 != 0 {
        d.resize(data.len() + (4 - (data.len() % 4)), 0);
    }
    let mut converted = Vec::new();
    for chunk in d.chunks_exact(4) {
        converted.push(u32::from_le_bytes(chunk.try_into().unwrap()));
    }
    converted
}

// taken from rust doc https://doc.rust-lang.org/std/primitive.u32.html#method.from_be_bytes
pub(crate) fn read_le_u32(input: &mut &[u8]) -> u32 {
    let (int_bytes, rest) = input.split_at(std::mem::size_of::<u32>());
    *input = rest;
    u32::from_le_bytes(int_bytes.try_into().unwrap())
}

/// Convert a list of elements to a curve point.
pub fn convert_slice_to_curve_point<T: Copy>(s: &[T]) -> ([T; 5], [T; 5], T) {
    // 5 F for each coordinates + 1 bool flag
    assert!(s.len() >= 2 * N + 1);

    let x = s[..N].try_into().unwrap();
    let y = s[N..2 * N].try_into().unwrap();
    let flag = s[2 * N];

    (x, y, flag)
}

/// Convert a tuple of point to a curve target.
pub fn convert_point_to_curve_target(point: ([Target; 5], [Target; 5], Target)) -> CurveTarget {
    let (x, y, is_inf) = point;

    let x = QuinticExtensionTarget(x);
    let y = QuinticExtensionTarget(y);
    let flag = BoolTarget::new_unsafe(is_inf);

    CurveTarget(([x, y], flag))
}

/// Hash left and right children to one value.
pub fn hash_two_to_one<F: RichField, H: Hasher<F>>(
    left: HashOutput,
    right: HashOutput,
) -> HashOutput {
    let [left, right] = [left, right].map(|bytes| H::Hash::from_bytes(&bytes));
    H::two_to_one(left, right).to_bytes().try_into().unwrap()
}

// TODO move that to a vec/array specific module?
pub trait ToFields {
    fn to_fields<F: RichField>(&self) -> Vec<F>;
}

impl ToFields for &[u8] {
    fn to_fields<F: RichField>(&self) -> Vec<F> {
        self.iter().map(|x| F::from_canonical_u8(*x)).collect()
    }
}
impl ToFields for &[u32] {
    fn to_fields<F: RichField>(&self) -> Vec<F> {
        self.iter().map(|x| F::from_canonical_u32(*x)).collect()
    }
}
pub trait Fieldable {
    fn to_field<F: RichField>(&self) -> F;
}

impl Fieldable for u8 {
    fn to_field<F: RichField>(&self) -> F {
        F::from_canonical_u8(*self)
    }
}
impl<T: Fieldable> ToFields for Vec<T> {
    fn to_fields<F: RichField>(&self) -> Vec<F> {
        self.iter().map(|x| x.to_field()).collect()
    }
}

impl<const N: usize, T: Fieldable> ToFields for [T; N] {
    fn to_fields<F: RichField>(&self) -> Vec<F> {
        self.iter().map(|x| x.to_field()).collect()
    }
}

impl Fieldable for u32 {
    fn to_field<F: RichField>(&self) -> F {
        F::from_canonical_u32(*self)
    }
}

pub trait Packer {
    type T;
    fn pack(&self) -> Vec<Self::T>;
}

impl Packer for &[u8] {
    type T = u32;
    fn pack(&self) -> Vec<u32> {
        convert_u8_to_u32_slice(self)
    }
}

impl Packer for Vec<u8> {
    type T = u32;
    fn pack(&self) -> Vec<u32> {
        convert_u8_to_u32_slice(self)
    }
}

impl<const N: usize> Packer for &[u8; N] {
    type T = u32;
    fn pack(&self) -> Vec<u32> {
        convert_u8_to_u32_slice(self.as_slice())
    }
}
impl<const N: usize> Packer for [u8; N] {
    type T = u32;
    fn pack(&self) -> Vec<u32> {
        convert_u8_to_u32_slice(self.as_slice())
    }
}
#[cfg(test)]
pub(crate) mod test {
    use crate::utils::{
        bits_to_num, convert_u8_to_u32_slice, greater_than, greater_than_or_equal_to, less_than,
        less_than_or_equal_to, num_to_bits,
    };
    use anyhow::Result;
    use ethers::types::Address;
    use itertools::Itertools;
    use plonky2::field::extension::Extendable;
    use plonky2::field::goldilocks_field::GoldilocksField;
    use plonky2::field::types::Field;
    use plonky2::hash::hash_types::RichField;
    use plonky2::iop::target::Target;
    use plonky2::iop::witness::{PartialWitness, WitnessWrite};
    use plonky2::plonk::circuit_builder::CircuitBuilder;
    use plonky2::plonk::circuit_data::CircuitConfig;
    use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
    use rand::{thread_rng, Rng, RngCore};

    #[test]
    fn test_pack() {
        let addr = Address::random();
        let packed_addr: Vec<GoldilocksField> = addr.as_fixed_bytes().pack().to_fields();
    }
    use super::{read_le_u32, Packer, ToFields};
    pub(crate) fn random_vector<T>(size: usize) -> Vec<T>
    where
        rand::distributions::Standard: rand::distributions::Distribution<T>,
    {
        (0..size).map(|_| thread_rng().gen::<T>()).collect()
    }
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
    fn test_convert_u8_to_u32_slice() {
        const SIZE: usize = 45; // size of the byte array
        let mut rng = rand::thread_rng();

        // Generate a random array of bytes
        let mut data = vec![0u8; SIZE];
        rng.fill_bytes(&mut data);

        // Convert the byte array to a u32 slice
        let u32_slice = convert_u8_to_u32_slice(&data);

        // Check if the length of the u32 slice is correct
        assert_eq!(u32_slice.len(), (SIZE + (4 - (SIZE % 4))) / 4);
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
