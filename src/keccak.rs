use anyhow::{ensure, Result};
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::{
        target::{BoolTarget, Target},
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::circuit_builder::CircuitBuilder,
    util::ceil_div_usize,
};
use plonky2_crypto::{
    biguint::BigUintTarget,
    hash::{
        keccak256::{CircuitBuilderHashKeccak, KECCAK256_R},
        HashInputTarget,
    },
    u32::arithmetic_u32::U32Target,
};

use crate::{
    array::{Array, VectorWire},
    circuit::UserCircuit,
    utils::{convert_u8_to_u32, less_than, IntTargetWriter},
};

/// Length of a hash in bytes.
const HASH_LEN: usize = 32;
/// Length of a hash in U32
const PACKED_HASH_LEN: usize = 8;

/// Keccak pads data before "hashing" it. This method returns the full size
/// of the padded data before hashing. This is useful to know the actual number
/// of allocated wire one needs to reserve inside the circuit.
pub const fn compute_size_with_padding(data_len: usize) -> usize {
    let input_len_bits = data_len * 8; // only pad the data that is inside the fixed buffer
    let num_actual_blocks = 1 + input_len_bits / KECCAK256_R;
    let padded_len_bits = num_actual_blocks * KECCAK256_R;
    // reason why ^: this is annoying to do in circuit.
    ceil_div_usize(padded_len_bits, 8)
}

/// This returns only the amount of padding applied on top of the data.
pub const fn compute_padding_size(data_len: usize) -> usize {
    compute_size_with_padding(data_len) - data_len
}

/// Represents the output of the keccak hash function.
/// It's a wrapper to implement some utility functions on top.
pub type OutputHash = Array<U32Target, PACKED_HASH_LEN>;

/// Circuit able to hash any arrays of bytes of dynamic sizes as long as its
/// padded version length is less than N. In other words, N is the maximal size
/// of the array + padding to hash.
#[derive(Clone, Copy, Debug)]
pub struct KeccakCircuit<const N: usize> {
    data: [u8; N],
    unpadded_len: usize,
}
#[derive(Clone, Debug)]
pub struct KeccakWires<const N: usize>
where
    [(); N / 4]:,
{
    input_array: VectorWire<N>,
    /// this is the input node but in u32 format and padded.
    /// It is useful to keep around as we are comparing hashes in u32 format in other
    /// circuits. Note it's an array here because at this point we don't care
    /// anymore of the real len.
    pub padded_u32: Array<U32Target, { N / 4 }>,
    diff: Target,
    // 256/u32 = 8
    pub output_array: OutputHash,
}

impl<const N: usize> KeccakCircuit<N>
where
    [(); N / 4]:,
{
    pub fn new(mut data: Vec<u8>) -> Result<Self> {
        let total = compute_size_with_padding(data.len());
        ensure!(
            total <= N,
            "{} bytes can't fit in {} bytes with padding (data len {})",
            total,
            N,
            data.len(),
        );
        // NOTE we don't pad anymore because we enforce that the resulting length is already a multiple
        // of 4 so it will fit the conversion to u32 and circuit vk would stay the same for different
        // data length
        ensure!(
            N % 4 == 0,
            "Fixed array size must be 0 mod 4 for conversion with u32"
        );

        let unpadded_len = data.len();
        data.resize(N, 0);
        Ok(Self {
            data: data.try_into().unwrap(),
            unpadded_len,
        })
    }

    /// Takes an array which is _already_ at the right padded length.
    /// The circuit fills the padding part and hash it.
    pub fn hash_vector<F: RichField + Extendable<D>, const D: usize>(
        b: &mut CircuitBuilder<F, D>,
        a: &VectorWire<N>,
    ) -> KeccakWires<N> {
        let diff_target = b.add_virtual_target();
        let end_padding = b.add(a.real_len, diff_target);
        let one = b.one();
        let end_padding = b.sub(end_padding, one); // inclusive range
                                                   // little endian so we start padding from the end of the byte
        let single_pad = b.constant(F::from_canonical_usize(0x81)); // 1000 0001
        let begin_pad = b.constant(F::from_canonical_usize(0x01)); // 0000 0001
        let end_pad = b.constant(F::from_canonical_usize(0x80)); // 1000 0000
                                                                 // TODO : make that const generic
        let padded_node = a
            .arr
            .arr
            .iter() // TODO: implement iterable for Vector & Array
            .enumerate()
            .map(|(i, byte)| {
                let i_target = b.constant(F::from_canonical_usize(i));
                // condition if we are within the data range ==> i < length
                let is_data = less_than(b, i_target, a.real_len, 32);
                // condition if we start the padding ==> i == length
                let is_start_padding = b.is_equal(i_target, a.real_len);
                // condition if we are done with the padding ==> i == length + diff - 1
                let is_end_padding = b.is_equal(i_target, end_padding);
                // condition if we only need to add one byte 1000 0001 to pad
                // because we work on u8 data, we know we're at least adding 1 byte and in
                // this case it's 0x81 = 1000 0001
                // i == length == diff - 1
                let is_start_and_end = b.and(is_start_padding, is_end_padding);

                // nikko XXX: Is this sound ? I think so but not 100% sure.
                // I think it's ok to not use `quin_selector` or `b.random_acess` because
                // if the prover gives another byte target, then the resulting hash would be invalid,
                let item_data = b.mul(is_data.target, *byte);
                let item_start_padding = b.mul(is_start_padding.target, begin_pad);
                let item_end_padding = b.mul(is_end_padding.target, end_pad);
                let item_start_and_end = b.mul(is_start_and_end.target, single_pad);
                // if all of these conditions are false, then item will be 0x00,i.e. the padding
                let mut item = item_data;
                item = b.add(item, item_start_padding);
                item = b.add(item, item_end_padding);
                item = b.add(item, item_start_and_end);
                item
            })
            .collect::<Vec<_>>();

        // convert padded node to u32
        let node_u32_target: Vec<U32Target> = convert_u8_to_u32(b, &padded_node);

        // fixed size block delimitation: this is where we tell the hash function gadget
        // to only look at a certain portion of our data, each bool says if the hash function
        // will update its state for this block or not.
        let rate_bytes = b.constant(F::from_canonical_usize(KECCAK256_R / 8));
        let end_padding_offset = b.add(end_padding, one);
        let nb_blocks = b.div(end_padding_offset, rate_bytes);
        // - 1 because keccak always take first block so we don't count it
        let nb_actual_blocks = b.sub(nb_blocks, one);
        let total_num_blocks = N / (KECCAK256_R / 8) - 1;
        let blocks = (0..total_num_blocks)
            .map(|i| {
                let i_target = b.constant(F::from_canonical_usize(i));
                less_than(b, i_target, nb_actual_blocks, 8)
            })
            .collect::<Vec<_>>();

        let hash_target = HashInputTarget {
            input: BigUintTarget {
                limbs: node_u32_target.clone(),
            },
            input_bits: 0,
            blocks,
        };

        let hash_output = b.hash_keccak256(&hash_target);
        KeccakWires {
            // TODO: this is fixed length, should be able to use const generics
            padded_u32: Array::try_from(node_u32_target).unwrap(),
            input_array: a.clone(),
            diff: diff_target,
            // TODO: this is fixed length should be able to use const generics
            output_array: OutputHash::try_from(hash_output.limbs).unwrap(),
        }
    }

    /// In the case we already have the array coming from another circuit, i.e.
    /// the cleartext bytes are not available,
    /// we can use this function during proving time. However, we do need the
    /// unpadded length to correctly compute the padding currently.
    /// NOTE: we could remove this requirement but it would mean computing the
    /// padding size in circuit, which is annoying. Computing off circuit is
    /// usually secure in our cases because we use it to check consistency with
    /// a known hash, so if one tweaks the len, it will give invalid output hash.
    fn prove_from_array<F: RichField>(
        pw: &mut PartialWitness<F>,
        wires: &KeccakWires<N>,
        unpadded_len: usize,
    ) {
        let diff = compute_padding_size(unpadded_len);
        pw.set_target(wires.diff, F::from_canonical_usize(diff));
    }
}

#[cfg(test)]
mod test {
    use super::{KeccakCircuit, KeccakWires};
    use crate::{
        array::{Array, VectorWire},
        circuit::{test::test_simple_circuit, PCDCircuit, ProofOrDummyTarget, UserCircuit},
        keccak::{compute_padding_size, compute_size_with_padding, PACKED_HASH_LEN},
        utils::{keccak256, read_le_u32},
    };
    use core::array::from_fn as create_array;
    use plonky2::{
        field::extension::Extendable,
        hash::hash_types::RichField,
        iop::witness::{PartialWitness, WitnessWrite},
        plonk::{
            circuit_builder::CircuitBuilder,
            config::{GenericConfig, PoseidonGoldilocksConfig},
        },
    };
    use rand::{thread_rng, Rng};

    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    impl<F, const D: usize, const N: usize> UserCircuit<F, D> for KeccakCircuit<N>
    where
        F: RichField + Extendable<D>,
        [(); N / 4]:,
    {
        type Wires = KeccakWires<N>;

        fn build(b: &mut CircuitBuilder<F, D>) -> Self::Wires {
            let input_array = VectorWire::<N>::new(b);
            Self::hash_vector(b, &input_array)
        }

        fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
            wires
                .input_array
                .arr
                .assign(pw, &create_array(|i| F::from_canonical_u8(self.data[i])));
            pw.set_target(
                wires.input_array.real_len,
                F::from_canonical_usize(self.unpadded_len),
            );
            Self::prove_from_array(pw, wires, self.unpadded_len);
        }
    }
    impl<F, const D: usize, const BYTES: usize, const ARITY: usize> PCDCircuit<F, D, ARITY>
        for KeccakCircuit<BYTES>
    where
        [(); BYTES / 4]:,
        F: RichField + Extendable<D>,
    {
        fn build_recursive(
            b: &mut CircuitBuilder<F, D>,
            _: &[ProofOrDummyTarget<D>; ARITY],
        ) -> Self::Wires {
            let wires = <Self as UserCircuit<F, D>>::build(b);
            wires.output_array.register_as_public_input(b);
            wires
            // TODO: check the proof public input match what is in the hash node for example for MPT
        }
        fn base_inputs(&self) -> Vec<F> {
            // since we don't care about the public inputs of the first
            // proof (since we're not reading them , because we take array
            // to hash as witness)
            // 8 * u32 = 256 bits
            F::rand_vec(8)
        }
        fn num_io() -> usize {
            8
        }
    }

    #[test]
    fn test_keccak_output() {
        const SIZE: usize = 64;
        const PADDED_LEN: usize = compute_size_with_padding(SIZE);

        #[derive(Clone, Debug)]
        struct TestKeccak<const N: usize> {
            c: KeccakCircuit<N>,
            exp: Vec<u8>,
        }

        impl<F, const D: usize, const N: usize> UserCircuit<F, D> for TestKeccak<N>
        where
            F: RichField + Extendable<D>,
            [(); N / 4]:,
        {
            type Wires = KeccakWires<N>;

            fn build(b: &mut CircuitBuilder<F, D>) -> Self::Wires {
                let input_array = VectorWire::<N>::new(b);
                KeccakCircuit::hash_vector(b, &input_array)
            }

            fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
                wires
                    .input_array
                    .arr
                    .assign(pw, &create_array(|i| F::from_canonical_u8(self.c.data[i])));
                pw.set_target(
                    wires.input_array.real_len,
                    F::from_canonical_usize(self.c.unpadded_len),
                );
                KeccakCircuit::prove_from_array(pw, wires, self.c.unpadded_len);
                let exp_u32 = self
                    .exp
                    .chunks(4)
                    .map(|c| F::from_canonical_u32(read_le_u32(&mut c.clone())))
                    .collect::<Vec<_>>();

                wires.output_array.assign(pw, &exp_u32.try_into().unwrap());
            }
        }

        let mut rng = thread_rng();
        let mut arr = [0u8; SIZE];
        rng.fill(&mut arr[..SIZE]);
        let exp = keccak256(&arr[..SIZE]);
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        let circuit = TestKeccak::<PADDED_LEN> {
            c: KeccakCircuit::<PADDED_LEN>::new(arr.to_vec()).unwrap(),
            exp,
        };
        test_simple_circuit::<F, D, C, _>(circuit);
    }
}
