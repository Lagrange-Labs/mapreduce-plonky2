use anyhow::{ensure, Result};
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::{
        target::Target,
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
use serde::{Deserialize, Serialize};

use crate::{
    array::{Array, Vector, VectorWire},
    utils::{convert_u8_targets_to_u32, keccak256, less_than},
};

/// Length of a hash in bytes.
pub const HASH_LEN: usize = 32;
/// Length of a hash in U32
pub const PACKED_HASH_LEN: usize = HASH_LEN / 4;

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

/// Represents the output of the keccak hash function. This output
/// is in a packed representation where bytes are packed into
/// 32bits.
pub type OutputHash = Array<U32Target, PACKED_HASH_LEN>;

/// Represents the output of the keccak hash function. This output
/// is in a byte representation.
pub type OutputByteHash = Array<Target, HASH_LEN>;

/// Circuit able to hash any arrays of bytes of dynamic sizes as long as its
/// padded version length is less than N. In other words, N is the maximal size
/// of the array + padding to hash.
#[derive(Clone, Debug)]
pub struct KeccakCircuit<const N: usize> {
    data: Vec<u8>,
}
/// Wires containing the output of the hash function as well as the intermediate
/// wires created. It requires assigning during proving time because of a small
/// computation done outside the circuit that requires the original input data.
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct KeccakWires<const N: usize> {
    input_array: VectorWire<Target, N>,
    diff: Target,
    // 256/u32 = 8
    pub output_array: OutputHash,
}
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct ByteKeccakWires<const N: usize> {
    keccak: KeccakWires<N>,
    pub output: OutputByteHash,
}

impl<const N: usize> KeccakCircuit<N> {
    pub fn new(data: Vec<u8>) -> Result<Self> {
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

        Ok(Self { data })
    }

    /// Takes an array which is _already_ at the right padded length.
    /// The circuit fills the padding part and hash it.
    pub fn hash_vector<F: RichField + Extendable<D>, const D: usize>(
        b: &mut CircuitBuilder<F, D>,
        a: &VectorWire<Target, N>,
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
        let node_u32_target: Vec<U32Target> = convert_u8_targets_to_u32(b, &padded_node);

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
            input_array: a.clone(),
            diff: diff_target,
            // TODO: this is fixed length should be able to use const generics
            output_array: OutputHash::try_from(hash_output.limbs).unwrap(),
        }
    }

    /// hash_to_bytes hashes the vector as usual but also returns an
    /// output array which is in bytes. This is useful to compare things
    /// with an expected byte location in some nodes or to re-use in a
    /// subsequent hashing operation etc.
    /// WARNING: if the output is used in a subsequent hashing operation,
    /// then no need to range check the node output. If it is needed for
    /// other purposes, like comparing with a given hash, then the output
    /// _needs_ to be range checked to be bytes.
    pub fn hash_to_bytes<F: RichField + Extendable<D>, const D: usize>(
        b: &mut CircuitBuilder<F, D>,
        a: &VectorWire<Target, N>,
    ) -> ByteKeccakWires<N> {
        let tru = b._true();
        let wires = Self::hash_vector(b, a);
        let hash_bytes = Array::<Target, HASH_LEN>::new(b);
        let packed_hash = Array {
            arr: convert_u8_targets_to_u32(b, &hash_bytes.arr)
                .try_into()
                .unwrap(),
        };
        let t = packed_hash.equals(b, &wires.output_array);
        b.connect(tru.target, t.target);
        ByteKeccakWires::<N> {
            keccak: wires,
            output: hash_bytes,
        }
    }

    /// This
    /// Usually the input data is already assigned in other places of our circuits.
    /// This method takes the data and aHowever, we do need the
    /// unpadded length to correctly compute the padding currently.
    /// NOTE: we could remove this requirement but it would mean computing the
    /// padding size in circuit, which is annoying. Computing off circuit is
    /// usually secure in our cases because we use it to check consistency with
    /// a known hash, so if one tweaks the len, it will give invalid output hash.
    pub fn assign<F: RichField>(
        pw: &mut PartialWitness<F>,
        wires: &KeccakWires<N>,
        data: &InputData<u8, N>,
    ) {
        if let InputData::NonAssigned(vector) = data {
            wires.input_array.assign(pw, &vector);
        }
        let diff = compute_padding_size(data.real_len());
        pw.set_target(wires.diff, F::from_canonical_usize(diff));
    }

    /// TODO: naming not great. Probably worth refactoring on its own gadget
    pub fn assign_byte_keccak<F: RichField>(
        pw: &mut PartialWitness<F>,
        wires: &ByteKeccakWires<N>,
        data: &InputData<u8, N>,
    ) {
        Self::assign(pw, &wires.keccak, data);
        let expected_hash = match data {
            InputData::Assigned(a) => keccak256(&a.arr[0..a.real_len]),
            InputData::NonAssigned(a) => keccak256(&a.arr[0..a.real_len]),
        };
        wires
            .output
            .assign_bytes(pw, &expected_hash.try_into().unwrap());
    }
}

/// InputData holds the information if the input data wire is already assigned or not.
/// Usually in most cases the input data is already assigned in other places of our circuits.
/// For some cases like only hashing or bench or tests, we need to assign the data to the
/// wires still.
pub enum InputData<'a, F, const N: usize> {
    /// During assignement time (proving time), keccak circuit assumes the data
    /// is already assigned to the respective input wires. However, it still needs
    /// to assign the padding size difference, an internal keccak wire.
    Assigned(&'a Vector<F, N>),
    /// In this mode, keccak circuit will assign both the data and the padding difference
    /// size. Useful in case the input data is not created elsewhere.
    NonAssigned(&'a Vector<F, N>),
}

impl<'a, F, const N: usize> InputData<'a, F, N> {
    pub fn real_len(&self) -> usize {
        match self {
            InputData::Assigned(v) => v.real_len,
            InputData::NonAssigned(v) => v.real_len,
        }
    }
}

#[cfg(test)]
mod test {
    use super::{InputData, KeccakCircuit, KeccakWires};
    use crate::{
        array::{Array, Vector, VectorWire},
        circuit::{test::run_circuit, PCDCircuit, ProofOrDummyTarget, UserCircuit},
        keccak::{compute_size_with_padding, ByteKeccakWires, OutputByteHash, HASH_LEN},
        utils::{keccak256, read_le_u32},
    };
    use plonky2::{
        field::extension::Extendable,
        hash::hash_types::RichField,
        iop::{target::Target, witness::PartialWitness},
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
            let input_array = VectorWire::<Target, N>::new(b);
            Self::hash_vector(b, &input_array)
        }

        fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
            let vector = Vector::<u8, N>::from_vec(&self.data).unwrap();
            KeccakCircuit::<N>::assign(pw, wires, &InputData::NonAssigned(&vector));
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
                let input_array = VectorWire::<Target, N>::new(b);
                KeccakCircuit::hash_vector(b, &input_array)
            }

            fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
                let vec = Vector::<u8, N>::from_vec(&self.c.data).unwrap();
                KeccakCircuit::<N>::assign(pw, wires, &InputData::NonAssigned(&vec));
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
        run_circuit::<F, D, C, _>(circuit);
    }

    #[test]
    fn test_keccak_bytes_output() {
        const SIZE: usize = 45;
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
            type Wires = (ByteKeccakWires<N>, Array<Target, HASH_LEN>);

            fn build(b: &mut CircuitBuilder<F, D>) -> Self::Wires {
                let input_array = VectorWire::<Target, N>::new(b);
                let wires = KeccakCircuit::hash_to_bytes(b, &input_array);
                let exp_output = OutputByteHash::new(b);
                let t = exp_output.equals(b, &wires.output);
                let tru = b._true();
                b.connect(tru.target, t.target);
                (wires, exp_output)
            }

            fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
                KeccakCircuit::<N>::assign_byte_keccak(
                    pw,
                    &wires.0,
                    &InputData::NonAssigned(&Vector::<u8, N>::from_vec(&self.c.data).unwrap()),
                );
                wires
                    .1
                    .assign_bytes(pw, &self.exp.clone().try_into().unwrap());
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
        run_circuit::<F, D, C, _>(circuit);
    }
}
