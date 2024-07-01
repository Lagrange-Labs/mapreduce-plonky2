use itertools::Itertools;
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{RichField, NUM_HASH_OUT_ELTS},
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
    poseidon::{H, P},
    utils::{less_than, read_le_u32, Endianness, PackerTarget},
    D, F,
};

use plonky2::hash::hashing::PlonkyPermutation;
use plonky2::plonk::config::AlgebraicHasher;

// maybe swap the first two elements and hashes the rest after with it
pub fn hash_maybe_first(
    c: &mut CircuitBuilder<F, D>,
    should_swap: BoolTarget,
    elem1: [Target; NUM_HASH_OUT_ELTS],
    elem2: [Target; NUM_HASH_OUT_ELTS],
    rest: &[Target],
) -> Vec<Target> {
    let zero = c.zero();
    let mut state = P::new(core::iter::repeat(zero));
    // absorb the first two inputs and do the swap
    state.set_from_slice(&[elem1, elem2].concat(), 0);
    state = H::permute_swapped(state, should_swap, c);
    // Absorb all the rest of the input chunks.
    let t = c._false();
    for input_chunk in rest.chunks(P::RATE) {
        state.set_from_slice(input_chunk, 0);
        state = H::permute_swapped(state, t, c);
    }

    // Squeeze until we have the desired number of outputs.
    let mut outputs = Vec::new();
    loop {
        for &item in state.squeeze() {
            outputs.push(item);
            if outputs.len() == NUM_HASH_OUT_ELTS {
                return outputs;
            }
        }
        state.permute();
    }
}
// TODO: is this used?
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

// TODO: is this used?
pub(crate) fn hash_array<F: RichField + Extendable<D>, const D: usize>(
    b: &mut CircuitBuilder<F, D>,
    pw: &mut PartialWitness<F>,
    node: &[Target],       // assume constant size : TODO make it const generic
    length_target: Target, // the size of the data inside this fixed size array
    length: usize,         // could maybe be done with a generator but simpler this way
) -> Vec<Target> {
    let total_len = node.len();
    // the computation of the padding length can be done outside the circuit
    // because the important thing is that we prove in crcuit (a) we did some padding
    // starting from the end of the message and (b) that padded array is transformed
    // into u32 array correctly.
    // We don't care if the _padding length_ if done incorrectly,
    // because the hash output will be incorrect because hash computation is constrained.
    // If the prover gave a incorrect length_target, that means either the data buffer
    // will be changed, OR the the padding "buffer" will be changed from what is expected
    // -> in both cases, the resulting hash will be different.
    // (a) is necessary to allow the circuit to take as witness this length_target such
    // that we can _directly_ lookup the data that is interesting for us _without_ passing
    // through the expensive RLP decoding steps. To do this, we need to make sure, the prover
    // can NOT give a target_length value which points to an index > to where we actually
    // start padding the data. Otherwise, target_length could point to _any_ byte after
    // the end of the data slice up to the end of the fixed size array.
    let input_len_bits = length * 8; // only pad the data that is inside the fixed buffer
    let num_actual_blocks = 1 + input_len_bits / KECCAK256_R;
    let padded_len_bits = num_actual_blocks * KECCAK256_R;
    // reason why ^: this is annoying to do in circuit.
    let num_bytes = ceil_div_usize(padded_len_bits, 8);
    let diff = num_bytes - length;
    // we need to make sure that there is enough data len to fit the padding inside
    assert!(
        length + diff <= total_len,
        "not enough data to fit padding: (data) {}+{} (padding) > {}",
        length,
        diff,
        total_len
    );

    let diff_target = b.add_virtual_target();
    pw.set_target(diff_target, F::from_canonical_usize(diff));
    let end_padding = b.add(length_target, diff_target);
    let one = b.one();
    let end_padding = b.sub(end_padding, one); // inclusive range
                                               // little endian so we start padding from the end of the byte
    let single_pad = b.constant(F::from_canonical_usize(0x81)); // 1000 0001
    let begin_pad = b.constant(F::from_canonical_usize(0x01)); // 0000 0001
    let end_pad = b.constant(F::from_canonical_usize(0x80)); // 1000 0000
                                                             // TODO : make that const generic
    let padded_node = node
        .iter()
        .enumerate()
        .map(|(i, byte)| {
            let i_target = b.constant(F::from_canonical_usize(i));
            // condition if we are within the data range ==> i < length
            let is_data = less_than(b, i_target, length_target, 32);
            // condition if we start the padding ==> i == length
            let is_start_padding = b.is_equal(i_target, length_target);
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

    // NOTE we don't pad anymore because we enforce that the resulting length is already a multiple
    // of 4 so it will fit the conversion to u32 and circuit vk would stay the same for different
    // data length
    assert!(total_len % 4 == 0);

    // convert padded node to u32
    let node_u32_target: Vec<U32Target> = padded_node.pack(b, Endianness::Little);

    // fixed size block delimitation: this is where we tell the hash function gadget
    // to only look at a certain portion of our data, each bool says if the hash function
    // will update its state for this block or not.
    let rate_bytes = b.constant(F::from_canonical_usize(KECCAK256_R / 8));
    let end_padding_offset = b.add(end_padding, one);
    let nb_blocks = b.div(end_padding_offset, rate_bytes);
    // - 1 because keccak always take first block so we don't count it
    let nb_actual_blocks = b.sub(nb_blocks, one);
    let total_num_blocks = total_len / (KECCAK256_R / 8) - 1;
    let blocks = (0..total_num_blocks)
        .map(|i| {
            let i_target = b.constant(F::from_canonical_usize(i));
            less_than(b, i_target, nb_actual_blocks, 8)
        })
        .collect::<Vec<_>>();

    let hash_target = HashInputTarget {
        input: BigUintTarget {
            limbs: node_u32_target,
        },
        //input_bits: padded_len_bits,
        input_bits: 0,
        blocks,
    };

    let hash_output = b.hash_keccak256(&hash_target);
    hash_output
        .limbs
        .iter()
        .map(|limb| limb.0)
        .collect::<Vec<_>>()
}

#[cfg(test)]
mod test {
    use crate::C;
    use plonky2::field::types::Sample;
    use plonky2::hash::hashing::hash_n_to_hash_no_pad;

    use plonky2::plonk::config::Hasher;
    use plonky2::{
        hash::hash_types::NUM_HASH_OUT_ELTS,
        iop::{
            target::{BoolTarget, Target},
            witness::WitnessWrite,
        },
        plonk::circuit_builder::CircuitBuilder,
    };

    use crate::{CHasher, D, F};
    use mp2_test::circuit::{run_circuit, UserCircuit};

    const REST: usize = 7;
    #[derive(Debug, Clone)]
    struct TestPartialSwap {
        elem1: Vec<F>,
        elem2: Vec<F>,
        should_swap: bool,
        rest: Vec<F>,
    }

    impl UserCircuit<F, D> for TestPartialSwap {
        type Wires = (Vec<Target>, Vec<Target>, BoolTarget, Vec<Target>);

        fn build(c: &mut CircuitBuilder<F, D>) -> Self::Wires {
            let elem1 = c.add_virtual_targets(NUM_HASH_OUT_ELTS);
            let elem2 = c.add_virtual_targets(NUM_HASH_OUT_ELTS);
            let cond = c.add_virtual_bool_target_safe();
            let rest = c.add_virtual_targets(REST);
            let hash = super::hash_maybe_first(
                c,
                cond,
                elem1.clone().try_into().unwrap(),
                elem2.clone().try_into().unwrap(),
                &rest,
            );
            c.register_public_inputs(&hash);
            (elem1, elem2, cond, rest)
        }

        fn prove(&self, pw: &mut plonky2::iop::witness::PartialWitness<F>, wires: &Self::Wires) {
            pw.set_target_arr(&wires.0, &self.elem1);
            pw.set_target_arr(&wires.1, &self.elem2);
            pw.set_bool_target(wires.2, self.should_swap);
            pw.set_target_arr(&wires.3, &self.rest);
        }
    }

    #[test]
    fn test_partial_swap() {
        let elem1 = (0..NUM_HASH_OUT_ELTS)
            .map(|_| F::rand())
            .collect::<Vec<_>>();
        let elem2 = (0..NUM_HASH_OUT_ELTS)
            .map(|_| F::rand())
            .collect::<Vec<_>>();
        let rest = (0..REST).map(|_| F::rand()).collect::<Vec<_>>();
        for should_swap in [true, false] {
            let circuit = TestPartialSwap {
                elem1: elem1.clone(),
                elem2: elem2.clone(),
                should_swap,
                rest: rest.clone(),
            };
            let proof = run_circuit::<F, D, C, _>(circuit);
            let pi = proof.public_inputs;
            // do it outside circuit
            let tuple = match should_swap {
                false => [elem1.clone(), elem2.clone()].concat(),
                true => [elem2.clone(), elem1.clone()].concat(),
            };
            let inputs = tuple.iter().chain(rest.iter()).cloned().collect::<Vec<_>>();
            let hash = hash_n_to_hash_no_pad::<F, <CHasher as Hasher<F>>::Permutation>(&inputs);
            assert_eq!(&hash.elements.as_slice(), &pi.as_slice());
        }
    }
}
