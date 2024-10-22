use crate::array::{Array, VectorWire};

use crate::utils::{greater_than_or_equal_to_unsafe, less_than, less_than_unsafe, num_to_bits};
use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::plonk::circuit_builder::CircuitBuilder;

/// The maximum number of bytes the length of data can take.
/// NOTE: However, this is set arbitrarily because there can be up 7 bytes
/// expressing the length of the data according to RLP specs for long lists
/// size = prefix - 248 (where prefix is a single byte so can go up to 255)
/// 2 is the usual in practice for eth MPT related data.
/// nikko: verify that assumption.
const MAX_LEN_BYTES: usize = 2;

/// Maximum size a key can have inside a MPT node.
/// 33 bytes because key is compacted encoded, so it can add up to 1 byte more.
const MAX_ENC_KEY_LEN: usize = 33;
/// Simply the maximum number of nibbles a key can have.
pub const MAX_KEY_NIBBLE_LEN: usize = 64;

pub const MAX_ITEMS_IN_LIST: usize = 17;

#[derive(Clone, Copy, Debug)]
pub struct RlpHeader {
    // Length of the actual data
    pub len: Target,
    // offset from which to read the data from the array
    pub offset: Target,
    // whether it's a string or a list
    pub data_type: Target,
}

/// Contains the header information for all the elements in a list.
#[derive(Clone, Debug)]
pub struct RlpList<const N: usize> {
    pub offset: Array<Target, N>,
    pub len: Array<Target, N>,
    pub data_type: Array<Target, N>,
    pub num_fields: Target,
}

impl<const N: usize> RlpList<N> {
    pub fn select<F: RichField + Extendable<D>, const D: usize>(
        &self,
        b: &mut CircuitBuilder<F, D>,
        at: Target,
    ) -> RlpHeader {
        let offset = self.offset.value_at(b, at);
        let len = self.len.value_at(b, at);
        let dtype = self.data_type.value_at(b, at);
        RlpHeader {
            len,
            offset,
            data_type: dtype,
        }
    }
}
pub fn decode_compact_encoding<F: RichField + Extendable<D>, const D: usize, const N: usize>(
    b: &mut CircuitBuilder<F, D>,
    input: &Array<Target, N>,
    key_header: &RlpHeader,
) -> (VectorWire<Target, MAX_KEY_NIBBLE_LEN>, BoolTarget) {
    let zero = b.zero();
    let two = b.two();
    let first_byte = input.value_at(b, key_header.offset);
    let (most_bits, least_bits) = b.split_low_high(first_byte, 4, 8);
    // little endian
    let mut prev_nibbles = (least_bits, most_bits);

    let mut cur_nibbles: (Target, Target);
    let mut nibbles: [Target; MAX_KEY_NIBBLE_LEN] = [b.zero(); MAX_KEY_NIBBLE_LEN];

    let first_nibble = prev_nibbles.0;
    let first_nibble_as_bits = num_to_bits(b, 4, first_nibble);
    let parity = first_nibble_as_bits[0].target;
    // TODO: why this doesn't work always !!
    //let parity = b.split_le(first_nibble, 2)[0].target;

    // if parity is 1 => odd length => (1 - p) * next_nibble = 0
    //   -> in this case, no need to add another nibble (since the rest of key + 1 == even now)
    // if parity is 0 => even length => (1 - p) * next_nibble = next_nibble
    //   -> in this case, need to add another nibble, which is supposed to be zero
    //   -> i.e. next_nibble == 0
    let res_multi = b.mul_sub(parity, prev_nibbles.1, prev_nibbles.1);
    let cond = b.is_equal(res_multi, zero);

    // -1 because first nibble is the HP information, and the following loop
    // analyzes pairs of consecutive nibbles, so the second nibble will be seen
    // during the first iteration of this loop.
    let one = b.one();
    let mut i_offset = key_header.offset;
    for i in 0..MAX_ENC_KEY_LEN - 1 {
        i_offset = b.add(i_offset, one);
        // look now at the encoded path
        let x = input.value_at(b, i_offset);
        // next nibble in little endian
        cur_nibbles = {
            let (most_bits, least_bits) = b.split_low_high(x, 4, 8);
            (least_bits, most_bits)
        };

        // nibble[2*i] = parity*prev_nibbles.1 + (1 - parity)*cur_nibbles.0;
        // => if parity == 1, we take the previous last nibble, because that's the next in line
        // => if parity == 0, we take lowest significant nibble because the previous last nibble is
        //                    the special "0" nibble to make overall length even
        // when developped, expression equals p*(prev.1 - curr.0) + curr.0
        let diff = b.sub(prev_nibbles.1, cur_nibbles.0);
        nibbles[2 * i] = b.mul_add(parity, diff, cur_nibbles.0);

        // nibble[2*i + 1] = parity*cur_nibbles.0 + (1 - parity)*cur_nibbles.1;
        // => if parity == 1, take lowest significant nibble as successor of previous.highest_nibble
        // => if parity == 0, take highest significant nibble as success of current.lowest_nibble
        // when developped, expression equals p*(curr.0 - curr.1) + curr.1
        let diff = b.sub(cur_nibbles.0, cur_nibbles.1);
        nibbles[2 * i + 1] = b.mul_add(parity, diff, cur_nibbles.1);

        prev_nibbles = cur_nibbles;
    }

    // 2 * length + parity - 2
    // - 2*length because it's the length in nibble not in bytes
    // - parity - 2 means that we take out only one nibble when len is odd, because
    //   this is the nibble telling us that len is odd.
    //   In case len is even, RLP adds another 0 nibble so we take out 2 nibbles
    //   from the length
    let length_in_nibble = b.mul(two, key_header.len);
    let pm2 = b.sub(parity, two);
    let key_len: Target = b.add(length_in_nibble, pm2);

    (
        VectorWire {
            arr: Array::from_array(nibbles),
            real_len: key_len,
        },
        cond,
    )
}
// Returns the length from the RLP prefix in case of long string or long list
// data is the full data starting from the "type" byte of RLP encoding
// data length needs to be a power of 2
// non power of 2 lengths are padded leading zeros
pub fn data_len<F: RichField + Extendable<D>, const D: usize>(
    b: &mut CircuitBuilder<F, D>,
    data: &[Target],
    len_of_len: Target,
    offset: Target,
) -> Target {
    let mut res = b.zero();
    let one = b.one();
    let const_256 = b.constant(F::from_canonical_u64(256));

    for i in 0..MAX_LEN_BYTES {
        let i_tgt = b.constant(F::from_canonical_u8(i as u8));
        // make sure we don't read out more than the actual len
        let len_of_len_pred = less_than_unsafe(b, i_tgt, len_of_len, 8);
        // this part offset i to read from the array
        let i_offset = b.add(i_tgt, offset);
        // i+1 because first byte is the RLP type
        let i_plus_1 = b.add(i_offset, one);
        let item = quin_selector(b, data, i_plus_1);

        // shift result by one byte
        let multiplicand = b.mul(const_256, res);
        // res += 2^i * arr[i+1] only if we're in right range
        let sum = b.add(multiplicand, item);
        let multiplicand_2 = b.mul(sum, len_of_len_pred.target);

        let not_len_of_len_pred_target = b.not(len_of_len_pred);
        let multiplicand_3 = b.mul(not_len_of_len_pred_target.target, res);
        // res = (2^i * arr[i+1]) * (i < len_len) + res * (i >= len_len)
        res = b.add(multiplicand_2, multiplicand_3);
    }

    res
}
// We read the RLP header but knowing it is a value that is always <55bytes long
// we can hardcode the type of RLP header it is and directly get the real number len
// in this case, the header marker is 0x80 that we can directly take out from first byte
pub fn short_string_len<F: RichField + Extendable<D>, const D: usize>(
    b: &mut CircuitBuilder<F, D>,
    header: &Target,
) -> Target {
    let byte_80 = b.constant(F::from_canonical_usize(128));
    b.sub(*header, byte_80)
}
/// It returns the RLP header information starting at data[offset]. The header.offset
/// is absolute from the 0-index of data (not from the `offset` index)
pub fn decode_header<F: RichField + Extendable<D>, const D: usize>(
    b: &mut CircuitBuilder<F, D>,
    data: &[Target],
    offset: Target,
) -> RlpHeader {
    let one = b.one();
    let zero = b.zero();

    let prefix = quin_selector(b, data, offset);

    let byte_80 = b.constant(F::from_canonical_usize(128));
    let byte_b7 = b.constant(F::from_canonical_usize(183));
    let byte_b8 = b.constant(F::from_canonical_usize(184));
    let byte_c0 = b.constant(F::from_canonical_usize(192));
    let byte_f7 = b.constant(F::from_canonical_usize(247));
    let byte_f8 = b.constant(F::from_canonical_usize(248));

    let prefix_less_0x80 = less_than(b, prefix, byte_80, 8);
    let prefix_less_0xb8 = less_than(b, prefix, byte_b8, 8);
    let prefix_less_0xc0 = less_than(b, prefix, byte_c0, 8);
    let prefix_less_0xf8 = less_than(b, prefix, byte_f8, 8);

    // This part determines at which offset should we read the data
    let prefix_plus_one = b.add(prefix, one);
    // if it's in [0xf8,0xff] -> long list, offset to read the data from arr[prefix-0xf7+1:]
    let prefix_plus_one_minus_f7 = b.sub(prefix_plus_one, byte_f7);
    // select1 = if prefix < 0xf8 { 1 } else { prefix + 1 - 0xf7 }
    // i.e. if it's in [0xc0,0xf7] -> short list, offset of 1 cause length already encoded in first byte
    // nikko XXX TODO: We should handle the case of an empty list, 0xc0
    let select_1 = b._if(prefix_less_0xf8, one, prefix_plus_one_minus_f7);
    let prefix_plus_one_minus_b7 = b.sub(prefix_plus_one, byte_b7);
    // select2 = if prefix < 0xc0 { prefix + 1 - 0xb7 } else  { select1 }
    // i.e. if it's in [0xb8,0xbf] -> long string, and we read data from arr[prefix-0xb7+1:]
    let select_2 = b._if(prefix_less_0xc0, prefix_plus_one_minus_b7, select_1);
    // select3 = if prefix < 0xb8 { 1 } else  { select2 }
    // i.e. if it's in [0x80,0xb8] -> short string, 1 offset because length already encoded in first byte
    let select_3 = b._if(prefix_less_0xb8, one, select_2);
    // offset = if prefix < 0x80 { 0 } else  { select3 }
    // i.e. if it's a single byte value, no offset we directly read value
    let offset_data = b._if(prefix_less_0x80, zero, select_3);

    // read the lenght encoded depending on the type
    let prefix_minus_f7 = b.sub(prefix, byte_f7);
    let long_list_len = data_len(b, data, prefix_minus_f7, offset);
    let short_list_len = b.sub(prefix, byte_c0);
    let select_1 = b._if(prefix_less_0xf8, short_list_len, long_list_len);
    let prefix_minus_b7 = b.sub(prefix, byte_b7);
    let long_str_len = data_len(b, data, prefix_minus_b7, offset);
    let select_2 = b._if(prefix_less_0xc0, long_str_len, select_1);
    let short_str_len = b.sub(prefix, byte_80);
    let select_3 = b._if(prefix_less_0xb8, short_str_len, select_2);
    let len = b._if(prefix_less_0x80, one, select_3);

    let data_type = greater_than_or_equal_to_unsafe(b, prefix, byte_c0, 8).target;

    let final_offset = b.add(offset, offset_data);
    RlpHeader {
        len,
        offset: final_offset,
        data_type,
    }
}

/// Decodes the header of the list, and then decodes the first N items of the list.
///
/// The offsets decoded in the returned list are starting from the 0-index of `data`
/// not from the `offset` index.
/// If N is less than the actual number of items, then the number of fields will be N.
/// Otherwise, the number of fields returned is determined by the header the RLP list.
pub fn decode_fixed_list<F: RichField + Extendable<D>, const D: usize, const N: usize>(
    b: &mut CircuitBuilder<F, D>,
    data: &[Target],
    data_offset: Target,
) -> RlpList<N> {
    let zero = b.zero();

    let mut num_fields = zero;
    let mut dec_off = [zero; N];
    let mut dec_len = [zero; N];
    let mut dec_type = [zero; N];

    let list_header = decode_header(b, data, data_offset);
    let mut offset = list_header.offset;
    // end_idx starts at `data_offset` and  includes the
    // header byte + potential len_len bytes + payload len
    let end_idx = b.add(list_header.offset, list_header.len);
    // decode each headers of each items ofthe list
    // remember in a list each item of the list is RLP encoded
    for i in 0..N {
        // stop when you've looked at exactly the same number of  bytes than
        // the RLP list header indicates
        let at_the_end = b.is_equal(offset, end_idx);
        // offset always equals offset after we've reached end_idx so before_the_end
        // is only true when we haven't reached the end yet
        let before_the_end = b.not(at_the_end);

        // read the header starting from the offset
        let header = decode_header(b, data, offset);
        let new_offset = b.add(header.offset, header.len);

        dec_off[i] = header.offset;
        dec_len[i] = header.len;
        dec_type[i] = header.data_type;

        // move offset to the next field in the list
        // updates offset such that is is either < end_idx or after that
        // always equals to end_idx
        let diff = b.sub(new_offset, offset);
        offset = b.mul_add(before_the_end.target, diff, offset);
        num_fields = b.add(num_fields, before_the_end.target);
    }

    RlpList {
        offset: Array { arr: dec_off },
        len: Array { arr: dec_len },
        data_type: Array { arr: dec_type },
        num_fields,
    }
}

/// Returns an element of the array at index n
/// TODO: replace with random_access from plonky2 and compare constraints
pub fn quin_selector<F: RichField + Extendable<D>, const D: usize>(
    b: &mut CircuitBuilder<F, D>,
    arr: &[Target],
    n: Target,
) -> Target {
    let mut nums: Vec<Target> = vec![];

    for (i, el) in arr.iter().enumerate() {
        let i_target = b.constant(F::from_canonical_usize(i));
        let is_eq = b.is_equal(i_target, n);
        // (i == n (idx) ) * element
        let product = b.mul(is_eq.target, *el);
        nums.push(product);
    }
    // SUM_i (i == n (idx) ) * element
    // -> sum = element
    calculate_total(b, &nums)
}

fn calculate_total<F: RichField + Extendable<D>, const D: usize>(
    b: &mut CircuitBuilder<F, D>,
    arr: &[Target],
) -> Target {
    b.add_many(arr)
}

#[cfg(test)]
mod tests {
    use std::array::from_fn as create_array;

    use anyhow::Result;

    use eth_trie::{Nibbles, Trie};
    use mp2_test::mpt_sequential::generate_random_storage_mpt;
    use plonky2::field::extension::Extendable;
    use plonky2::field::types::Field;
    use plonky2::hash::hash_types::RichField;
    use plonky2::iop::target::Target;
    use plonky2::iop::witness::PartialWitness;
    use plonky2::plonk::circuit_builder::CircuitBuilder;
    use plonky2::plonk::circuit_data::CircuitConfig;

    use crate::array::Array;
    use crate::rlp::{
        decode_compact_encoding, decode_fixed_list, decode_header, RlpHeader, MAX_ENC_KEY_LEN,
        MAX_LEN_BYTES,
    };
    use crate::utils::{keccak256, less_than_or_equal_to, IntTargetWriter};
    use crate::{C, D, F};

    use super::quin_selector;

    /// Returns an array of length `M` from the array `arr` starting at index `offset`
    pub fn extract_array<F: RichField + Extendable<D>, const D: usize, const M: usize>(
        b: &mut CircuitBuilder<F, D>,
        arr: &[Target],
        offset: Target,
    ) -> [Target; M] {
        let mut out: [Target; M] = [arr[0]; M];

        let m = b.constant(F::from_canonical_usize(M));
        let upper_bound = b.add(offset, m);
        for (i, out_val) in out.iter_mut().enumerate().take(M) {
            let i_target = b.constant(F::from_canonical_usize(i));
            let i_plus_n_target = b.add(offset, i_target);

            // nikko: ((i + offset) <= n + M)
            let lt = less_than_or_equal_to(b, i_plus_n_target, upper_bound, 32);
            // ((i+n) <= n+M) * (i+n)
            let j = b.mul(lt.target, i_plus_n_target);

            // out_val = arr[((i+n)<=n+M) * (i+n)]
            *out_val = quin_selector(b, arr, j);
        }

        out
    }

    fn visit_branch_node(node: &[u8]) -> Vec<(usize, usize)> {
        println!("[+] Visiting branch node of {} bytes", node.len());
        let root_rlp = rlp::Rlp::new(node);
        let root_nb_items = root_rlp.item_count().unwrap();
        let mut inc_index = root_rlp.payload_info().unwrap().header_len;
        (0..root_nb_items)
            .map(|nibble| {
                let sub_rlp = root_rlp.at(nibble).unwrap();
                let sub_header = sub_rlp.payload_info().unwrap();
                let sub_index = inc_index + sub_header.header_len;
                inc_index = sub_index + sub_header.value_len;
                println!(
                    "[+] Root nibble {} - index {} - value {}",
                    nibble,
                    sub_index,
                    hex::encode(sub_rlp.data().unwrap())
                );
                (nibble, sub_index)
            })
            .collect::<Vec<_>>()
    }
    #[test]
    fn test_branch_node_rlp_decoding() -> Result<()> {
        //let child = hex::decode("f85180a0d43c798529ffaaa2316f8adaaa27105dd0fb20dc97d250ad784386e0edaa97e1808080a0602346785e1ced15445758e363f43723de0d5e365cb4f483845988113f22f6ea8080808080808080808080").unwrap();
        //let root = hex::decode("f8f180a080a15846e63f90955f3492af55951f272302e08fa4360d13d25ead42ef1f8e1580a0103dad8651d136072de73a52b6c1e81afec60eeadcd971e88cbdd835f58523718080a0c7e63df28028e3906459eb3b7ea253bf7ef278f06b4e1705485cba52a42b33da8080a0a2fe320d0471b6eed27e651ba18be7c1cd36f4530c1931c2e2bfd8beed9044e980a03a613d04fd7bb29df0b0444d58118058d3107c2291c32476511969c85f98953e80a0e9acd2a316add27ea52dd4e844c78f041a89349eff4327e21a0b0f64f4aec234a0b34cd83dc3174901e6cc1a8f43de2866a247b6f769e49710de0b5c501032e50b8080").unwrap();
        let child = hex::decode("f843a02067c48d3958a3b9335247b9a6d430ecfd7ec47d2795b4094f779cda9f6700caa1a0f585f458b52f38dcab96f07d5cc6406dd4e8c8007f0ec9c6af3175e7886d8bc5").unwrap();
        let root = hex::decode("f851a0afd82fd956b6402e358eb2e18ed40295a4d819a3e473282f257b41d913f70476808080808080808080808080a0c63a5260ddf114504213daf4b15a236fd2d33726768f44e896487326f7c136f6808080").unwrap();
        println!("[+] Child hash {}", hex::encode(keccak256(&child)));
        let exp_offsets = visit_branch_node(&root);
        const N_ITEMS: usize = 17;
        let config = CircuitConfig::standard_recursion_config();
        let mut pw = PartialWitness::new();
        let mut b = CircuitBuilder::<F, D>::new(config);
        let node_t = b.add_virtual_targets(root.len());
        let zero = b.zero();
        let rlp_headers = decode_fixed_list::<_, _, N_ITEMS>(&mut b, &node_t, zero);
        let exp_nb_items = b.constant(F::from_canonical_usize(N_ITEMS));
        b.connect(rlp_headers.num_fields, exp_nb_items);

        // check each offsets
        for (nibble, offset) in exp_offsets {
            let nibble_t = b.constant(F::from_canonical_usize(nibble));
            let offset_t = b.constant(F::from_canonical_usize(offset));
            let header = rlp_headers.select(&mut b, nibble_t);
            b.connect(header.offset, offset_t);
        }
        let data = b.build::<C>();
        pw.set_int_targets(&node_t, &root);
        let proof = data.prove(pw)?;
        data.verify(proof)?;
        Ok(())
    }
    #[test]
    fn test_custom_rlp_list() -> Result<()> {
        let (mut trie, key) = generate_random_storage_mpt::<4, 32>();
        let mut proof = trie.get_proof(&key).unwrap();
        proof.reverse();
        let encoded_leaf = proof.first().unwrap();
        let leaf_list: Vec<Vec<u8>> = rlp::decode_list(encoded_leaf);
        assert!(leaf_list.len() == 2);
        let config = CircuitConfig::standard_recursion_config();
        let mut pw = PartialWitness::new();
        let mut b = CircuitBuilder::<F, D>::new(config);
        let rlp_targets = b.add_virtual_targets(encoded_leaf.len());
        let zero = b.zero();
        let two = b.two();

        let decoded_headers = decode_fixed_list::<_, _, 4>(&mut b, &rlp_targets, zero);
        b.connect(decoded_headers.num_fields, two);
        let data = b.build::<C>();
        pw.set_int_targets(&rlp_targets, encoded_leaf);
        let proof = data.prove(pw)?;
        data.verify(proof)?;
        Ok(())
    }
    #[test]
    fn test_decode_header_long_list() -> Result<()> {
        let n_items = 5;
        let data_len = 65;
        let data = (0..n_items)
            .map(|_| {
                (0..data_len)
                    .map(|_| rand::random::<u8>())
                    .collect::<Vec<u8>>()
            })
            .collect::<Vec<_>>();
        let rlp_data = rlp::encode_list::<Vec<u8>, _>(&data);
        let stream = rlp::Rlp::new(&rlp_data);
        let header = stream.payload_info().unwrap();
        let proto = stream.prototype().unwrap();
        match proto {
            rlp::Prototype::List(n) if n == n_items => {}
            _ => {
                panic!("not a good list")
            }
        }
        let header_len = header.header_len;
        let header0 = stream.at(0)?.payload_info()?;
        let h0_len = header0.header_len;
        let first_item = rlp::Rlp::new(&rlp_data[header_len..]);
        let first_item_header = first_item.payload_info()?;
        assert!(first_item_header.header_len == h0_len);
        assert!(first_item_header.value_len == header0.value_len);

        let config = CircuitConfig::standard_recursion_config();
        let mut pw = PartialWitness::new();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let rlp_data_tgt = builder.add_virtual_targets(rlp_data.len());
        pw.set_int_targets(&rlp_data_tgt, &rlp_data);
        let hlen_tgt = builder.constant(F::from_canonical_u32(header_len as u32));
        let vlen_tgt = builder.constant(F::from_canonical_u32(header.value_len as u32));
        let zero = builder.zero();
        let header_tgt = decode_header(&mut builder, &rlp_data_tgt, zero);
        // compare the header len outside circuit with inside circuit
        builder.connect(header_tgt.offset, hlen_tgt);
        // compare the header value len outside circuit with inside circuit
        builder.connect(header_tgt.len, vlen_tgt);

        // first item (header + value) starts directly after the first header
        let offset = header_tgt.offset;
        // decode the header of the first item in the list starting at the right position
        let h0 = decode_header(&mut builder, &rlp_data_tgt, offset);
        let h0len_tgt = builder.constant(F::from_canonical_u32(h0_len as u32));
        let v0len_tgt = builder.constant(F::from_canonical_u32(header0.value_len as u32));
        // since decode_header returns based off 0-index we need to shift expected header
        // header || header0 || v0 || ...
        // so h0offset (where v0 starts) is header len + header0 len
        let h0offset = builder.add(h0len_tgt, offset);
        // compare header of first item in list len outside circuit with inside circuit
        builder.connect(h0.offset, h0offset);
        // compare value len of first item in list outside circuit with inside circuit
        // note len doesn't change from offset so it's good
        builder.connect(h0.len, v0len_tgt);

        // check if decoding long list gives same result
        let list = decode_fixed_list::<F, D, 1>(&mut builder, &rlp_data_tgt, zero);
        builder.connect(h0offset, list.offset[0]);
        builder.connect(h0.len, list.len[0]);

        let data = builder.build::<C>();
        let proof = data.prove(pw)?;
        data.verify(proof)?;
        Ok(())
    }

    // TODO: replace these tests by deterministic tests by cr
    #[test]
    fn test_data_len() -> Result<()> {
        let config = CircuitConfig::standard_recursion_config();
        let pw = PartialWitness::new();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let data: Vec<Target> = [185, 4, 0]
            .iter()
            .map(|x| builder.constant(F::from_canonical_u64(*x)))
            .collect();
        let ret_target = builder.constant(F::from_canonical_u64(1024));

        let len_of_len = builder.constant(F::from_canonical_u64(2));
        let zero = builder.zero();
        let res = super::data_len(&mut builder, &data, len_of_len, zero);
        builder.connect(res, ret_target);

        builder.register_public_inputs(&data);
        builder.register_public_input(ret_target);

        let data = builder.build::<C>();
        let proof = data.prove(pw)?;
        data.verify(proof)
    }

    // TODO: replace these tests by deterministic tests by creating the data first and then
    // encoding in RLP and give that to circuit. Right now we just don't know what these vectors hold.
    #[test]
    fn test_decode_len() -> Result<()> {
        let config = CircuitConfig::standard_recursion_config();
        let pw = PartialWitness::new();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let zero = builder.zero();

        let data1: Vec<Target> = [130, 4, 0]
            .iter()
            .map(|x| builder.constant(F::from_canonical_u64(*x)))
            .collect();

        let rlp_header1 = RlpHeader {
            offset: builder.constant(F::from_canonical_usize(1)),
            len: builder.constant(F::from_canonical_usize(2)),
            data_type: builder.constant(F::from_canonical_usize(0)),
        };

        let res_rlp_header1 = super::decode_header(&mut builder, &data1, zero);

        // builder.connect(rlp_header.len, res_rlp_header.len);
        builder.connect(rlp_header1.offset, res_rlp_header1.offset);
        builder.connect(rlp_header1.data_type, res_rlp_header1.data_type);

        builder.register_public_inputs(&data1);
        builder.register_public_input(rlp_header1.offset);
        builder.register_public_input(rlp_header1.len);
        builder.register_public_input(rlp_header1.data_type);

        let data2: Vec<Target> = [
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
            251, 252, 253, 254, 255, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17,
            18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39,
            40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61,
            62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83,
            84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103,
            104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120,
            121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134, 135, 136, 137,
            138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149, 150, 151, 152, 153, 154,
            155, 156, 157, 158, 159, 160, 161, 162, 163, 164, 165, 166, 167, 168, 169, 170, 171,
            172, 173, 174, 175, 176, 177, 178, 179, 180, 181, 182, 183, 184, 185, 186, 187, 188,
            189, 190, 191, 192, 193, 194, 195, 196, 197, 198, 199, 200, 201, 202, 203, 204, 205,
            206, 207, 208, 209, 210, 211, 212, 213, 214, 215, 216, 217, 218, 219, 220, 221, 222,
            223, 224, 225, 226, 227, 228, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238, 239,
            240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251, 252, 253, 254, 255, 0, 1,
            2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
            26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47,
            48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69,
            70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91,
            92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110,
            111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127,
            128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144,
            145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161,
            162, 163, 164, 165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178,
            179, 180, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191, 192, 193, 194, 195,
            196, 197, 198, 199, 200, 201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211, 212,
            213, 214, 215, 216, 217, 218, 219, 220, 221, 222, 223, 224, 225, 226, 227, 228, 229,
            230, 231, 232, 233, 234, 235, 236, 237, 238, 239, 240, 241, 242, 243, 244, 245, 246,
            247, 248, 249, 250, 251, 252, 253, 254, 255, 0,
        ]
        .iter()
        .map(|x| builder.constant(F::from_canonical_u64(*x)))
        .collect();

        let rlp_header2 = RlpHeader {
            offset: builder.constant(F::from_canonical_usize(3)),
            len: builder.constant(F::from_canonical_usize(1024)),
            data_type: builder.constant(F::from_canonical_usize(0)),
        };

        let res_rlp_header2 = super::decode_header(&mut builder, &data2, zero);

        // builder.connect(rlp_header.len, res_rlp_header.len);
        builder.connect(rlp_header2.offset, res_rlp_header2.offset);
        builder.connect(rlp_header2.data_type, res_rlp_header2.data_type);

        builder.register_public_inputs(&data2);
        builder.register_public_input(rlp_header2.offset);
        builder.register_public_input(rlp_header2.len);
        builder.register_public_input(rlp_header2.data_type);

        let data3: Vec<Target> = [199, 192, 193, 192, 195, 192, 193, 192]
            .iter()
            .map(|x| builder.constant(F::from_canonical_u64(*x)))
            .collect();

        let rlp_header3 = RlpHeader {
            offset: builder.constant(F::from_canonical_usize(1)),
            len: builder.constant(F::from_canonical_usize(7)),
            data_type: builder.constant(F::from_canonical_usize(1)),
        };

        let res_dot_drop = extract_array::<F, D, { MAX_LEN_BYTES + 1 }>(&mut builder, &data3, zero);
        let res_rlp_header3 = super::decode_header(&mut builder, &res_dot_drop, zero);

        // builder.connect(rlp_header.len, res_rlp_header.len);
        builder.connect(rlp_header3.offset, res_rlp_header3.offset);
        builder.connect(rlp_header3.data_type, res_rlp_header3.data_type);

        builder.register_public_inputs(&data3);
        builder.register_public_input(rlp_header3.offset);
        builder.register_public_input(rlp_header3.len);
        builder.register_public_input(rlp_header3.data_type);

        let data = builder.build::<C>();
        let proof = data.prove(pw)?;
        data.verify(proof)
    }

    #[test]
    fn test_rlp_decode() -> Result<()> {
        let data: [u64; 532] = [
            249, 2, 17, 160, 10, 210, 58, 71, 229, 91, 254, 185, 245, 139, 35, 127, 191, 50, 125,
            165, 19, 165, 59, 86, 127, 77, 226, 197, 94, 143, 9, 69, 104, 149, 113, 39, 160, 164,
            115, 165, 166, 228, 180, 44, 203, 222, 52, 48, 157, 214, 190, 69, 130, 116, 84, 133,
            170, 215, 193, 212, 152, 106, 149, 100, 253, 145, 220, 246, 94, 160, 69, 11, 1, 238,
            164, 195, 225, 91, 51, 198, 134, 50, 21, 34, 253, 120, 157, 26, 173, 81, 148, 24, 94,
            179, 165, 5, 99, 85, 90, 78, 104, 180, 160, 82, 128, 145, 254, 48, 73, 106, 165, 234,
            223, 46, 5, 168, 79, 141, 218, 64, 98, 200, 87, 199, 28, 213, 222, 164, 182, 145, 219,
            253, 186, 121, 39, 160, 167, 139, 46, 219, 193, 195, 174, 240, 47, 40, 188, 121, 97,
            50, 227, 220, 35, 99, 122, 36, 94, 78, 156, 78, 197, 54, 232, 163, 249, 213, 16, 58,
            160, 111, 180, 73, 26, 200, 238, 6, 49, 66, 159, 230, 23, 226, 13, 10, 230, 7, 51, 103,
            45, 139, 187, 57, 125, 86, 1, 146, 77, 200, 196, 223, 158, 160, 55, 41, 196, 37, 89,
            112, 4, 6, 183, 246, 239, 121, 175, 146, 171, 71, 19, 99, 239, 56, 75, 116, 235, 20,
            239, 208, 243, 25, 211, 222, 248, 120, 160, 203, 87, 65, 73, 168, 197, 46, 86, 209,
            173, 204, 46, 232, 157, 204, 145, 75, 151, 105, 166, 72, 142, 173, 255, 186, 120, 43,
            121, 104, 228, 130, 134, 160, 150, 115, 130, 186, 247, 99, 108, 21, 244, 243, 60, 208,
            96, 34, 93, 32, 175, 77, 181, 18, 59, 49, 192, 153, 255, 123, 231, 108, 251, 75, 134,
            92, 160, 78, 107, 27, 31, 43, 92, 213, 101, 63, 87, 83, 248, 163, 19, 104, 103, 84,
            248, 119, 180, 32, 209, 82, 52, 250, 148, 101, 219, 76, 194, 160, 125, 160, 83, 37,
            183, 243, 189, 9, 79, 122, 28, 120, 150, 139, 190, 225, 222, 184, 206, 225, 117, 233,
            244, 162, 244, 212, 38, 220, 37, 129, 215, 25, 93, 53, 160, 229, 6, 255, 207, 78, 120,
            107, 238, 212, 128, 106, 189, 84, 39, 136, 172, 149, 67, 89, 238, 163, 122, 88, 90,
            149, 80, 59, 121, 249, 7, 238, 1, 160, 81, 214, 156, 64, 149, 165, 65, 36, 216, 223,
            167, 73, 213, 180, 230, 230, 32, 106, 193, 147, 176, 40, 93, 119, 210, 13, 1, 159, 16,
            112, 114, 103, 160, 211, 15, 4, 49, 74, 86, 24, 146, 109, 246, 80, 207, 194, 97, 226,
            153, 241, 94, 43, 233, 192, 2, 152, 171, 150, 86, 26, 250, 234, 179, 74, 156, 160, 175,
            157, 156, 73, 109, 26, 48, 12, 182, 175, 211, 173, 181, 241, 131, 247, 105, 98, 255,
            101, 7, 227, 21, 63, 78, 41, 155, 58, 231, 222, 15, 141, 160, 219, 213, 163, 116, 191,
            119, 232, 215, 182, 77, 130, 102, 90, 48, 66, 197, 228, 202, 43, 169, 232, 246, 11, 23,
            100, 50, 211, 205, 202, 115, 60, 49, 128,
        ];

        let config = CircuitConfig::standard_recursion_config();

        let pw = PartialWitness::new();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let data: Vec<Target> = data
            .iter()
            .map(|x| builder.constant(F::from_canonical_u64(*x)))
            .collect();
        let zero = builder.zero();
        let decoded = super::decode_fixed_list::<F, D, 17>(&mut builder, &data, zero);

        let offset: Vec<Target> = [
            4, 37, 70, 103, 136, 169, 202, 235, 268, 301, 334, 367, 400, 433, 466, 499, 532,
        ]
        .iter()
        .map(|x| builder.constant(F::from_canonical_u64(*x)))
        .collect();
        let len: Vec<Target> = [
            32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 0,
        ]
        .iter()
        .map(|x| builder.constant(F::from_canonical_u64(*x)))
        .collect();
        let data_type: Vec<Target> = [0; 17]
            .iter()
            .map(|x| builder.constant(F::from_canonical_u64(*x)))
            .collect();

        for i in 0..17 {
            builder.connect(decoded.offset[i], offset[i]);
            builder.connect(decoded.len[i], len[i]);
            builder.connect(decoded.data_type[i], data_type[i]);
        }

        let data = builder.build::<C>();
        let proof = data.prove(pw)?;
        data.verify(proof)
    }
    #[test]
    fn test_compact_decode() -> Result<()> {
        struct TestCase {
            input: [u8; MAX_ENC_KEY_LEN],
            key_len: usize,
            expected: Vec<u8>,
        }

        let run_test_case = |tc: TestCase| {
            let config = CircuitConfig::standard_recursion_config();
            let mut pw = PartialWitness::new();
            let mut builder = CircuitBuilder::<F, D>::new(config);
            let wire1 = Array::<Target, MAX_ENC_KEY_LEN>::new(&mut builder);
            wire1.assign::<F>(
                &mut pw,
                &create_array(|i| F::from_canonical_u8(tc.input[i])),
            );
            let key_header = RlpHeader {
                offset: builder.constant(F::from_canonical_usize(0)),
                len: builder.constant(F::from_canonical_usize(tc.key_len)),
                data_type: builder.constant(F::from_canonical_usize(0)),
            };
            let (nibbles, cond) = decode_compact_encoding(&mut builder, &wire1, &key_header);
            builder.assert_bool(cond);
            let exp_nib_len = builder.constant(F::from_canonical_usize(tc.expected.len()));
            builder.connect(nibbles.real_len, exp_nib_len);
            for (i, nib) in tc.expected.iter().enumerate() {
                let num = builder.constant(F::from_canonical_u8(*nib));
                builder.connect(nibbles.arr[i], num);
            }
            let data = builder.build::<C>();
            let proof = data.prove(pw).unwrap();
            data.verify(proof).unwrap();
        };
        let tc1 = TestCase {
            input: [
                0x11, 0x23, 0x45, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0,
            ],
            key_len: 3,
            expected: (0..5).map(|i| i + 1).collect::<Vec<u8>>(),
        };

        let tc2 = TestCase {
            input: [
                0x20, 0x0f, 0x1c, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0,
            ],
            key_len: 4,
            expected: vec![0, 15, 1, 12, 11, 8],
        };

        let tc3 = TestCase {
            input: [
                0x3f, 0x1c, 0xb8, 0x99, 0xab, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ],
            key_len: 3,
            expected: vec![15, 1, 12, 11, 8],
        };
        run_test_case(tc1);
        run_test_case(tc2);
        run_test_case(tc3);

        {
            let (mut trie, rlp_key) = generate_random_storage_mpt::<5, 32>();
            let proof = trie.get_proof(&rlp_key).unwrap();
            println!(" ------ TEST CASE -----\n");
            let leaf_node = proof.last().unwrap().clone();
            let leaf_tuple: Vec<Vec<u8>> = rlp::decode_list(&leaf_node);
            let partial_key_compact: Vec<u8> = rlp::decode(&leaf_tuple[0]).unwrap();
            let partial_key_struct = Nibbles::from_compact(&partial_key_compact);
            let partial_key_nibbles = partial_key_struct.nibbles();
            let tc = TestCase {
                input: create_array(|i| {
                    if i < partial_key_compact.len() {
                        partial_key_compact[i]
                    } else {
                        0
                    }
                }),
                key_len: partial_key_compact.len(),
                expected: partial_key_nibbles.to_vec(),
            };
            println!(
                "partial key nibbles ({} len): {:02x?} -- input 0x{:02x?}",
                partial_key_nibbles.len(),
                hex::encode(partial_key_nibbles).to_string(),
                hex::encode(tc.input)[..10].to_string()
            );

            run_test_case(tc);
        }
        Ok(())
    }

    #[test]
    fn test_weird_branch() -> Result<()> {
        //let node: Vec<u8> = vec![
        //    249, 2, 17, 160, 238, 166, 95, 91, 53, 7, 134, 99, 120, 19, 254, 39, 208, 113, 61, 202,
        //    207, 233, 74, 22, 106, 42, 228, 163, 86, 251, 181, 225, 223, 70, 186, 160, 160, 138,
        //    162, 212, 219, 187, 163, 67, 230, 15, 29, 160, 165, 91, 241, 189, 200, 163, 72, 160,
        //    155, 240, 12, 44, 107, 179, 251, 132, 254, 37, 172, 5, 10, 160, 102, 170, 94, 64, 159,
        //    42, 60, 53, 172, 174, 48, 120, 73, 104, 224, 107, 137, 211, 222, 250, 166, 2, 226, 225,
        //    204, 57, 172, 92, 174, 55, 190, 12, 160, 224, 135, 210, 71, 107, 59, 88, 208, 98, 120,
        //    49, 139, 219, 146, 110, 50, 151, 42, 164, 223, 41, 48, 200, 194, 40, 36, 153, 1, 122,
        //    105, 138, 192, 160, 133, 228, 240, 217, 248, 214, 107, 249, 164, 161, 15, 255, 74, 215,
        //    15, 245, 143, 24, 166, 86, 4, 74, 21, 174, 36, 93, 237, 240, 43, 232, 241, 213, 160,
        //    66, 28, 111, 74, 176, 167, 149, 38, 135, 124, 28, 226, 34, 205, 55, 168, 194, 255, 167,
        //    19, 230, 81, 148, 167, 16, 175, 42, 15, 30, 158, 178, 139, 160, 126, 123, 146, 5, 98,
        //    29, 28, 144, 127, 238, 8, 66, 225, 193, 157, 16, 41, 166, 31, 232, 71, 163, 69, 186,
        //    43, 96, 63, 92, 248, 71, 251, 157, 160, 21, 150, 214, 117, 146, 168, 111, 236, 216,
        //    135, 237, 67, 202, 57, 81, 136, 196, 64, 215, 249, 127, 83, 41, 190, 238, 252, 144, 24,
        //    244, 189, 179, 151, 160, 207, 37, 216, 205, 246, 134, 113, 65, 176, 159, 163, 235, 15,
        //    131, 54, 218, 39, 213, 11, 239, 98, 58, 191, 65, 223, 166, 246, 248, 112, 25, 92, 75,
        //    160, 215, 207, 43, 87, 202, 186, 85, 196, 35, 141, 153, 165, 154, 13, 221, 213, 142,
        //    39, 157, 167, 115, 165, 234, 34, 187, 61, 194, 63, 242, 199, 70, 12, 160, 30, 241, 92,
        //    181, 43, 8, 26, 133, 4, 116, 108, 217, 71, 254, 8, 230, 231, 224, 237, 133, 93, 128,
        //    228, 227, 97, 180, 246, 54, 248, 244, 103, 131, 160, 86, 45, 77, 142, 209, 77, 15, 43,
        //    247, 103, 106, 3, 163, 49, 95, 97, 25, 173, 214, 0, 140, 0, 64, 108, 51, 83, 234, 178,
        //    20, 125, 85, 218, 160, 60, 102, 86, 20, 239, 78, 158, 210, 221, 142, 161, 219, 186,
        //    234, 66, 26, 3, 43, 77, 220, 137, 43, 84, 131, 197, 159, 192, 193, 241, 39, 189, 37,
        //    160, 228, 215, 88, 57, 38, 191, 250, 126, 134, 25, 237, 226, 220, 11, 158, 154, 122, 5,
        //    251, 161, 232, 198, 171, 242, 113, 105, 53, 164, 165, 96, 132, 43, 160, 165, 220, 242,
        //    196, 237, 133, 47, 3, 154, 137, 222, 188, 65, 182, 8, 236, 45, 42, 120, 5, 61, 244,
        //    125, 189, 141, 233, 123, 214, 197, 149, 96, 8, 160, 187, 15, 137, 203, 82, 103, 101,
        //    213, 207, 128, 191, 124, 29, 242, 224, 113, 98, 255, 83, 253, 32, 149, 207, 251, 252,
        //    119, 74, 117, 15, 155, 215, 192, 128,
        //];
        let node: Vec<u8> = vec![
            249, 2, 17, 160, 142, 226, 122, 80, 219, 210, 241, 138, 84, 233, 135, 248, 23, 247, 69,
            193, 225, 193, 111, 220, 159, 118, 50, 137, 191, 157, 140, 56, 213, 57, 254, 43, 160,
            152, 231, 137, 28, 3, 188, 193, 138, 220, 129, 6, 211, 209, 33, 217, 182, 200, 128,
            106, 76, 46, 142, 227, 187, 0, 106, 34, 192, 117, 84, 201, 158, 160, 180, 115, 158,
            144, 7, 101, 108, 29, 251, 209, 167, 85, 99, 24, 62, 201, 142, 226, 86, 4, 126, 142,
            235, 113, 6, 134, 195, 41, 241, 197, 63, 121, 160, 20, 33, 184, 78, 141, 91, 120, 196,
            125, 43, 234, 239, 101, 142, 52, 182, 244, 241, 166, 75, 205, 22, 149, 108, 66, 238,
            45, 168, 184, 112, 244, 26, 160, 93, 157, 69, 179, 87, 57, 78, 222, 224, 63, 122, 157,
            170, 114, 206, 247, 127, 2, 200, 161, 96, 22, 193, 114, 167, 231, 37, 235, 255, 230,
            50, 87, 160, 9, 103, 108, 19, 153, 224, 46, 234, 10, 193, 93, 244, 8, 196, 206, 190,
            96, 210, 105, 160, 150, 139, 70, 44, 212, 202, 220, 59, 163, 222, 201, 221, 160, 39,
            123, 107, 200, 154, 191, 47, 217, 66, 100, 161, 132, 20, 26, 132, 207, 196, 17, 82,
            100, 11, 40, 217, 136, 133, 175, 142, 58, 232, 180, 76, 215, 160, 37, 13, 9, 44, 88,
            73, 5, 135, 171, 4, 191, 172, 208, 215, 12, 18, 181, 217, 85, 70, 255, 47, 145, 33,
            123, 52, 17, 133, 226, 88, 147, 201, 160, 65, 166, 78, 252, 250, 153, 190, 12, 186,
            158, 223, 61, 165, 71, 193, 237, 184, 198, 250, 11, 218, 122, 5, 139, 52, 56, 50, 153,
            93, 227, 173, 122, 160, 131, 226, 32, 107, 137, 169, 36, 173, 166, 85, 183, 131, 45,
            55, 127, 187, 213, 228, 107, 88, 57, 141, 239, 62, 31, 137, 81, 48, 117, 150, 172, 77,
            160, 254, 102, 152, 4, 106, 158, 116, 8, 247, 112, 82, 160, 148, 117, 247, 89, 0, 33,
            222, 115, 85, 230, 182, 185, 183, 209, 103, 185, 45, 111, 239, 36, 160, 115, 166, 229,
            219, 96, 221, 115, 153, 251, 106, 35, 169, 57, 34, 176, 35, 122, 83, 184, 12, 38, 74,
            184, 65, 223, 211, 217, 212, 148, 104, 195, 52, 160, 251, 166, 29, 182, 94, 61, 21,
            158, 213, 101, 206, 4, 14, 40, 235, 252, 155, 154, 40, 198, 80, 3, 210, 232, 163, 25,
            192, 206, 91, 120, 89, 54, 160, 150, 210, 86, 110, 224, 9, 239, 199, 160, 163, 53, 26,
            88, 209, 64, 191, 39, 157, 226, 50, 130, 93, 173, 18, 6, 12, 201, 242, 66, 198, 128,
            59, 160, 84, 126, 25, 76, 57, 159, 176, 39, 181, 164, 47, 19, 162, 58, 166, 9, 68, 69,
            138, 197, 58, 83, 223, 185, 28, 106, 24, 104, 148, 206, 241, 108, 160, 76, 184, 85,
            109, 183, 223, 213, 95, 59, 178, 192, 224, 111, 123, 230, 93, 234, 222, 121, 38, 205,
            90, 248, 37, 15, 176, 185, 209, 56, 175, 195, 118, 128,
        ];
        let state = rlp::Rlp::new(&node);
        assert!(state.is_list());
        for (i, d) in state.iter().enumerate() {
            println!("slot {}: data {:?}", i, d.data()?);
        }
        Ok(())
    }
}
