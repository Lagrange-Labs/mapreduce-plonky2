use crate::utils::{greater_than_or_equal_to, less_than, less_than_or_equal_to};
use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::Target;
use plonky2::plonk::circuit_builder::CircuitBuilder;

/// The maximum number of bytes the length of data can take.
/// NOTE: However, this is set arbitrarily because there can be up 7 bytes
/// expressing the length of the data according to RLP specs for long lists
/// size = prefix - 248 (where prefix is a single byte so can go up to 255)
/// 2 is the usual in practice for eth MPT related data.
/// nikko: verify that assumption.
const MAX_LEN_BYTES: usize = 2;

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
#[derive(Clone, Copy, Debug)]
pub struct RlpList<const N: usize> {
    pub offset: [Target; N],
    pub len: [Target; N],
    pub data_type: [Target; N],
    pub num_fields: Target,
}

// Returns the length from the RLP prefix in case of long string or long list
// data is the full data starting from the "type" byte of RLP encoding
// data length needs to be a power of 2
// non power of 2 lengths are padded leading zeros
pub fn data_len<F: RichField + Extendable<D>, const D: usize>(
    b: &mut CircuitBuilder<F, D>,
    data: &[Target],
    len_of_len: Target,
) -> Target {
    let mut res = b.zero();
    let const_256 = b.constant(F::from_canonical_u64(256));
    let arr_len = data.len();

    for i in 0..MAX_LEN_BYTES {
        // this makes sure we don't read outside of the data length: it can happen
        // because we call this function in circuit regardless of the actual
        // type of rlp data. If it's a single short value, then reading after 1st byte
        // might just fail.
        let arr_len_pred: usize = if i + 1 < arr_len { 1 } else { 0 };

        let i_target = b.constant(F::from_canonical_usize(i));
        let len_of_len_pred = less_than(b, i_target, len_of_len, 8);

        // i+1 because first byte is the RLP type
        let arr_access = data[(i + 1) * arr_len_pred];
        // shift result by one byte
        let multiplicand = b.mul(const_256, res);
        // res += 2^i * arr[i+1] only if we're in right range
        let sum = b.add(multiplicand, arr_access);
        let multiplicand_2 = b.mul(sum, len_of_len_pred.target);

        let not_len_of_len_pred_target = b.not(len_of_len_pred);
        let multiplicand_3 = b.mul(not_len_of_len_pred_target.target, res);
        // res = (2^i * arr[i+1]) * (i < len_len) + res * (i >= len_len)
        res = b.add(multiplicand_2, multiplicand_3);
    }

    res
}
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
    let offset = b._if(prefix_less_0x80, zero, select_3);

    // read the lenght encoded depending on the type
    let prefix_minus_f7 = b.sub(prefix, byte_f7);
    let long_list_len = data_len(b, data, prefix_minus_f7);
    let short_list_len = b.sub(prefix, byte_c0);
    let select_1 = b._if(prefix_less_0xf8, short_list_len, long_list_len);
    let prefix_minus_b7 = b.sub(prefix, byte_b7);
    let long_str_len = data_len(b, data, prefix_minus_b7);
    let select_2 = b._if(prefix_less_0xc0, long_str_len, select_1);
    let short_str_len = b.sub(prefix, byte_80);
    let select_3 = b._if(prefix_less_0xb8, short_str_len, select_2);
    let len = b._if(prefix_less_0x80, one, select_3);

    let data_type = greater_than_or_equal_to(b, prefix, byte_c0, 8).target;

    RlpHeader {
        len,
        offset,
        data_type,
    }
}

/// Decodes a list of two elements.
pub(crate) fn decode_tuple<F: RichField + Extendable<D>, const D: usize>(
    b: &mut CircuitBuilder<F, D>,
    data: &[Target],
    data_offset: Target,
) -> RlpList<2> {
    decode_fixed_list::<F, D, 2>(b, data, data_offset)
}

/// Decodes the header of the list, and then decodes the first N items of the list.
/// NOTE: the `num_field` is set to N in this case, since it does not read the full array.
/// Hence, N can be lower than the actual number of fields in the list.
pub fn decode_fixed_list<F: RichField + Extendable<D>, const D: usize, const N: usize>(
    b: &mut CircuitBuilder<F, D>,
    data: &[Target],
    data_offset: Target,
) -> RlpList<N> {
    let zero = b.zero();
    let one = b.one();
    let n_target = b.constant(F::from_canonical_usize(N));

    let mut num_fields = zero;
    let mut dec_off = [zero; N];
    let mut dec_len = [zero; N];
    let mut dec_type = [zero; N];

    let list_header = decode_header(b, data, data_offset);
    let mut offset = b.add(data_offset, list_header.offset);

    // decode each headers of each items ofthe list
    // remember in a list each item of the list is RLP encoded
    for i in 0..N {
        // stop when you've looked at the number of expected items
        let mut loop_p = b.is_equal(num_fields, n_target);
        loop_p = b.not(loop_p);

        // read the header starting from the offset -
        // nikko: this is assuming the header will take at least 1 bytes and less than 1 + MAX_LEN_BYTES
        //let header = extract_array::<F, D, { MAX_LEN_BYTES + 1 }>(b, data, offset);
        let RlpHeader {
            len: field_len,
            offset: field_offset,
            data_type: field_type,
        } = decode_header(b, data, offset);
        let total_field_len = b.add(field_offset, field_len);

        let one_sub_field_type = b.sub(one, field_type);
        // d_off_i = ((1-field_type) * field_offset + offset) * (offset != total_len)
        //  - if type is 0, str, then d_off_i basically = field_offset + offset
        //  - if type is 1, list, then d_off_i basically = offset because it's a list so we
        // again need to decode the rlp header
        let mut d_off_i = b.mul(one_sub_field_type, field_offset);
        d_off_i = b.add(d_off_i, offset);
        d_off_i = b.mul(loop_p.target, d_off_i);

        // d_len_i = ((field_type * field_offset) + field_len) * (offset != total_len)
        // - if type is 0, str, then d_len_i = field_len
        // - if type is 1, list, then d_len_i = field_offset + field_len
        // index where to find the data within the item array
        let mut d_len_i = b.mul(field_type, field_offset);
        d_len_i = b.add(d_len_i, field_len);
        d_len_i = b.mul(loop_p.target, d_len_i);
        let d_type_i = b.mul(loop_p.target, field_type);

        dec_off[i] = d_off_i;
        dec_len[i] = d_len_i;
        dec_type[i] = d_type_i;

        // move offset to the next field in the list
        offset = b.mul_add(loop_p.target, total_field_len, offset);
        num_fields = b.add(num_fields, loop_p.target);
    }

    RlpList {
        offset: dec_off,
        len: dec_len,
        data_type: dec_type,
        num_fields,
    }
}

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
        let lt = less_than_or_equal_to(b, i_plus_n_target, upper_bound, 63);
        // ((i+n) <= n+M) * (i+n)
        let j = b.mul(lt.target, i_plus_n_target);

        // out_val = arr[((i+n)<=n+M) * (i+n)]
        *out_val = quin_selector(b, arr, j);
    }

    out
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

    use anyhow::Result;

    use plonky2::field::types::Field;
    use plonky2::iop::target::Target;
    use plonky2::iop::witness::PartialWitness;
    use plonky2::plonk::circuit_builder::CircuitBuilder;
    use plonky2::plonk::circuit_data::CircuitConfig;
    use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};

    use crate::rlp::{decode_header, RlpHeader, MAX_LEN_BYTES};
    use crate::utils::IntTargetWriter;
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

        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
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
        // compare header of first item in list len outside circuit with inside circuit
        builder.connect(h0.offset, h0len_tgt);
        // compare value len of first item in list outside circuit with inside circuit
        builder.connect(h0.len, v0len_tgt);

        let data = builder.build::<C>();
        let proof = data.prove(pw)?;
        data.verify(proof)?;
        Ok(())
    }

    // TODO: replace these tests by deterministic tests by cr
    #[test]
    fn test_data_len() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        let config = CircuitConfig::standard_recursion_config();
        let pw = PartialWitness::new();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let data: Vec<Target> = [185, 4, 0]
            .iter()
            .map(|x| builder.constant(F::from_canonical_u64(*x)))
            .collect();
        let ret_target = builder.constant(F::from_canonical_u64(1024));

        let len_of_len = builder.constant(F::from_canonical_u64(2));
        let res = super::data_len(&mut builder, &data, len_of_len);
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
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
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

        let res_dot_drop =
            super::extract_array::<F, D, { MAX_LEN_BYTES + 1 }>(&mut builder, &data3, zero);
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

        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
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
}
