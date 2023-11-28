use anyhow::Result;
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{circuit_builder::CircuitBuilder, circuit_data::CircuitConfig, config::GenericConfig},
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
    rlp::{decode_fixed_list, decode_tuple, extract_array},
    utils::{convert_u8_to_u32, less_than},
    ProofTuple,
};

/// The maximum length of a RLP encoded leaf node in a MPT tree holding a legacy tx.
const MAX_LEGACY_TX_NODE_LENGTH: usize = 532;
/// The maximum size a RLP encoded legacy tx can take. This is different from
/// `LEGACY_TX_NODE_LENGTH` because the latter contains the key in the path
/// as well.
const MAX_LEGACY_TX_LENGTH: usize = 532;
/// Maximum size the gas value can take in bytes.
const MAX_GAS_VALUE_LEN: usize = 32;

pub fn legacy_tx_leaf_proof<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
>(
    config: &CircuitConfig,
    node: &[u8],
    node_length: usize,
    gas_offset: usize,
    extract_unsafe: bool,
) -> Result<ProofTuple<F, C, D>> {
    assert_eq!(node.len(), MAX_LEGACY_TX_NODE_LENGTH);

    let mut b = CircuitBuilder::<F, D>::new(config.clone());
    let mut pw = PartialWitness::new();

    let node_targets = b.add_virtual_targets(MAX_LEGACY_TX_NODE_LENGTH);

    let gas_offset_target = b.add_virtual_target();

    // Witness assignement
    for i in 0..MAX_LEGACY_TX_NODE_LENGTH {
        pw.set_target(node_targets[i], F::from_canonical_u8(node[i]));
    }
    pw.set_target(gas_offset_target, F::from_canonical_usize(gas_offset));

    // Hash computation and exposing as public input
    let length_target = b.add_virtual_target();
    pw.set_target(length_target, F::from_canonical_usize(node_length));
    hash_node(&mut b, &mut pw, &node_targets, length_target, node_length);

    // Gas value extraction and exposing as public input
    if extract_unsafe {
        unsafe_extract_gas_value(&mut b, &node_targets, gas_offset_target);
    } else {
        extract_gas_value(&mut b, &node_targets);
    }
    let data = b.build::<C>();

    let proof = data.prove(pw)?;

    Ok((proof, data.verifier_only, data.common))
}

/// Directly read the gas value at the specified offset.
/// NOTE: It does NOT guarantee the offset is _correct_. The prover CAN give
/// any offset within the given slice that has been hashed, and claim it is
/// the gas value.
/// This method is only useful for testing & quick prototyping purposes,
/// it is NOT safe.
fn unsafe_extract_gas_value<F: RichField + Extendable<D>, const D: usize>(
    b: &mut CircuitBuilder<F, D>,
    node: &[Target],
    gas_offset: Target,
) {
    let gas_value_array = extract_array(b, node, gas_offset, MAX_GAS_VALUE_LEN);
    b.register_public_inputs(&gas_value_array);
}

/// Reads the header of the RLP node, then reads the header of the TX item
/// then reads the header of the third items in the list (which is the gas).
/// From that, it exact the gas value and registers it as public input.
fn extract_gas_value<F: RichField + Extendable<D>, const D: usize>(
    b: &mut CircuitBuilder<F, D>,
    node: &[Target],
) {
    // First, decode headers of RLP ( RLP (key), RLP(tx) )
    let tuple_headers = decode_tuple(b, node);
    let rlp_tx_index = 1;
    // extract the RLP(tx) from the node encoding
    let tx_offset = tuple_headers.offset[rlp_tx_index];
    let rlp_tx = extract_array(b, node, tx_offset, MAX_LEGACY_TX_LENGTH);

    // then extract the gas fees: it's the third item in the tx list (out of 9 for legacy tx)
    // NOTE: we should only decode the things we need, so for example here
    // the gas fee is at the 3rd position then we only need to decode up to the 3rd
    // headers in the list and keep the rest untouched. However, later user query might
    // want the whole thing.
    let tx_list = decode_fixed_list::<F, D, 3>(b, &rlp_tx);
    // -------- GAS PRICE EXTRACTION ------
    let gas_index = 2;
    let gas_offset = tx_list.offset[gas_index];
    // maximum length that the RLP(gas) == RLP(U256) can take:
    // * 32 bytes for the value (U256 = 32 bytes)
    // extracted gas value
    let gas_value_array = extract_array(b, &rlp_tx, gas_offset, MAX_GAS_VALUE_LEN);
    // TODO: pack the gas value into U32Target - more compact
    b.register_public_inputs(&gas_value_array);
}

fn hash_node<F: RichField + Extendable<D>, const D: usize>(
    b: &mut CircuitBuilder<F, D>,
    pw: &mut PartialWitness<F>,
    node: &[Target],       // assume constant size : TODO make it const generic
    length_target: Target, // the size of the data inside this fixed size array
    length: usize,         // could maybe be done with a generator but simpler this way
) {
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
    let node_u32_target: Vec<U32Target> = convert_u8_to_u32(b, &padded_node);

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
        input_bits: padded_len_bits,
        blocks,
    };

    let hash_output = b.hash_keccak256(&hash_target);
    b.register_public_inputs(
        &hash_output
            .limbs
            .iter()
            .map(|limb| limb.0)
            .collect::<Vec<_>>(),
    );
}

#[cfg(test)]
mod test {
    use anyhow::Result;
    use plonky2::{
        iop::witness::PartialWitness,
        plonk::{
            circuit_builder::CircuitBuilder,
            circuit_data::CircuitConfig,
            config::{GenericConfig, PoseidonGoldilocksConfig},
        },
    };
    const STRING: usize = 0;
    const LIST: usize = 1;

    use crate::utils::test::connect;
    use crate::utils::test::data_to_constant_targets;
    use crate::{
        mpt_tx::MAX_LEGACY_TX_NODE_LENGTH,
        rlp::{decode_header, decode_tuple},
    };

    #[test]
    fn test_rlp_mpt_node_list() -> Result<()> {
        // come from last tx in block 10593417, leaf node for tx idx 03 in the MPT
        let data_str = "f87420b871f86f826b2585199c82cc0083015f9094e955ede0a3dbf651e2891356ecd0509c1edb8d9c8801051fdc4efdc0008025a02190f26e70a82d7f66354a13cda79b6af1aa808db768a787aeb348d425d7d0b3a06a82bd0518bc9b69dc551e20d772a1b06222edfc5d39b6973e4f4dc46ed8b196";
        let mut data = hex::decode(data_str).unwrap();
        assert!(data.len() > 55);

        let r = rlp::Rlp::new(&data);
        let prototype = r.prototype().expect("error reading prototype");
        assert!(
            matches!(prototype, rlp::Prototype::List(2)),
            "prototype is {:?}",
            prototype
        );
        let header = r.payload_info().expect("can't get payload info");
        let key_rlp = r.at(0).expect("can't get key rlp");
        let value_rlp = r.at(1).expect("can't get value rlp");
        let key_header = key_rlp.payload_info().expect("can't get key payload info");
        let value_header = value_rlp
            .payload_info()
            .expect("can't get value payload info");
        assert!(key_header.header_len == 0); // this is short value so directly single byte! 0x20
        assert!(key_header.value_len > 0); // there is a value to be read
        assert!(value_header.header_len > 0); // tx is more than 55 bytes long
        assert!(key_header.value_len > 0);

        // check total value checks out for sub items length
        let computed_len = header.header_len
            + key_header.value_len
            + value_header.value_len
            + key_header.header_len
            + value_header.header_len;
        // add redundant header_len to mimick the circuit function
        assert!(header.value_len + header.header_len == computed_len);

        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        let config = CircuitConfig::standard_recursion_config();

        let mut pw = PartialWitness::new();
        let mut b = CircuitBuilder::<F, D>::new(config);

        // before transforming to targets, we pad to constant size so circuit always work for different sizes
        // Note we can't do it when reading rlp data offcircuit because rlp library continues to read until the
        // end of the array so it's not gonna be a list(2) anymore but much longer list.
        data.resize(MAX_LEGACY_TX_NODE_LENGTH, 0);
        let node_targets = data_to_constant_targets(&mut b, &data);

        // check the header of the list is correctly decoded
        let rlp_header = decode_header(&mut b, &node_targets);
        connect(&mut b, &mut pw, rlp_header.offset, header.header_len as u32);
        connect(&mut b, &mut pw, rlp_header.len, header.value_len as u32);
        // it's a list so type = 1
        connect(&mut b, &mut pw, rlp_header.data_type, LIST as u32);

        // decode all the sub headers now, we know there are only two
        let rlp_list = decode_tuple(&mut b, &node_targets);
        // check the first sub header which is the key of the MPT leaf node
        // value of the key header starts after first header and after header of the key item
        let expected_key_value_offset = key_header.header_len + header.header_len;

        connect(
            &mut b,
            &mut pw,
            rlp_list.offset[0],
            expected_key_value_offset as u32,
        );
        connect(&mut b, &mut pw, rlp_list.data_type[0], STRING as u32);
        connect(
            &mut b,
            &mut pw,
            rlp_list.len[0],
            key_header.value_len as u32,
        );
        // check the second sub header which is the key of the MPT leaf node
        // value starts after first header, after key header, after key value and after value header
        let expected_value_value_offset = value_header.header_len
            + key_header.header_len
            + key_header.value_len
            + header.header_len;
        connect(
            &mut b,
            &mut pw,
            rlp_list.offset[1],
            expected_value_value_offset as u32,
        );
        connect(&mut b, &mut pw, rlp_list.data_type[1], STRING as u32);
        connect(
            &mut b,
            &mut pw,
            rlp_list.len[1],
            value_header.value_len as u32,
        );

        let data = b.build::<C>();
        let proof = data.prove(pw)?;
        data.verify(proof)
    }
}
