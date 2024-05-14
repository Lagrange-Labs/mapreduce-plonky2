//! Database length extraction circuits

use mp2_common::{
    mpt_sequential::{
        Circuit as MPTCircuit, InputWires as MPTInputWires, OutputWires as MPTOutputWires, PAD_LEN,
    },
    storage_key::SimpleSlotWires,
    types::{CBuilder, CBuilderD, GFp},
    utils::less_than,
};
use plonky2::{field::types::Field, iop::target::Target};
use plonky2_crypto::u32::arithmetic_u32::U32Target;

mod leaf_mapping;
mod leaf_value;

pub mod public_inputs;

#[cfg(test)]
mod leaf_tests;

/// Build the circuit, assigning the public inputs and returning the internal wires.
pub fn build_length_slot<const DEPTH: usize, const NODE_LEN: usize>(
    cb: &mut CBuilder,
    length_slot: &SimpleSlotWires,
) -> (
    MPTInputWires<DEPTH, NODE_LEN>,
    MPTOutputWires<DEPTH, NODE_LEN>,
    U32Target,
)
where
    [(); PAD_LEN(NODE_LEN)]:,
    [(); DEPTH - 1]:,
{
    // we don't check the range of length & variable because they define the public input DM;
    // hence, they are guaranteed by the verifier to be correct

    let zero = cb.zero();
    let one = cb.one();

    let mpt_input = MPTCircuit::create_input_wires(cb, Some(length_slot.mpt_key.clone()));
    let mpt_output = MPTCircuit::verify_mpt_proof(cb, &mpt_input);

    mpt_input.nodes.iter().for_each(|n| n.assert_bytes(cb));

    // extract the recursive length prefix element from the output
    let prefix = mpt_output.leaf.arr[0];

    // constant used to extract the RLP header, if present
    let x80 = cb.constant(GFp::from_canonical_usize(0x80));
    let is_single_byte = less_than(cb, prefix, x80, 8);
    let len_x80 = cb.sub(prefix, x80);

    // extract the length, depending on the prefix header
    let value = cb.select(is_single_byte, one, x80);
    let offset = cb.select(is_single_byte, zero, one);
    let rlp_length = mpt_output
        .leaf
        .extract_array::<_, CBuilderD, 4>(cb, offset)
        .into_vec(value)
        .arr
        .reverse()
        .convert_u8_to_u32(cb)[0];

    (mpt_input, mpt_output, rlp_length)
}
