//! This is the block-inputs gadget. It builds the circuit to prove that the
//! hash of state MPT root should be included in the block header.

use crate::{
    array::{Array, Vector, VectorWire},
    keccak::{ByteKeccakWires, InputData, KeccakCircuit, OutputByteHash, OutputHash, HASH_LEN},
    mpt_sequential::PAD_LEN,
    rlp::decode_fixed_list,
    utils::{less_than, PackedU64Target, U64Target, U64_LEN},
};
use anyhow::Result;
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::{target::Target, witness::PartialWitness},
    plonk::circuit_builder::CircuitBuilder,
};
use plonky2_crypto::u32::arithmetic_u32::U32Target;
use std::array;

/// Parent hash offset in RLP encoded header
const HEADER_RLP_PARENT_HASH_OFFSET: usize = 4;
/// State root offset in RLP encoded header
const HEADER_RLP_STATE_ROOT_OFFSET: usize = 91;
/// Number offset in RLP encoded header
const HEADER_RLP_NUMBER_OFFSET: usize = 450;

/// The block input wires
pub struct BlockInputsWires<const MAX_LEN: usize>
where
    [(); PAD_LEN(MAX_LEN)]:,
{
    /// Block number
    pub(crate) number: U32Target,
    /// Block parent hash
    pub(crate) parent_hash: OutputHash,
    /// The keccak wires computed from RLP encoded header
    pub(crate) hash: ByteKeccakWires<{ PAD_LEN(MAX_LEN) }>,
    /// RLP encoded bytes of block header
    pub(crate) header_rlp: VectorWire<Target, MAX_LEN>,
}

/// The block input gadget
#[derive(Clone, Debug)]
pub struct BlockInputs {
    /// RLP encoded bytes of block header
    header_rlp: Vec<u8>,
}

impl BlockInputs {
    pub fn new(header_rlp: Vec<u8>) -> Self {
        Self { header_rlp }
    }

    /// Build for circuit.
    pub fn build<F, const D: usize, const MAX_LEN: usize>(
        cb: &mut CircuitBuilder<F, D>,
    ) -> BlockInputsWires<MAX_LEN>
    where
        F: RichField + Extendable<D>,
        [(); PAD_LEN(MAX_LEN)]:,
    {
        let header_rlp = VectorWire::new(cb);

        // Calculate the keccak hash of RLP encoded header.
        let zero = cb.zero();
        let mut arr = [zero; PAD_LEN(MAX_LEN)];
        arr[..MAX_LEN].copy_from_slice(&header_rlp.arr.arr);
        let bytes_to_keccak = &VectorWire::<Target, { PAD_LEN(MAX_LEN) }> {
            real_len: header_rlp.real_len,
            arr: Array { arr },
        };
        let hash = KeccakCircuit::hash_to_bytes(cb, bytes_to_keccak);

        // Get the parent hash from RLP encoded header.
        let parent_hash_offset =
            cb.constant(F::from_canonical_usize(HEADER_RLP_PARENT_HASH_OFFSET));
        let parent_hash: OutputByteHash = header_rlp.arr.extract_array(cb, parent_hash_offset);
        let parent_hash: OutputHash = parent_hash.convert_u8_to_u32(cb);

        // Get the block number from 4 bytes of specified offset in RLP encoded
        // header.
        let number_offset = cb.constant(F::from_canonical_usize(HEADER_RLP_NUMBER_OFFSET));
        // We assume so far it always fit in 32 bits, which give block number < 4 billion so it
        // should be ok.
        let number: Array<Target, 4> = header_rlp.arr.extract_array(cb, number_offset);
        let number: U32Target = number.reverse().convert_u8_to_u32(cb)[0];

        // This code is used for the mutable length of block number.
        // // The indexes of parent-hash, state-root and block-number in RLP header
        // // are [0, 3, 8]. These RLP offsets should be constants, since the
        // // encoded Block fields are all H256 before block-number.
        // // The block-number is an U64, its RLP encoded length is mutable, the
        // // leading zeros are deleted during RLP encoding.
        // let rlp_headers = decode_fixed_list::<_, _, 9>(cb, &header_rlp.arr.arr, zero);
        // let number_len = rlp_headers.len[8];
        // let number_offset = cb.constant(F::from_canonical_usize(HEADER_RLP_NUMBER_OFFSET));
        // let start = cb.add(number_offset, number_len);
        // let number = U64Target::from_array(array::from_fn(|i| {
        //     // offset = number_offset + number_len - 8 + i
        //     let eight_sub_i = cb.constant(F::from_canonical_usize(U64_LEN - i));
        //     let data_offset = cb.sub(start, eight_sub_i);
        //     let data = header_rlp.arr.value_at(cb, data_offset);
        //     let is_invalid = less_than(cb, data_offset, number_offset, 9);
        //     cb.select(is_invalid, zero, data)
        // }));
        // let number: PackedU64Target = number.convert_u8_to_u32(cb);

        BlockInputsWires {
            number,
            parent_hash,
            hash,
            header_rlp,
        }
    }

    /// Assign the wires.
    pub fn assign<F, const MAX_LEN: usize>(
        &self,
        pw: &mut PartialWitness<F>,
        wires: &BlockInputsWires<MAX_LEN>,
    ) -> Result<()>
    where
        F: RichField,
        [(); PAD_LEN(MAX_LEN)]:,
    {
        // Assign the RLP encoded block header.
        wires
            .header_rlp
            .assign(pw, &Vector::from_vec(&self.header_rlp)?);

        // Assign the keccak value of RLP encoded header.
        KeccakCircuit::<{ PAD_LEN(MAX_LEN) }>::assign_byte_keccak(
            pw,
            &wires.hash,
            &InputData::Assigned(
                &Vector::from_vec(&self.header_rlp)
                    .expect("Cannot create vector input for keccak RLP encoded header"),
            ),
        );

        Ok(())
    }

    /// Verify the block header includes the hash of state MPT root. We use an
    /// offset given as wire to indicate where the hash resides in the encoded
    /// block header. The circuit doesn't need to decode the RLP headers as we
    /// rely on the security of the hash function.
    pub fn verify_state_root_hash_inclusion<F, const D: usize, const MAX_LEN: usize>(
        cb: &mut CircuitBuilder<F, D>,
        wires: &BlockInputsWires<MAX_LEN>,
        state_root_hash: &OutputHash,
    ) where
        F: RichField + Extendable<D>,
        [(); PAD_LEN(MAX_LEN)]:,
    {
        let tt = cb._true();

        // Verify the offset of state MPT root hash is within range.
        let state_root_offset = cb.constant(F::from_canonical_usize(HEADER_RLP_STATE_ROOT_OFFSET));
        let within_range = less_than(cb, state_root_offset, wires.header_rlp.real_len, 10);
        cb.connect(within_range.target, tt.target);

        // Verify the block header includes the state MPT root hash.
        let expected_state_root: OutputByteHash =
            wires.header_rlp.arr.extract_array(cb, state_root_offset);
        expected_state_root
            .convert_u8_to_u32(cb)
            .enforce_equal(cb, &state_root_hash);
    }
}

#[cfg(test)]
mod test {
    use anyhow::Result;
    use ethers::types::BlockNumber;
    use plonky2::{
        field::extension::Extendable,
        hash::hash_types::RichField,
        iop::target::Target,
        plonk::config::{GenericConfig, PoseidonGoldilocksConfig},
    };
    use plonky2_crypto::u32::{
        arithmetic_u32::{CircuitBuilderU32, U32Target},
        witness::WitnessU32,
    };

    use crate::{
        array::Array,
        circuit::{test::run_circuit, UserCircuit},
        eth::{BlockData, BlockUtil},
        mpt_sequential::PAD_LEN,
        utils::{convert_u8_to_u32_slice, find_index_subvector},
    };

    use super::{BlockInputs, BlockInputsWires, HEADER_RLP_NUMBER_OFFSET};

    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;
    const MAX_BLOCK_LEN: usize = 620;
    type SWires = BlockInputsWires<MAX_BLOCK_LEN>;
    #[derive(Debug, Clone)]
    struct TestBlockCircuit {
        block: BlockInputs,
        exp_number: u32,
        exp_array: [u8; 4],
    }

    impl<F: RichField + Extendable<D>, const D: usize> UserCircuit<F, D> for TestBlockCircuit
    where
        [(); PAD_LEN(MAX_BLOCK_LEN)]:,
        [(); MAX_BLOCK_LEN]:,
    {
        type Wires = (SWires, U32Target, Array<Target, 4>);

        fn build(c: &mut plonky2::plonk::circuit_builder::CircuitBuilder<F, D>) -> Self::Wires {
            let w = BlockInputs::build(c);
            let n = c.add_virtual_u32_target();
            let number_offset = c.constant(F::from_canonical_usize(HEADER_RLP_NUMBER_OFFSET));
            let number_array = w.header_rlp.arr.extract_array::<_, _, 4>(c, number_offset);
            let exp_array = Array::<Target, 4>::new(c);
            number_array.enforce_equal(c, &exp_array);
            c.connect(w.number.0, n.0);
            (w, n, exp_array)
        }

        fn prove(&self, pw: &mut plonky2::iop::witness::PartialWitness<F>, wires: &Self::Wires) {
            self.block.assign(pw, &wires.0);
            pw.set_u32_target(wires.1, self.exp_number);
            wires.2.assign_bytes(pw, &self.exp_array);
        }
    }

    #[tokio::test]
    async fn test_block_header_decoding() -> Result<()> {
        let data = BlockData::fetch(BlockNumber::Latest).await?;
        //let block_number = 5395662;
        let block_number = BlockNumber::Latest;
        //let mut block = BlockData::fetch(BlockNumber::Latest).await?;
        let mut block = BlockData::fetch(block_number).await?;
        println!("block.number: {:?}", block.block.number.unwrap());
        let encoded = block.block.rlp();
        let hash = block.block.block_hash();
        assert_eq!(&block.block.hash.unwrap().to_fixed_bytes()[..], &hash);
        let state_index = find_index_subvector(&encoded, block.block.state_root.as_bytes());
        println!("state root index: {:?}", state_index);
        let parent_index = find_index_subvector(&encoded, block.block.parent_hash.as_bytes());
        println!("parent hash index: {:?}", parent_index);
        let rlp = rlp::Rlp::new(&encoded);
        let mut offset = rlp.payload_info().unwrap().header_len;
        for i in 0..=7 {
            let r = rlp.at(i).unwrap().payload_info().unwrap();
            offset += r.header_len + r.value_len;
        }
        let number_rlp = rlp.at(8).unwrap().payload_info().unwrap();
        offset += number_rlp.header_len;
        let number_index = offset;
        //let index = find_index_subvector(&encoded, data);
        println!("block number index: {:?}", number_index);
        let real_number_len = number_rlp.value_len;
        assert_eq!(real_number_len, 4);
        let ext_slice = encoded[number_index..number_index + real_number_len].to_vec();
        println!(
            "Block Number FROM RLP LEN = {} => data {:?}",
            real_number_len, ext_slice,
        );
        let converted =
            convert_u8_to_u32_slice(&ext_slice.iter().cloned().rev().collect::<Vec<u8>>())[0];
        println!("CONVERTED u32 -> {}", converted);
        assert_eq!(converted, block.block.number.unwrap().as_u32());
        let circuit = TestBlockCircuit {
            block: BlockInputs {
                header_rlp: encoded,
            },
            exp_number: block.block.number.unwrap().as_u32(),
            exp_array: ext_slice.try_into().unwrap(),
        };
        run_circuit::<F, D, C, _>(circuit);
        Ok(())
    }
}
