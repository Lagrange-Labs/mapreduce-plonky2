//! This is the block-inputs gadget. It builds the circuit to prove that the
//! hash of state MPT root should be included in the block header.

use crate::{
    array::{Array, Vector, VectorWire, L32},
    keccak::{InputData, KeccakCircuit, KeccakWires, OutputHash, HASH_LEN},
    mpt_sequential::PAD_LEN,
    utils::convert_u8_targets_to_u32,
};
use anyhow::Result;
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::{target::Target, witness::PartialWitness},
    plonk::circuit_builder::CircuitBuilder,
};
use plonky2_crypto::u32::arithmetic_u32::U32Target;

/// Parent hash offset in RLP encoded header
const HEADER_RLP_PARENT_HASH_OFFSET: usize = 4;
/// State root offset in RLP encoded header
const HEADER_RLP_STATE_ROOT_OFFSET: usize = 91;
/// Number offset in RLP encoded header
const HEADER_RLP_NUMBER_OFFSET: usize = 450;

pub(super) const SEPOLIA_NUMBER_LEN: usize = 3;
pub(super) const MAINNET_NUMBER_LEN: usize = 4;

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
    pub(crate) hash: KeccakWires<{ PAD_LEN(MAX_LEN) }>,
    /// RLP encoded bytes of block header
    pub(crate) header_rlp: VectorWire<Target, MAX_LEN>,
}

/// The block input gadget
#[derive(Clone, Debug)]
pub struct BlockInputs<const NUMBER_LEN: usize> {
    /// RLP encoded bytes of block header
    header_rlp: Vec<u8>,
}

impl<const NUMBER_LEN: usize> BlockInputs<NUMBER_LEN>
where
    [(); L32(NUMBER_LEN)]:,
{
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
        let hash = KeccakCircuit::hash_vector(cb, bytes_to_keccak);

        // Get the parent hash from RLP encoded header.
        let parent_hash = &header_rlp.arr.arr
            [HEADER_RLP_PARENT_HASH_OFFSET..HEADER_RLP_PARENT_HASH_OFFSET + HASH_LEN];
        let parent_hash: OutputHash = convert_u8_targets_to_u32(cb, parent_hash)
            .try_into()
            .unwrap();

        // We assume so far it always fit in 32 bits, which give block number < 4 billion so it
        // should be ok.
        let mut number = header_rlp.arr.arr
            [HEADER_RLP_NUMBER_OFFSET..HEADER_RLP_NUMBER_OFFSET + NUMBER_LEN]
            .to_vec();
        number.reverse();
        let number: U32Target = convert_u8_targets_to_u32(cb, &number)[0];

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
        KeccakCircuit::<{ PAD_LEN(MAX_LEN) }>::assign(
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
        // Verify the block header includes the state MPT root hash.
        let expected_state_root = &wires.header_rlp.arr.arr
            [HEADER_RLP_STATE_ROOT_OFFSET..HEADER_RLP_STATE_ROOT_OFFSET + HASH_LEN];
        let expected_state_root: OutputHash = convert_u8_targets_to_u32(cb, expected_state_root)
            .try_into()
            .unwrap();
        expected_state_root.enforce_equal(cb, &state_root_hash);
    }
}

#[cfg(test)]
mod test {
    use anyhow::Result;
    use ethers::{
        providers::{Http, Middleware, Provider},
        types::{BlockNumber, U64},
    };
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
    use serial_test::serial;

    use crate::{
        array::{Array, L32},
        circuit::{test::run_circuit, UserCircuit},
        eth::{BlockData, BlockUtil},
        keccak::{OutputByteHash, HASH_LEN},
        mpt_sequential::PAD_LEN,
        state::block_linking::block_inputs::{MAINNET_NUMBER_LEN, SEPOLIA_NUMBER_LEN},
        utils::{convert_u8_targets_to_u32, convert_u8_to_u32_slice, find_index_subvector},
    };

    use super::{
        BlockInputs, BlockInputsWires, HEADER_RLP_NUMBER_OFFSET, HEADER_RLP_STATE_ROOT_OFFSET,
    };

    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;
    const MAX_BLOCK_LEN: usize = 620;
    type SWires = BlockInputsWires<MAX_BLOCK_LEN>;
    #[derive(Debug, Clone)]
    struct TestBlockCircuit<const NL: usize> {
        block: BlockInputs<NL>,
        exp_number: u32,
        exp_state_hash: Vec<u8>,
    }

    impl<const NL: usize, F: RichField + Extendable<D>, const D: usize> UserCircuit<F, D>
        for TestBlockCircuit<NL>
    where
        [(); PAD_LEN(MAX_BLOCK_LEN)]:,
        [(); MAX_BLOCK_LEN]:,
        [(); L32(NL)]:,
    {
        type Wires = (SWires, U32Target);

        fn build(c: &mut plonky2::plonk::circuit_builder::CircuitBuilder<F, D>) -> Self::Wires {
            let w = BlockInputs::<NL>::build(c);
            let n = c.add_virtual_u32_target();
            let number_offset = c.constant(F::from_canonical_usize(HEADER_RLP_NUMBER_OFFSET));
            c.connect(w.number.0, n.0);
            let exp_state_root = Array::<Target, HASH_LEN>::new(c);
            let state_root_offset =
                c.constant(F::from_canonical_usize(HEADER_RLP_STATE_ROOT_OFFSET));
            let extracted_state_root = w.header_rlp.arr.arr
                [HEADER_RLP_STATE_ROOT_OFFSET..HEADER_RLP_STATE_ROOT_OFFSET + HASH_LEN]
                .to_vec()
                .try_into()
                .unwrap();
            exp_state_root.enforce_equal(c, &extracted_state_root);
            (w, n)
        }

        fn prove(&self, pw: &mut plonky2::iop::witness::PartialWitness<F>, wires: &Self::Wires) {
            self.block.assign(pw, &wires.0).unwrap();
            pw.set_u32_target(wires.1, self.exp_number);
        }
    }

    #[tokio::test]
    async fn test_block_header_decoding_on_sepolia() -> Result<()> {
        #[cfg(feature = "ci")]
        let url = env::var("CI_SEPOLIA").expect("CI_SEPOLIA env var not set");
        #[cfg(not(feature = "ci"))]
        let url = "https://ethereum-sepolia-rpc.publicnode.com";

        test_block_header_decoding::<SEPOLIA_NUMBER_LEN>(url).await
    }

    #[tokio::test]
    async fn test_block_header_decoding_on_mainnet() -> Result<()> {
        let url = "https://eth.llamarpc.com";

        test_block_header_decoding::<MAINNET_NUMBER_LEN>(url).await
    }

    async fn test_block_header_decoding<const NUMBER_LEN: usize>(url: &str) -> Result<()>
    where
        [(); L32(NUMBER_LEN)]:,
    {
        let provider =
            Provider::<Http>::try_from(url).expect("could not instantiate HTTP Provider");
        let block_number = provider.get_block_number().await?;
        let block = provider.get_block(block_number).await?.unwrap();
        println!("block.number: {:?}", block.number.unwrap());
        let encoded = block.rlp();
        let hash = block.block_hash();
        assert_eq!(&block.hash.unwrap().to_fixed_bytes()[..], &hash);
        let state_index = find_index_subvector(&encoded, block.state_root.as_bytes());
        println!("state root index: {:?}", state_index);
        let parent_index = find_index_subvector(&encoded, block.parent_hash.as_bytes());
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
        assert!(real_number_len <= 4);
        let ext_slice = encoded[number_index..number_index + real_number_len].to_vec();
        println!(
            "Block Number FROM RLP LEN = {} => data {:?}",
            real_number_len, ext_slice,
        );
        let converted =
            convert_u8_to_u32_slice(&ext_slice.iter().cloned().rev().collect::<Vec<u8>>())[0];
        println!("CONVERTED u32 -> {}", converted);
        assert_eq!(converted, block.number.unwrap().as_u32());
        let mut encoded2 = ext_slice.clone();
        encoded2.resize(4, 0);
        println!("encoded2 = {:?}", encoded2);
        let converted2 = convert_u8_to_u32_slice(
            &encoded2
                .iter()
                // THIS LINE: remove it and you get the error in circuit
                // FIX:
                // * implement u8 -> u32 in be order in circuit
                //  * and only analyze number of bytes
                .take(real_number_len)
                .cloned()
                .rev()
                .collect::<Vec<u8>>(),
        )[0];
        assert_eq!(converted2, block.number.unwrap().as_u32());
        let circuit = TestBlockCircuit::<NUMBER_LEN> {
            block: BlockInputs {
                header_rlp: encoded,
            },
            exp_number: block.number.unwrap().as_u32(),
            exp_state_hash: block.state_root.as_bytes().to_vec(),
        };
        run_circuit::<F, D, C, _>(circuit);
        Ok(())
    }
}
