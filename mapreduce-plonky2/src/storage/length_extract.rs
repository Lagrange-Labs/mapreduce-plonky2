//! This circuit is used to verify the length value extracted from storage trie.
use super::{
    key::{SimpleSlot, SimpleSlotWires},
    MAX_BRANCH_NODE_LEN,
};
use crate::{
    api::{default_config, serialize_proof},
    keccak::{OutputHash, PACKED_HASH_LEN},
    mpt_sequential::{
        Circuit as MPTCircuit, InputWires as MPTInputWires, OutputWires as MPTOutputWires, PAD_LEN,
    },
    utils::less_than,
};
use anyhow::Result;
use ethers::types::H160;
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::{target::Target, witness::PartialWitness},
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::CircuitData,
        config::{AlgebraicHasher, GenericConfig},
    },
};
use plonky2_crypto::u32::arithmetic_u32::U32Target;
use recursion_framework::serialization::circuit_data_serialization::SerializableRichField;
use recursion_framework::serialization::{deserialize, serialize};
use serde::{Deserialize, Serialize};
use std::array::{self};

/// This is a wrapper around an array of targets set as public inputs of any
/// proof generated in this module. They all share the same structure.
/// `C` MPT root hash
/// `S` storage slot of the variable holding the length
/// `V` Integer value stored at key `S` (can be given by prover)
#[derive(Clone, Debug)]
pub struct PublicInputs<'a, T: Clone> {
    pub(crate) proof_inputs: &'a [T],
}

impl<'a> PublicInputs<'a, Target> {
    pub fn register<F, const D: usize>(
        cb: &mut CircuitBuilder<F, D>,
        mpt_root_hash: &OutputHash,
        storage_slot: Target,
        length_value: Target,
    ) where
        F: RichField + Extendable<D>,
    {
        mpt_root_hash.register_as_public_input(cb);
        cb.register_public_input(storage_slot);
        cb.register_public_input(length_value);
    }

    pub fn root_hash(&self) -> OutputHash {
        let data = self.root_hash_data();
        OutputHash::from_array(array::from_fn(|i| U32Target(data[i])))
    }
}

impl<'a, T: Copy> PublicInputs<'a, T> {
    pub(crate) const C_IDX: usize = 0;
    pub(crate) const S_IDX: usize = Self::C_IDX + PACKED_HASH_LEN;
    pub(crate) const V_IDX: usize = Self::S_IDX + 1;
    pub(crate) const TOTAL_LEN: usize = Self::V_IDX + 1;

    pub fn from(arr: &'a [T]) -> Self {
        Self { proof_inputs: arr }
    }

    pub fn root_hash_data(&self) -> &[T] {
        &self.proof_inputs[Self::C_IDX..Self::S_IDX]
    }

    pub fn storage_slot(&self) -> T {
        self.proof_inputs[Self::S_IDX]
    }

    pub fn length_value(&self) -> T {
        self.proof_inputs[Self::V_IDX]
    }
}

#[derive(Serialize, Deserialize)]
pub(crate) struct LengthExtractWires<const DEPTH: usize, const NODE_LEN: usize>
where
    [(); PAD_LEN(NODE_LEN)]:,
    [(); DEPTH - 1]:,
{
    /// Simple slot wires
    slot: SimpleSlotWires,
    /// Input wires of MPT circuit
    mpt_input: MPTInputWires<DEPTH, NODE_LEN>,
    /// Output wires of MPT circuit
    mpt_output: MPTOutputWires<DEPTH, NODE_LEN>,
}

/// Circuit extracting the length from an array variable from the storage trie
/// i.e. the mpt key = keccak(left_pad32(slot)) indicates the length of the array
/// in the storage trie. This length is RLP encoded however and circuit takes care
/// of extracting it in a U32.
/// Assumption is the the length is always < 2**32.
#[derive(Clone, Debug)]
pub struct ArrayLengthExtractCircuit<const DEPTH: usize, const NODE_LEN: usize> {
    /// Storage slot saved the length value
    slot: SimpleSlot,
    /// MPT circuit used to verify the nodes of storage Merkle Tree
    mpt_circuit: MPTCircuit<DEPTH, NODE_LEN>,
}

impl<const DEPTH: usize, const NODE_LEN: usize> ArrayLengthExtractCircuit<DEPTH, NODE_LEN>
where
    [(); PAD_LEN(NODE_LEN)]:,
    [(); DEPTH - 1]:,
{
    pub fn new(slot: u8, _contract_address: H160, nodes: Vec<Vec<u8>>) -> Self {
        let slot = SimpleSlot::new(slot);
        let mpt_circuit = MPTCircuit::new(slot.0.mpt_key(), nodes);

        Self { slot, mpt_circuit }
    }

    /// Build for circuit.
    pub(crate) fn build<F, const D: usize>(
        cb: &mut CircuitBuilder<F, D>,
    ) -> LengthExtractWires<DEPTH, NODE_LEN>
    where
        F: RichField + Extendable<D>,
    {
        let zero = cb.zero();
        let one = cb.one();
        let slot = SimpleSlot::build(cb);

        // Generate the input and output wires of MPT circuit.
        let mpt_input = MPTCircuit::create_input_wires(cb, Some(slot.mpt_key.clone()));
        let mpt_output = MPTCircuit::verify_mpt_proof(cb, &mpt_input);

        // Range check to constrain only bytes for each node of state MPT input.
        mpt_input.nodes.iter().for_each(|n| n.assert_bytes(cb));

        // NOTE: The length value shouldn't exceed 4-bytes (U32).
        // We read the RLP header, there are basically two cases:
        // * if the length is a single byte less than 0x80 there is no RLP header
        // * otherwise by assumption, there is a one byte fixed RLP header (assume len <55bytes long)
        // we can hardcode the type of RLP header it is and directly get the real number len
        // in this case, the header marker is 0x80 that we can directly take out from first byte
        let prefix = mpt_output.leaf.arr[0];
        let byte_80 = cb.constant(F::from_canonical_usize(128));
        let is_single_byte = less_than(cb, prefix, byte_80, 8);
        let value_len_80 = cb.sub(mpt_output.leaf.arr[0], byte_80);
        let value_len = cb.select(is_single_byte, one, value_len_80);
        let offset = cb.select(is_single_byte, zero, one);
        let value = mpt_output
            .leaf
            .extract_array::<F, _, 4>(cb, offset)
            .into_vec(value_len)
            .normalize_left::<_, _, 4>(cb) // left_pad::<4>()
            .reverse() // big endian to little endian
            .convert_u8_to_u32(cb);

        let reduced_value = value[0];

        // Register the public inputs.
        PublicInputs::register(cb, &mpt_output.root, slot.slot, reduced_value.0);

        LengthExtractWires {
            slot,
            mpt_input,
            mpt_output,
        }
    }

    /// Assign the wires.
    pub(crate) fn assign<F, const D: usize>(
        &self,
        pw: &mut PartialWitness<F>,
        wires: &LengthExtractWires<DEPTH, NODE_LEN>,
    ) -> Result<()>
    where
        F: RichField + Extendable<D>,
    {
        // Assign the slot.
        self.slot.assign(pw, &wires.slot);

        // Assign the input and output wires of MPT circuit.
        self.mpt_circuit
            .assign_wires(pw, &wires.mpt_input, &wires.mpt_output)
    }
}

#[derive(Serialize, Deserialize)]
pub struct Parameters<
    const DEPTH: usize,
    const NODE_LEN: usize,
    F: SerializableRichField<D>,
    const D: usize,
    C,
> where
    C: GenericConfig<D, F = F> + 'static,
    C::Hasher: AlgebraicHasher<F>,
    [(); DEPTH - 1]:,
    [(); PAD_LEN(NODE_LEN)]:,
{
    #[serde(serialize_with = "serialize", deserialize_with = "deserialize")]
    data: CircuitData<F, C, D>,
    wires: LengthExtractWires<DEPTH, NODE_LEN>,
}

impl<const DEPTH: usize, const NODE_LEN: usize, F, const D: usize, C>
    Parameters<DEPTH, NODE_LEN, F, D, C>
where
    C: GenericConfig<D, F = F> + 'static,
    F: SerializableRichField<D>,
    C::Hasher: AlgebraicHasher<F>,
    [(); DEPTH - 1]:,
    [(); PAD_LEN(NODE_LEN)]:,
{
    pub fn build() -> Self {
        let mut cb = CircuitBuilder::<F, D>::new(default_config());
        let wires = ArrayLengthExtractCircuit::<DEPTH, NODE_LEN>::build(&mut cb);
        let data = cb.build();
        Self { data, wires }
    }
    pub fn generate(&self, inputs: ArrayLengthExtractCircuit<DEPTH, NODE_LEN>) -> Result<Vec<u8>> {
        let mut pw = PartialWitness::new();
        inputs.assign::<F, D>(&mut pw, &self.wires)?;
        let proof = self.data.prove(pw)?;
        // TODO: move serialization to common place
        serialize_proof(&proof)
    }

    pub(crate) fn circuit_data(&self) -> &CircuitData<F, C, D> {
        &self.data
    }
}

pub const MAX_DEPTH_TRIE: usize = 6;
pub type CircuitInput = ArrayLengthExtractCircuit<MAX_DEPTH_TRIE, MAX_BRANCH_NODE_LEN>;
pub type PublicParameters = Parameters<
    MAX_DEPTH_TRIE,
    MAX_BRANCH_NODE_LEN,
    crate::api::F,
    { crate::api::D },
    crate::api::C,
>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        array::{Array, Vector, VectorWire},
        benches::init_logging,
        circuit::{test::run_circuit, UserCircuit},
        eth::{
            left_pad,
            test::{get_mainnet_url, get_sepolia_url},
            ProofQuery, StorageSlot,
        },
        mpt_sequential::{test::visit_proof, MAX_LEAF_VALUE_LEN},
        utils::{convert_u8_targets_to_u32, convert_u8_to_u32_slice, keccak256},
    };
    use eth_trie::{EthTrie, MemoryDB, Trie};
    use ethers::{
        providers::{Http, Provider},
        types::{Address, H160},
    };
    use plonky2::{
        field::types::Field,
        iop::witness::PartialWitness,
        plonk::config::{GenericConfig, PoseidonGoldilocksConfig},
    };
    use rand::{thread_rng, Rng};
    use std::{str::FromStr, sync::Arc};

    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    /// Test data
    struct TestData {
        /// Storage slot
        slot: u8,
        /// Expected length value
        value: u32,
        /// Contract address
        contract_address: H160,
        /// MPT nodes
        nodes: Vec<Vec<u8>>,
    }

    /// Test circuit
    #[derive(Clone, Debug)]
    struct LengthTestCircuit<const DEPTH: usize, const NODE_LEN: usize>
    where
        [(); PAD_LEN(NODE_LEN)]:,
        [(); DEPTH - 1]:,
    {
        base: ArrayLengthExtractCircuit<DEPTH, NODE_LEN>,
    }

    impl<const DEPTH: usize, const NODE_LEN: usize> UserCircuit<F, D>
        for LengthTestCircuit<DEPTH, NODE_LEN>
    where
        [(); PAD_LEN(NODE_LEN)]:,
        [(); DEPTH - 1]:,
    {
        type Wires = LengthExtractWires<DEPTH, NODE_LEN>;

        fn build(cb: &mut CircuitBuilder<F, D>) -> Self::Wires {
            ArrayLengthExtractCircuit::build(cb)
        }

        fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
            self.base.assign::<F, D>(pw, wires).unwrap();
        }
    }

    /// Test the length-match circuit with a generated random MPT.
    #[test]
    fn test_length_extract_circuit() {
        init_logging();

        const DEPTH: usize = 4;
        const NODE_LEN: usize = 500;

        let test_data = generate_test_data::<DEPTH>();

        // Get the expected public inputs.
        let exp_slot = F::from_canonical_u8(test_data.slot);
        let exp_value = F::from_canonical_u32(test_data.value);
        let exp_root_hash: Vec<_> =
            convert_u8_to_u32_slice(&keccak256(test_data.nodes.last().unwrap()))
                .into_iter()
                .map(F::from_canonical_u32)
                .collect();
        let test_circuit = LengthTestCircuit::<DEPTH, NODE_LEN> {
            base: ArrayLengthExtractCircuit::new(
                test_data.slot,
                test_data.contract_address,
                test_data.nodes,
            ),
        };
        let proof = run_circuit::<F, D, C, _>(test_circuit);

        // Verify the public inputs.
        let pi = PublicInputs::<F>::from(&proof.public_inputs);
        assert_eq!(pi.storage_slot(), exp_slot);
        assert_eq!(pi.length_value(), exp_value);
        assert_eq!(pi.root_hash_data(), exp_root_hash);
    }

    use anyhow::anyhow;
    use serial_test::serial;

    #[derive(Clone, Debug)]
    struct PidgyTest<const DEPTH: usize, const NODE_LEN: usize> {
        slot: u8,
        nodes: Vec<Vec<u8>>,
    }
    #[derive(Clone, Debug)]
    struct PidgyWires<const DEPTH: usize, const NODE_LEN: usize>
    where
        [(); PAD_LEN(NODE_LEN)]:,
        [(); DEPTH - 1]:,
    {
        slot: SimpleSlotWires,
        nodes: [VectorWire<Target, { PAD_LEN(NODE_LEN) }>; DEPTH],
    }
    use crate::mpt_sequential::Circuit;
    use crate::rlp::decode_fixed_list;

    impl<const DEPTH: usize, const NODE_LEN: usize> UserCircuit<F, D> for PidgyTest<DEPTH, NODE_LEN>
    where
        [(); PAD_LEN(NODE_LEN)]:,
        [(); DEPTH - 1]:,
    {
        type Wires = PidgyWires<DEPTH, NODE_LEN>;

        fn build(cb: &mut CircuitBuilder<F, D>) -> Self::Wires {
            let slot = SimpleSlot::build(cb);
            let zero = cb.zero();
            let t = cb._true();
            let key = slot.mpt_key.clone();
            // nodes should be ordered from leaf to root and padded at the end
            let nodes: [VectorWire<Target, _>; DEPTH] =
                array::from_fn(|_| VectorWire::<Target, { PAD_LEN(NODE_LEN) }>::new(cb));
            // small optimization here as we only need to decode two items for a leaf, since we know it's a leaf
            let leaf_headers = decode_fixed_list::<_, _, 2>(cb, &nodes[0].arr.arr, zero);
            let (_iterative_key, leaf_value, is_leaf) =
                Circuit::advance_key_leaf_or_extension::<_, _, _, MAX_LEAF_VALUE_LEN>(
                    cb,
                    &nodes[0].arr,
                    &key,
                    &leaf_headers,
                );
            cb.connect(t.target, is_leaf.target);
            let one = cb.one();
            let byte_80 = cb.constant(F::from_canonical_usize(128));
            let value_len = cb.sub(leaf_value.arr[0], byte_80);
            let mut end_iterator = cb.sub(value_len, one);

            let value_arr = Array::<Target, 4> {
                arr: array::from_fn(|i| leaf_value.arr[i + 1]),
            };
            // Then we need to convert from big endian to little endian only on this len
            let extract_len: [Target; 4] = array::from_fn(|i| {
                let it = cb.constant(F::from_canonical_usize(i));
                let in_value = less_than(cb, it, value_len, 4); // log2(4bytes) = 2, putting upper bound
                let rev_value = value_arr.value_at_failover(cb, end_iterator);
                // we can't access index < 0 with b.random_access so a small tweak to avoid it
                let is_done = cb.is_equal(end_iterator, one); // since first byte is RLP header
                let end_iterator_minus_one = cb.sub(end_iterator, one);
                end_iterator = cb.select(is_done, zero, end_iterator_minus_one);
                cb.select(in_value, rev_value, zero)
            });
            let length_value = convert_u8_targets_to_u32(cb, &extract_len)[0].0;
            cb.register_public_input(length_value);
            PidgyWires { slot, nodes }
        }

        fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
            let slot = SimpleSlot::new(self.slot);
            slot.assign(pw, &wires.slot);
            let _ = MPTCircuit::<DEPTH, NODE_LEN>::new(slot.0.mpt_key(), self.nodes.clone());
            let pad_len = DEPTH
                .checked_sub(self.nodes.len())
                .ok_or(anyhow!(
                    "Circuit depth {} too small for this MPT proof {}!",
                    DEPTH,
                    self.nodes.len()
                ))
                .unwrap();
            let padded_nodes = self
                .nodes
                .iter()
                .map(|n| Vector::<u8, { PAD_LEN(NODE_LEN) }>::from_vec(n))
                .chain((0..pad_len).map(|_| Ok(Vector::<u8, { PAD_LEN(NODE_LEN) }>::empty())))
                .collect::<Result<Vec<_>>>()
                .unwrap();
            for (wire, node) in wires.nodes.iter().zip(padded_nodes.iter()) {
                wire.assign(pw, node);
            }
        }
    }

    struct LengthTestData {
        url: String,
        contract: Address,
        len_slot: u8,
        exp_len: u32,
    }

    #[tokio::test]
    #[serial]
    async fn test_length_extract_custom_erc721_sepolia() -> Result<()> {
        let test_data = LengthTestData {
            url: get_sepolia_url(),
            contract: Address::from_str("0x363971ee2b96f360ec9d04b5809afd15c77b1af1")?,
            len_slot: 8,
            exp_len: 2,
        };
        test_length_extract(test_data).await
    }

    #[tokio::test]
    #[serial]
    async fn test_length_extract_pudgy_main() -> Result<()> {
        let test_data = LengthTestData {
            url: get_mainnet_url(),
            contract: Address::from_str("0xBd3531dA5CF5857e7CfAA92426877b022e612cf8")?,
            len_slot: 8,
            exp_len: 8888,
        };
        test_length_extract(test_data).await
    }

    async fn test_length_extract(t: LengthTestData) -> Result<()> {
        let url = t.url;
        let provider =
            Provider::<Http>::try_from(url).expect("could not instantiate HTTP Provider");

        let slot: u8 = t.len_slot;
        let exp_len = t.exp_len;
        // pidgy pinguins
        //let pidgy_address = Address::from_str("0xBd3531dA5CF5857e7CfAA92426877b022e612cf8")?;
        let pidgy_address = t.contract;
        let query = ProofQuery::new_simple_slot(pidgy_address, slot as usize);
        let res = query.query_mpt_proof(&provider, None).await?;
        ProofQuery::verify_storage_proof(&res)?;
        let leaf = res.storage_proof[0].proof.last().unwrap().to_vec();
        let leaf_list: Vec<Vec<u8>> = rlp::decode_list(&leaf);
        assert_eq!(leaf_list.len(), 2);
        let nodes = res.storage_proof[0]
            .proof
            .iter()
            .rev()
            .map(|x| x.to_vec())
            .collect::<Vec<_>>();
        visit_proof(&nodes);

        // implement the circuit logic:
        let first_byte = leaf_list[1][0];
        let slice = if first_byte < 0x80 {
            println!("[+] RLP small value: taking first byte");
            &leaf_list[1][..]
        } else {
            println!("[+] RLP long value: skipping first byte");
            &leaf_list[1][1..]
        }
        .to_vec();
        let slice = left_pad::<4>(&slice); // what happens in circuit effectively
                                           // we have to reverse since encoding is big endian on EVM and our function is little endian based
        let length = convert_u8_to_u32_slice(&slice.into_iter().rev().collect::<Vec<u8>>())[0];
        assert_eq!(length, exp_len);

        // extractd from test_pidgy_pinguins_slot
        const DEPTH: usize = 5;
        const NODE_LEN: usize = 532;
        assert!(nodes.iter().all(|x| x.len() <= NODE_LEN));
        assert!(nodes.len() <= DEPTH);
        // NOTE: only commented out so when things pop up again we can quickly test out
        // why.
        // this works
        //verify_storage_proof_from_query::<DEPTH, NODE_LEN>(&query, &res).unwrap();
        //let circuit = PidgyTest::<DEPTH, NODE_LEN> { slot, nodes };
        //let proof = run_circuit::<F, D, C, _>(circuit);
        //assert_eq!(F::from_canonical_u32(comp_value), proof.public_inputs[0]);
        let test_circuit = LengthTestCircuit::<DEPTH, NODE_LEN> {
            base: ArrayLengthExtractCircuit::new(slot, pidgy_address, nodes),
        };
        let proof = run_circuit::<F, D, C, _>(test_circuit);

        //// Verify the public inputs.
        let pi = PublicInputs::<F>::from(&proof.public_inputs);
        assert_eq!(pi.storage_slot(), F::from_canonical_u8(slot));
        assert_eq!(pi.length_value(), F::from_canonical_u32(length));
        let packed_root = convert_u8_to_u32_slice(res.storage_hash.as_bytes())
            .into_iter()
            .map(F::from_canonical_u32)
            .collect::<Vec<_>>();
        assert_eq!(pi.root_hash_data(), packed_root);
        Ok(())
    }

    fn generate_test_data<const DEPTH: usize>() -> TestData {
        let mut elements = Vec::new();
        let memdb = Arc::new(MemoryDB::new(true));
        let mut trie = EthTrie::new(Arc::clone(&memdb));

        // Loop to insert random elements as long as a random selected proof is
        // not of the right length.
        let mut rng = thread_rng();
        let (slot, contract_address, mpt_key, value_int) = loop {
            println!(
                "[+] Random mpt: insertion of {} elements so far...",
                elements.len(),
            );

            // Generate a MPT key from the slot and contract address.
            let slot = rng.gen::<u8>();
            let contract_address = H160(rng.gen::<[u8; 20]>());
            let storage_slot = StorageSlot::Simple(slot as usize);
            let key = storage_slot.mpt_key_vec();

            // Insert the key and value.
            let value = rng.gen::<u32>();
            // in eth, integers are big endian
            trie.insert(&key, &rlp::encode(&value.to_be_bytes().to_vec()))
                .unwrap();
            trie.root_hash().unwrap();

            // Save the slot, contract address and key temporarily.
            elements.push((slot, contract_address, key, value));

            // Check if any node has the DEPTH elements.
            if let Some((slot, contract_address, key, value)) = elements
                .iter()
                .find(|(_, _, key, _)| trie.get_proof(key).unwrap().len() == DEPTH)
            {
                break (*slot, *contract_address, key, value);
            }
        };

        let root_hash = trie.root_hash().unwrap();
        let value_buff: Vec<u8> = rlp::decode(&trie.get(mpt_key).unwrap().unwrap()).unwrap();
        // value is encoded with bigendian but our conversion to u32 expects little endian
        // and we exactly take 4 bytes so we need padding at the end
        let value_le_padded = value_buff
            .clone()
            .into_iter()
            .rev()
            .chain(std::iter::repeat(0))
            .take(4)
            .collect::<Vec<u8>>();

        let value = convert_u8_to_u32_slice(&value_le_padded)[0];
        assert_eq!(value, *value_int as u32);
        let mut nodes = trie.get_proof(mpt_key).unwrap();
        nodes.reverse();
        assert!(keccak256(nodes.last().unwrap()) == root_hash.to_fixed_bytes());

        TestData {
            slot,
            value,
            contract_address,
            nodes,
        }
    }
}
