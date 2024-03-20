//! This circuit is used to verify the length value extracted from storage trie.

use super::{
    key::{SimpleSlot, SimpleSlotWires},
    MAX_BRANCH_NODE_LEN,
};
use crate::{
    array::Array,
    keccak::{OutputHash, PACKED_HASH_LEN},
    mpt_sequential::{
        Circuit as MPTCircuit, InputWires as MPTInputWires, OutputWires as MPTOutputWires, PAD_LEN,
    },
    types::{PackedAddressTarget, PACKED_ADDRESS_LEN},
    utils::convert_u8_targets_to_u32,
};
use anyhow::Result;
use ethers::types::H160;
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::{target::Target, witness::PartialWitness},
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData},
        config::{AlgebraicHasher, GenericConfig},
    },
};
use plonky2_crypto::u32::arithmetic_u32::U32Target;
use recursion_framework::serialization::circuit_data_serialization::SerializableRichField;
use recursion_framework::serialization::{deserialize, serialize};
use serde::{Deserialize, Serialize};
use std::array::{self, from_fn as create_array};

/// This is a wrapper around an array of targets set as public inputs of any
/// proof generated in this module. They all share the same structure.
/// `C` MPT root hash
/// `S` storage slot of the variable holding the length
/// `V` Integer value stored at key `S` (can be given by prover)
#[derive(Clone, Debug)]
pub(crate) struct PublicInputs<'a, T: Clone> {
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
        mpt_root_hash.register_as_input(cb);
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

#[derive(Clone, Debug)]
pub struct LengthExtractCircuit<const DEPTH: usize, const NODE_LEN: usize> {
    /// Storage slot saved the length value
    slot: SimpleSlot,
    /// MPT circuit used to verify the nodes of storage Merkle Tree
    mpt_circuit: MPTCircuit<DEPTH, NODE_LEN>,
}

impl<const DEPTH: usize, const NODE_LEN: usize> LengthExtractCircuit<DEPTH, NODE_LEN>
where
    [(); PAD_LEN(NODE_LEN)]:,
    [(); DEPTH - 1]:,
{
    pub fn new(slot: u8, contract_address: H160, nodes: Vec<Vec<u8>>) -> Self {
        let slot = SimpleSlot::new(slot);
        let mpt_circuit = MPTCircuit::new(slot.0.mpt_key(), nodes);

        Self { slot, mpt_circuit }
    }

    /// Build for circuit.
    pub fn build<F, const D: usize>(
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
        //mpt_input.nodes.iter().for_each(|n| n.assert_bytes(cb));

        // NOTE: The length value shouldn't exceed 4-bytes (U32).
        // We read the RLP header but knowing it is a value that is always <55bytes long
        // we can hardcode the type of RLP header it is and directly get the real number len
        // in this case, the header marker is 0x80 that we can directly take out from first byte
        //let byte_80 = cb.constant(F::from_canonical_usize(128));
        //let value_len = cb.sub(mpt_output.leaf.arr[0], byte_80);
        // Normally one should do the following to access element with index
        // let value_len_it = cb.sub(value_len, one);
        // but in our case, since the first byte is the RLP header, we have to do +1
        // so we just keep the same value
        //let mut value_len_it = value_len;
        //// Then we need to convert from big endian to little endian only on this len
        //let extract_len: [Target; 4] = create_array(|i| {
        //    let it = cb.constant(F::from_canonical_usize(i));
        //    let in_value = less_than(cb, it, value_len, 3); // log2(4) = 2, putting upper bound
        //    let rev_value = mpt_output.leaf.value_at(cb, value_len_it);
        //    // we can't access index < 0 with b.random_access so a small tweak to avoid it
        //    let is_done = cb.is_equal(value_len_it, zero);
        //    let value_len_it_minus_one = cb.sub(value_len_it, one);
        //    value_len_it = cb.select(is_done, zero, value_len_it_minus_one);
        //    cb.select(in_value, rev_value, zero)
        //});
        //let length_value = convert_u8_targets_to_u32(cb, &extract_len)[0].0;
        let length_value = cb.zero();

        // Register the public inputs.
        PublicInputs::register(cb, &mpt_output.root, slot.slot, length_value);

        LengthExtractWires {
            slot,
            mpt_input,
            mpt_output,
        }
    }

    /// Assign the wires.
    pub fn assign<F, const D: usize>(
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
        let mut cb = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        let wires = LengthExtractCircuit::<DEPTH, NODE_LEN>::build(&mut cb);
        let data = cb.build();
        Self { data, wires }
    }
    pub fn generate(&self, inputs: LengthExtractCircuit<DEPTH, NODE_LEN>) -> Result<Vec<u8>> {
        let mut pw = PartialWitness::new();
        inputs.assign::<F, D>(&mut pw, &self.wires)?;
        let proof = self.data.prove(pw)?;
        // TODO: move serialization to common place
        let b = bincode::serialize(&proof)?;
        Ok(b)
    }
}

pub const MAX_DEPTH_TRIE: usize = 4;
pub type CircuitInput = LengthExtractCircuit<MAX_DEPTH_TRIE, MAX_BRANCH_NODE_LEN>;
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
        array::{Vector, VectorWire},
        benches::init_logging,
        circuit::{test::run_circuit, UserCircuit},
        eth::{ProofQuery, StorageSlot},
        keccak::{InputData, KeccakCircuit, KeccakWires},
        mpt_sequential::{
            bytes_to_nibbles,
            test::{verify_storage_proof_from_query, visit_proof},
            MPTKeyWire,
        },
        rlp::{MAX_ITEMS_IN_LIST, MAX_KEY_NIBBLE_LEN},
        utils::{convert_u8_to_u32_slice, keccak256},
    };
    use eth_trie::{EthTrie, MemoryDB, Nibbles, Trie};
    use ethers::{
        providers::{Http, Provider},
        types::{Address, H160},
    };
    use plonky2::{
        field::types::Field,
        iop::witness::{PartialWitness, WitnessWrite},
        plonk::config::{GenericConfig, PoseidonGoldilocksConfig},
    };
    use rand::{thread_rng, Rng};
    use std::{convert, str::FromStr, sync::Arc};

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
        base: LengthExtractCircuit<DEPTH, NODE_LEN>,
    }

    impl<const DEPTH: usize, const NODE_LEN: usize> UserCircuit<F, D>
        for LengthTestCircuit<DEPTH, NODE_LEN>
    where
        [(); PAD_LEN(NODE_LEN)]:,
        [(); DEPTH - 1]:,
    {
        type Wires = LengthExtractWires<DEPTH, NODE_LEN>;

        fn build(cb: &mut CircuitBuilder<F, D>) -> Self::Wires {
            LengthExtractCircuit::build(cb)
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
        let exp_contract_address: Vec<_> = convert_u8_to_u32_slice(&test_data.contract_address.0)
            .into_iter()
            .map(F::from_canonical_u32)
            .collect();

        let test_circuit = LengthTestCircuit::<DEPTH, NODE_LEN> {
            base: LengthExtractCircuit::new(
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
        contract_address: H160,
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
        keccak_wires: Vec<KeccakWires<{ PAD_LEN(NODE_LEN) }>>,
        child_hashes: [Array<Target, 32>; DEPTH - 1],
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
                create_array(|_| VectorWire::<Target, { PAD_LEN(NODE_LEN) }>::new(cb));
            // small optimization here as we only need to decode two items for a leaf, since we know it's a leaf
            let leaf_headers = decode_fixed_list::<_, _, 2>(cb, &nodes[0].arr.arr, zero);
            let (mut iterative_key, leaf_value, is_leaf) =
                Circuit::advance_key_leaf_or_extension(cb, &nodes[0].arr, &key, &leaf_headers);
            cb.connect(t.target, is_leaf.target);
            let mut keccak_wires = vec![];
            let leaf_hash = KeccakCircuit::<{ PAD_LEN(NODE_LEN) }>::hash_vector(cb, &nodes[0]);
            let mut last_hash_output = leaf_hash.output_array.clone();
            keccak_wires.push(leaf_hash);
            let expected_hashes_bytes: [Array<Target, 32>; DEPTH - 1] =
                create_array(|i| Array::new(cb));
            for i in 1..DEPTH {
                // look if hash is inside the node
                let (new_key, extracted_child_hash, valid_node) =
                    Circuit::advance_key(cb, &nodes[i].arr, &iterative_key);
                let extracted_hash_u32 = convert_u8_targets_to_u32(cb, &extracted_child_hash.arr);
                let found_hash_in_parent = last_hash_output.equals(
                    cb,
                    &Array::<U32Target, PACKED_HASH_LEN> {
                        arr: extracted_hash_u32.try_into().unwrap(),
                    },
                );
                if i < 2 {
                    //cb.connect(valid_node.target,t.target);
                    extracted_child_hash.enforce_equal(cb, &expected_hashes_bytes[i - 1]);
                    //cb.connect(t.target, found_hash_in_parent.target);
                }
                let hash_wires = KeccakCircuit::<{ PAD_LEN(NODE_LEN) }>::hash_vector(cb, &nodes[i]);
                iterative_key = new_key;
                keccak_wires.push(hash_wires)
            }
            PidgyWires {
                slot,
                nodes,
                keccak_wires,
                child_hashes: expected_hashes_bytes,
            }
        }

        fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
            let slot = SimpleSlot::new(self.slot);
            slot.assign(pw, &wires.slot);
            let mpt_circuit =
                MPTCircuit::<DEPTH, NODE_LEN>::new(slot.0.mpt_key(), self.nodes.clone());
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
            for (i, (wire, node)) in wires.nodes.iter().zip(padded_nodes.iter()).enumerate() {
                wire.assign(pw, node);
                KeccakCircuit::<{ PAD_LEN(NODE_LEN) }>::assign(
                    pw,
                    &wires.keccak_wires[i],
                    // Given we already assign the input data elsewhere, we notify to keccak circuit
                    // that it doesn't need to assign it again, just its add. wires.
                    // TODO: this might be doable via a generator implementation with Plonky2...?
                    &InputData::Assigned(node),
                );
            }
            // assign child hashes
            self.nodes
                .iter()
                .map(|n| keccak256(n))
                .take(DEPTH - 1)
                .zip(wires.child_hashes.iter())
                .enumerate()
                .for_each(|(i, (hash, wire))| {
                    println!("hash {}: {:?}", i, hash);
                    wire.assign_from_data(pw, &hash.try_into().unwrap());
                });
        }
    }

    #[derive(Clone, Debug)]
    struct ExtractionHashPidgy<const DEPTH: usize, const NODE_LEN: usize> {
        slot: u8,
        contract_address: H160,
        nodes: Vec<Vec<u8>>,
        after_leaf_key: (Vec<u8>, usize),
    }

    #[derive(Clone, Debug)]
    struct ExtractionWires<const DEPTH: usize, const NODE_LEN: usize>
    where
        [(); { PAD_LEN(NODE_LEN) }]:,
        [(); DEPTH - 1]:,
    {
        slot: SimpleSlotWires,
        exp_mpt_key: Array<Target, MAX_KEY_NIBBLE_LEN>,
        nodes: [VectorWire<Target, { PAD_LEN(NODE_LEN) }>; DEPTH],
        child_hashes: [Array<Target, 32>; DEPTH - 1],
        keccak_wires: [KeccakWires<{ PAD_LEN(NODE_LEN) }>; 1],
        exp_leaf_key: MPTKeyWire,
    }

    impl<const DEPTH: usize, const NODE_LEN: usize> UserCircuit<F, D>
        for ExtractionHashPidgy<DEPTH, NODE_LEN>
    where
        [(); DEPTH - 1]:,
        [(); { PAD_LEN(NODE_LEN) }]:,
    {
        type Wires = ExtractionWires<DEPTH, NODE_LEN>;

        fn build(b: &mut CircuitBuilder<F, D>) -> Self::Wires {
            let zero = b.zero();
            let t = b._true();
            let slot = SimpleSlot::build(b);
            let key = slot.mpt_key.clone();
            let exp_key = Array::<Target, MAX_KEY_NIBBLE_LEN>::new(b);
            key.key.enforce_equal(b, &exp_key);
            let exp_leaf_key = MPTKeyWire::new(b);
            exp_key.enforce_equal(b, &exp_leaf_key.key);
            let nodes: [VectorWire<Target, _>; DEPTH] =
                create_array(|_| VectorWire::<Target, { PAD_LEN(NODE_LEN) }>::new(b));
            let expected_hashes_bytes: [Array<Target, 32>; DEPTH - 1] =
                create_array(|i| Array::new(b));

            let leaf_headers = decode_fixed_list::<_, _, 2>(b, &nodes[0].arr.arr, zero);
            let (mut iterative_key, leaf_value, is_leaf) =
                Circuit::advance_key_leaf_or_extension(b, &nodes[0].arr, &key, &leaf_headers);
            b.connect(t.target, is_leaf.target);
            for (i, (comp_nib, exp_nib)) in iterative_key
                .key
                .arr
                .iter()
                .zip(exp_leaf_key.key.arr.iter())
                .enumerate()
            {
                if i < 0 {
                    b.connect(*comp_nib, *exp_nib);
                }
            }

            let leaf_hash = KeccakCircuit::<{ PAD_LEN(NODE_LEN) }>::hash_vector(b, &nodes[0]);
            let mut last_hash_output = leaf_hash.output_array.clone();
            let mut keccak_wires = vec![leaf_hash];
            // read from parent node
            for i in 1..2 {
                //let (new_key, extracted_child_hash, valid_node) =
                // Circuit::<DEPTH, NODE_LEN>::advance_key(b, &nodes[i].arr, &iterative_key);

                let (new_key, extracted_child_hash) = {
                    let rlp_headers =
                        decode_fixed_list::<F, D, MAX_ITEMS_IN_LIST>(b, &nodes[i].arr.arr, zero);
                    let leaf_info = Circuit::advance_key_leaf_or_extension(
                        b,
                        &nodes[i].arr,
                        &key,
                        &rlp_headers,
                    );
                    let tuple_condition = leaf_info.2;
                    let branch_info =
                        Circuit::advance_key_branch(b, &nodes[i].arr, &key, &rlp_headers);
                    let tuple_or_branch = b.or(leaf_info.2, branch_info.2);
                    let child_hash = leaf_info.1.select(b, tuple_condition, &branch_info.1);
                    let new_key = leaf_info.0.select(b, tuple_condition, &branch_info.0);
                    new_key.key.enforce_equal(b, &branch_info.0.key);
                    (new_key, child_hash)
                };

                //extracted_child_hash.enforce_equal(b, &expected_hashes_bytes[i - 1]);
                //let hash_wires = KeccakCircuit::<{ PAD_LEN(NODE_LEN) }>::hash_vector(b, &nodes[i]);
                //let extracted_hash_u32 = convert_u8_targets_to_u32(b, &extracted_child_hash.arr);
                //last_hash_output.enforce_equal(
                //    b,
                //    &Array::<U32Target, PACKED_HASH_LEN> {
                //        arr: extracted_hash_u32.try_into().unwrap(),
                //    },
                //);
                //last_hash_output = hash_wires.output_array.clone();
                //keccak_wires.push(hash_wires);
                iterative_key = new_key;
            }

            ExtractionWires {
                slot,
                exp_mpt_key: exp_key,
                nodes,
                child_hashes: expected_hashes_bytes,
                keccak_wires: keccak_wires.try_into().unwrap(),
                exp_leaf_key,
            }
        }

        fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
            let storage_slot = StorageSlot::Simple(self.slot as usize);
            let slot_circuit = SimpleSlot::from(storage_slot.clone());
            slot_circuit.assign(pw, &wires.slot);
            wires.exp_leaf_key.assign(
                pw,
                &self.after_leaf_key.0.clone().try_into().unwrap(),
                self.after_leaf_key.1,
            );
            assert!(bytes_to_nibbles(&storage_slot.mpt_key_vec()) == self.after_leaf_key.0);
            wires.exp_mpt_key.assign_bytes(
                pw,
                &bytes_to_nibbles(&storage_slot.mpt_key_vec())
                    .try_into()
                    .unwrap(),
            );
            let mpt_circuit = MPTCircuit::<DEPTH, NODE_LEN>::new(
                storage_slot.mpt_key_vec().try_into().unwrap(),
                self.nodes.clone(),
            );
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
            // assign child hashes
            self.nodes
                .iter()
                .map(|n| keccak256(n))
                .take(DEPTH - 1)
                .zip(wires.child_hashes.iter())
                .for_each(|(hash, wire)| {
                    wire.assign_from_data(pw, &hash.try_into().unwrap());
                });

            for (i, (wire, node)) in wires.nodes.iter().zip(padded_nodes.iter()).enumerate() {
                wire.assign(pw, node);
                if i < 1 {
                    KeccakCircuit::<{ PAD_LEN(NODE_LEN) }>::assign(
                        pw,
                        &wires.keccak_wires[i],
                        // Given we already assign the input data elsewhere, we notify to keccak circuit
                        // that it doesn't need to assign it again, just its add. wires.
                        // TODO: this might be doable via a generator implementation with Plonky2...?
                        &InputData::Assigned(node),
                    );
                }
            }
        }
    }

    #[tokio::test]
    #[serial]
    async fn test_length_extract_pidgy_contract() -> Result<()> {
        //let url = "https://eth.llamarpc.com";
        let url = "https://eth-mainnet.g.alchemy.com/v2/tiJoGEC6P5-Ln4vORe52r7Qvxa8JsSj7";
        let provider =
            Provider::<Http>::try_from(url).expect("could not instantiate HTTP Provider");

        let slot: u8 = 8;
        // pidgy pinguins
        let pidgy_address = Address::from_str("0xBd3531dA5CF5857e7CfAA92426877b022e612cf8")?;
        let query = ProofQuery::new_simple_slot(pidgy_address, slot as usize);
        let res = query.query_mpt_proof(&provider, None).await?;
        ProofQuery::verify_storage_proof(&res)?;
        let leaf = res.storage_proof[0].proof.last().unwrap().to_vec();
        let leaf_list: Vec<Vec<u8>> = rlp::decode_list(&leaf);
        assert_eq!(leaf_list.len(), 2);
        let leaf_value: Vec<u8> = rlp::decode(&leaf_list[1]).unwrap();
        // making sure we can simply skip the first byte - imitate circuit
        let sliced = &leaf_list[1][1..];
        assert_eq!(sliced, leaf_value.as_slice());
        // extracting len from RLP header - imitate circuit
        let len_slice = rlp::Rlp::new(&leaf_list[1])
            .payload_info()
            .unwrap()
            .value_len;
        // check that subbing 0x80 works
        let rlp_len_slice = leaf_list[1][0] - 128;
        assert_eq!(rlp_len_slice as usize, len_slice);
        let le_value: [u8; 4] = create_array(|i| {
            if i < len_slice {
                sliced[len_slice - 1 - i]
            } else {
                0
            }
        });
        let comp_value = convert_u8_to_u32_slice(&le_value)[0];
        assert_eq!(comp_value, 8888); // from contract
        println!("correct conversion ! ");
        let nodes = res.storage_proof[0]
            .proof
            .iter()
            .rev()
            .map(|x| x.to_vec())
            .collect::<Vec<_>>();
        visit_proof(&nodes);
        // extractd from test_pidgy_pinguins_slot
        const DEPTH: usize = 5;
        const NODE_LEN: usize = 532;
        assert!(nodes.iter().all(|x| x.len() <= NODE_LEN));
        assert!(nodes.len() <= DEPTH);
        // this works
        //verify_storage_proof_from_query::<DEPTH, NODE_LEN>(&query, &res).unwrap();
        //let circuit = PidgyTest::<DEPTH, NODE_LEN> {
        //    slot,
        //    contract_address: pidgy_address,
        //    nodes,
        //};
        //let circuit = ExtractionHashPidgy::<DEPTH, NODE_LEN> {
        //    slot,
        //    contract_address: pidgy_address,
        //    nodes: nodes.clone(),
        //    after_leaf_key: {
        //        let leaf: Vec<Vec<u8>> = rlp::decode_list(&nodes[0]);
        //        let key_nibbles_struct = Nibbles::from_compact(&leaf[0]);
        //        let key_nibbles = key_nibbles_struct.nibbles();
        //        let ptr = MAX_KEY_NIBBLE_LEN - 1 - key_nibbles.len();
        //        let branch: Vec<Vec<u8>> = rlp::decode_list(&nodes[1]);
        //        let mpt_key_nibbles = bytes_to_nibbles(&query.slot.mpt_key_vec());
        //        {
        //            let slot = SimpleSlot::new(slot);
        //            let slot_key_nibbles = bytes_to_nibbles(&slot.0.mpt_key_vec());
        //            assert!(
        //                mpt_key_nibbles == slot_key_nibbles,
        //                "MPT SLOT vs Query SLOT (eth) failing"
        //            );
        //        }
        //        let leaf_hash = branch[mpt_key_nibbles[ptr] as usize].clone();
        //        let exp_hash = keccak256(&nodes[0]);
        //        assert_eq!(leaf_hash, exp_hash);
        //        println!(
        //            "Check hash inclusion of leaf done -> FULL {:?}",
        //            bytes_to_nibbles(&query.slot.mpt_key_vec())
        //        );
        //        (mpt_key_nibbles, ptr)
        //    },
        //};
        //run_circuit::<F, D, C, _>(circuit);
        let test_circuit = LengthTestCircuit::<DEPTH, NODE_LEN> {
            base: LengthExtractCircuit::new(slot, pidgy_address, nodes),
        };
        let proof = run_circuit::<F, D, C, _>(test_circuit);

        //// Verify the public inputs.
        //let pi = PublicInputs::<F>::from(&proof.public_inputs);
        //assert_eq!(pi.storage_slot(), F::from_canonical_u8(slot));
        //assert_eq!(pi.length_value(), F::from_canonical_u32(comp_value));
        //let packed_root = convert_u8_to_u32_slice(res.storage_hash.as_bytes())
        //    .into_iter()
        //    .map(F::from_canonical_u32)
        //    .collect::<Vec<_>>();
        //assert_eq!(pi.root_hash_data(), packed_root);
        //let packed_address = convert_u8_to_u32_slice(&pidgy_address.as_bytes())
        //    .into_iter()
        //    .map(F::from_canonical_u32)
        //    .collect::<Vec<_>>();
        //assert_eq!(pi.packed_contract_address(), packed_address);
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
