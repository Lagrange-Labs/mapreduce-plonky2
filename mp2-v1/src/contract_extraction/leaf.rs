//! Module handling the leaf node inside a state trie

use super::public_inputs::PublicInputs;
use crate::MAX_LEAF_NODE_LEN;
use ethers::prelude::H160;
use mp2_common::{
    array::{Array, Vector, VectorWire},
    group_hashing::CircuitBuilderGroupHashing,
    keccak::{InputData, KeccakCircuit, KeccakWires, OutputByteHash, HASH_LEN},
    mpt_sequential::{MPTKeyWire, MPTLeafOrExtensionNode, MAX_LEAF_VALUE_LEN, PAD_LEN},
    public_inputs::PublicInputCommon,
    types::{AddressTarget, CBuilder, ADDRESS_LEN},
    utils::{less_than, ToTargets},
    D, F,
};
use plonky2::{
    field::types::Field,
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::circuit_builder::CircuitBuilder,
};
use recursion_framework::circuit_builder::CircuitLogicWires;
use serde::{Deserialize, Serialize};

/// Keccak input padded length for address
const INPUT_PADDED_ADDRESS_LEN: usize = PAD_LEN(ADDRESS_LEN);

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct LeafWires<const NODE_LEN: usize>
where
    [(); PAD_LEN(NODE_LEN)]:,
{
    /// The contract address
    contract_address: AddressTarget,
    /// The keccak wires computed from contract address, which is set to the
    /// state MPT root hash
    keccak_contract_address: KeccakWires<INPUT_PADDED_ADDRESS_LEN>,
    /// The offset of storage MPT root hash located in RLP encoded account node
    storage_root_offset: Target,
    node: VectorWire<Target, { PAD_LEN(NODE_LEN) }>,
    root: KeccakWires<{ PAD_LEN(NODE_LEN) }>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct LeafCircuit<const NODE_LEN: usize> {
    pub(crate) contract_address: H160,
    /// The offset of storage root hash located in RLP encoded account node
    pub(crate) storage_root_offset: usize,
    pub(crate) node: Vec<u8>,
}

impl<const NODE_LEN: usize> LeafCircuit<NODE_LEN>
where
    [(); PAD_LEN(NODE_LEN)]:,
{
    fn build(b: &mut CBuilder) -> LeafWires<NODE_LEN> {
        let zero = b.zero();
        let ttrue = b._true();
        let contract_address = Array::new(b);

        let storage_root_offset = b.add_virtual_target();

        // Calculate the keccak hash of contract address, and use it as the
        // state MPT root hash.
        let mut arr = [zero; INPUT_PADDED_ADDRESS_LEN];
        arr[..ADDRESS_LEN].copy_from_slice(&contract_address.arr);
        let bytes_to_keccak = &VectorWire::<Target, INPUT_PADDED_ADDRESS_LEN> {
            real_len: b.constant(F::from_canonical_usize(ADDRESS_LEN)),
            arr: Array { arr },
        };
        let keccak_contract_address = KeccakCircuit::hash_vector(b, bytes_to_keccak);
        let mpt_key = MPTKeyWire::init_from_u32_targets(b, &keccak_contract_address.output_array);

        // Build the node wires.
        let wires =
            MPTLeafOrExtensionNode::build_and_advance_key::<_, D, NODE_LEN, MAX_LEAF_VALUE_LEN>(
                b, &mpt_key,
            );
        let node = wires.node;
        let root = wires.root;
        let new_mpt_key = wires.key;

        // Verify the account node includes the hash of storage MPT root.
        // storage_root_offfset < node_real_len - hash_len + 1
        let hash_len_sub_one = b.constant(F::from_canonical_usize(HASH_LEN - 1));
        let max_storage_root_offset = b.sub(node.real_len, hash_len_sub_one);
        let within_range = less_than(b, storage_root_offset, max_storage_root_offset, 7);
        b.connect(within_range.target, ttrue.target);

        // Extract the storage root hash.
        let storage_root: OutputByteHash = node.arr.extract_array(b, storage_root_offset);

        // Register the public inputs.
        let h = root.output_array.to_targets().arr;
        // Compute the metadata digest - `D(pack_u32(contract_address))`.
        let packed_contract_address = contract_address.convert_u8_to_u32(b).to_targets().arr;
        let dm = b.map_to_curve_point(&packed_contract_address).to_targets();
        let s = storage_root.convert_u8_to_u32(b).to_targets().arr;
        PublicInputs::new(&h, &dm, &new_mpt_key.key.arr, &new_mpt_key.pointer, &s).register(b);

        LeafWires {
            contract_address,
            keccak_contract_address,
            storage_root_offset,
            node,
            root,
        }
    }

    /// Assign the wires.
    fn assign(&self, pw: &mut PartialWitness<F>, wires: &LeafWires<NODE_LEN>) {
        // Assign the contract address.
        wires
            .contract_address
            .assign(pw, &self.contract_address.0.map(F::from_canonical_u8));

        // Assign the keccak value of contract address.
        KeccakCircuit::<{ PAD_LEN(ADDRESS_LEN) }>::assign(
            pw,
            &wires.keccak_contract_address,
            &InputData::Assigned(
                &Vector::from_vec(&self.contract_address.0)
                    .expect("Cannot create vector input for keccak contract address"),
            ),
        );

        // Assign the offset of storage root hash located in RLP encoded account node.
        pw.set_target(
            wires.storage_root_offset,
            F::from_canonical_usize(self.storage_root_offset),
        );

        let pad_node =
            Vector::<u8, { PAD_LEN(NODE_LEN) }>::from_vec(&self.node).expect("invalid node given");
        wires.node.assign(pw, &pad_node);
        KeccakCircuit::<{ PAD_LEN(NODE_LEN) }>::assign(
            pw,
            &wires.root,
            &InputData::Assigned(&pad_node),
        );
    }
}

/// Num of children = 0
impl CircuitLogicWires<F, D, 0> for LeafWires<MAX_LEAF_NODE_LEN> {
    type CircuitBuilderParams = ();

    type Inputs = LeafCircuit<MAX_LEAF_NODE_LEN>;

    const NUM_PUBLIC_INPUTS: usize = PublicInputs::<F>::TOTAL_LEN;

    fn circuit_logic(
        builder: &mut CircuitBuilder<F, D>,
        _verified_proofs: [&plonky2::plonk::proof::ProofWithPublicInputsTarget<D>; 0],
        _builder_parameters: Self::CircuitBuilderParams,
    ) -> Self {
        LeafCircuit::build(builder)
    }

    fn assign_input(&self, inputs: Self::Inputs, pw: &mut PartialWitness<F>) -> anyhow::Result<()> {
        inputs.assign(pw, self);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use eth_trie::{Nibbles, Trie};
    use ethers::types::Address;
    use mp2_common::{
        group_hashing::map_to_curve_point,
        keccak::HASH_LEN,
        mpt_sequential::{mpt_key_ptr, utils::bytes_to_nibbles},
        rlp::MAX_KEY_NIBBLE_LEN,
        types::MAPPING_LEAF_VALUE_LEN,
        utils::{convert_u8_to_u32_slice, keccak256},
        C,
    };
    use mp2_test::{
        circuit::{run_circuit, UserCircuit},
        mpt_sequential::generate_random_storage_mpt,
        utils::random_vector,
    };
    use plonky2::field::types::Field;
    use rand::{thread_rng, Rng};
    use std::str::FromStr;

    const TEST_CONTRACT_ADDRESS: &str = "0x105dD0eF26b92a3698FD5AaaF688577B9Cafd970";

    impl<const NODE_LEN: usize> UserCircuit<F, D> for LeafCircuit<NODE_LEN>
    where
        [(); PAD_LEN(NODE_LEN)]:,
    {
        type Wires = LeafWires<NODE_LEN>;

        fn build(b: &mut CBuilder) -> Self::Wires {
            LeafCircuit::<NODE_LEN>::build(b)
        }

        fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
            self.assign(pw, wires);
        }
    }

    #[test]
    fn test_contract_extraction_leaf_circuit() {
        const NODE_LEN: usize = 80;

        let contract_address = Address::from_str(TEST_CONTRACT_ADDRESS).unwrap();
        let mpt_key = keccak256(&contract_address.0);

        let (mut trie, _) = generate_random_storage_mpt::<3, MAPPING_LEAF_VALUE_LEN>();
        let value = random_vector(MAPPING_LEAF_VALUE_LEN);
        let encoded_value: Vec<u8> = rlp::encode(&value).to_vec();
        trie.insert(&mpt_key, &encoded_value).unwrap();
        trie.root_hash().unwrap();

        let proof = trie.get_proof(&mpt_key).unwrap();
        let node = proof.last().unwrap().clone();
        let storage_root_offset = thread_rng().gen_range(0..node.len() - HASH_LEN);
        let storage_root = &node[storage_root_offset..storage_root_offset + HASH_LEN];

        let test_circuit = LeafCircuit::<NODE_LEN> {
            contract_address,
            node: node.clone(),
            storage_root_offset,
        };

        let proof = run_circuit::<F, D, C, _>(test_circuit);
        let pi = PublicInputs::from_slice(&proof.public_inputs);

        // Check packed block hash
        {
            let exp_block_hash = keccak256(&node);
            let exp_block_hash: Vec<_> = convert_u8_to_u32_slice(&exp_block_hash)
                .into_iter()
                .map(F::from_canonical_u32)
                .collect();

            assert_eq!(pi.h, exp_block_hash);
        }
        // Check metadata digest
        {
            let packed_contract_address: Vec<_> = convert_u8_to_u32_slice(&contract_address.0)
                .into_iter()
                .map(F::from_canonical_u32)
                .collect();

            let exp_digest = map_to_curve_point(&packed_contract_address);
            assert_eq!(pi.metadata_point(), exp_digest.to_weierstrass());
        }
        // Check MPT key and pointer
        {
            let key = pi.k;
            let ptr = pi.t;

            let exp_key: Vec<_> = bytes_to_nibbles(&mpt_key)
                .into_iter()
                .map(F::from_canonical_u8)
                .collect();
            assert_eq!(key, exp_key);

            let leaf_key: Vec<Vec<u8>> = rlp::decode_list(&node);
            let exp_ptr = F::from_canonical_usize(mpt_key_ptr(&leaf_key[0]));
            assert_eq!(exp_ptr, *ptr);
        }
        // Check packed storage root hash
        {
            let exp_storage_root_hash: Vec<_> = convert_u8_to_u32_slice(storage_root)
                .into_iter()
                .map(F::from_canonical_u32)
                .collect();

            assert_eq!(pi.s, exp_storage_root_hash);
        }
    }
}
