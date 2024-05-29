//! Database length extraction circuits

use core::array;

use mp2_common::{
    array::Vector,
    group_hashing::CircuitBuilderGroupHashing,
    keccak::PACKED_HASH_LEN,
    mpt_sequential::{
        MPTLeafOrExtensionNode, MPTLeafOrExtensionWires, MAX_LEAF_VALUE_LEN, PAD_LEN,
    },
    public_inputs::PublicInputCommon,
    storage_key::{SimpleSlot, SimpleSlotWires},
    types::{CBuilder, GFp},
    utils::less_than,
    D,
};
use plonky2::{
    field::types::Field,
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
};

use super::PublicInputs;

/// The wires structure for the leaf length extraction.
#[derive(Clone, Debug)]
pub struct LeafLengthWires<const NODE_LEN: usize>
where
    [(); PAD_LEN(NODE_LEN)]:,
{
    pub length_slot: SimpleSlotWires,
    pub length_mpt: MPTLeafOrExtensionWires<NODE_LEN, MAX_LEAF_VALUE_LEN>,
    pub variable_slot: Target,
}

/// The circuit definition for the leaf length extraction.
#[derive(Clone, Debug)]
pub struct LeafLengthCircuit<const NODE_LEN: usize>
where
    [(); PAD_LEN(NODE_LEN)]:,
{
    pub length_slot: SimpleSlot,
    pub length_node: Vector<u8, { PAD_LEN(NODE_LEN) }>,
    pub variable_slot: u8,
}

impl<const NODE_LEN: usize> LeafLengthCircuit<NODE_LEN>
where
    [(); PAD_LEN(NODE_LEN)]:,
{
    /// Creates a new instance of the circuit.
    pub fn new(length_slot: u8, length_node: &[u8], variable_slot: u8) -> anyhow::Result<Self> {
        Ok(Self {
            length_slot: SimpleSlot::new(length_slot),
            length_node: Vector::from_vec(length_node)?,
            variable_slot,
        })
    }

    /// Build the circuit, assigning the public inputs and returning the internal wires.
    pub fn build(cb: &mut CBuilder) -> LeafLengthWires<NODE_LEN> {
        let zero = cb.zero();
        let one = cb.one();

        // we don't range check the variable and length slots as they are part of the DM public
        // commitment
        let variable_slot = cb.add_virtual_target();
        let length_slot = SimpleSlot::build(cb);

        let length_mpt =
            MPTLeafOrExtensionNode::build_and_advance_key::<_, D, NODE_LEN, MAX_LEAF_VALUE_LEN>(
                cb,
                &length_slot.mpt_key,
            );

        // extract the rlp encoded value
        let prefix = length_mpt.value[0];
        let x80 = cb.constant(GFp::from_canonical_usize(128));
        let is_single_byte = less_than(cb, prefix, x80, 8);
        let rlp_value_x80 = cb.sub(prefix, x80);
        let rlp_value = cb.select(is_single_byte, one, rlp_value_x80);
        let offset = cb.select(is_single_byte, zero, one);
        let length_rlp_encoded = length_mpt
            .value
            .extract_array::<GFp, D, 4>(cb, offset)
            .into_vec(rlp_value)
            .normalize_left::<GFp, D, 4>(cb)
            .reverse()
            .convert_u8_to_u32(cb)[0];

        let dm = &cb.map_to_curve_point(&[length_slot.slot, variable_slot]);
        let h = &array::from_fn::<_, PACKED_HASH_LEN, _>(|i| length_mpt.root.output_array.arr[i].0);
        let k = &length_mpt.key.key.arr;
        let t = &length_mpt.key.pointer;
        let n = &length_rlp_encoded.0;

        PublicInputs::new(h, dm, k, t, n).register(cb);

        LeafLengthWires {
            length_slot,
            length_mpt,
            variable_slot,
        }
    }

    /// Assigns the values of this instance into the provided partial witness, using the generated
    /// circuit wires.
    pub fn assign(&self, pw: &mut PartialWitness<GFp>, wires: &LeafLengthWires<NODE_LEN>) {
        pw.set_target(
            wires.variable_slot,
            GFp::from_canonical_u8(self.variable_slot),
        );

        self.length_slot.assign(pw, &wires.length_slot);
        wires.length_mpt.assign(pw, &self.length_node);
    }
}

#[cfg(test)]
pub mod tests {
    use std::{array, sync::Arc};

    use eth_trie::{EthTrie, MemoryDB, Nibbles, Trie};
    use mp2_common::{
        eth::StorageSlot,
        group_hashing::{map_to_curve_point, EXTENSION_DEGREE},
        rlp::MAX_KEY_NIBBLE_LEN,
        types::{GFp, GFp5},
        utils::{convert_u8_to_u32_slice, keccak256},
        D,
    };
    use mp2_test::circuit::{prove_circuit, setup_circuit};
    use plonky2::{
        field::{extension::FieldExtension, types::Field},
        plonk::config::PoseidonGoldilocksConfig,
    };
    use plonky2_ecgfp5::curve::curve::WeierstrassPoint;
    use rand::{rngs::StdRng, Rng, RngCore, SeedableRng};

    use crate::length_extraction::{LeafLengthCircuit, PublicInputs};

    const NODE_LEN: usize = 532;

    #[test]
    fn prove_and_verify_length_extraction_leaf_circuit() {
        let rng = &mut StdRng::seed_from_u64(0xffff);
        let memdb = Arc::new(MemoryDB::new(true));
        let setup = setup_circuit::<_, D, PoseidonGoldilocksConfig, LeafLengthCircuit<NODE_LEN>>();
        let mut trie = EthTrie::new(Arc::clone(&memdb));
        let mut cases = vec![];

        cases.push(TestCase {
            depth: 1,
            length: 0,
        });
        cases.push(TestCase {
            depth: 2,
            length: 15,
        });
        cases.push(TestCase {
            depth: 3,
            length: u32::MAX - 1,
        });

        for TestCase { depth, length } in cases {
            let (length_slot, proof, mpt_key, value, variable_slot) = loop {
                let length_slot = rng.gen::<u8>();
                let variable_slot = rng.gen::<u8>();
                let storage_slot = StorageSlot::Simple(length_slot as usize);

                let mpt_key = storage_slot.mpt_key_vec();
                let value = rng.next_u32();
                let encoded = rlp::encode(&value).to_vec();

                trie.insert(&mpt_key, &encoded).unwrap();
                trie.root_hash().unwrap();

                let proof = trie.get_proof(&mpt_key).unwrap();
                if proof.len() == depth {
                    let value = length;
                    let encoded = rlp::encode(&value).to_vec();

                    trie.insert(&mpt_key, &encoded).unwrap();
                    trie.root_hash().unwrap();

                    let proof = trie.get_proof(&mpt_key).unwrap();

                    break (length_slot, proof, mpt_key, value, variable_slot);
                }
            };

            let mut key = Vec::with_capacity(64);
            for k in mpt_key {
                key.push(GFp::from_canonical_u8(k >> 4));
                key.push(GFp::from_canonical_u8(k & 0x0f));
            }

            let length = GFp::from_canonical_u32(value);
            let dm = map_to_curve_point(&[
                GFp::from_canonical_u8(length_slot),
                GFp::from_canonical_u8(variable_slot),
            ])
            .to_weierstrass();

            let node = proof.last().unwrap();
            let leaf_circuit = LeafLengthCircuit::new(length_slot, &node, variable_slot).unwrap();
            let leaf_proof = prove_circuit(&setup, &leaf_circuit);
            let leaf_pi = PublicInputs::<GFp>::from_slice(&leaf_proof.public_inputs);

            let y = array::from_fn::<_, EXTENSION_DEGREE, _>(|i| leaf_pi.metadata().1[i]);
            let x = array::from_fn::<_, EXTENSION_DEGREE, _>(|i| leaf_pi.metadata().0[i]);
            let is_inf = leaf_pi.metadata().2 == &GFp::ONE;
            let dm_p = WeierstrassPoint {
                x: GFp5::from_basefield_array(x),
                y: GFp5::from_basefield_array(y),
                is_inf,
            };
            let root: Vec<_> = convert_u8_to_u32_slice(&keccak256(&node))
                .into_iter()
                .map(GFp::from_canonical_u32)
                .collect();

            let rlp_headers: Vec<Vec<u8>> = rlp::decode_list(&node);
            let rlp_nibbles = Nibbles::from_compact(&rlp_headers[0]);
            let t = GFp::from_canonical_usize(MAX_KEY_NIBBLE_LEN - 1)
                - GFp::from_canonical_usize(rlp_nibbles.nibbles().len());

            assert_eq!(leaf_pi.length(), &length);
            assert_eq!(leaf_pi.root_hash(), &root);
            assert_eq!(leaf_pi.mpt_key(), &key);
            assert_eq!(dm, dm_p);
            assert_eq!(leaf_pi.mpt_key_pointer(), &t);
        }
    }

    pub struct TestCase {
        pub depth: usize,
        pub length: u32,
    }
}
