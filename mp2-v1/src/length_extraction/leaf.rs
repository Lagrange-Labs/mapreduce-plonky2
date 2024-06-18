//! Database length extraction circuits

use core::array;

use mp2_common::{
    array::Vector,
    group_hashing::CircuitBuilderGroupHashing,
    keccak::PACKED_HASH_LEN,
    mpt_sequential::{
        utils::left_pad_leaf_value, MPTLeafOrExtensionNode, MPTLeafOrExtensionWires,
        MAX_LEAF_VALUE_LEN,
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
    plonk::proof::ProofWithPublicInputsTarget,
};
use recursion_framework::circuit_builder::CircuitLogicWires;
use serde::{Deserialize, Serialize};

use crate::MAX_LEAF_NODE_LEN;

use super::PublicInputs;

type LengthMPTWires = MPTLeafOrExtensionWires<MAX_LEAF_NODE_LEN, MAX_LEAF_VALUE_LEN>;

/// The wires structure for the leaf length extraction.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LeafLengthWires {
    pub length_slot: SimpleSlotWires,
    pub length_mpt: LengthMPTWires,
    pub variable_slot: Target,
}

impl CircuitLogicWires<GFp, D, 0> for LeafLengthWires {
    type CircuitBuilderParams = ();
    type Inputs = LeafLengthCircuit;
    const NUM_PUBLIC_INPUTS: usize = PublicInputs::<GFp>::TOTAL_LEN;

    fn circuit_logic(
        cb: &mut CBuilder,
        _verified_proofs: [&ProofWithPublicInputsTarget<D>; 0],
        _builder_parameters: Self::CircuitBuilderParams,
    ) -> Self {
        Self::Inputs::build(cb)
    }

    fn assign_input(
        &self,
        inputs: Self::Inputs,
        pw: &mut PartialWitness<GFp>,
    ) -> anyhow::Result<()> {
        inputs.assign(pw, self);
        Ok(())
    }
}

/// The circuit definition for the leaf length extraction.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LeafLengthCircuit {
    pub length_slot: SimpleSlot,
    pub length_node: Vec<u8>,
    pub variable_slot: u8,
}

impl LeafLengthCircuit {
    /// Creates a new instance of the circuit.
    pub fn new(length_slot: u8, length_node: Vec<u8>, variable_slot: u8) -> Self {
        Self {
            length_slot: SimpleSlot::new(length_slot),
            length_node,
            variable_slot,
        }
    }

    /// Build the circuit, assigning the public inputs and returning the internal wires.
    pub fn build(cb: &mut CBuilder) -> LeafLengthWires {
        let zero = cb.zero();
        let one = cb.one();

        // we don't range check the variable and length slots as they are part of the DM public
        // commitment
        let variable_slot = cb.add_virtual_target();
        let length_slot = SimpleSlot::build(cb);

        let length_mpt = MPTLeafOrExtensionNode::build_and_advance_key::<
            _,
            D,
            MAX_LEAF_NODE_LEN,
            MAX_LEAF_VALUE_LEN,
        >(cb, &length_slot.mpt_key);

        // extract the rlp encoded value
        let length_rlp_encoded =
            left_pad_leaf_value::<GFp, D, MAX_LEAF_VALUE_LEN, 4>(cb, &length_mpt.value)
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
    pub fn assign(&self, pw: &mut PartialWitness<GFp>, wires: &LeafLengthWires) {
        pw.set_target(
            wires.variable_slot,
            GFp::from_canonical_u8(self.variable_slot),
        );

        self.length_slot.assign(pw, &wires.length_slot);
        wires.length_mpt.assign(
            pw,
            &Vector::from_vec(&self.length_node).expect("invalid node length"),
        );
    }
}

#[cfg(test)]
pub mod tests {
    use std::sync::Arc;

    use eth_trie::{EthTrie, MemoryDB, Nibbles, Trie};
    use mp2_common::{
        eth::StorageSlot,
        group_hashing::map_to_curve_point,
        rlp::MAX_KEY_NIBBLE_LEN,
        types::{CBuilder, GFp},
        utils::{convert_u8_to_u32_slice, keccak256},
        D,
    };
    use mp2_test::circuit::{prove_circuit, setup_circuit, UserCircuit};
    use plonky2::{
        field::types::Field, iop::witness::PartialWitness, plonk::config::PoseidonGoldilocksConfig,
    };
    use rand::{rngs::StdRng, Rng, RngCore, SeedableRng};

    use crate::length_extraction::{LeafLengthCircuit, PublicInputs};

    use super::LeafLengthWires;

    #[test]
    fn prove_and_verify_length_extraction_leaf_circuit() {
        let rng = &mut StdRng::seed_from_u64(0xffff);
        let memdb = Arc::new(MemoryDB::new(true));
        let setup = setup_circuit::<_, D, PoseidonGoldilocksConfig, LeafLengthCircuit>();
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
            let leaf_circuit = LeafLengthCircuit::new(length_slot, node.clone(), variable_slot);
            let leaf_proof = prove_circuit(&setup, &leaf_circuit);
            let leaf_pi = PublicInputs::<GFp>::from_slice(&leaf_proof.public_inputs);

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
            assert_eq!(leaf_pi.metadata_point(), dm);
            assert_eq!(leaf_pi.mpt_key_pointer(), &t);
        }
    }

    impl UserCircuit<GFp, D> for LeafLengthCircuit {
        type Wires = LeafLengthWires;

        fn build(cb: &mut CBuilder) -> Self::Wires {
            LeafLengthCircuit::build(cb)
        }

        fn prove(&self, pw: &mut PartialWitness<GFp>, wires: &Self::Wires) {
            self.assign(pw, wires);
        }
    }

    pub struct TestCase {
        pub depth: usize,
        pub length: u32,
    }
}
