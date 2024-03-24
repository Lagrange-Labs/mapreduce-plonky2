use plonky2::{
    field::goldilocks_field::GoldilocksField,
    iop::{target::Target, witness::PartialWitness},
    plonk::circuit_builder::CircuitBuilder,
};
use recursion_framework::circuit_builder::CircuitLogicWires;
use serde::{Deserialize, Serialize};

use crate::{
    array::{Vector, VectorWire},
    keccak::{InputData, KeccakCircuit, KeccakWires, HASH_LEN},
    mpt_sequential::{Circuit as MPTCircuit, PAD_LEN},
    rlp::decode_fixed_list,
    storage::MAX_EXTENSION_NODE_LEN,
};

use super::public_inputs::PublicInputs;

const PADDED_LEN: usize = PAD_LEN(MAX_EXTENSION_NODE_LEN);

/// Circuit proving the processing of an extension node as part of the recursive
/// MPT proof verification circuits.
#[derive(Clone, Debug)]
pub struct ExtensionNodeCircuit {
    pub(super) node: Vec<u8>,
}

/// Wires associated with this processing.
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct ExtensionWires {
    pub(super) node: VectorWire<Target, PADDED_LEN>,
    keccak: KeccakWires<PADDED_LEN>,
}

impl ExtensionNodeCircuit {
    pub fn build(
        b: &mut CircuitBuilder<GoldilocksField, 2>,
        // TODO : replace by proof later
        child_proof: PublicInputs<Target>,
    ) -> ExtensionWires {
        let zero = b.zero();
        let tru = b._true();
        let node = VectorWire::<Target, PADDED_LEN>::new(b);
        // first check node is bytes and then hash the nodes
        node.assert_bytes(b);
        let root = KeccakCircuit::<PADDED_LEN>::hash_vector(b, &node);

        // then look at the key from the children proof and move its pointer according to this node
        let child_mpt_key = child_proof.mpt_key();
        // only 2 elements in an extension node
        let rlp_headers = decode_fixed_list::<_, _, 2>(b, &node.arr.arr, zero);
        // TODO: refactor these methods - gets too complex when attached with MPTCircuit
        let (new_key, child_hash, valid) =
            MPTCircuit::<1, MAX_EXTENSION_NODE_LEN>::advance_key_leaf_or_extension::<
                _,
                _,
                2,
                HASH_LEN,
            >(b, &node.arr, &child_mpt_key, &rlp_headers);
        b.connect(tru.target, valid.target);
        // make sure the extracted hash is the one exposed by the proof
        let packed_child_hash = child_hash.convert_u8_to_u32(b);
        let given_child_hash = child_proof.root_hash();
        let equals = packed_child_hash.equals(b, &given_child_hash);
        b.connect(tru.target, equals.target);

        // now it's only a matter of exposing the right public inputs
        PublicInputs::register(
            b,
            // we pass the "advanced" key
            &new_key,
            child_proof.mapping_slot(),
            child_proof.n(),
            // the root hash is now the root of this node
            &root.output_array,
            // we pass the same accumulator since we didn't look at any value in this node
            &child_proof.accumulator(),
        );
        ExtensionWires { node, keccak: root }
    }

    pub fn assign(&self, pw: &mut PartialWitness<GoldilocksField>, wires: &ExtensionWires) {
        let vec = Vector::<u8, PADDED_LEN>::from_vec(&self.node).unwrap();
        wires.node.assign(pw, &vec);
        KeccakCircuit::<PADDED_LEN>::assign(pw, &wires.keccak, &InputData::Assigned(&vec));
    }
}

/// D = 2,
/// Num of children = 1
impl CircuitLogicWires<GoldilocksField, 2, 1> for ExtensionWires {
    type CircuitBuilderParams = ();

    type Inputs = ExtensionNodeCircuit;

    const NUM_PUBLIC_INPUTS: usize = PublicInputs::<GoldilocksField>::TOTAL_LEN;

    fn circuit_logic(
        builder: &mut CircuitBuilder<GoldilocksField, 2>,
        verified_proofs: [&plonky2::plonk::proof::ProofWithPublicInputsTarget<2>; 1],
        _builder_parameters: Self::CircuitBuilderParams,
    ) -> Self {
        let inputs = PublicInputs::from(&verified_proofs[0].public_inputs);
        ExtensionNodeCircuit::build(builder, inputs)
    }

    fn assign_input(
        &self,
        inputs: Self::Inputs,
        pw: &mut PartialWitness<GoldilocksField>,
    ) -> anyhow::Result<()> {
        inputs.assign(pw, self);
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use std::panic;
    use std::sync::Arc;

    use eth_trie::{EthTrie, MemoryDB, Nibbles, Trie};
    use plonky2::field::types::Field;
    use plonky2::{
        field::goldilocks_field::GoldilocksField,
        iop::{target::Target, witness::WitnessWrite},
        plonk::{
            circuit_builder::CircuitBuilder,
            config::{GenericConfig, PoseidonGoldilocksConfig},
        },
    };
    use rand::{thread_rng, Rng};

    use crate::circuit::test::run_circuit;
    use crate::rlp::MAX_KEY_NIBBLE_LEN;
    use crate::storage::mapping::extension::MAX_EXTENSION_NODE_LEN;
    use crate::utils::{convert_u8_to_u32_slice, keccak256};
    use crate::{
        circuit::UserCircuit, group_hashing::map_to_curve_point,
        storage::mapping::public_inputs::PublicInputs, utils::test::random_vector,
    };

    use super::ExtensionNodeCircuit;
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    #[test]
    fn test_len() {
        let k: Vec<u8> = random_vector(32);
        let v: Vec<u8> = random_vector(32);
        let encoded = rlp::encode_list::<Vec<u8>, _>(&[k, v]);
        assert!(encoded.len() <= MAX_EXTENSION_NODE_LEN);
    }

    #[derive(Clone, Debug)]
    struct TestExtCircuit<'a> {
        c: ExtensionNodeCircuit,
        inputs: PublicInputs<'a, F>,
    }

    impl<'a> UserCircuit<GoldilocksField, 2> for TestExtCircuit<'a> {
        // second is the public inputs of the child proof
        type Wires = (super::ExtensionWires, Vec<Target>);
        fn build(b: &mut CircuitBuilder<GoldilocksField, 2>) -> Self::Wires {
            let inputs = b.add_virtual_targets(PublicInputs::<Target>::TOTAL_LEN);
            let wires = ExtensionNodeCircuit::build(b, PublicInputs::from(&inputs));
            (wires, inputs)
        }

        fn prove(
            &self,
            pw: &mut plonky2::iop::witness::PartialWitness<GoldilocksField>,
            wires: &Self::Wires,
        ) {
            self.c.assign(pw, &wires.0);
            assert_eq!(
                self.inputs.proof_inputs.len(),
                PublicInputs::<Target>::TOTAL_LEN
            );
            assert_eq!(self.inputs.proof_inputs.len(), wires.1.len());
            pw.set_target_arr(&wires.1, self.inputs.proof_inputs)
        }
    }

    #[test]
    fn test_extension_circuit() {
        // We need to create a trie that for sure contains an extension node:
        // We insert two values under two keys which only differ by their last nibble/byte
        // Normally, the trie should look like :
        // root = extension node
        // branch = point of different between the two keys
        // two leaves
        let memdb = Arc::new(MemoryDB::new(true));
        let mut trie = EthTrie::new(Arc::clone(&memdb));
        let key1 = random_vector(32);
        let mut key2 = key1.clone();
        key2[31] = thread_rng().gen();
        let value1 = random_vector(32);
        let value2 = random_vector(32);
        trie.insert(&key1, &value1).unwrap();
        trie.insert(&key2, &value2).unwrap();
        trie.root_hash().unwrap();
        let proof = trie.get_proof(&key1).unwrap();
        let node = proof.first().unwrap().clone();
        let root_rlp: Vec<Vec<u8>> = rlp::decode_list(&node);
        assert_eq!(root_rlp.len(), 2);
        // now prepare the public inputs for the extension circuit
        // a random accumulator value
        let accumulator = map_to_curve_point(
            &random_vector(12)
                .into_iter()
                .map(F::from_canonical_u8)
                .collect::<Vec<_>>(),
        )
        .to_weierstrass();
        let key = random_vector(64);
        let ptr = 63;
        // hash the child of the extension node, in packed mode
        let child_hash = convert_u8_to_u32_slice(&keccak256(&proof[1]));
        let slot = 10;
        let n = 15;
        let arr =
            PublicInputs::create_public_inputs_arr(&key, ptr, slot, n, &child_hash, &accumulator);
        // quick test to see if we can convert back to public inputs
        let pi = PublicInputs::from(&arr);
        assert_eq!(pi.accumulator(), accumulator);
        let (fkey, fptr) = pi.mpt_key_info();
        assert_eq!(
            fkey,
            key.iter()
                .cloned()
                .map(F::from_canonical_u8)
                .collect::<Vec<_>>()
        );
        assert_eq!(fptr, F::from_canonical_usize(ptr));
        assert_eq!(F::from_canonical_usize(slot), pi.mapping_slot());
        assert_eq!(F::from_canonical_usize(n), pi.n());
        assert_eq!(pi.root_hash(), child_hash);

        let circuit = TestExtCircuit {
            c: ExtensionNodeCircuit { node: node.clone() },
            inputs: PublicInputs::from(&arr),
        };
        let proof = run_circuit::<F, 2, C, _>(circuit);
        let ext_pi = PublicInputs::from(&proof.public_inputs);
        // check the outputs are as expected
        {
            // accumulator should be the same
            assert_eq!(pi.accumulator(), ext_pi.accumulator());
            // key should be the same, ptr should have moved
            let (new_key, new_ptr) = ext_pi.mpt_key_info();
            let partial_nibbles = Nibbles::from_compact(&root_rlp[0]);
            let partial_key_len = partial_nibbles.nibbles().len();
            let exp_ptr = MAX_KEY_NIBBLE_LEN - 1 - partial_key_len;
            assert_eq!(F::from_canonical_usize(exp_ptr), new_ptr);
            assert_eq!(new_key, fkey);
            // root hash must be hash of ext node
            let root_hash_f = convert_u8_to_u32_slice(&keccak256(&node))
                .into_iter()
                .map(F::from_canonical_u32)
                .collect::<Vec<_>>();
            assert_eq!(root_hash_f, ext_pi.root_hash_info());
            // n should be the same, as mapping slot
            assert_eq!(ext_pi.n(), pi.n());
            assert_eq!(ext_pi.mapping_slot(), pi.mapping_slot());
        }
        // trying with a wrong hash
        let inv_child_hash = convert_u8_to_u32_slice(&keccak256(&random_vector(32)));
        let inv_arr = PublicInputs::create_public_inputs_arr(
            &key,
            ptr,
            slot,
            n,
            &inv_child_hash,
            &accumulator,
        );
        let circuit = TestExtCircuit {
            c: ExtensionNodeCircuit { node: node.clone() },
            inputs: PublicInputs::from(&inv_arr),
        };
        let res = panic::catch_unwind(|| {
            run_circuit::<F, 2, C, _>(circuit);
        });
        //assert!(res.is_err());
    }
}
