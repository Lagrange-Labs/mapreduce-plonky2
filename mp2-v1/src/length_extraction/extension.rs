//! Database length extraction circuits for extension node

use core::array;

use mp2_common::{
    array::{Targetable, Vector, VectorWire},
    keccak::{InputData, KeccakCircuit, KeccakWires, HASH_LEN, PACKED_HASH_LEN},
    mpt_sequential::{MPTLeafOrExtensionNode, PAD_LEN},
    public_inputs::PublicInputCommon,
    types::{CBuilder, GFp},
    D,
};
use plonky2::iop::{target::Target, witness::PartialWitness};

use crate::values_extraction::MAX_EXTENSION_NODE_LEN;

use super::PublicInputs;

const PADDED_LEN: usize = PAD_LEN(MAX_EXTENSION_NODE_LEN);

/// The wires structure for the extension extension extraction.
#[derive(Clone, Debug)]
pub struct ExtensionLengthWires {
    node: VectorWire<Target, PADDED_LEN>,
    root: KeccakWires<PADDED_LEN>,
}

/// The circuit definition for the extension length extraction.
#[derive(Clone, Debug)]
pub struct ExtensionLengthCircuit {
    node: Vec<u8>,
}

impl ExtensionLengthCircuit {
    /// Creates a new instance of the circuit.
    pub fn new(node: Vec<u8>) -> Self {
        Self { node }
    }

    /// Build the circuit, assigning the public inputs and returning the internal wires.
    pub fn build(cb: &mut CBuilder, child_proof: PublicInputs<Target>) -> ExtensionLengthWires {
        let key = child_proof.mpt_key_wire();
        let mpt = MPTLeafOrExtensionNode::build_and_advance_key::<
            _,
            D,
            MAX_EXTENSION_NODE_LEN,
            HASH_LEN,
        >(cb, &key);

        mpt.value
            .convert_u8_to_u32(cb)
            .arr
            .iter()
            .zip(child_proof.root_hash().iter())
            .for_each(|(v, p)| cb.connect(v.to_target(), *p));

        let PublicInputs { dm, k, n, .. } = child_proof;
        let t = &mpt.key.pointer;
        let h = &array::from_fn::<_, PACKED_HASH_LEN, _>(|i| mpt.root.output_array.arr[i].0);
        PublicInputs { h, dm, k, t, n }.register(cb);

        ExtensionLengthWires {
            node: mpt.node,
            root: mpt.root,
        }
    }

    /// Assigns the values of this instance into the provided partial witness, using the generated
    /// circuit wires.
    pub fn assign(&self, pw: &mut PartialWitness<GFp>, wires: &ExtensionLengthWires) {
        let node = Vector::<u8, PADDED_LEN>::from_vec(&self.node).unwrap();

        wires.node.assign(pw, &node);

        KeccakCircuit::<PADDED_LEN>::assign(pw, &wires.root, &InputData::Assigned(&node));
    }
}

#[cfg(test)]
pub mod tests {
    use std::{array, iter, sync::Arc};

    use eth_trie::{EthTrie, MemoryDB, Trie};
    use mp2_common::{
        eth::StorageSlot,
        group_hashing::{map_to_curve_point, EXTENSION_DEGREE},
        types::{CBuilder, GFp, GFp5},
        utils::{convert_u8_to_u32_slice, keccak256},
        D,
    };
    use mp2_test::circuit::{run_circuit, UserCircuit};
    use plonky2::{
        field::{extension::FieldExtension, types::Field},
        iop::{
            target::Target,
            witness::{PartialWitness, WitnessWrite},
        },
        plonk::config::PoseidonGoldilocksConfig,
    };
    use plonky2_ecgfp5::curve::curve::WeierstrassPoint;
    use rand::{rngs::StdRng, Rng, RngCore, SeedableRng};

    use crate::length_extraction::PublicInputs;

    use super::{ExtensionLengthCircuit, ExtensionLengthWires};

    #[test]
    fn prove_and_verify_length_extraction_extension_circuit() {
        let rng = &mut StdRng::seed_from_u64(0xffff);
        let memdb = Arc::new(MemoryDB::new(true));
        let mut trie = EthTrie::new(Arc::clone(&memdb));

        let length_slot = rng.gen::<u8>();
        let variable_slot = rng.gen::<u8>();
        let storage_slot = StorageSlot::Simple(length_slot as usize);

        let key1 = storage_slot.mpt_key_vec();
        let key2: Vec<u8> = key1
            .iter()
            .enumerate()
            .map(|(i, k)| if i == 31 { rng.gen() } else { *k })
            .collect();

        let value1 = rng.next_u32();
        let value2 = rng.next_u32();

        let bytes1: Vec<u8> = value1
            .to_be_bytes()
            .into_iter()
            .chain(iter::repeat(0).take(28))
            .collect();

        let bytes2: Vec<u8> = value2
            .to_be_bytes()
            .into_iter()
            .chain(iter::repeat(0).take(28))
            .collect();

        trie.insert(&key1, &bytes1).unwrap();
        trie.insert(&key2, &bytes2).unwrap();
        trie.root_hash().unwrap();

        let proof = trie.get_proof(&key1).unwrap();
        let node = proof.first().unwrap().clone();
        let root_rlp: Vec<Vec<u8>> = rlp::decode_list(&node);
        assert_eq!(root_rlp.len(), 2);

        let mut key = Vec::with_capacity(64);
        for k in key1 {
            key.push(GFp::from_canonical_u8(k >> 4));
            key.push(GFp::from_canonical_u8(k & 0b00001111));
        }

        let length = GFp::from_canonical_u32(value1);
        let t = GFp::from_canonical_u8(63);
        let dm = map_to_curve_point(&[
            GFp::from_canonical_u8(length_slot),
            GFp::from_canonical_u8(variable_slot),
        ])
        .to_weierstrass();
        let is_inf = GFp::from_bool(dm.is_inf);
        let child_hash: Vec<_> = convert_u8_to_u32_slice(&keccak256(&proof[1]))
            .into_iter()
            .map(GFp::from_canonical_u32)
            .collect();

        let ext_pi =
            PublicInputs::from_parts(&child_hash, (&dm.x.0, &dm.y.0, &is_inf), &key, &t, &length);

        let ext_circuit = ExtensionTestCircuit {
            base: ExtensionLengthCircuit::new(node.clone()),
            pi: &ext_pi.to_vec(),
        };
        let ext_proof = run_circuit::<_, D, PoseidonGoldilocksConfig, _>(ext_circuit);
        let ext_pi = PublicInputs::<GFp>::from_slice(&ext_proof.public_inputs);

        let y = array::from_fn::<_, EXTENSION_DEGREE, _>(|i| ext_pi.metadata().1[i]);
        let x = array::from_fn::<_, EXTENSION_DEGREE, _>(|i| ext_pi.metadata().0[i]);
        let is_inf = ext_pi.metadata().2 == &GFp::ONE;
        let dm_p = WeierstrassPoint {
            x: GFp5::from_basefield_array(x),
            y: GFp5::from_basefield_array(y),
            is_inf,
        };
        let root: Vec<_> = convert_u8_to_u32_slice(&keccak256(&proof[0]))
            .into_iter()
            .map(GFp::from_canonical_u32)
            .collect();

        assert_eq!(ext_pi.length(), &length);
        assert_eq!(ext_pi.root_hash(), &root);
        assert_eq!(ext_pi.mpt_key(), &key);
        assert_eq!(dm, dm_p);
        assert_eq!(ext_pi.mpt_key_pointer(), &GFp::ONE);
    }

    #[derive(Debug, Clone)]
    pub struct ExtensionTestWires {
        pub base: ExtensionLengthWires,
        pub pi: Vec<Target>,
    }

    #[derive(Debug, Clone)]
    pub struct ExtensionTestCircuit<'a> {
        pub base: ExtensionLengthCircuit,
        pub pi: &'a [GFp],
    }

    impl<'a> UserCircuit<GFp, D> for ExtensionTestCircuit<'a> {
        type Wires = ExtensionTestWires;

        fn build(cb: &mut CBuilder) -> Self::Wires {
            let pi = cb.add_virtual_targets(PublicInputs::<Target>::TOTAL_LEN);
            let base = ExtensionLengthCircuit::build(cb, PublicInputs::from_slice(&pi));

            ExtensionTestWires { base, pi }
        }

        fn prove(&self, pw: &mut PartialWitness<GFp>, wires: &Self::Wires) {
            pw.set_target_arr(&wires.pi, self.pi);
            self.base.assign(pw, &wires.base);
        }
    }
}
