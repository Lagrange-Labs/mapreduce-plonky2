//! Database branch length extraction circuits

use core::array;

use mp2_common::{
    array::{Vector, VectorWire},
    keccak::{InputData, KeccakCircuit, KeccakWires, PACKED_HASH_LEN},
    mpt_sequential::{Circuit as MPTCircuit, PAD_LEN},
    public_inputs::PublicInputCommon,
    rlp::{decode_fixed_list, MAX_ITEMS_IN_LIST},
    types::{CBuilder, GFp},
    utils::convert_u8_targets_to_u32,
    D,
};
use plonky2::iop::{target::Target, witness::PartialWitness};

use super::PublicInputs;

/// The wires structure for the branch length extraction.
#[derive(Clone, Debug)]
pub struct BranchLengthWires<const NODE_LEN: usize>
where
    [(); PAD_LEN(NODE_LEN)]:,
{
    node: VectorWire<Target, { PAD_LEN(NODE_LEN) }>,
    root: KeccakWires<{ PAD_LEN(NODE_LEN) }>,
}

/// The circuit definition for the branch length extraction.
#[derive(Clone, Debug)]
pub struct BranchLengthCircuit<const NODE_LEN: usize>
where
    [(); PAD_LEN(NODE_LEN)]:,
{
    node: Vector<u8, { PAD_LEN(NODE_LEN) }>,
}

impl<const NODE_LEN: usize> BranchLengthCircuit<NODE_LEN>
where
    [(); PAD_LEN(NODE_LEN)]:,
{
    /// Creates a new instance of the circuit.
    pub fn new(node: &[u8]) -> anyhow::Result<Self> {
        Ok(Self {
            node: Vector::from_vec(node)?,
        })
    }

    /// Build the circuit, assigning the public inputs and returning the internal wires.
    pub fn build(
        cb: &mut CBuilder,
        child_proof: PublicInputs<Target>,
    ) -> BranchLengthWires<NODE_LEN> {
        let zero = cb.zero();

        let node = VectorWire::<Target, { PAD_LEN(NODE_LEN) }>::new(cb);
        let headers = decode_fixed_list::<_, D, MAX_ITEMS_IN_LIST>(cb, &node.arr.arr, zero);

        node.assert_bytes(cb);

        let key = child_proof.mpt_key_wire();
        let (key, hash, is_branch, _) =
            MPTCircuit::<1, NODE_LEN>::advance_key_branch(cb, &node.arr, &key, &headers);

        // asserts this is a branch node
        cb.assert_one(is_branch.target);

        for (i, h) in convert_u8_targets_to_u32(cb, &hash.arr)
            .into_iter()
            .enumerate()
        {
            cb.connect(h.0, child_proof.root_hash()[i]);
        }

        let root = KeccakCircuit::<{ PAD_LEN(NODE_LEN) }>::hash_vector(cb, &node);
        let h = &array::from_fn::<_, PACKED_HASH_LEN, _>(|i| root.output_array.arr[i].0);
        let t = &key.pointer;

        let PublicInputs { dm, k, n, .. } = child_proof;
        PublicInputs { h, dm, k, t, n }.register(cb);

        BranchLengthWires { node, root }
    }

    /// Assigns the values of this instance into the provided partial witness, using the generated
    /// circuit wires.
    pub fn assign(&self, pw: &mut PartialWitness<GFp>, wires: &BranchLengthWires<NODE_LEN>) {
        wires.node.assign(pw, &self.node);

        KeccakCircuit::<{ PAD_LEN(NODE_LEN) }>::assign(
            pw,
            &wires.root,
            &InputData::Assigned(&self.node),
        );
    }
}

#[cfg(test)]
pub mod tests {
    use std::{array, sync::Arc};

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

    use super::{BranchLengthCircuit, BranchLengthWires};

    const NODE_LEN: usize = 532;

    #[test]
    fn prove_and_verify_length_extraction_branch_circuit() {
        let rng = &mut StdRng::seed_from_u64(0xffff);
        let memdb = Arc::new(MemoryDB::new(true));
        let mut trie = EthTrie::new(Arc::clone(&memdb));

        let (length_slot, proof, mpt_key, value, variable_slot) = loop {
            let length_slot = rng.gen::<u8>();
            let variable_slot = rng.gen::<u8>();
            let storage_slot = StorageSlot::Simple(length_slot as usize);

            let mpt_key = storage_slot.mpt_key_vec();
            let value = rng.next_u32();
            let mut encoded = rlp::encode(&value).to_vec();

            encoded.resize(32, 0);

            trie.insert(&mpt_key, &encoded).unwrap();
            trie.root_hash().unwrap();

            let proof = trie.get_proof(&mpt_key).unwrap();
            if proof.len() == 4 {
                break (length_slot, proof, mpt_key, value, variable_slot);
            }
        };

        let mut key = Vec::with_capacity(64);
        for k in &mpt_key {
            key.push(GFp::from_canonical_u8(k >> 4));
            key.push(GFp::from_canonical_u8(k & 0x0f));
        }

        let length = GFp::from_canonical_u32(value);
        let t = GFp::from_canonical_u8(0);
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

        let branch_pi =
            PublicInputs::from_parts(&child_hash, (&dm.x.0, &dm.y.0, &is_inf), &key, &t, &length);
        let branch_circuit = BranchTestCircuit {
            base: BranchLengthCircuit::new(&proof[0].clone()).unwrap(),
            pi: &branch_pi.to_vec(),
        };
        let branch_proof = run_circuit::<_, D, PoseidonGoldilocksConfig, _>(branch_circuit);
        let branch_pi = PublicInputs::<GFp>::from_slice(&branch_proof.public_inputs);

        let y = array::from_fn::<_, EXTENSION_DEGREE, _>(|i| branch_pi.metadata().1[i]);
        let x = array::from_fn::<_, EXTENSION_DEGREE, _>(|i| branch_pi.metadata().0[i]);
        let is_inf = branch_pi.metadata().2 == &GFp::ONE;
        let dm_p = WeierstrassPoint {
            x: GFp5::from_basefield_array(x),
            y: GFp5::from_basefield_array(y),
            is_inf,
        };
        let root: Vec<_> = convert_u8_to_u32_slice(&keccak256(&proof[0]))
            .into_iter()
            .map(GFp::from_canonical_u32)
            .collect();

        assert_eq!(branch_pi.length(), &length);
        assert_eq!(branch_pi.root_hash(), &root);
        assert_eq!(branch_pi.mpt_key(), &key);
        assert_eq!(dm, dm_p);
        assert_eq!(branch_pi.mpt_key_pointer(), &(GFp::ZERO - GFp::ONE));
    }

    #[derive(Debug, Clone)]
    pub struct BranchTestWires {
        pub base: BranchLengthWires<NODE_LEN>,
        pub pi: Vec<Target>,
    }

    #[derive(Debug, Clone)]
    pub struct BranchTestCircuit<'a> {
        pub base: BranchLengthCircuit<NODE_LEN>,
        pub pi: &'a [GFp],
    }

    impl<'a> UserCircuit<GFp, D> for BranchTestCircuit<'a> {
        type Wires = BranchTestWires;

        fn build(cb: &mut CBuilder) -> Self::Wires {
            let pi = cb.add_virtual_targets(PublicInputs::<Target>::TOTAL_LEN);
            let base = BranchLengthCircuit::build(cb, PublicInputs::from_slice(&pi));

            BranchTestWires { base, pi }
        }

        fn prove(&self, pw: &mut PartialWitness<GFp>, wires: &Self::Wires) {
            pw.set_target_arr(&wires.pi, self.pi);
            self.base.assign(pw, &wires.base);
        }
    }
}
