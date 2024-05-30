//! Database branch length extraction circuits

use core::array;

use mp2_common::{
    array::{Vector, VectorWire},
    keccak::{InputData, KeccakCircuit, KeccakWires, PACKED_HASH_LEN},
    mpt_sequential::Circuit as MPTCircuit,
    public_inputs::PublicInputCommon,
    rlp::{decode_fixed_list, MAX_ITEMS_IN_LIST},
    types::{CBuilder, GFp},
    utils::convert_u8_targets_to_u32,
    D,
};
use plonky2::{
    iop::{target::Target, witness::PartialWitness},
    plonk::proof::ProofWithPublicInputsTarget,
};
use recursion_framework::circuit_builder::CircuitLogicWires;
use serde::{Deserialize, Serialize};

use crate::{MAX_BRANCH_NODE_LEN, MAX_BRANCH_NODE_LEN_PADDED};

use super::PublicInputs;

/// The wires structure for the branch length extraction.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BranchLengthWires {
    node: VectorWire<Target, MAX_BRANCH_NODE_LEN_PADDED>,
    root: KeccakWires<MAX_BRANCH_NODE_LEN_PADDED>,
}

impl CircuitLogicWires<GFp, D, 1> for BranchLengthWires {
    type CircuitBuilderParams = ();
    type Inputs = BranchLengthCircuit;
    const NUM_PUBLIC_INPUTS: usize = PublicInputs::<GFp>::TOTAL_LEN;

    fn circuit_logic(
        cb: &mut CBuilder,
        verified_proofs: [&ProofWithPublicInputsTarget<D>; 1],
        _builder_parameters: Self::CircuitBuilderParams,
    ) -> Self {
        let pis = &verified_proofs[0].public_inputs[..PublicInputs::<GFp>::TOTAL_LEN];
        let pis = PublicInputs::from_slice(pis);

        BranchLengthCircuit::build(cb, pis)
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

/// The circuit definition for the branch length extraction.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BranchLengthCircuit {
    node: Vec<u8>,
}

impl BranchLengthCircuit {
    /// Creates a new instance of the circuit.
    pub fn new(node: Vec<u8>) -> Self {
        Self { node }
    }

    /// Build the circuit, assigning the public inputs and returning the internal wires.
    pub fn build(cb: &mut CBuilder, child_proof: PublicInputs<Target>) -> BranchLengthWires {
        let zero = cb.zero();

        let node = VectorWire::<Target, MAX_BRANCH_NODE_LEN_PADDED>::new(cb);
        let headers = decode_fixed_list::<_, D, MAX_ITEMS_IN_LIST>(cb, &node.arr.arr, zero);

        node.assert_bytes(cb);

        let key = child_proof.mpt_key_wire();
        let (key, hash, is_branch, _) =
            MPTCircuit::<1, MAX_BRANCH_NODE_LEN>::advance_key_branch(cb, &node.arr, &key, &headers);

        // asserts this is a branch node
        cb.assert_one(is_branch.target);

        for (i, h) in convert_u8_targets_to_u32(cb, &hash.arr)
            .into_iter()
            .enumerate()
        {
            cb.connect(h.0, child_proof.root_hash()[i]);
        }

        let root = KeccakCircuit::<MAX_BRANCH_NODE_LEN_PADDED>::hash_vector(cb, &node);
        let h = &array::from_fn::<_, PACKED_HASH_LEN, _>(|i| root.output_array.arr[i].0);
        let t = &key.pointer;

        let PublicInputs { dm, k, n, .. } = child_proof;
        PublicInputs { h, dm, k, t, n }.register(cb);

        BranchLengthWires { node, root }
    }

    /// Assigns the values of this instance into the provided partial witness, using the generated
    /// circuit wires.
    pub fn assign(&self, pw: &mut PartialWitness<GFp>, wires: &BranchLengthWires) {
        let node = Vector::from_vec(&self.node).expect("invalid node length");

        wires.node.assign(pw, &node);

        KeccakCircuit::<MAX_BRANCH_NODE_LEN_PADDED>::assign(
            pw,
            &wires.root,
            &InputData::Assigned(&node),
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
    use mp2_test::circuit::{prove_circuit, setup_circuit, UserCircuit};
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

    #[test]
    fn prove_and_verify_length_extraction_branch_circuit() {
        let rng = &mut StdRng::seed_from_u64(0xffff);
        let setup = setup_circuit::<_, D, PoseidonGoldilocksConfig, BranchTestCircuit>();
        let memdb = Arc::new(MemoryDB::new(true));
        let mut trie = EthTrie::new(Arc::clone(&memdb));

        let depth = 4;
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
                break (length_slot, proof, mpt_key, value, variable_slot);
            }
        };

        let mut key = Vec::with_capacity(64);
        for k in &mpt_key {
            key.push(GFp::from_canonical_u8(k >> 4));
            key.push(GFp::from_canonical_u8(k & 0x0f));
        }
        let length = GFp::from_canonical_u32(value);
        let dm = map_to_curve_point(&[
            GFp::from_canonical_u8(length_slot),
            GFp::from_canonical_u8(variable_slot),
        ])
        .to_weierstrass();
        let is_inf = GFp::from_bool(dm.is_inf);

        // compute the public inputs for the first iteration

        let child = &proof[depth - 1];
        let d = GFp::from_canonical_usize(depth - 2);
        let child_hash: Vec<_> = convert_u8_to_u32_slice(&keccak256(child))
            .into_iter()
            .map(GFp::from_canonical_u32)
            .collect();

        let mut branch_pi =
            PublicInputs::from_parts(&child_hash, (&dm.x.0, &dm.y.0, &is_inf), &key, &d, &length)
                .to_vec();

        // traverse from leaf's child to root
        for d in (0..depth - 1).rev() {
            let node = &proof[d];
            let d = GFp::from_canonical_usize(d);
            let t = d - GFp::ONE;

            let branch_circuit = BranchTestCircuit {
                base: BranchLengthCircuit::new(node.clone()),
                pi: &branch_pi,
            };
            let branch_proof = prove_circuit(&setup, &branch_circuit);
            let proof_pi = PublicInputs::<GFp>::from_slice(&branch_proof.public_inputs);

            branch_pi = proof_pi.to_vec();

            let y = array::from_fn::<_, EXTENSION_DEGREE, _>(|i| proof_pi.metadata().1[i]);
            let x = array::from_fn::<_, EXTENSION_DEGREE, _>(|i| proof_pi.metadata().0[i]);
            let is_inf = proof_pi.metadata().2 == &GFp::ONE;
            let dm_p = WeierstrassPoint {
                x: GFp5::from_basefield_array(x),
                y: GFp5::from_basefield_array(y),
                is_inf,
            };
            let root: Vec<_> = convert_u8_to_u32_slice(&keccak256(&node))
                .into_iter()
                .map(GFp::from_canonical_u32)
                .collect();

            assert_eq!(proof_pi.length(), &length);
            assert_eq!(proof_pi.root_hash(), &root);
            assert_eq!(proof_pi.mpt_key(), &key);
            assert_eq!(dm, dm_p);
            assert_eq!(proof_pi.mpt_key_pointer(), &t);
        }
    }

    #[derive(Debug, Clone)]
    pub struct BranchTestWires {
        pub base: BranchLengthWires,
        pub pi: Vec<Target>,
    }

    #[derive(Debug, Clone)]
    pub struct BranchTestCircuit<'a> {
        pub base: BranchLengthCircuit,
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
