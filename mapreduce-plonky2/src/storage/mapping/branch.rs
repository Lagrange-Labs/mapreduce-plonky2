use std::array::from_fn as create_array;

use plonky2::{
    field::{goldilocks_field::GoldilocksField, types::Field},
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::circuit_builder::CircuitBuilder,
};
use plonky2_crypto::u32::arithmetic_u32::U32Target;
use plonky2_ecgfp5::gadgets::curve::CircuitBuilderEcGFp5;
use recursion_framework::circuit_builder::CircuitLogicWires;
use serde::{Deserialize, Serialize};

use crate::{
    array::{Array, Vector, VectorWire},
    keccak::{InputData, KeccakCircuit, KeccakWires, HASH_LEN, PACKED_HASH_LEN},
    mpt_sequential::{Circuit as MPTCircuit, MPTKeyWire, PAD_LEN},
    rlp::{decode_fixed_list, MAX_ITEMS_IN_LIST},
    utils::convert_u8_targets_to_u32,
};

use super::public_inputs::PublicInputs;

#[derive(Clone, Debug)]
pub struct BranchCircuit<const NODE_LEN: usize, const N_CHILDRENS: usize> {
    pub(super) node: Vec<u8>,
    // in nibbles
    pub(super) common_prefix: Vec<u8>,
    pub(super) expected_pointer: usize,
    pub(super) mapping_slot: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct BranchWires<const NODE_LEN: usize>
where
    [(); PAD_LEN(NODE_LEN)]:,
{
    /// input node - right now only branch
    node: VectorWire<Target, { PAD_LEN(NODE_LEN) }>,
    /// key provided by prover as a "point of reference" to verify
    /// all children proofs's exposed keys
    common_prefix: MPTKeyWire,
    keccak: KeccakWires<{ PAD_LEN(NODE_LEN) }>,
    mapping_slot: Target,
}

impl<const NODE_LEN: usize, const N_CHILDREN: usize> BranchCircuit<NODE_LEN, N_CHILDREN>
where
    [(); PAD_LEN(NODE_LEN)]:,
    [(); HASH_LEN / 4]:,
    [(); HASH_LEN]:,
{
    /// TODO: replace the inputs by the inputs of the proofs to verify when integrating with universal
    /// verifier / recursion framework.
    pub fn build(
        b: &mut CircuitBuilder<GoldilocksField, 2>,
        inputs: &[PublicInputs<Target>; N_CHILDREN],
    ) -> BranchWires<NODE_LEN> {
        let node = VectorWire::<Target, { PAD_LEN(NODE_LEN) }>::new(b);
        // always ensure the node is bytes at the beginning
        node.assert_bytes(b);
        // Key exposed as common prefix. We need to make sure all children proofs share the same common prefix
        let common_prefix = MPTKeyWire::new(b);
        // mapping slot will be exposed as public input. Need to make sure all
        // children proofs are valid with respect to the same mapping slot.
        let mapping_slot = b.add_virtual_target();

        let zero = b.zero();
        let tru = b._true();
        // First expose the keccak root of this subtree starting at this node
        let root = KeccakCircuit::<{ PAD_LEN(NODE_LEN) }>::hash_vector(b, &node);

        // Then do the work for each children proofs
        // accumulator being the addition of all children accumulator
        let mut accumulator = b.curve_zero();
        // n being the total number of entries recursively verified
        let mut n = b.zero();
        // we already decode the rlp headers here since we need it to verify
        // the validity of the hash exposed by the proofs
        let headers = decode_fixed_list::<_, _, MAX_ITEMS_IN_LIST>(b, &node.arr.arr, zero);
        let ffalse = b._false();
        let mut seen_nibbles = vec![];
        for proof_inputs in inputs {
            let child_accumulator = proof_inputs.accumulator();
            accumulator = b.curve_add(accumulator, child_accumulator);
            // add the number of leaves this proof has processed
            n = b.add(n, proof_inputs.n());
            let child_key = proof_inputs.mpt_key();
            let (_, hash, is_valid, nibble) =
                MPTCircuit::<1, NODE_LEN>::advance_key_branch(b, &node.arr, &child_key, &headers);
            // we always enforce it's a branch node, i.e. that it has 17 entries
            b.connect(is_valid.target, tru.target);
            // make sure we don't process twice the same proof for same nibble
            seen_nibbles.iter().for_each(|sn| {
                let is_equal = b.is_equal(*sn, nibble);
                b.connect(is_equal.target, ffalse.target);
            });
            seen_nibbles.push(nibble);
            // we check the hash is the one exposed by the proof
            // first convert the extracted hash to packed one to compare
            let packed_hash = Array::<U32Target, PACKED_HASH_LEN> {
                arr: convert_u8_targets_to_u32(b, &hash.arr).try_into().unwrap(),
            };
            let child_hash = proof_inputs.root_hash();
            let hash_equals = packed_hash.equals(b, &child_hash);
            b.connect(hash_equals.target, tru.target);
            // we now check that the MPT key at this point is equal to the one given
            // by the prover. Reason why it is secure is because this circuit only cares
            // that _all_ keys share the _same_ prefix, so if they're all equal
            // to `common_prefix`, they're all equal.
            common_prefix.enforce_prefix_equal(b, &child_key);
            // We also check proof is valid for the _same_ mapping slot
            b.connect(mapping_slot, proof_inputs.mapping_slot());
        }
        let one = b.one();
        // We've compared the pointers _before_ advancing the key for each leaf
        // so now we can advance the pointer to move to the next node - if any
        let new_prefix = common_prefix.advance_by(b, one);

        // we now extract the public input to register for this proofs
        let c = root.output_array.clone();
        PublicInputs::register(b, &new_prefix, mapping_slot, n, &c, &accumulator);
        BranchWires {
            node,
            common_prefix,
            keccak: root,
            mapping_slot,
        }
    }
    fn assign(&self, pw: &mut PartialWitness<GoldilocksField>, wires: &BranchWires<NODE_LEN>) {
        let vec = Vector::<u8, { PAD_LEN(NODE_LEN) }>::from_vec(&self.node).unwrap();
        wires.node.assign(pw, &vec);
        wires.common_prefix.assign(
            pw,
            &self.common_prefix.clone().try_into().unwrap(),
            self.expected_pointer,
        );
        KeccakCircuit::<{ PAD_LEN(NODE_LEN) }>::assign(
            pw,
            &wires.keccak,
            &InputData::Assigned(&vec),
        );
        pw.set_target(
            wires.mapping_slot,
            GoldilocksField::from_canonical_usize(self.mapping_slot),
        );
    }
}

/// D = 2,
/// Num of children = 0
impl<const NODE_LEN: usize, const N_CHILDREN: usize>
    CircuitLogicWires<GoldilocksField, 2, N_CHILDREN> for BranchWires<NODE_LEN>
where
    [(); PAD_LEN(NODE_LEN)]:,
{
    type CircuitBuilderParams = ();

    type Inputs = BranchCircuit<NODE_LEN, N_CHILDREN>;

    const NUM_PUBLIC_INPUTS: usize = PublicInputs::<GoldilocksField>::TOTAL_LEN;

    fn circuit_logic(
        builder: &mut CircuitBuilder<GoldilocksField, 2>,
        verified_proofs: [&plonky2::plonk::proof::ProofWithPublicInputsTarget<2>; N_CHILDREN],
        _: Self::CircuitBuilderParams,
    ) -> Self {
        let inputs: [PublicInputs<Target>; N_CHILDREN] =
            create_array(|i| PublicInputs::from(&verified_proofs[i].public_inputs));
        BranchCircuit::build(builder, &inputs)
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
    use std::array::from_fn as create_array;
    use std::sync::Arc;

    use eth_trie::{EthTrie, MemoryDB, Nibbles, Trie};
    use plonky2::field::types::Field;
    use plonky2::iop::witness::WitnessWrite;
    use plonky2::{
        field::goldilocks_field::GoldilocksField,
        iop::target::Target,
        plonk::config::{GenericConfig, PoseidonGoldilocksConfig},
    };
    use rand::{thread_rng, Rng};

    use crate::circuit::test::run_circuit;
    use crate::mpt_sequential::bytes_to_nibbles;
    use crate::{
        circuit::UserCircuit,
        group_hashing::map_to_curve_point,
        mpt_sequential::PAD_LEN,
        rlp::MAX_KEY_NIBBLE_LEN,
        storage::mapping::public_inputs::PublicInputs,
        utils::{convert_u8_to_u32_slice, keccak256, test::random_vector},
    };

    use super::{BranchCircuit, BranchWires};
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;
    #[test]
    fn test_len() {
        let v: Vec<Vec<u8>> = (0..17)
            .map(|_| random_vector::<u8>(32))
            .collect::<Vec<Vec<u8>>>();
        let encoded = rlp::encode_list::<Vec<u8>, _>(&v);
        println!("BRANCH NODE: {:?}", encoded.len());
    }
    #[derive(Clone, Debug)]
    struct TestBranchCircuit<'a, const NODE_LEN: usize, const N_CHILDREN: usize> {
        c: BranchCircuit<NODE_LEN, N_CHILDREN>,
        inputs: [PublicInputs<'a, F>; N_CHILDREN],
    }

    impl<'a, const NODE_LEN: usize, const N_CHILDREN: usize> UserCircuit<F, D>
        for TestBranchCircuit<'a, NODE_LEN, N_CHILDREN>
    where
        [(); PAD_LEN(NODE_LEN)]:,
    {
        type Wires = (BranchWires<NODE_LEN>, [Vec<Target>; N_CHILDREN]);

        fn build(
            c: &mut plonky2::plonk::circuit_builder::CircuitBuilder<GoldilocksField, 2>,
        ) -> Self::Wires {
            let inputs = (0..N_CHILDREN)
                .map(|_| c.add_virtual_targets(PublicInputs::<Target>::TOTAL_LEN))
                .collect::<Vec<_>>();
            let pinputs = create_array(|i| PublicInputs::from(&inputs[i]));
            let wires = BranchCircuit::<NODE_LEN, N_CHILDREN>::build(c, &pinputs);
            (wires, inputs.try_into().unwrap())
        }

        fn prove(
            &self,
            pw: &mut plonky2::iop::witness::PartialWitness<GoldilocksField>,
            wires: &Self::Wires,
        ) {
            assert_eq!(self.inputs.len(), wires.1.len());
            for i in 0..N_CHILDREN {
                assert_eq!(wires.1[i].len(), self.inputs[i].proof_inputs.len());
                pw.set_target_arr(&wires.1[i], self.inputs[i].proof_inputs);
            }
            self.c.assign(pw, &wires.0);
        }
    }

    #[test]
    fn test_branch_circuit() {
        const NODE_LEN: usize = 100;
        const N_CHILDREN: usize = 2;
        // We need to create a trie that for sure contains an branch node:
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
        let proof1 = trie.get_proof(&key1).unwrap();
        let proof2 = trie.get_proof(&key2).unwrap();
        assert!(proof1.len() == 3);
        assert_eq!(proof1[1], proof2[1]);
        let node = proof1[1].clone();
        let leaf1 = proof1.last().unwrap();
        let leaf2 = proof2.last().unwrap();
        let compute_key = |leaf: &[u8]| {
            let tuple: Vec<Vec<u8>> = rlp::decode_list(leaf);
            let partial_nibbles = Nibbles::from_compact(&tuple[0]);
            let partial_key_len = partial_nibbles.nibbles().len();
            MAX_KEY_NIBBLE_LEN - 1 - partial_key_len
        };
        let ptr1 = compute_key(leaf1);
        let ptr2 = compute_key(leaf2);
        println!("ptr1: {}, ptr2: {}", ptr1, ptr2);
        assert_eq!(ptr1, ptr2);
        let slot = 10;
        let branch_circuit = BranchCircuit::<NODE_LEN, N_CHILDREN> {
            node: node.clone(),
            // any of the two keys will do since we only care about the common prefix
            common_prefix: bytes_to_nibbles(&key1),
            expected_pointer: ptr1,
            mapping_slot: slot,
        };
        // create the public inputs
        let compute_pi = |key: &[u8], leaf: &[u8], value: &[u8]| {
            let c = convert_u8_to_u32_slice(&keccak256(leaf));
            let d = map_to_curve_point(
                &value
                    .iter()
                    .map(|b| F::from_canonical_u8(*b))
                    .collect::<Vec<_>>(),
            )
            .to_weierstrass();
            // both ptr should be the same
            // set 1 becaues it' s leaf
            PublicInputs::create_public_inputs_arr(&bytes_to_nibbles(key), ptr1, slot, 1, &c, &d)
        };
        let pi1 = compute_pi(&key1, leaf1, &value1);
        let pi2 = compute_pi(&key2, leaf2, &value2);
        assert_eq!(pi1.len(), PublicInputs::<F>::TOTAL_LEN);
        let circuit = TestBranchCircuit {
            c: branch_circuit,
            inputs: [PublicInputs::from(&pi1), PublicInputs::from(&pi2)],
            //inputs: [PublicInputs::from(&pi1)],
        };
        let proof = run_circuit::<F, 2, C, _>(circuit);
        let pi = PublicInputs::<F>::from(&proof.public_inputs);
        // now we check the expected outputs
        {
            // Accumulator check: since we can not add WeiressPoint, together, we recreate the
            // expected leafs accumulator and add them
            let acc1 = map_to_curve_point(
                &value1
                    .iter()
                    .map(|b| F::from_canonical_u8(*b))
                    .collect::<Vec<_>>(),
            );
            let acc2 = map_to_curve_point(
                &value2
                    .iter()
                    .map(|b| F::from_canonical_u8(*b))
                    .collect::<Vec<_>>(),
            );
            let branch_acc = acc1 + acc2;
            assert_eq!(branch_acc.to_weierstrass(), pi.accumulator());
        }
        {
            // n check should be equal to 2 since it processed two leaves
            assert_eq!(pi.n(), F::from_canonical_usize(N_CHILDREN));
        }
        {
            // check mpt root hash
            let root = convert_u8_to_u32_slice(&keccak256(&node));
            assert_eq!(&pi.root_hash(), &root);
        }
        {
            // check key and pointer
            let common_prefix = bytes_to_nibbles(&key1)
                .into_iter()
                .map(F::from_canonical_u8)
                .collect::<Vec<_>>();
            let (fkey, fptr) = pi.mpt_key_info();
            assert_eq!(fkey, common_prefix);
            // -1 because branch circuit exposes the new pointer
            let exp_ptr = ptr1 - 1;
            assert_eq!(fptr, F::from_canonical_usize(exp_ptr));
        }
        {
            // check mapping slot
            let exp_mapping = F::from_canonical_usize(slot);
            assert_eq!(pi.mapping_slot(), exp_mapping);
        }
    }
}
