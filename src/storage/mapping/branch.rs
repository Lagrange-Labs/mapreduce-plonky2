use crate::mpt_sequential::PAD_LEN;
pub struct BranchCircuit<const NODE_LEN: usize, const N_CHILDRENS: usize> {
    node: Vec<u8>,
}

pub struct BranchWires<const NODE_LEN: usize>
where
    [(); PAD_LEN(NODE_LEN)]:,
{
    /// TODO replace by proof when we have the framework in place
    inputs: Vec<Target>,
    /// input node - right now only branch
    node: VectorWire<{ PAD_LEN(NODE_LEN) }>,
    /// key provided by prover as a "point of reference" to verify
    /// all children proofs's exposed keys
    common_prefix: MPTKeyWire,
}

impl<const NODE_LEN: usize, const N_CHILDREN: usize> BranchCircuit<NODE_LEN, N_CHILDREN>
where
    [(); PAD_LEN(NODE_LEN)]:,
    [(); HASH_LEN / 4]:,
    [(); HASH_LEN]:,
{
    pub fn build(b: &mut CircuitBuilder<GoldilocksField, 2>) {
        let inputs = (0..N_CHILDREN)
            .map(|_| b.add_virtual_targets(PublicInputs::MAX_ELEMENTS))
            .collect::<Vec<_>>();
        let node = VectorWire::<Target, { PAD_LEN(NODE_LEN) }>::new(b);
        // always ensure the node is bytes at the beginning
        node.assert_bytes(b);
        // WIll be exposed as common prefix. We need to make sure all children proofs share the same common prefix
        let common_prefix = MPTKeyWire::new(b);
        // mapping slot will be exposed as public input. Need to make sure all
        // children proofs are valid with respect to the same mapping slot.
        let mapping_slot = b.add_virtual_target();

        let one = b.one();
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
        for i in 0..N_CHILDREN {
            let proof_inputs = PublicInputs::from(&inputs[i]);
            let child_accumulator = proof_inputs.accumulator();
            accumulator = b.curve_add(accumulator, child_accumulator);
            // add the number of leaves this proof has processed
            n = b.add(n, proof_inputs.n());
            let child_key = proof_inputs.mpt_key();
            let (new_key, hash, is_valid) =
                MPTCircuit::<1, NODE_LEN>::advance_key_branch(b, &node.arr, &child_key, &headers);
            // we always enforce it's a branch node
            // TODO: this is a redundant check and should be moved out from ^
            b.connect(is_valid.target, tru.target);
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
            let have_common_prefix = common_prefix.is_prefix_equal(b, &new_key);
            b.connect(have_common_prefix.target, tru.target);
            // We also check proof is valid for the _same_ mapping slot
            b.connect(mapping_slot, proof_inputs.mapping_slot());
        }

        // we now extract the public input to register for this proofs
        let c = root.output_array;
        PublicInputs::register(b, &common_prefix, mapping_slot, n, &c, &accumulator);
    }
}
