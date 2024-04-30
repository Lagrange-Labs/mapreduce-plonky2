//! Module handling the mapping entries inside a storage trie

use super::{
    key::{MappingSlot, MappingSlotWires},
    public_inputs::PublicInputs,
    MAX_LEAF_NODE_LEN,
};
use mp2_common::{
    array::{Array, Vector, VectorWire},
    keccak::{InputData, KeccakCircuit, KeccakWires},
    mpt_sequential::{left_pad_leaf_value, MPTNodeWires, MAX_LEAF_VALUE_LEN, PAD_LEN},
    types::{CBuilder, GFp, MAPPING_KEY_LEN, MAPPING_LEAF_VALUE_LEN},
    utils::pack_and_compute_digest,
};
use plonky2::{
    field::types::Field,
    hash::poseidon::PoseidonHash,
    iop::{target::Target, witness::PartialWitness},
    plonk::circuit_builder::CircuitBuilder,
};
use recursion_framework::circuit_builder::CircuitLogicWires;
use serde::{Deserialize, Serialize};
use std::iter;

const KEY_ID_PREFIX: &[u8] = b"KEY";
const VALUE_ID_PREFIX: &[u8] = b"VALUE";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct LeafMappingWires<const NODE_LEN: usize>
where
    [(); PAD_LEN(NODE_LEN)]:,
{
    node: VectorWire<Target, { PAD_LEN(NODE_LEN) }>,
    root: KeccakWires<{ PAD_LEN(NODE_LEN) }>,
    slot: MappingSlotWires,
    value: Array<Target, MAPPING_LEAF_VALUE_LEN>,
}
impl<const N: usize> LeafMappingWires<N>
where
    [(); PAD_LEN(N)]:,
{
    pub fn mapping_key(&self) -> Array<Target, MAPPING_KEY_LEN> {
        self.slot.mapping_key.clone()
    }

    pub fn mapping_slot(&self) -> Target {
        self.slot.mapping_slot
    }
}

/// Circuit to prove the correct derivation of the MPT key from a mapping slot
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct LeafMappingCircuit<const NODE_LEN: usize> {
    pub(crate) node: Vec<u8>,
    pub(crate) slot: MappingSlot,
}

impl<const NODE_LEN: usize> LeafMappingCircuit<NODE_LEN>
where
    [(); PAD_LEN(NODE_LEN)]:,
{
    pub fn build(b: &mut CBuilder) -> LeafMappingWires<NODE_LEN> {
        let zero = b.zero();
        let one = b.one();
        let tru = b._true();

        let slot = MappingSlot::mpt_key(b);

        // Ensure the node only includes bytes.
        let node = VectorWire::<Target, { PAD_LEN(NODE_LEN) }>::new(b);
        node.assert_bytes(b);

        // Build the node wires.
        let wires = MPTNodeWires::<NODE_LEN, MAX_LEAF_VALUE_LEN>::build_and_advance_key(
            b,
            &slot.keccak_mpt.mpt_key,
        );
        let node = wires.node;
        let root = wires.root;

        // Left pad the leaf value.
        let value = left_pad_leaf_value(b, &wires.value);

        // Compute the key ID - Poseidon(KEY || slot).
        let key_id_prefix: Vec<_> = KEY_ID_PREFIX
            .iter()
            .cloned()
            .map(GFp::from_canonical_u8)
            .collect();
        let key_id_prefix = b.constants(&key_id_prefix);
        let inputs: Vec<_> = key_id_prefix
            .into_iter()
            .chain(iter::once(slot.mapping_slot))
            .collect();
        let key_id = b.hash_n_to_hash_no_pad::<PoseidonHash>(inputs).elements;

        // Compute the value ID - Poseidon(VALUE || slot).
        let value_id_prefix: Vec<_> = VALUE_ID_PREFIX
            .iter()
            .cloned()
            .map(GFp::from_canonical_u8)
            .collect();
        let value_id_prefix = b.constants(&value_id_prefix);
        let inputs: Vec<_> = value_id_prefix
            .into_iter()
            .chain(iter::once(slot.mapping_slot))
            .collect();
        let value_id = b.hash_n_to_hash_no_pad::<PoseidonHash>(inputs).elements;

        // Compute the metadata digest - D(key_id || value_id || slot).
        let inputs: Vec<_> = key_id
            .iter()
            .cloned()
            .chain(value_id)
            .chain(iter::once(slot.mapping_slot))
            .collect();
        let metadata_digest = pack_and_compute_digest(b, &inputs);

        // Compute the values digest - D(D(key_id || key) + D(value_id || value)).
        let inputs: Vec<_> = key_id.into_iter().chain(slot.mapping_key.arr).collect();
        let k_digest = pack_and_compute_digest(b, &inputs);
        let inputs: Vec<_> = value_id.into_iter().chain(value.arr).collect();
        let v_digest = pack_and_compute_digest(b, &inputs);
        let inputs: Vec<_> = k_digest
            .0
             .0
            .into_iter()
            .flat_map(|ext| ext.0)
            .chain(iter::once(k_digest.0 .1.target))
            .chain(v_digest.0 .0.into_iter().flat_map(|ext| ext.0))
            .chain(iter::once(v_digest.0 .1.target))
            .collect();
        let values_digest = pack_and_compute_digest(b, &inputs);

        // Register the public inputs.
        PublicInputs::register(
            b,
            &root.output_array,
            &wires.key,
            values_digest,
            metadata_digest,
            one,
        );

        LeafMappingWires {
            node,
            root,
            slot,
            value,
        }
    }

    pub fn assign(&self, pw: &mut PartialWitness<GFp>, wires: &LeafMappingWires<NODE_LEN>) {
        let pad_node =
            Vector::<u8, { PAD_LEN(NODE_LEN) }>::from_vec(&self.node).expect("invalid node given");
        wires.node.assign(pw, &pad_node);
        KeccakCircuit::<{ PAD_LEN(NODE_LEN) }>::assign(
            pw,
            &wires.root,
            &InputData::Assigned(&pad_node),
        );
        self.slot.assign(pw, &wires.slot);
    }
}

/// D = 2,
/// Num of children = 0
impl CircuitLogicWires<GFp, 2, 0> for LeafMappingWires<MAX_LEAF_NODE_LEN> {
    type CircuitBuilderParams = ();

    type Inputs = LeafMappingCircuit<MAX_LEAF_NODE_LEN>;

    const NUM_PUBLIC_INPUTS: usize = PublicInputs::<GFp>::TOTAL_LEN;

    fn circuit_logic(
        builder: &mut CircuitBuilder<GFp, 2>,
        _verified_proofs: [&plonky2::plonk::proof::ProofWithPublicInputsTarget<2>; 0],
        _builder_parameters: Self::CircuitBuilderParams,
    ) -> Self {
        LeafMappingCircuit::build(builder)
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
