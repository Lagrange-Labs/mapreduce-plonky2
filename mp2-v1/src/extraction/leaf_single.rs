//! Module handling the single variable inside a storage trie

use super::{
    key::{SimpleSlot, SimpleSlotWires},
    public_inputs::PublicInputs,
    MAX_LEAF_NODE_LEN,
};
use mp2_common::{
    array::{Array, Vector, VectorWire},
    keccak::{InputData, KeccakCircuit, KeccakWires},
    mpt_sequential::{left_pad_leaf_value, MPTNodeWires, MAX_LEAF_VALUE_LEN, PAD_LEN},
    types::{CBuilder, GFp, MAPPING_LEAF_VALUE_LEN},
    utils::pack_and_compute_digest,
};
use plonky2::{
    hash::poseidon::PoseidonHash,
    iop::{target::Target, witness::PartialWitness},
    plonk::circuit_builder::CircuitBuilder,
};
use recursion_framework::circuit_builder::CircuitLogicWires;
use serde::{Deserialize, Serialize};
use std::iter;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct LeafSingleWires<const NODE_LEN: usize>
where
    [(); PAD_LEN(NODE_LEN)]:,
{
    node: VectorWire<Target, { PAD_LEN(NODE_LEN) }>,
    root: KeccakWires<{ PAD_LEN(NODE_LEN) }>,
    slot: SimpleSlotWires,
    value: Array<Target, MAPPING_LEAF_VALUE_LEN>,
}
impl<const N: usize> LeafSingleWires<N>
where
    [(); PAD_LEN(N)]:,
{
    pub fn slot(&self) -> Target {
        self.slot.slot
    }
}

/// Circuit to prove the correct derivation of the MPT key from a simple slot
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct LeafSingleCircuit<const NODE_LEN: usize> {
    pub(crate) node: Vec<u8>,
    pub(crate) slot: SimpleSlot,
}

impl<const NODE_LEN: usize> LeafSingleCircuit<NODE_LEN>
where
    [(); PAD_LEN(NODE_LEN)]:,
{
    pub fn build(b: &mut CBuilder) -> LeafSingleWires<NODE_LEN> {
        let zero = b.zero();
        let one = b.one();
        let tru = b._true();

        let slot = SimpleSlot::build(b);

        // Build the node wires.
        let wires =
            MPTNodeWires::<NODE_LEN, MAX_LEAF_VALUE_LEN>::build_and_advance_key(b, &slot.mpt_key);
        let node = wires.node;
        let root = wires.root;

        // Left pad the leaf value.
        let value = left_pad_leaf_value(b, &wires.value);

        // Compute the identifier (simple slot which is assumed to fit in a single byte).
        let identifier = b
            .hash_n_to_hash_no_pad::<PoseidonHash>(vec![slot.slot])
            .elements;

        // Compute the metadata digest - D(identifier || slot).
        let inputs: Vec<_> = identifier
            .into_iter()
            .chain(iter::once(slot.slot))
            .collect();
        let metadata_digest = pack_and_compute_digest(b, &inputs);

        // Compute the values digest - D(identifier || value).
        let inputs: Vec<_> = identifier.into_iter().chain(value.arr).collect();
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

        LeafSingleWires {
            node,
            root,
            slot,
            value,
        }
    }

    pub fn assign(&self, pw: &mut PartialWitness<GFp>, wires: &LeafSingleWires<NODE_LEN>) {
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
impl CircuitLogicWires<GFp, 2, 0> for LeafSingleWires<MAX_LEAF_NODE_LEN> {
    type CircuitBuilderParams = ();

    type Inputs = LeafSingleCircuit<MAX_LEAF_NODE_LEN>;

    const NUM_PUBLIC_INPUTS: usize = PublicInputs::<GFp>::TOTAL_LEN;

    fn circuit_logic(
        builder: &mut CircuitBuilder<GFp, 2>,
        _verified_proofs: [&plonky2::plonk::proof::ProofWithPublicInputsTarget<2>; 0],
        _builder_parameters: Self::CircuitBuilderParams,
    ) -> Self {
        LeafSingleCircuit::build(builder)
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
