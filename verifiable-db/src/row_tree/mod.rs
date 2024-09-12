use alloy::primitives::U256;
use derive_more::Constructor;
use mp2_common::{
    group_hashing::CircuitBuilderGroupHashing,
    u256::{CircuitBuilderU256, UInt256Target, WitnessWriteU256},
    utils::{ToFields, ToTargets},
    D, F,
};
use plonky2::{
    iop::{
        target::{BoolTarget, Target},
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::circuit_builder::CircuitBuilder,
};
use plonky2_ecgfp5::gadgets::curve::CurveTarget;
use serde::{Deserialize, Serialize};

mod api;
mod full_node;
mod leaf;
mod partial_node;
mod public_inputs;

pub use api::{extract_hash_from_proof, CircuitInput, PublicParameters};
pub use public_inputs::PublicInputs;

/// The value to give at each node of the row tree
#[derive(Clone, Debug, Constructor)]
pub struct IndexTuple {
    /// identifier of the column for the secondary index
    index_identifier: F,
    /// secondary index value
    index_value: U256,
    /// is the secondary value should be included in multiplier digest or not
    is_multiplier: bool,
}

impl IndexTuple {
    pub(crate) fn assign_wires(&self, pw: &mut PartialWitness<F>, wires: &IndexTupleWire) {
        pw.set_u256_target(&wires.index_value, self.index_value);
        pw.set_target(wires.index_identifier, self.index_identifier);
    }
}

impl ToFields<F> for IndexTuple {
    fn to_fields(&self) -> Vec<F> {
        [self.index_identifier]
            .into_iter()
            .chain(self.index_value.to_fields())
            .collect()
    }
}

/// The basic wires generated for each circuit of the row tree
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct IndexTupleWire {
    index_value: UInt256Target,
    index_identifier: Target,
    #[serde(serialize_with = "serialize", deserialize_with = "deserialize")]
    is_multiplier: BoolTarget,
}

impl IndexTupleWire {
    pub(crate) fn new(b: &mut CircuitBuilder<F, D>) -> Self {
        Self {
            index_value: b.add_virtual_u256(),
            index_identifier: b.add_virtual_target(),
            is_multiplier: b.add_virtual_bool_target_safe(),
        }
    }
    pub(crate) fn digest(&self, b: &mut CircuitBuilder<F, D>) -> CurveTarget {
        b.map_to_curve_point(&self.to_targets())
    }
}

impl ToTargets for IndexTupleWire {
    fn to_targets(&self) -> Vec<Target> {
        self.index_identifier
            .to_targets()
            .into_iter()
            .chain(self.index_value.to_targets())
            .collect::<Vec<_>>()
    }
}
