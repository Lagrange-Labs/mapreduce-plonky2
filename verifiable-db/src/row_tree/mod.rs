use derive_more::Constructor;
use ethers::types::U256;
use mp2_common::{
    group_hashing::CircuitBuilderGroupHashing,
    u256::{CircuitBuilderU256, UInt256Target, WitnessWriteU256},
    utils::{ToFields, ToTargets},
    D, F,
};
use plonky2::{
    hash::hash_types::RichField,
    iop::{
        target::Target,
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

/// The value to give at each node of the row tree
#[derive(Clone, Debug, Constructor)]
struct IndexTuple {
    /// identifier of the column for the secondary index
    index_identifier: F,
    /// secondary index value
    index_value: U256,
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
            .chain(self.index_value.to_fields().into_iter())
            .collect()
    }
}

/// The basic wires generated for each circuit of the row tree
#[derive(Clone, Debug, Serialize, Deserialize)]
struct IndexTupleWire {
    index_value: UInt256Target,
    index_identifier: Target,
}

impl IndexTupleWire {
    pub(crate) fn new(b: &mut CircuitBuilder<F, D>) -> Self {
        Self {
            index_value: b.add_virtual_u256(),
            index_identifier: b.add_virtual_target(),
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
            .chain(self.index_value.to_targets().into_iter())
            .collect::<Vec<_>>()
    }
}
