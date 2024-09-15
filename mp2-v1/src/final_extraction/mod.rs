pub(crate) mod api;
mod base_circuit;
mod lengthed_circuit;
mod merge;
mod public_inputs;
mod simple_circuit;

pub use api::{CircuitInput, PublicParameters};
use derive_more::{From, Into};
use mp2_common::{group_hashing::CircuitBuilderGroupHashing, D, F};
use plonky2::{
    iop::{
        target::BoolTarget,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::circuit_builder::CircuitBuilder,
};
use plonky2_ecgfp5::gadgets::curve::{CircuitBuilderEcGFp5, CurveTarget};
pub use public_inputs::PublicInputs;

pub(crate) use base_circuit::BaseCircuitProofInputs;
pub(crate) use lengthed_circuit::LengthedCircuitInput as LengthedCircuit;
use serde::{Deserialize, Serialize};
pub(crate) use simple_circuit::SimpleCircuitInput as SimpleCircuit;

/// Whether the table's digest is composed of a single row, or multiple rows.
/// For example when extracting mapping entries in one single sweep of the MPT, the digest contains
/// multiple rows inside.
/// When extracting single variables on one sweep, there is only a single row contained in the
/// digest.
pub enum TableDimension {
    /// Set to Single for types that only generate a single row at a given block. For example, a
    /// uint256 or a bytes32 will only generate a single row per block.
    Single,
    /// Set to Compound for types that
    /// * have multiple entries (like an mapping, unlike a single uin256 for example)
    /// * don't need or have an associated length slot to combine with
    /// It happens contracts don't have a length slot associated with the mapping
    /// like ERC20 and thus there is no proof circuits have looked at _all_ the entries
    /// due to limitations on EVM (there is no mapping.len()).
    Compound,
}

impl TableDimension {
    pub fn assign_wire(&self, pw: &mut PartialWitness<F>, wire: &TableDimensionWire) {
        match self {
            TableDimension::Single => pw.set_bool_target(wire.0, false),
            TableDimension::Compound => pw.set_bool_target(wire.0, true),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, From, Into)]
pub struct TableDimensionWire(
    #[serde(serialize_with = "serialize", deserialize_with = "deserialize")] BoolTarget,
);

impl TableDimensionWire {
    pub fn conditional_digest(
        &self,
        c: &mut CircuitBuilder<F, D>,
        digest: CurveTarget,
    ) -> CurveTarget {
        let single = c.map_to_curve_point(&digest);
        c.curve_select(self.0, digest, single)
    }
}
