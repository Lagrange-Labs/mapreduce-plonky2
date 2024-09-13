mod api;
mod empty_node;
mod full_node;
mod leaf;
mod partial_node;
mod public_inputs;

use alloy::primitives::U256;
pub use api::{build_circuits_params, extract_hash_from_proof, CircuitInput, PublicParameters};
use mp2_common::{
    group_hashing::CircuitBuilderGroupHashing,
    types::CBuilder,
    u256::{CircuitBuilderU256, UInt256Target, WitnessWriteU256},
    utils::{ToFields, ToTargets},
    F,
};
use plonky2::{
    iop::{
        target::{BoolTarget, Target},
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::circuit_builder::CircuitBuilder,
};
use plonky2_ecgfp5::gadgets::curve::CurveTarget;
pub use public_inputs::PublicInputs;

/// A cell represents a column || value tuple. it can be given in the cells tree or as the
/// secondary index value in the row tree.
#[derive(Clone, Debug, Constructor)]
pub struct Cell {
    /// identifier of the column for the secondary index
    pub identifier: F,
    /// secondary index value
    pub value: U256,
    /// is the secondary value should be included in multiplier digest or not
    pub is_multiplier: bool,
}

impl Cell {
    pub(crate) fn assign_wires(&self, pw: &mut PartialWitness<F>, wires: &CellWire) {
        pw.set_u256_target(&wires.value, self.value);
        pw.set_target(wires.identifier, self.identifier);
        pw.set_bool_target(wires.is_multiplier, self.is_multiplier);
    }
}

impl ToFields<F> for Cell {
    fn to_fields(&self) -> Vec<F> {
        [self.identifier]
            .into_iter()
            .chain(self.value.to_fields())
            .collect()
    }
}

/// The basic wires generated for each circuit of the row tree
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct CellWire {
    pub(crate) value: UInt256Target,
    pub(crate) identifier: Target,
    #[serde(serialize_with = "serialize", deserialize_with = "deserialize")]
    pub(crate) is_multiplier: BoolTarget,
}

impl CellWire {
    pub(crate) fn new(b: &mut CircuitBuilder<F, D>) -> Self {
        Self {
            value: b.add_virtual_u256(),
            identifier: b.add_virtual_target(),
            is_multiplier: b.add_virtual_bool_target_safe(),
        }
    }
    pub(crate) fn digest(&self, b: &mut CircuitBuilder<F, D>) -> CurveTarget {
        b.map_to_curve_point(&self.to_targets())
    }
}

impl ToTargets for CellWire {
    fn to_targets(&self) -> Vec<Target> {
        self.identifier
            .to_targets()
            .into_iter()
            .chain(self.value.to_targets())
            .collect::<Vec<_>>()
    }
}
pub(crate) fn decide_digest_section(
    c: &mut CBuilder,
    digest: CurveTarget,
    is_multiplier: BoolTarget,
) -> (CurveTarget, CurveTarget) {
    let zero_curve = b.curve_zero();
    let digest_ind = b.curve_select(is_multiplier, zero_curve, digest);
    let digest_mult = b.curve_select(is_multiplier, digest, zero_curve);
    (digest_ind, digest_mult)
}
/// aggregate the digest of the child proof in the right digest
pub(crate) fn accumulate_proof_digest(
    c: &mut CBuilder,
    ind: CurveTarget,
    mul: CurveTarget,
    child_proof: PublicInputs<Target>,
) -> (CurveTarget, CurveTarget) {
    let child_digest_ind = child_proof.individual_digest_target();
    let digest_ind = c.add_curve_point(&[child_digest_ind, ind]).to_targets();
    let child_digest_mult = child_proof.multiplier_digest_target();
    let digest_mul = c.add_curve_point(&[child_digest_mult, mul]).to_targets();
    (digest_ind, digest_mul)
}
