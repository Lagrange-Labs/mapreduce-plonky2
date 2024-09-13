mod api;
mod empty_node;
mod full_node;
mod leaf;
mod partial_node;
mod public_inputs;

use serde::{Deserialize, Serialize};

use alloy::primitives::U256;
pub use api::{build_circuits_params, extract_hash_from_proof, CircuitInput, PublicParameters};
use derive_more::Constructor;
use mp2_common::{
    group_hashing::{map_to_curve_point, weierstrass_to_point, CircuitBuilderGroupHashing},
    serialization::{deserialize, serialize},
    types::CBuilder,
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
use plonky2_ecgfp5::{
    curve::curve::Point,
    gadgets::curve::{CircuitBuilderEcGFp5, CurveTarget},
};
pub use public_inputs::PublicInputs;

/// A cell represents a column || value tuple. it can be given in the cells tree or as the
/// secondary index value in the row tree.
#[derive(Clone, Debug, Serialize, Deserialize, Constructor)]
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
    pub(crate) fn digest(&self) -> Point {
        map_to_curve_point(&self.to_fields())
    }
    pub(crate) fn split_digest(&self) -> (Point, Point) {
        let digest = self.digest();
        field_decide_digest_section(digest, self.is_multiplier)
    }
    pub(crate) fn split_and_accumulate_digest(&self, pis: &PublicInputs<F>) -> (Point, Point) {
        let (ind, mul) = self.split_digest();
        field_accumulate_proof_digest(ind, mul, pis)
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
    pub(crate) fn split_digest(&self, c: &mut CBuilder) -> (CurveTarget, CurveTarget) {
        let d = self.digest(c);
        circuit_decide_digest_section(c, d, self.is_multiplier)
    }
    pub(crate) fn split_and_accumulate_digest(
        &self,
        c: &mut CBuilder,
        pis: &PublicInputs<Target>,
    ) -> (CurveTarget, CurveTarget) {
        let (ind, mul) = self.split_digest(c);
        circuit_accumulate_proof_digest(c, ind, mul, pis)
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
/// Returns the individual and multiplier digest
pub(crate) fn circuit_decide_digest_section(
    c: &mut CBuilder,
    digest: CurveTarget,
    is_multiplier: BoolTarget,
) -> (CurveTarget, CurveTarget) {
    let zero_curve = c.curve_zero();
    let digest_ind = c.curve_select(is_multiplier, zero_curve, digest);
    let digest_mult = c.curve_select(is_multiplier, digest, zero_curve);
    (digest_ind, digest_mult)
}
/// aggregate the digest of the child proof in the right digest
/// Returns the individual and multiplier digest
pub(crate) fn circuit_accumulate_proof_digest(
    c: &mut CBuilder,
    ind: CurveTarget,
    mul: CurveTarget,
    child_proof: &PublicInputs<Target>,
) -> (CurveTarget, CurveTarget) {
    let child_digest_ind = child_proof.individual_digest_target();
    let digest_ind = c.add_curve_point(&[child_digest_ind, ind]);
    let child_digest_mult = child_proof.multiplier_digest_target();
    let digest_mul = c.add_curve_point(&[child_digest_mult, mul]);
    (digest_ind, digest_mul)
}

/// Returns the individual and multiplier digest
pub(crate) fn field_decide_digest_section(digest: Point, is_multiplier: bool) -> (Point, Point) {
    match is_multiplier {
        true => (Point::NEUTRAL, digest),
        false => (digest, Point::NEUTRAL),
    }
}

pub(crate) fn field_accumulate_proof_digest(
    ind: Point,
    mul: Point,
    child_proof: &PublicInputs<F>,
) -> (Point, Point) {
    let child_digest_ind = child_proof.individual_digest_point();
    let child_digest_mult = child_proof.multiplier_digest_point();
    (
        weierstrass_to_point(&child_digest_ind) + ind,
        weierstrass_to_point(&child_digest_mult) + mul,
    )
}
