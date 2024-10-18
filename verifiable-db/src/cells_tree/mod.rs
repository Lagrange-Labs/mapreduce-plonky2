mod api;
mod empty_node;
mod full_node;
mod leaf;
mod partial_node;
mod public_inputs;

use std::{convert::identity, iter::once};

use alloy::primitives::U256;
pub use api::{build_circuits_params, extract_hash_from_proof, CircuitInput, PublicParameters};
use derive_more::Constructor;
use itertools::Itertools;
use mp2_common::{
    digest::{Digest, SplitDigestPoint, SplitDigestTarget},
    group_hashing::{map_to_curve_point, CircuitBuilderGroupHashing},
    serialization::{deserialize, serialize},
    types::{CBuilder, CURVE_TARGET_LEN},
    u256::{CircuitBuilderU256, UInt256Target, WitnessWriteU256},
    utils::{ToFields, ToTargets},
    D, F,
};
use serde::{Deserialize, Serialize};

use plonky2::{
    hash::hash_types::{HashOut, HashOutTarget, NUM_HASH_OUT_ELTS},
    iop::{
        target::{BoolTarget, Target},
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::circuit_builder::CircuitBuilder,
};
use plonky2_ecgfp5::gadgets::curve::{CircuitBuilderEcGFp5, CurveTarget};
pub use public_inputs::PublicInputs;

/// A cell represents a column || value tuple. it can be given in the cells tree or as the
/// secondary index value in the row tree.
#[derive(Clone, Debug, Serialize, Deserialize, Constructor)]
pub(crate) struct Cell {
    /// identifier of the column for the secondary index
    pub(crate) identifier: F,
    /// secondary index value
    pub(crate) value: U256,
    /// is the secondary value should be included in multiplier digest or not
    pub(crate) is_multiplier: bool,
    /// mpt_metadata : [4]F - Hash of the metadata associated to this cell, as computed in MPT extraction circuits
    pub(crate) mpt_metadata: HashOut<F>,
}

impl Cell {
    pub(crate) fn assign_wires(&self, pw: &mut PartialWitness<F>, wires: &CellWire) {
        pw.set_u256_target(&wires.value, self.value);
        pw.set_target(wires.identifier, self.identifier);
        pw.set_bool_target(wires.is_multiplier, self.is_multiplier);
        pw.set_hash_target(wires.mpt_metadata, self.mpt_metadata);
    }
    pub(crate) fn digest(&self) -> Digest {
        map_to_curve_point(&self.to_fields())
    }
    pub(crate) fn split_digest(&self) -> SplitDigestPoint {
        let digest = self.digest();
        SplitDigestPoint::from_single_digest_point(digest, self.is_multiplier)
    }
    pub(crate) fn split_and_accumulate_digest(
        &self,
        child_digest: SplitDigestPoint,
    ) -> SplitDigestPoint {
        let sd = self.split_digest();
        sd.accumulate(&child_digest)
    }
}

impl ToFields<F> for Cell {
    fn to_fields(&self) -> Vec<F> {
        [self.identifier]
            .into_iter()
            .chain(self.value.to_fields())
            // TODO: Could we ignore is_multiplier here?
            .chain(self.mpt_metadata.to_fields())
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
    #[serde(serialize_with = "serialize", deserialize_with = "deserialize")]
    pub(crate) mpt_metadata: HashOutTarget,
}

impl CellWire {
    pub(crate) fn new(b: &mut CBuilder) -> Self {
        Self {
            value: b.add_virtual_u256(),
            identifier: b.add_virtual_target(),
            is_multiplier: b.add_virtual_bool_target_safe(),
            mpt_metadata: b.add_virtual_hash(),
        }
    }
    /// Compute the individual and multiplier values digests.
    pub(crate) fn individual_multiplier_values_digests(
        &self,
        b: &mut CBuilder,
    ) -> (CurveTarget, CurveTarget) {
        let curve_zero = b.curve_zero();

        // # value digest for current cell
        // vd = D(identifier || pack_u32(value))
        let inputs = once(self.identifier)
            .chain(self.value.to_targets())
            .collect_vec();
        let digest = b.map_to_curve_point(&inputs);

        // individual_vd = is_individual ? vd : CURVE_ZERO
        let individual_vd = b.curve_select(self.is_multiplier, curve_zero, digest);

        // multiplier_vd = is_individual ? CURVE_ZERO : vd
        let multiplier_vd = b.curve_select(self.is_multiplier, digest, curve_zero);

        (individual_vd, multiplier_vd)
    }
    /// Compute the individual and multiplier metdata digests.
    pub(crate) fn individual_multiplier_metadata_digests(
        &self,
        b: &mut CBuilder,
    ) -> (CurveTarget, CurveTarget) {
        let curve_zero = b.curve_zero();

        // # metadata digest for current cell
        // md = D(mpt_metadata || identifier)
        let inputs = self
            .mpt_metadata
            .to_targets()
            .into_iter()
            .chain(once(self.identifier))
            .collect_vec();
        let digest = b.map_to_curve_point(&inputs);

        // individual_md = is_individual ? md : CURVE_ZERO
        let individual_md = b.curve_select(self.is_multiplier, curve_zero, digest);

        // multiplier_md = is_individual ? CURVE_ZERO : md
        let multiplier_md = b.curve_select(self.is_multiplier, digest, curve_zero);

        (individual_md, multiplier_md)
    }

    // gupeng
    /// Returns the digest of the cell
    pub(crate) fn digest(&self, b: &mut CircuitBuilder<F, D>) -> CurveTarget {
        b.map_to_curve_point(&self.to_targets())
    }
    /// Returns the different digest, multiplier or individual
    pub(crate) fn split_digest(&self, c: &mut CBuilder) -> SplitDigestTarget {
        let d = self.digest(c);
        SplitDigestTarget::from_single_digest_target(c, d, self.is_multiplier)
    }
    /// Returns the split digest from this cell added with the one from the proof.
    /// NOTE: it calls agains split_digest, so call that first if you need the individual
    /// SplitDigestTarget
    pub(crate) fn split_and_accumulate_digest(
        &self,
        c: &mut CBuilder,
        child_digest: SplitDigestTarget,
    ) -> SplitDigestTarget {
        let sd = self.split_digest(c);
        sd.accumulate(c, &child_digest)
    }
}

impl ToTargets for CellWire {
    fn to_targets(&self) -> Vec<Target> {
        self.identifier
            .to_targets()
            .into_iter()
            .chain(self.value.to_targets())
            // TODO: Could we ignore is_multiplier here?
            .chain(self.mpt_metadata.to_targets())
            .collect::<Vec<_>>()
    }
}
