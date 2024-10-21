mod api;
mod empty_node;
mod full_node;
mod leaf;
mod partial_node;
mod public_inputs;

use alloy::primitives::U256;
pub use api::{build_circuits_params, extract_hash_from_proof, CircuitInput, PublicParameters};
use derive_more::Constructor;
use itertools::Itertools;
use mp2_common::{
    digest::{Digest, SplitDigestPoint, SplitDigestTarget},
    group_hashing::{map_to_curve_point, CircuitBuilderGroupHashing},
    serialization::{deserialize, serialize},
    types::CBuilder,
    u256::{CircuitBuilderU256, UInt256Target, WitnessWriteU256},
    utils::{ToFields, ToTargets},
    F,
};
use serde::{Deserialize, Serialize};
use std::iter::once;

use plonky2::{
    hash::hash_types::{HashOut, HashOutTarget},
    iop::{
        target::{BoolTarget, Target},
        witness::{PartialWitness, WitnessWrite},
    },
};
use plonky2_ecgfp5::gadgets::curve::CurveTarget;
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
    /// Hash of the metadata associated to this cell, as computed in MPT extraction circuits
    pub(crate) mpt_metadata: HashOut<F>,
}

impl Cell {
    pub(crate) fn assign_wires(&self, pw: &mut PartialWitness<F>, wires: &CellWire) {
        pw.set_u256_target(&wires.value, self.value);
        pw.set_target(wires.identifier, self.identifier);
        pw.set_bool_target(wires.is_multiplier, self.is_multiplier);
        pw.set_hash_target(wires.mpt_metadata, self.mpt_metadata);
    }
    pub(crate) fn split_metadata_digest(&self) -> SplitDigestPoint {
        let digest = self.metadata_digest();
        SplitDigestPoint::from_single_digest_point(digest, self.is_multiplier)
    }
    pub(crate) fn split_values_digest(&self) -> SplitDigestPoint {
        let digest = self.values_digest();
        SplitDigestPoint::from_single_digest_point(digest, self.is_multiplier)
    }
    pub(crate) fn split_and_accumulate_metadata_digest(
        &self,
        child_digest: SplitDigestPoint,
    ) -> SplitDigestPoint {
        let split_digest = self.split_metadata_digest();
        split_digest.accumulate(&child_digest)
    }
    pub(crate) fn split_and_accumulate_values_digest(
        &self,
        child_digest: SplitDigestPoint,
    ) -> SplitDigestPoint {
        let split_digest = self.split_values_digest();
        split_digest.accumulate(&child_digest)
    }
    fn metadata_digest(&self) -> Digest {
        // D(mpt_metadata || identifier)
        let inputs = self
            .mpt_metadata
            .to_fields()
            .into_iter()
            .chain(once(self.identifier))
            .collect_vec();

        map_to_curve_point(&inputs)
    }
    fn values_digest(&self) -> Digest {
        // D(identifier || pack_u32(value))
        let inputs = once(self.identifier)
            .chain(self.value.to_fields())
            .collect_vec();

        map_to_curve_point(&inputs)
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
    pub(crate) fn split_metadata_digest(&self, b: &mut CBuilder) -> SplitDigestTarget {
        let digest = self.metadata_digest(b);
        SplitDigestTarget::from_single_digest_target(b, digest, self.is_multiplier)
    }
    pub(crate) fn split_values_digest(&self, b: &mut CBuilder) -> SplitDigestTarget {
        let digest = self.values_digest(b);
        SplitDigestTarget::from_single_digest_target(b, digest, self.is_multiplier)
    }
    pub(crate) fn split_and_accumulate_metadata_digest(
        &self,
        b: &mut CBuilder,
        child_digest: SplitDigestTarget,
    ) -> SplitDigestTarget {
        let split_digest = self.split_metadata_digest(b);
        split_digest.accumulate(b, &child_digest)
    }
    pub(crate) fn split_and_accumulate_values_digest(
        &self,
        b: &mut CBuilder,
        child_digest: SplitDigestTarget,
    ) -> SplitDigestTarget {
        let split_digest = self.split_values_digest(b);
        split_digest.accumulate(b, &child_digest)
    }
    fn metadata_digest(&self, b: &mut CBuilder) -> CurveTarget {
        // D(mpt_metadata || identifier)
        let inputs = self
            .mpt_metadata
            .to_targets()
            .into_iter()
            .chain(once(self.identifier))
            .collect_vec();

        b.map_to_curve_point(&inputs)
    }
    fn values_digest(&self, b: &mut CBuilder) -> CurveTarget {
        // D(identifier || pack_u32(value))
        let inputs = once(self.identifier)
            .chain(self.value.to_targets())
            .collect_vec();

        b.map_to_curve_point(&inputs)
    }
}
