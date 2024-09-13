use super::{public_inputs::PublicInputsArgs, PublicInputs};
use mp2_common::{
    group_hashing::{circuit_hashed_scalar_mul, CircuitBuilderGroupHashing},
    public_inputs::PublicInputCommon,
    serialization::{deserialize, serialize},
    types::CBuilder,
    utils::{ToFields, ToTargets},
    F,
};
use plonky2::{
    field::types::Field,
    iop::target::{BoolTarget, Target},
};
use plonky2_ecgfp5::gadgets::curve::CircuitBuilderEcGFp5;
use serde::{Deserialize, Serialize};

/// This merge table circuit is responsible for computing the right digest of the values and
/// metadata of the table when one wants to combine two singleton table.
/// A singleton table is simply a table represented by either a single compound variable (mapping,
/// array...) OR a list of single variable(uint256, etc).
/// WARNING: This circuit should only be called ONCE. We can not "merge a merged table", i.e. we
/// can only aggregate 2 singletons table together and can only aggregate once.
pub struct MergeTable {}
#[derive(Clone, Debug, Serialize, Deserialize)]
struct MergeTableWires {
    #[serde(deserialize_with = "deserialize", serialize_with = "serialize")]
    is_table_a_multiplier: BoolTarget,
}

impl MergeTable {
    pub fn build<'a>(
        b: &mut CBuilder,
        table_a: PublicInputs<'a, Target>,
        table_b: PublicInputs<'a, Target>,
    ) -> MergeTableWires {
        let is_table_a_multiplier = b.add_virtual_bool_target_safe();
        // combine the value digest together
        let input_a = table_a.values_digest_target();
        let input_b = table_b.values_digest_target();
        let multiplier = b.select_curve_point(is_table_a_multiplier, input_a, input_b);
        let base = b.select_curve_point(is_table_a_multiplier, input_b, input_a);
        let new_dv = circuit_hashed_scalar_mul(b, multiplier.to_targets(), base);

        // combine the table metadata hashes together
        let input_a = table_a.metadata_digest_target();
        let input_b = table_b.metadata_digest_target();
        // here we simply add the metadata digests, since we don't really need to differentiate in
        // the metadata who is the multiplier or not.
        let new_md = b.curve_add(input_a, input_b);

        // Check both proofs share the same MPT proofs
        // NOTE: this enforce both variables are from the same contract. If we remove this
        // check this opens the door to merging different variables from different contracts.
        table_a
            .root_hash_target()
            .enforce_equal(b, &table_b.root_hash_target());

        // Enforce that both MPT keys have their pointer at -1, i.e. we are only merging such
        // proofs at the ROOT of the MPT
        let minus_one = b.constant(F::NEG_ONE);
        b.connect(table_a.mpt_key().pointer, minus_one);
        b.connect(table_b.mpt_key().pointer, minus_one);
        PublicInputsArgs {
            h: &table_a.root_hash_target(),
            k: &table_b.mpt_key(),
            dv: new_dv,
            dm: new_md,
            n: b.add(table_a.n(), table_b.n()),
        }
        .register(b);
        MergeTableWires {
            is_table_a_multiplier,
        }
    }
}
