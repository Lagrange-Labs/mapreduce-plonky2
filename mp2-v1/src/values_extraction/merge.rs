use super::{public_inputs::PublicInputsArgs, PublicInputs};
use mp2_common::{
    group_hashing::{circuit_hashed_scalar_mul, CircuitBuilderGroupHashing},
    public_inputs::PublicInputCommon,
    serialization::{deserialize, serialize},
    types::{CBuilder, GFp},
    utils::{ToFields, ToTargets},
    D, F,
};
use plonky2::{
    field::types::Field,
    iop::{
        target::{BoolTarget, Target},
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::proof::ProofWithPublicInputsTarget,
};
use plonky2_ecgfp5::gadgets::curve::CircuitBuilderEcGFp5;
use recursion_framework::circuit_builder::CircuitLogicWires;
use serde::{Deserialize, Serialize};

/// This merge table circuit is responsible for computing the right digest of the values and
/// metadata of the table when one wants to combine two singleton table.
/// A singleton table is simply a table represented by either a single compound variable (mapping,
/// array...) OR a list of single variable(uint256, etc).
/// WARNING: This circuit should only be called ONCE. We can not "merge a merged table", i.e. we
/// can only aggregate 2 singletons table together and can only aggregate once.
#[derive(Clone, Debug)]
pub struct MergeTable {
    pub(crate) is_table_a_multiplier: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct MergeTableWires {
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
        // Here we don't need
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
    fn assign(&self, pw: &mut PartialWitness<F>, wires: &MergeTableWires) {
        pw.set_bool_target(wires.is_table_a_multiplier, self.is_table_a_multiplier);
    }
}

/// Num of children = 2 - always two proofs to merge
impl CircuitLogicWires<GFp, D, 2> for MergeTableWires {
    type CircuitBuilderParams = ();

    type Inputs = MergeTable;

    const NUM_PUBLIC_INPUTS: usize = PublicInputs::<GFp>::TOTAL_LEN;

    fn circuit_logic(
        builder: &mut CBuilder,
        verified_proofs: [&ProofWithPublicInputsTarget<D>; 2],
        _builder_parameters: Self::CircuitBuilderParams,
    ) -> Self {
        let table_a = PublicInputs::new(&verified_proofs[0].public_inputs);
        let table_b = PublicInputs::new(&verified_proofs[0].public_inputs);
        MergeTable::build(builder, table_a, table_b)
    }

    fn assign_input(
        &self,
        inputs: Self::Inputs,
        pw: &mut PartialWitness<GFp>,
    ) -> anyhow::Result<()> {
        inputs.assign(pw, &self);
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use std::iter::once;

    use super::*;
    use mp2_common::{
        group_hashing::{field_hashed_scalar_mul, weierstrass_to_point as wp},
        keccak::PACKED_HASH_LEN,
        rlp::MAX_KEY_NIBBLE_LEN,
        C, D, F,
    };
    use mp2_test::circuit::{run_circuit, UserCircuit};
    use plonky2::{
        field::types::Sample,
        iop::witness::{PartialWitness, WitnessWrite},
    };
    use plonky2_ecgfp5::curve::curve::Point;

    use super::MergeTableWires;

    #[derive(Clone, Debug)]
    struct TestMerge {
        merge: MergeTable,
        table_a: Vec<F>,
        table_b: Vec<F>,
    }

    impl UserCircuit<F, D> for TestMerge {
        type Wires = (MergeTableWires, Vec<Target>, Vec<Target>);

        fn build(b: &mut CBuilder) -> Self::Wires {
            let table_a = b.add_virtual_targets(PublicInputs::<Target>::TOTAL_LEN);
            let table_b = b.add_virtual_targets(PublicInputs::<Target>::TOTAL_LEN);
            let wires =
                MergeTable::build(b, PublicInputs::new(&table_a), PublicInputs::new(&table_b));
            (wires, table_a, table_b)
        }

        fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
            self.merge.assign(pw, &wires.0);
            pw.set_target_arr(&wires.1, &self.table_a);
            pw.set_target_arr(&wires.2, &self.table_b);
        }
    }

    fn random_field_vector(n: usize) -> Vec<F> {
        (0..n).map(|_| F::rand()).collect()
    }

    fn random_public_input(root_hash: Option<Vec<F>>) -> Vec<F> {
        let h = root_hash.unwrap_or_else(|| random_field_vector(PACKED_HASH_LEN));
        let k = random_field_vector(MAX_KEY_NIBBLE_LEN);
        let t = F::NEG_ONE;
        let dv = Point::rand().to_fields();
        let dm = Point::rand().to_fields();
        let n = F::from_canonical_u8(10);
        h.into_iter()
            .chain(k)
            .chain(once(t))
            .chain(dv)
            .chain(dm)
            .chain(once(n))
            .collect()
    }

    #[test]
    fn test_merge_table() {
        let table_a = random_public_input(None);
        let table_a_pi = PublicInputs::new(&table_a);
        // making sure they both share the same root hash
        let table_b = random_public_input(Some(table_a_pi.root_hash_info().to_vec()));
        let table_b_pi = PublicInputs::new(&table_b);
        let is_table_a_multiplier = true;
        let test_circuit = TestMerge {
            merge: MergeTable {
                is_table_a_multiplier,
            },
            table_a: table_a.clone(),
            table_b: table_b.clone(),
        };

        let proof = run_circuit::<F, D, C, _>(test_circuit);
        let pi = PublicInputs::new(&proof.public_inputs);

        let (scalar, base) = match is_table_a_multiplier {
            true => (table_a_pi.values_digest(), table_b_pi.values_digest()),
            false => (table_b_pi.values_digest(), table_a_pi.values_digest()),
        };
        let combined_digest = field_hashed_scalar_mul(scalar.to_fields(), wp(&base));
        assert_eq!(combined_digest, wp(&pi.values_digest()));
        let combined_metadata =
            wp(&table_a_pi.metadata_digest()) + wp(&table_b_pi.metadata_digest());
        assert_eq!(combined_metadata, wp(&pi.metadata_digest()));
    }
}
