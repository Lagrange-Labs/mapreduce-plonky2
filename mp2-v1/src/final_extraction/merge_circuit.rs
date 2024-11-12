use crate::values_extraction;

use super::{
    api::{FinalExtractionBuilderParams, NUM_IO},
    base_circuit::{self, BaseCircuitProofWires},
    BaseCircuitProofInputs, PublicInputs,
};
use mp2_common::{
    digest::{SplitDigestTarget, TableDimension, TableDimensionWire},
    serialization::{deserialize, serialize},
    types::CBuilder,
    utils::ToTargets,
    D, F,
};
use plonky2::{
    iop::{
        target::{BoolTarget, Target},
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::circuit_builder::CircuitBuilder,
};
use recursion_framework::circuit_builder::CircuitLogicWires;
use serde::{Deserialize, Serialize};
use verifiable_db::extraction::ExtractionPI;

/// This merge table circuit is responsible for computing the right digest of the values and
/// metadata of the table when one wants to combine two singleton table.
/// A singleton table is simply a table represented by either a single compound variable (mapping,
/// array...) OR a list of single variable(uint256, etc).
/// WARNING: This circuit should only be called ONCE. We can not "merge a merged table", i.e. we
/// can only aggregate 2 singletons table together and can only aggregate once.
#[derive(Clone, Debug)]
pub struct MergeTable {
    pub(crate) is_table_a_multiplier: bool,
    pub(crate) dimension_a: TableDimension,
    pub(crate) dimension_b: TableDimension,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct MergeTableWires {
    #[serde(deserialize_with = "deserialize", serialize_with = "serialize")]
    is_table_a_multiplier: BoolTarget,
    dimension_a: TableDimensionWire,
    dimension_b: TableDimensionWire,
}

impl MergeTable {
    pub fn build(
        b: &mut CBuilder,
        block_pi: &[Target],
        contract_pi: &[Target],
        table_a: &[Target],
        table_b: &[Target],
    ) -> MergeTableWires {
        // First do the final extraction logic on both table, i.e. both tables are checked against
        // the block and contract proofs to match for storage root trie and state root trie
        let base_wires =
            base_circuit::BaseCircuit::build(b, block_pi, contract_pi, vec![table_a, table_b]);

        let table_a = values_extraction::PublicInputs::new(table_a);
        let table_b = values_extraction::PublicInputs::new(table_b);

        // prepare the table digest if they're compound or not
        // At final extraction, if we're extracting a single type table, then we need to digest one
        // more time the value proof digest. The value proof digest gives us SUM D(column) but at
        // this stage we want D ( SUM D(column)).
        // NOTE: in practice at first we only gonna have one table being the single table with a
        // single row and the other one being a mapping. But this implementation should allow for
        // mappings X mappings, or arrays X mappings etc.
        let table_a_dimension = TableDimensionWire(b.add_virtual_bool_target_safe());
        let table_b_dimension = TableDimensionWire(b.add_virtual_bool_target_safe());
        let digest_a = table_a_dimension.conditional_row_digest(b, table_a.values_digest_target());
        let digest_b = table_b_dimension.conditional_row_digest(b, table_b.values_digest_target());

        // Combine the two digest depending on which table is the multiplier
        let is_table_a_multiplier = b.add_virtual_bool_target_safe();
        let is_table_b_multiplier = b.not(is_table_a_multiplier);
        let split_a =
            SplitDigestTarget::from_single_digest_target(b, digest_a, is_table_a_multiplier);
        let split_b =
            SplitDigestTarget::from_single_digest_target(b, digest_b, is_table_b_multiplier);
        // combine the value digest together, splitting between the table that is on the outer side
        // (the multiplier) and the inner side (the "individual")
        // H(table_multiplier_digest) * table_individual_digest
        let combined_split = split_a.accumulate(b, &split_b);
        let new_dv = combined_split.combine_to_digest(b);

        PublicInputs::new(
            &base_wires.bh,
            &base_wires.prev_bh,
            &new_dv.to_targets(),
            &base_wires.dm.to_targets(),
            &base_wires.bn.to_targets(),
            &[b._true().target],
        )
        .register_args(b);
        MergeTableWires {
            is_table_a_multiplier,
            dimension_a: table_a_dimension,
            dimension_b: table_b_dimension,
        }
    }
    fn assign(&self, pw: &mut PartialWitness<F>, wires: &MergeTableWires) {
        self.dimension_a.assign_wire(pw, &wires.dimension_a);
        self.dimension_b.assign_wire(pw, &wires.dimension_b);
        pw.set_bool_target(wires.is_table_a_multiplier, self.is_table_a_multiplier);
    }
}

/// The wires that are needed for the recursive framework, that concerns verifying  the input
/// proofs
#[derive(Serialize, Deserialize, Clone, Debug)]
pub(crate) struct MergeTableRecursiveWires {
    /// Wires containing the block, and contract information,
    /// It contains two value proofs, table a and table b
    base: BaseCircuitProofWires,
    /// Wires information to merge properly the tables
    merge: MergeTableWires,
}

/// The full input to generate a merge proof including the proofs of contract block and value
/// extraction
pub(crate) struct MergeCircuitInput {
    pub(crate) base: BaseCircuitProofInputs,
    pub(crate) merge: MergeTable,
}

impl MergeCircuitInput {
    // CHORE: Remove this when relevant PR is merged
    #[allow(dead_code)]
    pub(crate) fn new(base: BaseCircuitProofInputs, merge: MergeTable) -> Self {
        Self { base, merge }
    }
}

impl CircuitLogicWires<F, D, 0> for MergeTableRecursiveWires {
    type CircuitBuilderParams = FinalExtractionBuilderParams;

    type Inputs = MergeCircuitInput;

    const NUM_PUBLIC_INPUTS: usize = NUM_IO;

    fn circuit_logic(
        builder: &mut CircuitBuilder<F, D>,
        _verified_proofs: [&plonky2::plonk::proof::ProofWithPublicInputsTarget<D>; 0],
        builder_parameters: Self::CircuitBuilderParams,
    ) -> Self {
        // value proof for table a and value proof for table b = 2
        let base = BaseCircuitProofInputs::build(builder, &builder_parameters, 2);
        let wires = MergeTable::build(
            builder,
            base.get_block_public_inputs(),
            base.get_contract_public_inputs(),
            base.get_value_public_inputs_at(0),
            base.get_value_public_inputs_at(1),
        );
        Self { base, merge: wires }
    }

    fn assign_input(&self, inputs: Self::Inputs, pw: &mut PartialWitness<F>) -> anyhow::Result<()> {
        inputs.base.assign_proof_targets(pw, &self.base)?;
        inputs.merge.assign(pw, &self.merge);
        Ok(())
    }
}

#[cfg(test)]
mod test {

    use crate::values_extraction;

    use super::*;
    use base_circuit::test::{ProofsPi, ProofsPiTarget};
    use mp2_common::{
        digest::SplitDigestPoint, group_hashing::weierstrass_to_point as wp, C, D, F,
    };
    use mp2_test::circuit::{run_circuit, UserCircuit};
    use plonky2::iop::witness::WitnessWrite;

    use super::MergeTableWires;

    #[derive(Clone, Debug)]
    struct TestMergeCircuit {
        circuit: MergeTable,
        pis_a: ProofsPi,
        pis_b: Vec<F>,
    }

    struct TestMergeWires {
        circuit: MergeTableWires,
        pis_a: ProofsPiTarget,
        pis_b: Vec<Target>,
    }

    impl UserCircuit<F, D> for TestMergeCircuit {
        type Wires = TestMergeWires;
        fn build(c: &mut plonky2::plonk::circuit_builder::CircuitBuilder<F, D>) -> Self::Wires {
            let pis_a = ProofsPiTarget::new(c);
            let pis_b = c.add_virtual_targets(values_extraction::PublicInputs::<Target>::TOTAL_LEN);
            let wires = MergeTable::build(
                c,
                &pis_a.blocks_pi,
                &pis_a.contract_pi,
                &pis_a.values_pi,
                &pis_b,
            );
            TestMergeWires {
                circuit: wires,
                pis_a,
                pis_b,
            }
        }
        fn prove(&self, pw: &mut plonky2::iop::witness::PartialWitness<F>, wires: &Self::Wires) {
            self.circuit.assign(pw, &wires.circuit);
            wires.pis_a.assign(pw, &self.pis_a);
            pw.set_target_arr(&wires.pis_b, &self.pis_b);
        }
    }

    #[test]
    fn test_final_merge_circuit() {
        let pis_a = ProofsPi::random();
        let pis_b = pis_a.generate_new_random_value();
        let table_a_dimension = TableDimension::Single;
        let table_b_dimension = TableDimension::Compound;

        let table_a_multiplier = true;
        let test_circuit = TestMergeCircuit {
            pis_a: pis_a.clone(),
            pis_b: pis_b.values_pi.clone(),
            circuit: MergeTable {
                is_table_a_multiplier: table_a_multiplier,
                dimension_a: table_a_dimension,
                dimension_b: table_b_dimension,
            },
        };

        let proof = run_circuit::<F, D, C, _>(test_circuit);
        let pi = PublicInputs::from_slice(&proof.public_inputs);

        // first compute the right digest for each table according to their dimension
        let table_a_digest =
            table_a_dimension.conditional_row_digest(wp(&pis_a.value_inputs().values_digest()));
        let table_b_digest =
            table_b_dimension.conditional_row_digest(wp(&pis_b.value_inputs().values_digest()));
        // then do the splitting according to how we want to merge them (i.e. which is the
        // multiplier)
        let split_a =
            SplitDigestPoint::from_single_digest_point(table_a_digest, table_a_multiplier);
        let split_b =
            SplitDigestPoint::from_single_digest_point(table_b_digest, !table_a_multiplier);
        // then finally combined them into a single one
        let split_total = split_a.accumulate(&split_b);
        let final_digest = split_total.combine_to_row_digest();
        // testing the digest values
        assert_eq!(final_digest, wp(&pi.value_point()));
        let combined_metadata = wp(&pis_a.value_inputs().metadata_digest())
            + wp(&pis_b.value_inputs().metadata_digest())
            + wp(&pis_a.contract_inputs().metadata_point());
        assert_eq!(combined_metadata, wp(&pi.metadata_point()));
        let block_pi = pis_a.block_inputs();
        assert_eq!(pi.bn, block_pi.bn);
        assert_eq!(pi.h, block_pi.bh);
        assert_eq!(pi.ph, block_pi.prev_bh);
    }
}
