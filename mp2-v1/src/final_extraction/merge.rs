use super::{
    api::{FinalExtractionBuilderParams, MergeTableInput, NUM_IO},
    base_circuit::{self, BaseCircuitProofWires},
    public_inputs::PublicInputsArgs,
    BaseCircuitProofInputs, PublicInputs, TableDimension, TableDimensionWire,
};
use mp2_common::{
    group_hashing::{
        circuit_hashed_scalar_mul, cond_circuit_hashed_scalar_mul, CircuitBuilderGroupHashing,
    },
    public_inputs::PublicInputCommon,
    serialization::{deserialize, serialize},
    types::{CBuilder, GFp},
    utils::{SliceConnector, ToFields, ToTargets},
    C, D, F,
};
use plonky2::{
    field::types::Field,
    iop::{
        target::{BoolTarget, Target},
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{circuit_builder::CircuitBuilder, proof::ProofWithPublicInputsTarget},
};
use plonky2_ecgfp5::gadgets::curve::CircuitBuilderEcGFp5;
use recursion_framework::{
    circuit_builder::CircuitLogicWires,
    framework::{RecursiveCircuits, RecursiveCircuitsVerifierTarget},
};
use serde::{Deserialize, Serialize};
use sqlparser::ast::Table;
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
    pub fn build<'a>(
        b: &mut CBuilder,
        block_pi: &[Target],
        contract_pi: &[Target],
        table_a: &[Target],
        table_b: &[Target],
    ) -> MergeTableWires {
        /// First do the final extraction logic on both table
        let base_wires_a = base_circuit::BaseCircuit::build(b, block_pi, contract_pi, table_a);
        let base_wires_b = base_circuit::BaseCircuit::build(b, block_pi, contract_pi, table_a);

        // Check both proofs share the same MPT proofs
        // NOTE: this enforce both variables are from the same contract. If we remove this
        // check this opens the door to merging different variables from different contracts.
        let table_a = super::PublicInputs::from_slice(table_a);
        let table_b = super::PublicInputs::from_slice(table_b);
        b.connect_slice(&table_a.commitment(), &table_b.commitment());

        let is_table_a_multiplier = b.add_virtual_bool_target_safe();
        // prepare the table digest if they're compound or not
        let digest_a = table_a.value_set_digest();
        let dimension_a: TableDimensionWire = b.add_virtual_bool_target_safe().into();
        let input_a = dimension_a.conditional_digest(b, digest_a);

        let digest_b = table_b.value_set_digest();
        let dimension_b: TableDimensionWire = b.add_virtual_bool_target_safe().into();
        let input_b = dimension_b.conditional_digest(b, digest_b);

        // combine the value digest together, splitting between the table that is on the outer side
        // (the multiplier) and the inner side (the "individual")
        // TODO: put in common with verifiable-db
        let multiplier = b.select_curve_point(is_table_a_multiplier, input_a, input_b);
        let base = b.select_curve_point(is_table_a_multiplier, input_b, input_a);
        // Since we are always merging two tables here, we don't need to use the conditional variant.
        let new_dv = circuit_hashed_scalar_mul(b, multiplier.to_targets(), base);

        // combine the table metadata hashes together
        // NOTE: this combine twice the contract address for example
        let input_a = table_a.metadata_set_digest();
        let input_b = table_b.metadata_set_digest();
        // here we simply add the metadata digests, since we don't really need to differentiate in
        // the metadata who is the multiplier or not.
        let new_md = b.curve_add(input_a, input_b);

        PublicInputs::new(
            &base_wires_a.bh,
            &base_wires_a.prev_bh,
            &new_dv.to_targets(),
            &new_md.to_targets(),
            &base_wires_a.bn.to_targets(),
        )
        .register_args(b);
        MergeTableWires {
            is_table_a_multiplier,
            dimension_a,
            dimension_b,
        }
    }
    fn assign(&self, pw: &mut PartialWitness<F>, wires: &MergeTableWires) {
        self.dimension_a.assign_wire(pw, &wires.dimension_a);
        self.dimension_b.assign_wire(pw, &wires.dimension_b);
        pw.set_bool_target(wires.is_table_a_multiplier, self.is_table_a_multiplier);
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub(crate) struct MergeTableRecursiveWires {
    /// Wires containing the block, and contract information, as well as the table_a extraction
    /// proof.
    base_a: BaseCircuitProofWires,
    /// table_b extraction proof. It will be verified against the same block and contract proof
    /// contained in base_a.
    value_b: RecursiveCircuitsVerifierTarget<D>,
    /// Wires information to merge properly the tables
    merge_wires: MergeTableWires,
}

pub struct MergeCircuitInput {
    base_a: BaseCircuitProofInputs,
    table_b: RecursiveCircuits<F, C, D>,
    merge: MergeTable,
}

impl MergeCircuitInput {
    pub(crate) fn new(
        base_a: BaseCircuitProofInputs,
        table_b: RecursiveCircuits<F, C, D>,
        merge: MergeTable,
    ) -> Self {
        Self {
            base_a,
            table_b,
            merge,
        }
    }
}

impl CircuitLogicWires<F, D, 0> for MergeTableRecursiveWires {
    type CircuitBuilderParams = FinalExtractionBuilderParams;

    type Inputs = MergeTableInput;

    const NUM_PUBLIC_INPUTS: usize = NUM_IO;

    fn circuit_logic(
        builder: &mut CircuitBuilder<F, D>,
        _verified_proofs: [&plonky2::plonk::proof::ProofWithPublicInputsTarget<D>; 0],
        builder_parameters: Self::CircuitBuilderParams,
    ) -> Self {
        let base = BaseCircuitProofInputs::build(builder, &builder_parameters);
        let wires = MergeTable::build(
            builder,
            base.get_block_public_inputs(),
            base.get_contract_public_inputs(),
            base.get_value_public_inputs(),
        );
        Self {
            base,
            simple_wires: wires,
        }
    }

    fn assign_input(&self, inputs: Self::Inputs, pw: &mut PartialWitness<F>) -> anyhow::Result<()> {
        inputs.base.assign_proof_targets(pw, &self.base)?;
        inputs.simple.assign(pw, &self.simple_wires);
        Ok(())
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
        let table_b = PublicInputs::new(&verified_proofs[1].public_inputs);
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

    use crate::values_extraction;

    use super::*;
    use base_circuit::test::{ProofsPi, ProofsPiTarget};
    use mp2_common::{
        group_hashing::{
            cond_field_hashed_scalar_mul, field_hashed_scalar_mul, weierstrass_to_point as wp,
        },
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

    fn random_field_vector(n: usize) -> Vec<F> {
        (0..n).map(|_| F::rand()).collect()
    }

    #[test]
    fn test_merge_table() {
        let pis_a = ProofsPi::random();
        let pis_b = pis_a.generate_new_random_value();
        let table_a_multiplier = true;
        let test_circuit = TestMergeCircuit {
            pis_a,
            pis_b: pis_b.values_pi.clone(),
            circuit: MergeTable {
                is_table_a_multiplier: table_a_multiplier,
                dimension_a: TableDimension::Single,
                dimension_b: TableDimension::Compound,
            },
        };

        let proof = run_circuit::<F, D, C, _>(test_circuit);
        let pi = PublicInputs::from_slice(&proof.public_inputs);

        let (scalar, base) = match table_a_multiplier {
            true => (
                pis_a.value_inputs().values_digest(),
                pis_b.value_inputs().values_digest(),
            ),
            false => (
                pis_b.value_inputs().values_digest(),
                pis_a.value_inputs().values_digest(),
            ),
        };
        let combined_digest = field_hashed_scalar_mul(scalar, wp(&base));
        assert_eq!(combined_digest, wp(&pi.value_set_digest()));
        let combined_metadata = wp(&pis_a.value_inputs().metadata_digest())
            + wp(&pis_b.value_inputs().metadata_digest());
        assert_eq!(combined_metadata, wp(&pi.metadata_set_digest()));
    }
}
