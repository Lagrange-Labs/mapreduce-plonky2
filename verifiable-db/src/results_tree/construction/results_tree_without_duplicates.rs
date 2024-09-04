use super::public_inputs::PublicInputs;
use crate::query::universal_circuit::build_cells_tree;
use alloy::primitives::U256;
use mp2_common::{
    group_hashing::CircuitBuilderGroupHashing,
    poseidon::{empty_poseidon_hash, H},
    public_inputs::PublicInputCommon,
    serialization::{
        deserialize, deserialize_array, deserialize_long_array, serialize, serialize_array,
        serialize_long_array,
    },
    types::CBuilder,
    u256::{CircuitBuilderU256, UInt256Target, WitnessWriteU256},
    utils::{SelectHashBuilder, ToTargets},
    D, F,
};
use plonky2::{
    iop::{
        target::{BoolTarget, Target},
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::proof::ProofWithPublicInputsTarget,
};
use plonky2_crypto::u32::arithmetic_u32::U32Target;
use plonky2_ecdsa::gadgets::{biguint::BigUintTarget, nonnative::CircuitBuilderNonNative};
use plonky2_ecgfp5::gadgets::curve::CircuitBuilderEcGFp5;
use recursion_framework::circuit_builder::CircuitLogicWires;
use serde::{Deserialize, Serialize};
use std::{array, iter};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResultsTreeWithoutDuplicatesWires<const S: usize> {
    #[serde(
        serialize_with = "serialize_long_array",
        deserialize_with = "deserialize_long_array"
    )]
    item_values: [UInt256Target; S],
    #[serde(
        serialize_with = "serialize_long_array",
        deserialize_with = "deserialize_long_array"
    )]
    ids: [Target; S],
    #[serde(
        serialize_with = "serialize_array",
        deserialize_with = "deserialize_array"
    )]
    is_item_included: [BoolTarget; S],
    multiplicity: Target,
    #[serde(serialize_with = "serialize", deserialize_with = "deserialize")]
    is_stored_in_leaf: BoolTarget,
    counter: Target,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResultsTreeWithoutDuplicatesCircuit<const S: usize> {
    /// `S` items values to be employed to build the record,
    /// corresponding to the output items extracted from the corresponding record of the original tree.
    #[serde(
        serialize_with = "serialize_long_array",
        deserialize_with = "deserialize_long_array"
    )]
    pub(crate) item_values: [U256; S],
    /// Integer identifiers of each of the S items.
    #[serde(
        serialize_with = "serialize_long_array",
        deserialize_with = "deserialize_long_array"
    )]
    pub(crate) ids: [F; S],
    /// Number of items accumulated in the results of the query for the given record.
    pub(crate) num_included_items: usize,
    /// Number of matching records of the original tree
    /// whose output items corresponds to `item_values`
    pub(crate) multiplicity: F,
    /// Boolean flag specifying whether this record is going to be stored
    /// in a leaf node of a rows tree.
    pub(crate) is_stored_in_leaf: bool,
    /// Counter value associated to the current record.
    pub(crate) counter: F,
}

impl<const S: usize> ResultsTreeWithoutDuplicatesCircuit<S> {
    pub fn build(b: &mut CBuilder) -> ResultsTreeWithoutDuplicatesWires<S> {
        let ttrue = b._true();
        let u256_zero = b.zero_u256();
        let empty_hash = b.constant_hash(*empty_poseidon_hash());

        let item_values: [UInt256Target; S] = b.add_virtual_u256_arr_unsafe();
        let ids: [Target; S] = b.add_virtual_target_arr();
        let is_item_included: [BoolTarget; S] =
            array::from_fn(|_| b.add_virtual_bool_target_safe());
        let multiplicity = b.add_virtual_target();
        let is_stored_in_leaf = b.add_virtual_bool_target_safe();
        let counter = b.add_virtual_target();

        let mut tree_hash =
            build_cells_tree(b, &item_values[2..], &ids[2..], &is_item_included[2..]);

        // Ensure that the prover cannot make 2 records distinct
        //by employing different values in slots which are not part of the accumulator
        // computed from the original tree.
        for i in 1..S {
            // if not is_item_included[i]:
            //   assert item_values[i] == 0
            // is_item_included[i] OR (item_values[i] == 0)
            let is_zero = b.is_zero(&item_values[i]);
            let condition = b.or(is_item_included[i], is_zero);
            b.connect(condition.target, ttrue.target);
        }

        // second_item = is_output_valid[1] ? output_items[1] : 0
        let second_item = b.select_u256(is_item_included[1], &item_values[1], &u256_zero);

        // Multiply the order-agnostic digest of the record by its multiplicity.
        // accumulator = multiplicity * D(ids[0] || item_values[0] || ids[1] || second_item || tree_hash)
        let accumulator_inputs: Vec<_> = iter::once(ids[0])
            .chain(item_values[0].to_targets())
            .chain(iter::once(ids[1]))
            .chain(second_item.to_targets())
            .chain(tree_hash.to_targets())
            .collect();
        let mut accumulator = b.map_to_curve_point(&accumulator_inputs);

        b.range_check(multiplicity, 32);
        let multiplicity_bituint = BigUintTarget {
            limbs: vec![U32Target(multiplicity)],
        };
        let multiplicity_nonnative = b.biguint_to_nonnative(&multiplicity_bituint);
        accumulator = b.curve_scalar_mul(accumulator, &multiplicity_nonnative);

        // H(H("") || H("") || second_item || second_item || ids[1] || second_item || tree_hash)
        let tree_hash_inputs = empty_hash
            .elements
            .iter()
            .cloned()
            .chain(empty_hash.elements)
            .chain(second_item.to_targets())
            .chain(second_item.to_targets())
            .chain(iter::once(ids[1]))
            .chain(second_item.to_targets())
            .chain(tree_hash.elements)
            .collect();
        let new_tree_hash = b.hash_n_to_hash_no_pad::<H>(tree_hash_inputs);
        tree_hash = b.select_hash(is_stored_in_leaf, &new_tree_hash, &tree_hash);

        let item_targets: Vec<_> = item_values[2..]
            .iter()
            .flat_map(|v| v.to_targets())
            .collect();

        // Register the public inputs.
        PublicInputs::<_, S>::new(
            &tree_hash.to_targets(),
            &second_item.to_targets(),
            &second_item.to_targets(),
            &item_targets,
            &item_targets,
            &[counter],
            &[counter],
            &item_values[0].to_targets(),
            &ids[..2],
            &[ttrue.target],
            &accumulator.to_targets(),
        )
        .register(b);

        ResultsTreeWithoutDuplicatesWires {
            item_values,
            ids,
            is_item_included,
            multiplicity,
            is_stored_in_leaf,
            counter,
        }
    }

    fn assign(&self, pw: &mut PartialWitness<F>, wires: &ResultsTreeWithoutDuplicatesWires<S>) {
        wires
            .item_values
            .iter()
            .zip(self.item_values)
            .for_each(|(t, v)| pw.set_u256_target(t, v));
        pw.set_target_arr(&wires.ids, &self.ids);
        wires
            .is_item_included
            .iter()
            .enumerate()
            .for_each(|(i, t)| pw.set_bool_target(*t, i < self.num_included_items));
        pw.set_target(wires.multiplicity, self.multiplicity);
        pw.set_bool_target(wires.is_stored_in_leaf, self.is_stored_in_leaf);
        pw.set_target(wires.counter, self.counter);
    }
}

/// Verified proof number = 0
pub(crate) const NUM_VERIFIED_PROOFS: usize = 0;

impl<const S: usize> CircuitLogicWires<F, D, NUM_VERIFIED_PROOFS>
    for ResultsTreeWithoutDuplicatesWires<S>
{
    type CircuitBuilderParams = ();
    type Inputs = ResultsTreeWithoutDuplicatesCircuit<S>;

    const NUM_PUBLIC_INPUTS: usize = PublicInputs::<F, S>::total_len();

    fn circuit_logic(
        builder: &mut CBuilder,
        _verified_proofs: [&ProofWithPublicInputsTarget<D>; NUM_VERIFIED_PROOFS],
        _builder_parameters: Self::CircuitBuilderParams,
    ) -> Self {
        Self::Inputs::build(builder)
    }

    fn assign_input(&self, inputs: Self::Inputs, pw: &mut PartialWitness<F>) -> anyhow::Result<()> {
        inputs.assign(pw, self);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mp2_common::{group_hashing::map_to_curve_point, utils::ToFields, C};
    use mp2_test::{
        cells_tree::{compute_cells_tree_hash, TestCell},
        circuit::{run_circuit, UserCircuit},
    };
    use plonky2::{
        field::types::{Field, PrimeField},
        plonk::config::Hasher,
    };
    use rand::{thread_rng, Rng};

    const S: usize = 20;

    impl UserCircuit<F, D> for ResultsTreeWithoutDuplicatesCircuit<S> {
        type Wires = ResultsTreeWithoutDuplicatesWires<S>;

        fn build(b: &mut CBuilder) -> Self::Wires {
            ResultsTreeWithoutDuplicatesCircuit::build(b)
        }

        fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
            self.assign(pw, wires);
        }
    }

    async fn test_results_tree_without_duplicates_circuit(
        is_stored_in_leaf: bool,
        num_included_items: usize,
    ) {
        let mut rng = thread_rng();
        let cells: Vec<TestCell> = (0..num_included_items)
            .map(|_| TestCell::random())
            .collect();
        let mut item_values = array::from_fn(|_| U256::ZERO);
        let mut ids = array::from_fn(|_| F::ZERO);
        let multiplicity = F::from_canonical_u32(rng.gen());
        for (i, cell) in cells.iter().enumerate() {
            item_values[i] = cell.value;
            ids[i] = cell.id;
        }
        let counter = F::from_canonical_usize(rng.gen());

        // Construct the test circuit.
        let test_circuit = ResultsTreeWithoutDuplicatesCircuit {
            item_values,
            ids,
            num_included_items,
            multiplicity,
            is_stored_in_leaf,
            counter,
        };

        // Proof for the test circuit.
        let proof = run_circuit::<F, D, C, _>(test_circuit);
        let pi = PublicInputs::<_, S>::from_slice(&proof.public_inputs);

        let second_item = if num_included_items > 1 {
            item_values[1]
        } else {
            U256::ZERO
        };
        let second_item_fields = second_item.to_fields();
        // Check the public inputs.

        // Tree hash
        let exp_hash = if cells.len() < 3 {
            *empty_poseidon_hash()
        } else {
            compute_cells_tree_hash(cells[2..].to_vec()).await
        };

        if is_stored_in_leaf {
            let empty_hash = empty_poseidon_hash();
            let empty_hash_fields = empty_hash.to_fields();
            let hash_inputs: Vec<_> = empty_hash_fields
                .clone()
                .into_iter()
                .chain(empty_hash_fields)
                .chain(second_item_fields.clone())
                .chain(second_item_fields.clone())
                .chain(iter::once(ids[1]))
                .chain(second_item_fields.clone())
                .chain(exp_hash.to_fields())
                .collect();
            let new_hash = H::hash_no_pad(&hash_inputs);
            assert_eq!(pi.tree_hash(), new_hash);
        } else {
            assert_eq!(pi.tree_hash(), exp_hash);
        }

        // Min value
        assert_eq!(pi.min_value(), second_item);

        // Max value
        assert_eq!(pi.max_value(), second_item);

        // Min items
        assert_eq!(pi.min_items(), item_values[2..]);

        // Max items
        assert_eq!(pi.max_items(), item_values[2..]);

        // Min counter
        assert_eq!(pi.min_counter(), counter);

        // Max counter
        assert_eq!(pi.max_counter(), counter);

        // Primary index value
        assert_eq!(pi.primary_index_value(), item_values[0]);

        // Index ids
        assert_eq!(pi.index_ids(), ids[..2]);

        // No duplicates
        assert_eq!(pi.no_duplicates_flag(), true);

        // Accumulator
        let accumulator_inputs: Vec<_> = iter::once(ids[0])
            .chain(item_values[0].to_fields())
            .chain(iter::once(ids[1]))
            .chain(second_item_fields.clone())
            .chain(exp_hash.to_fields())
            .collect();
        let mut exp_accumulator = map_to_curve_point(&accumulator_inputs);
        let multiplicity_biguint = multiplicity.to_canonical_biguint();
        let multiplicity_scalar =
            plonky2_ecgfp5::curve::scalar_field::Scalar::from_noncanonical_biguint(
                multiplicity_biguint,
            );
        exp_accumulator *= multiplicity_scalar;
        assert_eq!(pi.accumulator(), exp_accumulator.to_weierstrass());
    }

    #[tokio::test]
    async fn test_results_tree_without_duplicates_circuit_storing_in_leaf() {
        test_results_tree_without_duplicates_circuit(true, S).await;
        test_results_tree_without_duplicates_circuit(true, S - 1).await;
        test_results_tree_without_duplicates_circuit(true, 1).await;
    }
    #[tokio::test]
    async fn test_results_tree_without_duplicates_circuit_storing_in_inter() {
        test_results_tree_without_duplicates_circuit(false, S).await;
        test_results_tree_without_duplicates_circuit(false, S - 1).await;
        test_results_tree_without_duplicates_circuit(false, 1).await;
    }
}
