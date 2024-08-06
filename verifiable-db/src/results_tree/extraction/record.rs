use crate::results_tree::extraction::PublicInputs;
use alloy::primitives::U256;
use mp2_common::{
    group_hashing::CircuitBuilderGroupHashing,
    poseidon::{empty_poseidon_hash, H},
    public_inputs::PublicInputCommon,
    serialization::{deserialize, deserialize_long_array, serialize, serialize_long_array},
    types::CBuilder,
    u256::{CircuitBuilderU256, UInt256Target, WitnessWriteU256},
    utils::{greater_than, less_than, SelectHashBuilder, ToTargets},
    D, F,
};
use plonky2::{
    hash::hash_types::{HashOut, HashOutTarget},
    iop::{
        target::{BoolTarget, Target},
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::proof::ProofWithPublicInputsTarget,
};
use recursion_framework::circuit_builder::CircuitLogicWires;
use serde::{Deserialize, Serialize};
use std::iter;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecordWires<const MAX_NUM_RESULTS: usize> {
    #[serde(
        serialize_with = "serialize_long_array",
        deserialize_with = "deserialize_long_array"
    )]
    indexed_items: [UInt256Target; MAX_NUM_RESULTS],
    #[serde(
        serialize_with = "serialize_long_array",
        deserialize_with = "deserialize_long_array"
    )]
    index_ids: [Target; 2],
    #[serde(serialize_with = "serialize", deserialize_with = "deserialize")]
    tree_hash: HashOutTarget,
    counter: Target,
    #[serde(serialize_with = "serialize", deserialize_with = "deserialize")]
    is_stored_in_leaf: BoolTarget,
    offset_range_min: Target,
    offset_range_max: Target,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecordCircuit<const MAX_NUM_RESULTS: usize> {
    /// Values of the indexed items for in this record;
    /// if there is no secondary indexed item, just place the dummy value `0`
    #[serde(
        serialize_with = "serialize_long_array",
        deserialize_with = "deserialize_long_array"
    )]
    pub(crate) indexed_items: [U256; MAX_NUM_RESULTS],
    /// Integer identifiers of the indexed items
    #[serde(
        serialize_with = "serialize_long_array",
        deserialize_with = "deserialize_long_array"
    )]
    pub(crate) index_ids: [F; 2],
    /// Hash of the cells tree for this record;
    /// could be empty hash if there is no cells tree for this record
    pub(crate) tree_hash: HashOut<F>,
    /// Counter for the node associated to this record
    pub(crate) counter: F,
    /// Boolean flag specifying whether this record is stored
    /// in a leaf node of a rows tree or not
    pub(crate) is_stored_in_leaf: bool,
    /// Minimum offset range bound
    pub(crate) offset_range_min: F,
    /// Maximum offset range bound
    pub(crate) offset_range_max: F,
}

impl<const MAX_NUM_RESULTS: usize> RecordCircuit<MAX_NUM_RESULTS> {
    pub fn build(b: &mut CBuilder) -> RecordWires<MAX_NUM_RESULTS> {
        let ffalse = b._false();
        let empty_hash = b.constant_hash(*empty_poseidon_hash());

        let indexed_items: [UInt256Target; MAX_NUM_RESULTS] = b.add_virtual_u256_arr_unsafe();
        let index_ids: [Target; 2] = b.add_virtual_target_arr();
        let tree_hash = b.add_virtual_hash();
        let counter = b.add_virtual_target();
        let is_stored_in_leaf = b.add_virtual_bool_target_safe();
        let [offset_range_min, offset_range_max] = b.add_virtual_target_arr();

        // H(H("")||H("")||indexed_items[1]||indexed_items[1]||index_ids[1]||indexed_items[1]||tree_hash)
        let tree_hash_inputs = empty_hash
            .elements
            .iter()
            .cloned()
            .chain(empty_hash.elements)
            .chain(indexed_items[1].to_targets())
            .chain(indexed_items[1].to_targets())
            .chain(iter::once(index_ids[1]))
            .chain(indexed_items[1].to_targets())
            .chain(tree_hash.elements)
            .collect();
        let new_tree_hash = b.hash_n_to_hash_no_pad::<H>(tree_hash_inputs);
        let final_tree_hash = b.select_hash(is_stored_in_leaf, &new_tree_hash, &tree_hash);

        // D(index_ids[0]||indexed_items[0]||index_ids[1]||indexed_items[1]||tree_hash)
        let accumulator_inputs: Vec<_> = iter::once(index_ids[0])
            .chain(indexed_items[0].to_targets())
            .chain(iter::once(index_ids[1]))
            .chain(indexed_items[1].to_targets())
            .chain(final_tree_hash.to_targets())
            .collect();
        let accumulator = b.map_to_curve_point(&accumulator_inputs);

        // Ensure the counter associated to the current record is in the range
        // specified by the query
        // offset_range_min <= counter <= offset_range_max
        // -> NOT((counter < offset_range_min) OR (counter > offset_range_max)
        let is_less_than = less_than(b, counter, offset_range_min, 32);
        let is_greater_than = greater_than(b, counter, offset_range_max, 32);
        let is_out_of_range = b.or(is_less_than, is_greater_than);
        b.connect(is_out_of_range.target, ffalse.target);

        // Register the public inputs.
        PublicInputs::<_, MAX_NUM_RESULTS>::new(
            &final_tree_hash.to_targets(),
            &indexed_items[1].to_targets(),
            &indexed_items[1].to_targets(),
            &indexed_items[0].to_targets(),
            &index_ids,
            &[counter],
            &[counter],
            &[offset_range_min],
            &[offset_range_max],
            &accumulator.to_targets(),
        )
        .register(b);

        RecordWires {
            indexed_items,
            index_ids,
            tree_hash,
            counter,
            is_stored_in_leaf,
            offset_range_min,
            offset_range_max,
        }
    }

    fn assign(&self, pw: &mut PartialWitness<F>, wires: &RecordWires<MAX_NUM_RESULTS>) {
        wires
            .indexed_items
            .iter()
            .zip(self.indexed_items)
            .for_each(|(t, v)| pw.set_u256_target(t, v));
        pw.set_target_arr(&wires.index_ids, &self.index_ids);
        pw.set_hash_target(wires.tree_hash, self.tree_hash);
        pw.set_target(wires.counter, self.counter);
        pw.set_bool_target(wires.is_stored_in_leaf, self.is_stored_in_leaf);
        pw.set_target(wires.offset_range_min, self.offset_range_min);
        pw.set_target(wires.offset_range_max, self.offset_range_max);
    }
}

/// Verified proof number = 0
pub(crate) const NUM_VERIFIED_PROOFS: usize = 0;

impl<const MAX_NUM_RESULTS: usize> CircuitLogicWires<F, D, NUM_VERIFIED_PROOFS>
    for RecordWires<MAX_NUM_RESULTS>
{
    type CircuitBuilderParams = ();
    type Inputs = RecordCircuit<MAX_NUM_RESULTS>;

    const NUM_PUBLIC_INPUTS: usize = PublicInputs::<F, MAX_NUM_RESULTS>::total_len();

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
    use mp2_common::{utils::ToFields, C};
    use mp2_test::{
        circuit::{run_circuit, UserCircuit},
        utils::{gen_random_field_hash, gen_random_u256},
    };
    use plonky2::{field::types::Field, plonk::config::Hasher};
    use rand::{thread_rng, Rng};
    use std::array;

    const MAX_NUM_RESULTS: usize = 20;

    impl UserCircuit<F, D> for RecordCircuit<MAX_NUM_RESULTS> {
        type Wires = RecordWires<MAX_NUM_RESULTS>;

        fn build(b: &mut CBuilder) -> Self::Wires {
            RecordCircuit::build(b)
        }

        fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
            self.assign(pw, wires);
        }
    }

    fn test_record_circuit(is_stored_in_leaf: bool) {
        // Construct the witness.
        let mut rng = thread_rng();
        let indexed_items = array::from_fn(|_| gen_random_u256(&mut rng));
        let index_ids = array::from_fn(|_| F::from_canonical_usize(rng.gen()));
        let tree_hash = gen_random_field_hash();
        let counter = F::from_canonical_u32(rng.gen());
        let offset_range_min = counter - F::ONE;
        let offset_range_max = counter + F::ONE;

        // Construct the circuit.
        let test_circuit = RecordCircuit {
            indexed_items,
            index_ids,
            tree_hash,
            counter,
            is_stored_in_leaf,
            offset_range_min,
            offset_range_max,
        };

        // Proof for the test circuit.
        let proof = run_circuit::<F, D, C, _>(test_circuit);
        let pi = PublicInputs::<_, MAX_NUM_RESULTS>::from_slice(&proof.public_inputs);

        // Check the public inputs.

        // Tree hash
        if is_stored_in_leaf {
            let empty_hash = empty_poseidon_hash();
            let empty_hash_fields = empty_hash.to_fields();
            let hash_inputs: Vec<_> = empty_hash_fields
                .clone()
                .into_iter()
                .chain(empty_hash_fields)
                .chain(indexed_items[1].to_fields())
                .chain(indexed_items[1].to_fields())
                .chain(iter::once(index_ids[1]))
                .chain(indexed_items[1].to_fields())
                .chain(tree_hash.to_fields())
                .collect();
            let exp_hash = H::hash_no_pad(&hash_inputs);
            assert_eq!(pi.tree_hash(), exp_hash);
        } else {
            assert_eq!(pi.tree_hash(), tree_hash);
        };

        // Min value
        assert_eq!(pi.min_value(), indexed_items[1]);

        // Max value
        assert_eq!(pi.max_value(), indexed_items[1]);

        // Primary index value
        assert_eq!(pi.primary_index_value(), indexed_items[0]);

        // Index ids
        assert_eq!(pi.index_ids(), index_ids);

        // Min counter
        assert_eq!(pi.min_counter(), counter);

        // Max counter
        assert_eq!(pi.max_counter(), counter);

        // Offset range min
        assert_eq!(pi.offset_range_min(), offset_range_min);

        // Offset range max
        assert_eq!(pi.offset_range_max(), offset_range_max);
    }

    #[test]
    fn test_record_circuit_storing_in_leaf() {
        test_record_circuit(true);
    }

    #[test]
    fn test_record_circuit_storing_in_inter() {
        test_record_circuit(false);
    }
}
