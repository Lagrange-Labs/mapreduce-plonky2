use std::iter::{once, repeat};

use itertools::Itertools;
use mp2_common::{array::ToField, poseidon::empty_poseidon_hash, utils::{SelectHashBuilder, ToTargets}, CHasher, D, F};
use plonky2::{field::types::Field, hash::{hash_types::{HashOut, HashOutTarget, RichField}, hashing::hash_n_to_hash_no_pad}, iop::target::{BoolTarget, Target}, plonk::{circuit_builder::CircuitBuilder, config::{GenericHashOut, Hasher}}, util::log2_ceil};

pub mod public_inputs;
pub mod universal_query_circuit;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Set of constant identifiers employed in the
/// computational hash, which is a compact representation
/// of the query being proven by the query circuits
pub enum ComputationalHashIdentifiers {
    AddOp,
    SubOp,
    MulOp,
    DivOp,
    ModOp,
    LessThanOp,
    EqOp,
    NeOp,
    GreaterThanOp,
    LessThanOrEqOp,
    GreaterThanOrEqOp,
    AndOp,
    OrOp,
    NotOp,
    XorOp,
    OutputWithAggregation,
    SumAggOp,
    MinAggOp,
    MaxAggOp,
    CountAggOp,
    AvgAggOp,
}

impl<F: RichField> ToField<F> for ComputationalHashIdentifiers {
    fn to_field(&self) -> F {
        F::from_canonical_usize(
            *self as usize
        )
    }
}

type HashPermutation = <CHasher as Hasher<F>>::Permutation;

impl ComputationalHashIdentifiers {
    pub(crate) fn output_with_aggregation_hash(
        predicate_hash: &HashOut<F>,
        column_hash: &[HashOut<F>],
        item_hash: &[HashOut<F>],
        selector: &[usize],
        agg_ops: &[ComputationalHashIdentifiers],
        num_outputs: usize
    ) -> HashOut<F> {
        let hash_identifier = Self::OutputWithAggregation.to_field();
        let mut output_hash = hash_n_to_hash_no_pad::<_, HashPermutation>(&
            once(hash_identifier)
            .chain(predicate_hash.to_vec().into_iter())
            .collect_vec()
        );
        for i in 0..num_outputs {
            let possible_hashes = column_hash.iter()
                .chain(once(&item_hash[i]))
                .collect_vec();
            let current_output_hash = possible_hashes[selector[i]];
            output_hash = hash_n_to_hash_no_pad::<_, HashPermutation>(&
                output_hash.to_vec().into_iter()
                .chain(once(agg_ops[i].to_field()))
                .chain(current_output_hash.to_vec().into_iter())
                .collect_vec()
            );
        }

        output_hash
        
    }
    pub(crate) fn output_with_aggregation_hash_circuit<const MAX_NUM_RESULTS: usize>(
        b: &mut CircuitBuilder<F, D>,
        predicate_hash: &HashOutTarget,
        column_hash: &[HashOutTarget],
        item_hash: &[HashOutTarget; MAX_NUM_RESULTS],
        selector: &[Target; MAX_NUM_RESULTS],
        agg_ops: &[Target; MAX_NUM_RESULTS],
        is_output_valid: &[BoolTarget; MAX_NUM_RESULTS],
    ) -> HashOutTarget {
        let empty_hash = b.constant_hash(*empty_poseidon_hash());
        let hash_identifier = b.constant(
                Self::OutputWithAggregation.to_field()
        );
        let mut output_hash = b.hash_n_to_hash_no_pad::<CHasher>(
            once(hash_identifier)
            .chain(predicate_hash.to_targets().into_iter())
            .collect()
        );
        for i in 0..MAX_NUM_RESULTS {
            let possible_output_hashes = column_hash.iter()
                .chain(once(&item_hash[i]))
                .chain(repeat(&empty_hash))
                .take(1 << log2_ceil(column_hash.len()+1)) // pad up to next power of 2 with empty_hash to safely use random_access gadget
                .cloned()
                .collect_vec();
            let current_output_hash = b.random_access_hash(selector[i], possible_output_hashes);

            let new_output_hash = b.hash_n_to_hash_no_pad::<CHasher>(
                output_hash.to_targets().into_iter()
                .chain(once(agg_ops[i]))
                .chain(current_output_hash.to_targets().into_iter())
                .collect()
            );

            // Output computational hash is updated only if there is a valid output to be
		    // computed for this slot
            output_hash = b.select_hash(
                is_output_valid[i], 
                &new_output_hash, 
                &output_hash,
            );
        }

        output_hash
    }
}
