use std::iter::once;

use itertools::Itertools;
use mp2_common::{
    public_inputs::{PublicInputCommon, PublicInputRange},
    types::CBuilder,
    u256::NUM_LIMBS,
};
use plonky2::{hash::hash_types::NUM_HASH_OUT_ELTS, iop::target::Target};

/// Query circuits public inputs
pub enum QueryPublicInputs {
    /// `H`: Hash of the tree
    TreeHash,
    /// `V`: `[u256; S]` Set of `u256` values representing the cumulative results of the query; `S` is a parameter
    /// specifying the maximum number of cumulative results we support
    OutputValues,
    /// `count`: `F` Number of matching records in the query
    NumMatching,
    /// `ops` : `[F; S]` Set of identifiers of the aggregation operations for each of the `S` items found in `V`
    OpIds,
    /// `I` : `u256` value of the indexed column for the given node (meaningful only for rows tree nodes)
    IndexValue,
    /// `min` : `u256` Minimum value of the indexed column among all the records stored in the subtree rooted
    /// in the current node
    MinValue,
    /// `max`` :  Maximum value of the indexed column among all the records stored in the subtree rooted
    /// in the current node
    MaxValue,
    /// `index_ids`` : `[2]F` Identifiers of indexed columns
    IndexIds,
    /// `MIN_I`: `u256` Lower bound of the range of indexed column values specified in the query
    MinQuery,
    /// `MAX_I`: `u256` Upper bound of the range of indexed column values specified in the query
    MaxQuery,
    /// `overflow` : `bool` Flag specifying whether an overflow error has occurred in arithmetic
    Overflow,
    /// `C`: computational hash
    ComputationalHash,
    /// `H_p` : placeholder hash
    PlaceholderHash,
}

#[derive(Clone, Debug)]
pub struct PublicInputs<'a, T, const S: usize> {
    pub(crate) h: &'a [T],
    pub(crate) v: &'a [T],
    pub(crate) count: &'a T,
    pub(crate) ops: &'a [T],
    pub(crate) i: &'a [T],
    pub(crate) min: &'a [T],
    pub(crate) max: &'a [T],
    pub(crate) ids: &'a [T],
    pub(crate) min_q: &'a [T],
    pub(crate) max_q: &'a [T],
    pub(crate) overflow: &'a T,
    pub(crate) ch: &'a [T],
    pub(crate) ph: &'a [T],
}

const NUM_PUBLIC_INPUTS: usize = QueryPublicInputs::PlaceholderHash as usize + 1;

impl<'a, T: Clone, const S: usize> PublicInputs<'a, T, S> {
    const PI_RANGES: [PublicInputRange; NUM_PUBLIC_INPUTS] = [
        Self::to_range(QueryPublicInputs::TreeHash),
        Self::to_range(QueryPublicInputs::OutputValues),
        Self::to_range(QueryPublicInputs::NumMatching),
        Self::to_range(QueryPublicInputs::OpIds),
        Self::to_range(QueryPublicInputs::IndexValue),
        Self::to_range(QueryPublicInputs::MinValue),
        Self::to_range(QueryPublicInputs::MaxValue),
        Self::to_range(QueryPublicInputs::IndexIds),
        Self::to_range(QueryPublicInputs::MinQuery),
        Self::to_range(QueryPublicInputs::MaxQuery),
        Self::to_range(QueryPublicInputs::Overflow),
        Self::to_range(QueryPublicInputs::ComputationalHash),
        Self::to_range(QueryPublicInputs::PlaceholderHash),
    ];

    const SIZES: [usize; NUM_PUBLIC_INPUTS] = [
        // Tree hash
        NUM_HASH_OUT_ELTS,
        // Output values
        NUM_LIMBS * S,
        // Number of matching records
        1,
        // Operation identifiers
        S,
        // Index column value
        NUM_LIMBS,
        // Minimum indexed column value
        NUM_LIMBS,
        // Maximum indexed column value
        NUM_LIMBS,
        // Indexed column IDs
        2,
        // Lower bound for indexed column specified in query
        NUM_LIMBS,
        // Upper bound for indexed column specified in query
        NUM_LIMBS,
        // Overflow flag
        1,
        // Computational hash
        NUM_HASH_OUT_ELTS,
        // Placeholder hash
        NUM_HASH_OUT_ELTS,
    ];

    pub(crate) const fn to_range(query_pi: QueryPublicInputs) -> PublicInputRange {
        let mut i = 0;
        let mut offset = 0;
        let pi_pos = query_pi as usize;
        while i < pi_pos {
            offset += Self::SIZES[i];
            i = i + 1;
        }
        offset..offset + Self::SIZES[pi_pos]
    }

    pub(crate) const fn total_len() -> usize {
        Self::to_range(QueryPublicInputs::PlaceholderHash).end
    }

    pub(crate) fn to_hash_raw(&self) -> &[T] {
        self.h
    }

    pub(crate) fn to_values_raw(&self) -> &[T] {
        self.v
    }

    pub(crate) fn to_count_raw(&self) -> &T {
        self.count
    }

    pub(crate) fn to_ops_raw(&self) -> &[T] {
        self.ops
    }

    pub(crate) fn to_index_value_raw(&self) -> &[T] {
        self.i
    }

    pub(crate) fn to_min_value_raw(&self) -> &[T] {
        self.min
    }

    pub(crate) fn to_max_value_raw(&self) -> &[T] {
        self.max
    }

    pub(crate) fn to_index_ids_raw(&self) -> &[T] {
        self.ids
    }

    pub(crate) fn to_min_query_raw(&self) -> &[T] {
        self.min_q
    }

    pub(crate) fn to_max_query_raw(&self) -> &[T] {
        self.max_q
    }

    pub(crate) fn to_overflow_raw(&self) -> &T {
        self.overflow
    }

    pub(crate) fn to_computational_hash_raw(&self) -> &[T] {
        self.ch
    }

    pub(crate) fn to_placeholder_hash_raw(&self) -> &[T] {
        self.ph
    }

    pub fn from_slice(input: &'a [T]) -> Self {
        assert!(
            input.len() >= Self::total_len(),
            "input slice too short to build query public inputs, must be at least {} elements",
            Self::total_len()
        );
        Self {
            h: &input[Self::PI_RANGES[0].clone()],
            v: &input[Self::PI_RANGES[1].clone()],
            count: &input[Self::PI_RANGES[2].clone()][0],
            ops: &input[Self::PI_RANGES[3].clone()],
            i: &input[Self::PI_RANGES[4].clone()],
            min: &input[Self::PI_RANGES[5].clone()],
            max: &input[Self::PI_RANGES[6].clone()],
            ids: &input[Self::PI_RANGES[7].clone()],
            min_q: &input[Self::PI_RANGES[8].clone()],
            max_q: &input[Self::PI_RANGES[9].clone()],
            overflow: &input[Self::PI_RANGES[10].clone()][0],
            ch: &input[Self::PI_RANGES[11].clone()],
            ph: &input[Self::PI_RANGES[12].clone()],
        }
    }

    pub fn to_vec(&self) -> Vec<T> {
        self.h
            .iter()
            .chain(self.v.iter())
            .chain(once(self.count))
            .chain(self.ops.iter())
            .chain(self.i.iter())
            .chain(self.min.iter())
            .chain(self.max.iter())
            .chain(self.ids.iter())
            .chain(self.min_q.iter())
            .chain(self.max_q.iter())
            .chain(once(self.overflow))
            .chain(self.ch.iter())
            .chain(self.ph.iter())
            .cloned()
            .collect_vec()
    }
}

impl<'a, const S: usize> PublicInputCommon for PublicInputs<'a, Target, S> {
    const RANGES: &'static [PublicInputRange] = &Self::PI_RANGES;

    fn register_args(&self, cb: &mut CBuilder) {
        cb.register_public_inputs(self.h);
        cb.register_public_inputs(self.v);
        cb.register_public_input(*self.count);
        cb.register_public_inputs(self.ops);
        cb.register_public_inputs(self.i);
        cb.register_public_inputs(self.min);
        cb.register_public_inputs(self.max);
        cb.register_public_inputs(self.ids);
        cb.register_public_inputs(self.min_q);
        cb.register_public_inputs(self.max_q);
        cb.register_public_input(*self.overflow);
        cb.register_public_inputs(self.ch);
        cb.register_public_inputs(self.ph);
    }
}

#[cfg(test)]
mod tests {

    use mp2_common::{public_inputs::PublicInputCommon, utils::ToFields, C, D, F};
    use mp2_test::{
        circuit::{run_circuit, UserCircuit},
        utils::random_vector,
    };
    use plonky2::{
        iop::{
            target::Target,
            witness::{PartialWitness, WitnessWrite},
        },
        plonk::circuit_builder::CircuitBuilder,
    };

    use crate::simple_query_circuits::public_inputs::QueryPublicInputs;

    use super::PublicInputs;

    const S: usize = 10;
    #[derive(Clone, Debug)]
    struct TestPublicInputs<'a> {
        pis: &'a [F],
    }

    impl<'a> UserCircuit<F, D> for TestPublicInputs<'a> {
        type Wires = Vec<Target>;

        fn build(c: &mut CircuitBuilder<F, D>) -> Self::Wires {
            let targets = c.add_virtual_target_arr::<{ PublicInputs::<Target, S>::total_len() }>();
            let pi_targets = PublicInputs::<Target, S>::from_slice(targets.as_slice());
            pi_targets.register_args(c);
            pi_targets.to_vec()
        }

        fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
            pw.set_target_arr(wires, self.pis)
        }
    }

    #[test]
    fn test_query_public_inputs() {
        let pis_raw: Vec<F> = random_vector::<u32>(PublicInputs::<F, S>::total_len()).to_fields();
        let pis = PublicInputs::<F, S>::from_slice(pis_raw.as_slice());
        // check public inputs are constructed correctly
        assert_eq!(
            &pis_raw[PublicInputs::<F, S>::to_range(QueryPublicInputs::TreeHash)],
            pis.to_hash_raw(),
        );
        assert_eq!(
            &pis_raw[PublicInputs::<F, S>::to_range(QueryPublicInputs::OutputValues)],
            pis.to_values_raw(),
        );
        assert_eq!(
            &pis_raw[PublicInputs::<F, S>::to_range(QueryPublicInputs::NumMatching)],
            &[*pis.to_count_raw()],
        );
        assert_eq!(
            &pis_raw[PublicInputs::<F, S>::to_range(QueryPublicInputs::OpIds)],
            pis.to_ops_raw(),
        );
        assert_eq!(
            &pis_raw[PublicInputs::<F, S>::to_range(QueryPublicInputs::IndexValue)],
            pis.to_index_value_raw(),
        );
        assert_eq!(
            &pis_raw[PublicInputs::<F, S>::to_range(QueryPublicInputs::MinValue)],
            pis.to_min_value_raw(),
        );
        assert_eq!(
            &pis_raw[PublicInputs::<F, S>::to_range(QueryPublicInputs::MaxValue)],
            pis.to_max_value_raw(),
        );
        assert_eq!(
            &pis_raw[PublicInputs::<F, S>::to_range(QueryPublicInputs::MinQuery)],
            pis.to_min_query_raw(),
        );
        assert_eq!(
            &pis_raw[PublicInputs::<F, S>::to_range(QueryPublicInputs::MaxQuery)],
            pis.to_max_query_raw(),
        );
        assert_eq!(
            &pis_raw[PublicInputs::<F, S>::to_range(QueryPublicInputs::IndexIds)],
            pis.to_index_ids_raw(),
        );
        assert_eq!(
            &pis_raw[PublicInputs::<F, S>::to_range(QueryPublicInputs::Overflow)],
            &[*pis.to_overflow_raw()],
        );
        assert_eq!(
            &pis_raw[PublicInputs::<F, S>::to_range(QueryPublicInputs::ComputationalHash)],
            pis.to_computational_hash_raw(),
        );
        assert_eq!(
            &pis_raw[PublicInputs::<F, S>::to_range(QueryPublicInputs::PlaceholderHash)],
            pis.to_placeholder_hash_raw(),
        );
        // use public inputs in circuit
        let test_circuit = TestPublicInputs { pis: &pis_raw };
        let proof = run_circuit::<F, D, C, _>(test_circuit);
        assert_eq!(proof.public_inputs, pis_raw);
    }
}
