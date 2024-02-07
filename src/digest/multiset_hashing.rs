//! Multiset hashing implemention for digest tree circuit used to prove Merkle
//! tree nodes recursively.

use super::{
    hash_to_curve_point_target, hash_to_curve_point_value, DigestTreeCircuit,
    ECGFP5_EXT_DEGREE as N,
};
use crate::{
    circuit::{PCDCircuit, ProofOrDummyTarget, UserCircuit},
    utils::{convert_u8_targets_to_u32, convert_u8_values_to_u32, less_than},
};
use plonky2::{
    field::extension::Extendable,
    hash::{
        hash_types::RichField,
        hashing::hash_n_to_m_no_pad,
        poseidon::{PoseidonHash, PoseidonPermutation},
    },
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::circuit_builder::CircuitBuilder,
};
use plonky2_ecgfp5::{
    curve::curve::Point,
    gadgets::curve::{CircuitBuilderEcGFp5, CurveTarget, PartialWitnessCurve},
};
use std::array;

/// The input value of leaf is [u8; 32].
type LeafValue<F> = [F; 32];
type LeafTarget = [Target; 32];

/// The branch has ARITY children at maximum, each is a curve point.
type BranchValue<const ARITY: usize> = [Point; ARITY];
type BranchTarget<const ARITY: usize> = [CurveTarget; ARITY];

/// Multiset hashing circuit wires including input and output targets
#[derive(Clone, Debug)]
pub struct MultisetHashingWires<const ARITY: usize> {
    /// The child number is zero if it's a leaf, otherwise it specifies child
    /// number of a branch. It's also used to identify if the current node is a
    /// leaf or branch, since branch has non-empty children.
    child_num: Target,
    /// Leaf input
    leaf_input: LeafTarget,
    /// Branch input
    branch_input: BranchTarget<ARITY>,
    /// The output is a curve point. It's converted from Poseidon hash if it's a
    /// leaf, otherwise it's the curve point addition for children of branch.
    output: CurveTarget,
}

/// Multiset hashing circuit used to prove Merkle tree recursively
#[derive(Clone, Debug)]
pub struct MultisetHashingCircuit<F, const D: usize, const ARITY: usize> {
    /// The child number is zero if it's a leaf, otherwise it specifies child
    /// number of a branch. It's also used to identify if the current node is a
    /// leaf or branch, since branch has non-empty children.
    child_num: usize,
    /// Leaf input
    leaf_input: LeafValue<F>,
    /// Branch input
    branch_input: BranchValue<ARITY>,
}

impl<F, const D: usize, const ARITY: usize> DigestTreeCircuit<Point>
    for MultisetHashingCircuit<F, D, ARITY>
where
    F: RichField + Extendable<D> + Extendable<N>,
{
    /// Create a circuit instance for a leaf of Merkle tree.
    fn new_leaf(value: [u8; 32]) -> Self {
        // Convert the u8 array to a base field array.
        let leaf_input = value.map(F::from_canonical_u8);

        Self {
            child_num: 0,
            leaf_input,
            branch_input: [Point::NEUTRAL; ARITY],
        }
    }

    /// Create a circuit instance for a branch of Merkle tree.
    fn new_branch(children: Vec<Point>) -> Self {
        // Child number must be greater than 0, and equal to or less than ARITY.
        let child_num = children.len();
        assert!((1..=ARITY).contains(&child_num));

        // Build branch input.
        let branch_input = array::from_fn(|i| children.get(i).cloned().unwrap_or(Point::NEUTRAL));

        Self {
            child_num,
            leaf_input: [F::ZERO; 32],
            branch_input,
        }
    }
}

impl<F, const D: usize, const ARITY: usize> UserCircuit<F, D>
    for MultisetHashingCircuit<F, D, ARITY>
where
    F: RichField + Extendable<D> + Extendable<N>,
    CircuitBuilder<F, D>: CircuitBuilderEcGFp5,
    PartialWitness<F>: PartialWitnessCurve<F>,
{
    type Wires = MultisetHashingWires<ARITY>;

    fn build(b: &mut CircuitBuilder<F, D>) -> Self::Wires {
        let child_num = b.add_virtual_target();
        let leaf_input = b.add_virtual_target_arr::<32>();
        let branch_input = [0; ARITY].map(|_| b.add_virtual_curve_target());

        // Generate the output of curve point for both leaf and branch.
        let leaf_output = build_leaf(b, &leaf_input);
        let branch_output = build_branch(b, &branch_input, child_num);

        // It's a leaf of Merkle tree if the child number is zero.
        let zero = b.zero();
        let is_leaf = b.is_equal(child_num, zero);
        let output = b.curve_select(is_leaf, leaf_output, branch_output);

        Self::Wires {
            child_num,
            leaf_input,
            branch_input,
            output,
        }
    }

    fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
        pw.set_target(wires.child_num, F::from_canonical_usize(self.child_num));
        pw.set_target_arr(&wires.leaf_input, &self.leaf_input);
        pw.set_curve_targets(
            &wires.branch_input,
            &self.branch_input.map(|point| point.to_weierstrass()),
        );

        // It's a leaf of Merkle tree if the child number is zero.
        let output = if self.child_num == 0 {
            // Convert the values from u8 array to u32.
            let inputs: Vec<_> = convert_u8_values_to_u32(&self.leaf_input);

            // Calculate the Poseidon hash and output N values of base field.
            let hash: [F; N] = hash_n_to_m_no_pad::<F, PoseidonPermutation<F>>(&inputs, N)
                .try_into()
                .unwrap();

            // Convert the hash to a curve point.
            hash_to_curve_point_value(hash)
        } else {
            // Calculate the curve point addition for children of branch.
            // <https://github.com/Lagrange-Labs/plonky2-ecgfp5/blob/08feaa03a006923fa721f2f5a26578d13bc25fa6/src/curve/curve.rs#L709>
            self.branch_input[..self.child_num]
                .iter()
                .cloned()
                .reduce(|acc, p| acc + p)
                .unwrap()
        };

        pw.set_curve_target(wires.output, output.to_weierstrass());
    }
}

impl<F, const D: usize, const ARITY: usize> PCDCircuit<F, D, ARITY>
    for MultisetHashingCircuit<F, D, ARITY>
where
    F: RichField + Extendable<D> + Extendable<N>,
    CircuitBuilder<F, D>: CircuitBuilderEcGFp5,
    PartialWitness<F>: PartialWitnessCurve<F>,
{
    fn build_recursive(
        b: &mut CircuitBuilder<F, D>,
        _: &[ProofOrDummyTarget<D>; ARITY],
    ) -> Self::Wires {
        let wires = <Self as UserCircuit<F, D>>::build(b);
        b.register_curve_public_input(wires.output);

        // TODO: check the proof public inputs match what is expected.

        wires
    }

    fn base_inputs(&self) -> Vec<F> {
        F::rand_vec(2 * N)
    }

    fn num_io() -> usize {
        2 * N
    }
}

/// Generate the curve point from the inputs of Merkle tree leaf.
fn build_leaf<F, const D: usize>(b: &mut CircuitBuilder<F, D>, inputs: &[Target]) -> CurveTarget
where
    F: RichField + Extendable<D> + Extendable<N>,
{
    // Convert the u8 target array to an u32 target array.
    let inputs: Vec<_> = convert_u8_targets_to_u32(b, &inputs)
        .into_iter()
        .map(|u32_target| u32_target.0)
        .collect();

    let hash = b
        .hash_n_to_m_no_pad::<PoseidonHash>(inputs, N)
        .try_into()
        .unwrap();

    hash_to_curve_point_target(hash)
}

/// Calculate the curve point addition for children of a Merkle tree branch.
fn build_branch<F, const D: usize>(
    b: &mut CircuitBuilder<F, D>,
    inputs: &[CurveTarget],
    valid_len: Target,
) -> CurveTarget
where
    F: RichField + Extendable<D> + Extendable<N>,
    CircuitBuilder<F, D>: CircuitBuilderEcGFp5,
{
    assert!(!inputs.is_empty());

    inputs
        .iter()
        .cloned()
        .enumerate()
        .reduce(|acc, (i, p)| {
            // Check if the point of current index is valid.
            let offset = b.constant(F::from_canonical_usize(i));
            let is_valid_point = less_than(b, offset, valid_len, 8);

            // Calculation the addition if it's a valid point.
            let old_sum = acc.1;
            let new_sum = b.curve_add(old_sum, p);
            let sum = b.curve_select(is_valid_point, new_sum, old_sum);

            (i, sum)
        })
        .unwrap()
        .1
}
