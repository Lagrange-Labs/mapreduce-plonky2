//! Multiset hashing implemention for digest tree circuit used to prove Merkle
//! tree nodes recursively.

use super::{DigestTreeCircuit, ECGFP5_EXT_DEGREE as N};
use crate::{
    circuit::{PCDCircuit, ProofOrDummyTarget, UserCircuit},
    map_to_curve::{ToCurvePoint, ToCurveTarget},
    utils::{convert_u8_targets_to_u32, convert_u8_values_to_u32},
};
use plonky2::{
    field::extension::{quintic::QuinticExtension, Extendable, FieldExtension},
    hash::{
        hash_types::RichField,
        hashing::hash_n_to_m_no_pad,
        poseidon::{PoseidonHash, PoseidonPermutation},
    },
    iop::{
        target::{BoolTarget, Target},
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::circuit_builder::CircuitBuilder,
};
use plonky2_ecgfp5::{
    curve::curve::Point,
    gadgets::{
        base_field::{CircuitBuilderGFp5, QuinticExtensionTarget},
        curve::{CircuitBuilderEcGFp5, CurveTarget, PartialWitnessCurve},
    },
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
    /// The flag is used to identify if the current node is a leaf or branch.
    is_leaf: BoolTarget,
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
    /// The flag is used to identify if the current node is a leaf or branch.
    is_leaf: bool,
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
            is_leaf: true,
            leaf_input,
            branch_input: [Point::NEUTRAL; ARITY],
        }
    }

    /// Create a circuit instance for a branch of Merkle tree.
    fn new_branch(children: Vec<Point>) -> Self {
        // Child number must be greater than 0, and equal to or less than ARITY.
        assert!((1..=ARITY).contains(&children.len()));

        // Build branch input.
        let branch_input = array::from_fn(|i| children.get(i).cloned().unwrap_or(Point::NEUTRAL));

        Self {
            is_leaf: false,
            leaf_input: [F::ZERO; 32],
            branch_input,
        }
    }
}

impl<F, const D: usize, const ARITY: usize> UserCircuit<F, D>
    for MultisetHashingCircuit<F, D, ARITY>
where
    F: RichField + Extendable<D> + Extendable<N>,
    QuinticExtension<F>: ToCurvePoint,
    CircuitBuilder<F, D>: CircuitBuilderGFp5<F> + CircuitBuilderEcGFp5,
    PartialWitness<F>: PartialWitnessCurve<F>,
{
    type Wires = MultisetHashingWires<ARITY>;

    fn build(b: &mut CircuitBuilder<F, D>) -> Self::Wires {
        let is_leaf = b.add_virtual_bool_target_safe();
        let leaf_input = b.add_virtual_target_arr::<32>();
        let branch_input = [0; ARITY].map(|_| b.add_virtual_curve_target());

        // Generate the output of curve point for both leaf and branch.
        let leaf_output = build_leaf(b, &leaf_input);
        let branch_output = build_branch(b, &branch_input);

        // Select the output according to the flag.
        let output = b.curve_select(is_leaf, leaf_output, branch_output);

        Self::Wires {
            is_leaf,
            leaf_input,
            branch_input,
            output,
        }
    }

    fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
        pw.set_bool_target(wires.is_leaf, self.is_leaf);
        pw.set_target_arr(&wires.leaf_input, &self.leaf_input);
        pw.set_curve_targets(
            &wires.branch_input,
            &self.branch_input.map(|point| point.to_weierstrass()),
        );

        #[cfg(debug_assertions)]
        {
            // Calculate the output.
            let output = if self.is_leaf {
                // Convert the values from u8 array to u32.
                let inputs: Vec<_> = convert_u8_values_to_u32(&self.leaf_input);

                // Calculate the Poseidon hash and output N values of base field.
                let hash: [F; N] = hash_n_to_m_no_pad::<F, PoseidonPermutation<F>>(&inputs, N)
                    .try_into()
                    .unwrap();

                // Convert the hash to a curve point.
                QuinticExtension::from_basefield_array(hash).map_to_curve_point()
            } else {
                // Calculate the curve point addition for children of branch.
                // <https://github.com/Lagrange-Labs/plonky2-ecgfp5/blob/08feaa03a006923fa721f2f5a26578d13bc25fa6/src/curve/curve.rs#L709>
                self.branch_input
                    .iter()
                    .cloned()
                    .reduce(|acc, p| acc + p)
                    .unwrap()
            };

            pw.set_curve_target(wires.output, output.to_weierstrass());
        }
    }
}

impl<F, const D: usize, const ARITY: usize> PCDCircuit<F, D, ARITY>
    for MultisetHashingCircuit<F, D, ARITY>
where
    F: RichField + Extendable<D> + Extendable<N>,
    QuinticExtension<F>: ToCurvePoint,
    CircuitBuilder<F, D>: CircuitBuilderGFp5<F> + CircuitBuilderEcGFp5,
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
        F::rand_vec(Self::num_io())
    }

    fn num_io() -> usize {
        // The curve target contains 2 extension targets and 1 bool target.
        2 * N + 1
    }
}

/// Generate the curve point from the inputs of Merkle tree leaf.
fn build_leaf<F, const D: usize>(b: &mut CircuitBuilder<F, D>, inputs: &[Target]) -> CurveTarget
where
    F: RichField + Extendable<D> + Extendable<N>,
    CircuitBuilder<F, D>: CircuitBuilderGFp5<F> + CircuitBuilderEcGFp5,
{
    // Convert the u8 target array to an u32 target array.
    let inputs: Vec<_> = convert_u8_targets_to_u32(b, &inputs)
        .into_iter()
        .map(|u32_target| u32_target.0)
        .collect();

    // Calculate the Poseidon hash.
    let hash = b
        .hash_n_to_m_no_pad::<PoseidonHash>(inputs, N)
        .try_into()
        .unwrap();

    // Convert the hash to a curve target.
    QuinticExtensionTarget(hash).map_to_curve_target(b)
}

/// Calculate the curve point addition for children of a Merkle tree branch.
fn build_branch<F, const D: usize>(
    b: &mut CircuitBuilder<F, D>,
    inputs: &[CurveTarget],
) -> CurveTarget
where
    F: RichField + Extendable<D> + Extendable<N>,
    CircuitBuilder<F, D>: CircuitBuilderGFp5<F> + CircuitBuilderEcGFp5,
{
    assert!(!inputs.is_empty());

    // The ARITY inputs are set to NEUTRAL point as default, which has no impact
    // for the addition.
    inputs
        .iter()
        .cloned()
        .reduce(|acc, point| b.curve_add(acc, point))
        .unwrap()
}
