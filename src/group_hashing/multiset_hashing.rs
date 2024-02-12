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

    fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
        pw.set_bool_target(wires.is_leaf, self.is_leaf);
        pw.set_target_arr(&wires.leaf_input, &self.leaf_input);
        pw.set_curve_targets(
            &wires.branch_input,
            &self.branch_input.map(|point| point.to_weierstrass()),
        );

        // The output target could be set to check consistency for debugging.
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

