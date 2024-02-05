//! Multiset hashing implemention for digest tree circuit used to prove Merkle
//! tree nodes recursively.
//! There're two degree parameter D and N in the code, D is used for circuit
//! builder and generic configuration, and N is used for the extension field, so
//! the base field F (as GoldilocksField) should implement both Extendable<D>
//! and Extendable<N>.

use super::{hash_to_field_point_target, hash_to_field_point_value, DigestTreeCircuit};
use crate::{
    circuit::{PCDCircuit, ProofOrDummyTarget, UserCircuit},
    extension::{add_ext_targets, add_ext_values, select_ext_target},
    utils::{convert_u8_targets_to_u32, convert_u8_values_to_u32},
};
use plonky2::{
    field::extension::Extendable,
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
use std::{array, ops::Add};

/// A point value of extension field including X and Y coordinates
#[derive(Clone, Debug)]
pub struct MultisetHashingPointValue<F, const N: usize> {
    /// X coordinate
    x: [F; N],
    /// Y coordinate
    y: [F; N],
}

/// Implement the Default trait for MultisetHashingPointValue.
impl<F, const N: usize> Default for MultisetHashingPointValue<F, N>
where
    F: RichField + Extendable<N>,
{
    fn default() -> Self {
        Self {
            x: [F::ZERO; N],
            y: [F::ZERO; N],
        }
    }
}

/// Implement the addition operator `+` for MultisetHashingPointValue.
impl<F, const N: usize> Add for &MultisetHashingPointValue<F, N>
where
    F: RichField + Extendable<N>,
{
    type Output = MultisetHashingPointValue<F, N>;

    fn add(self, other: Self) -> Self::Output {
        Self::Output {
            x: add_ext_values(self.x, other.x),
            y: add_ext_values(self.y, other.y),
        }
    }
}

/// A point target of extension field including X and Y coordinates
#[derive(Clone, Debug)]
pub struct MultisetHashingPointTarget<const N: usize> {
    /// X coordinate
    x: [Target; N],
    /// Y coordinate
    y: [Target; N],
}

/// Multiset hashing circuit wires including input and output targets
#[derive(Clone, Debug)]
pub struct MultisetHashingWires<const N: usize> {
    /// Flag target to identify if it's a leaf or branch.
    is_leaf: BoolTarget,
    /// The input targets are considered to be `[U8Target; 32]` if it's a leaf,
    /// otherwise the first `4*N` targets should be built from `[Target; 4 * N]`
    /// to `[ExtensionTarget; 4]` for branch, it's permuted as [X1, Y1, X2, Y2].
    /// N should be set to 5 for EcGFp5 curve as default, and must be equal to
    /// or less than 8 (32 / 4).
    inputs: [Target; 32],
    /// The output extension target is a point on the curve. It's converted from
    /// the Poseidon hash if it's a leaf, otherwise it's the addition of two
    /// extension points for branch.
    output: MultisetHashingPointTarget<N>,
}

/// Multiset hashing circuit used to prove Merkle tree recursively
/// There're two degree parameter D and N, D is used for circuit builder and
/// generic configuration, and N is used for the extension field, so the base
/// field F (as GoldilocksField) should implement both Extendable<D> and
/// Extendable<N>.
#[derive(Clone, Debug)]
pub struct MultisetHashingCircuit<F, const D: usize, const N: usize> {
    /// Flag to identify if it's a leaf or branch.
    is_leaf: bool,
    /// The input values are considered to be `[BaseField; 32]` if it's a leaf,
    /// otherwise the first `4*N` values should be built from
    /// `[BaseField; 4 * N]` to `[ExtensionField; 4]` for branch, it's permuted
    /// as [X1, Y1, X2, Y2]. N should be set to 5 for EcGFp5 curve as default,
    /// and must be equal to or less than 8 (32 / 4).
    inputs: [F; 32],
}

impl<F, const D: usize, const N: usize> DigestTreeCircuit<MultisetHashingPointValue<F, N>>
    for MultisetHashingCircuit<F, D, N>
where
    F: RichField + Extendable<D> + Extendable<N>,
{
    /// Create a circuit instance for a leaf of Merkle tree.
    fn new_leaf(value: [u8; 32]) -> Self {
        // Convert the u8 array to a base field array.
        let inputs = value
            .into_iter()
            .map(F::from_canonical_u8)
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        Self {
            is_leaf: true,
            inputs,
        }
    }

    /// Create a circuit instance for a branch of Merkle tree.
    fn new_branch(children: Vec<MultisetHashingPointValue<F, N>>) -> Self {
        // N must be equal to or less than 8 (32 / 4), since the inputs have a
        // constant length of 32.
        // And the child number must be 1 or 2, since it's a binary tree.
        assert!(N <= 8 && [1, 2].contains(&children.len()));

        // Flatten the child values as [X1, Y1, X2, Y2].
        let values: Vec<_> = children
            .iter()
            .flat_map(|child| child.x.into_iter().chain(child.y))
            .collect();

        let inputs = array::from_fn(|i| values.get(i).cloned().unwrap_or(F::ZERO));

        Self {
            is_leaf: false,
            inputs,
        }
    }
}

impl<F, const D: usize, const N: usize> UserCircuit<F, D> for MultisetHashingCircuit<F, D, N>
where
    F: RichField + Extendable<D> + Extendable<N>,
{
    type Wires = MultisetHashingWires<N>;

    fn build(b: &mut CircuitBuilder<F, D>) -> Self::Wires {
        let is_leaf = b.add_virtual_bool_target_safe();
        let inputs = b.add_virtual_target_arr::<32>();

        // Generate the output of extension point for both leaf and branch.
        let leaf_output = build_leaf(b, &inputs);
        let branch_output = build_branch(b, &inputs);

        // Build the output.
        let output = MultisetHashingPointTarget {
            x: select_ext_target(b, is_leaf, leaf_output.x, branch_output.x),
            y: select_ext_target(b, is_leaf, leaf_output.y, branch_output.y),
        };

        Self::Wires {
            is_leaf,
            inputs,
            output,
        }
    }

    fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
        pw.set_bool_target(wires.is_leaf, self.is_leaf);
        pw.set_target_arr(&wires.inputs, &self.inputs);

        let output = if self.is_leaf {
            // Convert the values from u8 array to u32.
            let inputs: Vec<_> = convert_u8_values_to_u32(&self.inputs);

            // Calculate the Poseidon hash and output N values of base field.
            let hash: [F; N] = hash_n_to_m_no_pad::<F, PoseidonPermutation<F>>(&inputs, N)
                .try_into()
                .unwrap();

            // Convert the hash to an extension point.
            hash_to_field_point_value(hash)
        } else {
            let [x1, y1, x2, y2] = array::from_fn(|i| array::from_fn(|j| self.inputs[i * N + j]));

            // Calculate the addition of two child points for branch.
            MultisetHashingPointValue {
                x: add_ext_values(x1, x2),
                y: add_ext_values(y1, y2),
            }
        };

        wires
            .output
            .x
            .into_iter()
            .zip(output.x)
            .for_each(|(t, v)| pw.set_target(t, v));
        wires
            .output
            .y
            .into_iter()
            .zip(output.y)
            .for_each(|(t, v)| pw.set_target(t, v));
    }
}

impl<F, const D: usize, const N: usize, const ARITY: usize> PCDCircuit<F, D, ARITY>
    for MultisetHashingCircuit<F, D, N>
where
    F: RichField + Extendable<D> + Extendable<N>,
{
    fn build_recursive(
        b: &mut CircuitBuilder<F, D>,
        _: &[ProofOrDummyTarget<D>; ARITY],
    ) -> Self::Wires {
        let wires = <Self as UserCircuit<F, D>>::build(b);
        b.register_public_inputs(&wires.output.x);
        b.register_public_inputs(&wires.output.y);

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

/// Generate the extension point from the inputs of Merkle tree leaf.
fn build_leaf<F, const D: usize, const N: usize>(
    b: &mut CircuitBuilder<F, D>,
    inputs: &[Target],
) -> MultisetHashingPointTarget<N>
where
    F: RichField + Extendable<D> + Extendable<N>,
{
    // Convert the u8 target array to u32 target array.
    let inputs: Vec<_> = convert_u8_targets_to_u32(b, &inputs)
        .into_iter()
        .map(|u32_target| u32_target.0)
        .collect();

    let hash = b
        .hash_n_to_m_no_pad::<PoseidonHash>(inputs, N)
        .try_into()
        .unwrap();

    hash_to_field_point_target(hash)
}

/// Generate the addition extension point from the two child point inputs of
/// Merkle tree branch.
fn build_branch<F, const D: usize, const N: usize>(
    b: &mut CircuitBuilder<F, D>,
    inputs: &[Target],
) -> MultisetHashingPointTarget<N>
where
    F: RichField + Extendable<D> + Extendable<N>,
{
    let [x1, y1, x2, y2] = array::from_fn(|i| array::from_fn(|j| inputs[i * N + j]));

    MultisetHashingPointTarget {
        x: add_ext_targets(b, x1, x2),
        y: add_ext_targets(b, y1, y2),
    }
}
