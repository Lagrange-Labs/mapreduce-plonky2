//! Multiset hashing implemention for digest tree circuit used to prove Merkle
//! tree nodes recursively.

use super::DigestTreeCircuit;
use crate::{
    circuit::{PCDCircuit, ProofOrDummyTarget, UserCircuit},
    utils::{convert_u8_targets_to_u32, convert_u8_values_to_u32},
};
use plonky2::{
    field::{
        extension::{quintic::QuinticExtension, Extendable, FieldExtension},
        goldilocks_field::GoldilocksField,
    },
    hash::{
        hash_types::RichField,
        hashing::hash_n_to_m_no_pad,
        poseidon::{PoseidonHash, PoseidonPermutation},
    },
    iop::{
        ext_target::ExtensionTarget,
        target::{BoolTarget, Target},
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{circuit_builder::CircuitBuilder, config::GenericConfig},
};
use serde::Serialize;
use std::array;

/// Configuration for multiset hashing.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct MultisetHashingConfig;
impl GenericConfig<5> for MultisetHashingConfig {
    type F = GoldilocksField;
    type FE = QuinticExtension<Self::F>;
    type Hasher = PoseidonHash;
    type InnerHasher = PoseidonHash;
}

/// A point value of extension field including X and Y coordinates
#[derive(Clone, Debug)]
pub struct MultisetHashingPointValue<F, const D: usize>
where
    F: RichField + Extendable<D>,
{
    /// X coordinate
    x: F::Extension,
    /// Y coordinate
    y: F::Extension,
}

/// A point target of extension field including X and Y coordinates
#[derive(Clone, Debug)]
struct MultisetHashingPointTarget<const D: usize> {
    /// X coordinate
    x: ExtensionTarget<D>,
    /// Y coordinate
    y: ExtensionTarget<D>,
}

/// Multiset hashing circuit wires including input and output targets
#[derive(Clone, Debug)]
pub struct MultisetHashingWires<const D: usize> {
    /// Flag target to identify if it's a leaf or branch.
    is_leaf: BoolTarget,
    /// The input targets are considered to be `[U8Target; 32]` if it's a leaf,
    /// otherwise the first `4*D` targets should be built from `[Target; 4 * D]`
    /// to `[ExtensionTarget; 4]` for branch, it's permuted as [X1, Y1, X2, Y2].
    /// D should be set to 5 for EcGFp5 curve as default, and must be equal to
    /// or less than 8 (32 / 4).
    inputs: [Target; 32],
    /// The output extension target is a point on the curve. It's converted from
    /// the Poseidon hash if it's a leaf, otherwise it's the addition of two
    /// extension points for branch.
    output: MultisetHashingPointTarget<D>,
}

/// Multiset hashing circuit used to prove Merkle tree recursively
#[derive(Clone, Debug)]
pub struct MultisetHashingCircuit<F, const D: usize> {
    /// Flag to identify if it's a leaf or branch.
    is_leaf: bool,
    /// The input values are considered to be `[BaseField; 32]` if it's a leaf,
    /// otherwise the first `4*D` values should be built
    /// from `[BaseField; 4 * D]` to `[ExtensionField; 4]` for branch, it's
    /// permuted as [X1, Y1, X2, Y2]. D should be set to 5 for EcGFp5 curve as
    /// default, and must be equal to or less than 8 (32 / 4).
    inputs: [F; 32],
}

impl<F, const D: usize> DigestTreeCircuit<F, D, D> for MultisetHashingCircuit<F, D>
where
    F: RichField + Extendable<D>,
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
    fn new_branch(children: Vec<[F; D]>) -> Self {
        // The children argument must have 4 elements and permute as
        // [X1, Y1, X2, Y2] of two points. Each element is an extension field
        // value as `[F; D]`.
        // D must be equal to or less than 8 (32 / 4), since the inputs have a
        // constant length of 32.
        assert!(D <= 8 && children.len() == 4);

        // Flatten the child values.
        let inputs = array::from_fn(|i| {
            if i < 4 * D {
                children[i / D][i % D]
            } else {
                F::ZERO
            }
        });

        Self {
            is_leaf: false,
            inputs,
        }
    }
}

impl<F, const D: usize> UserCircuit<F, D> for MultisetHashingCircuit<F, D>
where
    F: RichField + Extendable<D>,
{
    type Wires = MultisetHashingWires<D>;

    fn build(b: &mut CircuitBuilder<F, D>) -> Self::Wires {
        let is_leaf = b.add_virtual_bool_target_safe();
        let inputs = b.add_virtual_target_arr::<32>();

        // Generate the output of extension point for both leaf and branch.
        let leaf_output = build_leaf(b, &inputs);
        let branch_output = build_branch(b, &inputs);

        let output = MultisetHashingPointTarget {
            x: b.select_ext(is_leaf, leaf_output.x, branch_output.x),
            y: b.select_ext(is_leaf, leaf_output.y, branch_output.y),
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

            // Calculate the Poseidon hash and output D values of base field.
            let hash = hash_n_to_m_no_pad::<F, PoseidonPermutation<F>>(&inputs, D)
                .try_into()
                .unwrap();

            // Convert the hash to an extension point.
            hash_to_field_point_value(hash)
        } else {
            let [x1, y1, x2, y2] = self.inputs[..4 * D]
                .chunks(D)
                .map(|arr| F::Extension::from_basefield_array(arr.try_into().unwrap()))
                .collect::<Vec<_>>()
                .try_into()
                .unwrap();

            // Calculate the addition of two child points for branch.
            MultisetHashingPointValue {
                x: x1 + x2,
                y: y1 + y2,
            }
        };

        pw.set_extension_target(wires.output.x, output.x);
        pw.set_extension_target(wires.output.y, output.y);
    }
}

impl<F, const D: usize, const ARITY: usize> PCDCircuit<F, D, ARITY> for MultisetHashingCircuit<F, D>
where
    F: RichField + Extendable<D>,
{
    fn build_recursive(
        b: &mut CircuitBuilder<F, D>,
        _: &[ProofOrDummyTarget<D>; ARITY],
    ) -> Self::Wires {
        let wires = <Self as UserCircuit<F, D>>::build(b);
        b.register_public_inputs(&wires.output.x.0);
        b.register_public_inputs(&wires.output.y.0);

        // TODO: check the proof public inputs match what is expected.

        wires
    }

    fn base_inputs(&self) -> Vec<F> {
        F::rand_vec(2 * D)
    }

    fn num_io() -> usize {
        2 * D
    }
}

/// Generate the extension point from the inputs of Merkle tree leaf.
fn build_leaf<F, const D: usize>(
    b: &mut CircuitBuilder<F, D>,
    inputs: &[Target],
) -> MultisetHashingPointTarget<D>
where
    F: RichField + Extendable<D>,
{
    // Convert the u8 target array to u32 target array.
    let inputs: Vec<_> = convert_u8_targets_to_u32(b, &inputs)
        .into_iter()
        .map(|u32_target| u32_target.0)
        .collect();

    let hash = b
        .hash_n_to_m_no_pad::<PoseidonHash>(inputs, D)
        .try_into()
        .unwrap();

    hash_to_field_point_target(hash)
}

/// Generate the addition extension point from the two child point inputs of
/// Merkle tree branch.
fn build_branch<F, const D: usize>(
    b: &mut CircuitBuilder<F, D>,
    inputs: &[Target],
) -> MultisetHashingPointTarget<D>
where
    F: RichField + Extendable<D>,
{
    let [x1, y1, x2, y2] = inputs[..4 * D]
        .chunks(D)
        .map(|targets| targets.to_vec().try_into().unwrap())
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();

    MultisetHashingPointTarget {
        x: b.add_extension(x1, x2),
        y: b.add_extension(y1, y2),
    }
}

/// Convert the Poseidon hash value to a curve extension point value.
fn hash_to_field_point_value<F, const D: usize>(hash: [F; D]) -> MultisetHashingPointValue<F, D>
where
    F: RichField + Extendable<D>,
{
    // gupeng
    // expand_message
    todo!()
}

/// Convert the Poseidon hash target to a curve extension point target.
fn hash_to_field_point_target<const D: usize>(hash: [Target; D]) -> MultisetHashingPointTarget<D> {
    todo!()
}
