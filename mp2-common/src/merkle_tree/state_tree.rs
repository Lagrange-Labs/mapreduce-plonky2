//! A state tree Merkle opening with internal variable depth.

use plonky2::{
    field::extension::Extendable,
    hash::{
        hash_types::{HashOutTarget, RichField, NUM_HASH_OUT_ELTS},
        merkle_proofs::MerkleProofTarget,
        poseidon::PoseidonHash,
    },
    iop::{
        target::{BoolTarget, Target},
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::circuit_builder::CircuitBuilder,
};
use recursion_framework::serialization::{deserialize, serialize};
use serde::{Deserialize, Serialize};

use crate::poseidon::hash_maybe_swap;

/// A Merkle proof wire structure enabling verification of leaf data up to variable depth.
///
/// The circuit is designed such that all hash computations are always performed up to [MAX_DEPTH],
/// thereby ensuring the integrity and immutability of the circuit structure. Internal flags named
/// [is_value] will be activated upon reaching the target depth for each node, allowing the root
/// value to be replicated accurately while still processing subsequent permutations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateTreeWires<const MAX_DEPTH: usize> {
    /// A set of flags that will be `true` for the corresponding depth that should compute the
    /// Merkle root as a hash permutation. If `false`, the circuit will repeat the previous hash.
    #[serde(serialize_with = "serialize", deserialize_with = "deserialize")]
    pub is_value: Vec<BoolTarget>,
    /// The Merkle root at the variable depth.
    #[serde(serialize_with = "serialize", deserialize_with = "deserialize")]
    pub root: HashOutTarget,
    /// The proven root depth.
    pub depth: Target,
}

impl<const MAX_DEPTH: usize> StateTreeWires<MAX_DEPTH> {
    /// Builds the wire structure with the provided data for the variable depth.
    ///
    /// - `leaf_data` will be the preimage of the node of the branch at depth `0`.
    /// - `siblings` will be the full Merkle path up to [MAX_DEPTH]; the remainder nodes will be
    /// ignored.
    /// - `positions` will be bits path up to [MAX_DEPTH]; the remainder items will be ignored.
    /// - `depth` will be the variable depth to be proven.
    pub fn build<F, const D: usize>(
        cb: &mut CircuitBuilder<F, D>,
        leaf_data: &[Target],
        siblings: &MerkleProofTarget,
        positions: &[BoolTarget],
    ) -> Self
    where
        F: RichField + Extendable<D>,
    {
        assert_eq!(
            siblings.siblings.len(),
            MAX_DEPTH,
            "the siblings length must be padded to the max depth"
        );
        assert_eq!(
            positions.len(),
            MAX_DEPTH,
            "the positions length must be padded to the max depth"
        );

        let depth = cb.add_virtual_target();
        let mut positions = positions.to_vec();
        let is_value: Vec<_> = (0..MAX_DEPTH)
            .map(|_| cb.add_virtual_bool_target_safe())
            .collect();

        while positions.len() < MAX_DEPTH {
            positions.push(cb.add_virtual_bool_target_safe());
        }

        // asserts that the value flags are contiguous and up to the depth. the `is_value`
        // composition is encapsulated within `fn assign` and isn't exposed to the user. however,
        // we still need to constrain it to prevent malicious provers of hijacking it.
        // d == Σ(v₍ᵢ₋₁₎ · vᵢ)
        let mut val = cb.one();
        let mut acc = cb.zero();
        for i in 0..MAX_DEPTH {
            val = cb.mul(val, is_value[i].target);
            acc = cb.add(acc, val);
        }
        cb.connect(acc, depth);

        let mut root = cb.hash_n_to_hash_no_pad::<PoseidonHash>(leaf_data.to_vec());

        for d in 0..MAX_DEPTH {
            // always hash up to depth to preserve the same circuit structure, regardless of the
            // chosen depth
            let value = hash_maybe_swap(
                cb,
                &[root.elements, siblings.siblings[d].elements],
                positions[d],
            );

            // pick either the hashed value or the current root as the next depth, depending on the
            // `is_value` flag that is responsible to define the depths that should be computed as
            // a hash product.
            for i in 0..NUM_HASH_OUT_ELTS {
                root.elements[i] = cb.select(is_value[d], value.elements[i], root.elements[i]);
            }
        }

        Self {
            is_value,
            root,
            depth,
        }
    }

    /// Assigns the provided data as witness.
    ///
    /// - `depth` will be the variable depth to be proven. Will not be assigned to a target.
    pub fn assign<F>(&self, pw: &mut PartialWitness<F>, depth: F)
    where
        F: RichField,
    {
        pw.set_target(self.depth, depth);
        let depth_value = depth.to_canonical_u64() as usize;

        for i in 0..depth_value {
            pw.set_target(self.is_value[i].target, F::ONE);
        }

        for i in depth_value..MAX_DEPTH {
            pw.set_target(self.is_value[i].target, F::ZERO);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::array;

    use mp2_test::circuit::{run_circuit, UserCircuit};
    use plonky2::{
        field::{goldilocks_field::GoldilocksField, types::Field},
        hash::{
            hash_types::HashOut, hashing::hash_n_to_hash_no_pad, poseidon::PoseidonPermutation,
        },
        plonk::config::PoseidonGoldilocksConfig,
    };
    use rand::{rngs::StdRng, RngCore, SeedableRng};

    use super::*;

    const TEST_MAX_DEPTH: usize = 5;
    const LEAF_DATA_LEN: usize = 3;

    #[test]
    fn variable_depth_opening_works() {
        let seed = 0xdead;
        let depth = 3;
        let circuit = TestVariableDepthCircuit::from_seed_with_depth(seed, depth);
        let root = circuit.root.elements.to_vec();
        let proof = run_circuit::<_, _, PoseidonGoldilocksConfig, _>(circuit);

        assert_eq!(root, proof.public_inputs);
    }

    #[derive(Clone, Debug)]
    struct TestVariableDepthWires {
        pub wires: StateTreeWires<TEST_MAX_DEPTH>,
        pub leaf_data: Vec<Target>,
        pub siblings: MerkleProofTarget,
        pub positions: Vec<BoolTarget>,
    }

    #[derive(Clone, Debug)]
    struct TestVariableDepthCircuit {
        pub leaf_data: Vec<GoldilocksField>,
        pub siblings: Vec<HashOut<GoldilocksField>>,
        pub positions: Vec<GoldilocksField>,
        pub depth: GoldilocksField,
        pub root: HashOut<GoldilocksField>,
    }

    impl TestVariableDepthCircuit {
        fn from_seed_with_depth(seed: u64, depth: u32) -> Self {
            let rng = &mut StdRng::seed_from_u64(seed);

            let leaf_data: Vec<_> = (0..LEAF_DATA_LEN)
                .map(|_| rng.next_u32())
                .map(GoldilocksField::from_canonical_u32)
                .collect();

            let mut positions = vec![GoldilocksField::from_bool(false); TEST_MAX_DEPTH];
            let mut siblings = vec![
                HashOut {
                    elements: [GoldilocksField::ZERO; NUM_HASH_OUT_ELTS]
                };
                TEST_MAX_DEPTH
            ];

            let mut root = hash_n_to_hash_no_pad::<
                GoldilocksField,
                PoseidonPermutation<GoldilocksField>,
            >(leaf_data.as_slice());

            for d in 0..depth as usize {
                let pos = (rng.next_u32() & 1) == 1;

                positions[d] = GoldilocksField::from_bool(pos);
                siblings[d] = HashOut {
                    elements: array::from_fn(|_| {
                        GoldilocksField::from_canonical_u32(rng.next_u32())
                    }),
                };

                let mut preimage = Vec::with_capacity(NUM_HASH_OUT_ELTS);

                if pos {
                    preimage.extend_from_slice(&siblings[d].elements);
                    preimage.extend_from_slice(&root.elements);
                } else {
                    preimage.extend_from_slice(&root.elements);
                    preimage.extend_from_slice(&siblings[d].elements);
                }

                root = hash_n_to_hash_no_pad::<GoldilocksField, PoseidonPermutation<GoldilocksField>>(
                    preimage.as_slice(),
                );
            }

            let depth = GoldilocksField::from_canonical_u32(depth);

            Self {
                leaf_data,
                siblings,
                positions,
                depth,
                root,
            }
        }
    }

    impl UserCircuit<GoldilocksField, 2> for TestVariableDepthCircuit {
        type Wires = TestVariableDepthWires;

        fn build(b: &mut CircuitBuilder<GoldilocksField, 2>) -> Self::Wires {
            let leaf_data = b.add_virtual_targets(LEAF_DATA_LEN);
            let siblings = MerkleProofTarget {
                siblings: b.add_virtual_hashes(TEST_MAX_DEPTH),
            };
            let positions: Vec<_> = (0..TEST_MAX_DEPTH)
                .map(|_| b.add_virtual_bool_target_safe())
                .collect();
            let wires = StateTreeWires::build(b, &leaf_data, &siblings, &positions);

            b.register_public_inputs(&wires.root.elements);

            TestVariableDepthWires {
                wires,
                leaf_data,
                siblings,
                positions,
            }
        }

        fn prove(&self, pw: &mut PartialWitness<GoldilocksField>, wires: &Self::Wires) {
            for i in 0..self.leaf_data.len() {
                pw.set_target(wires.leaf_data[i], self.leaf_data[i]);
            }

            for i in 0..self.siblings.len() {
                pw.set_target(wires.positions[i].target, self.positions[i]);

                for j in 0..NUM_HASH_OUT_ELTS {
                    pw.set_target(
                        wires.siblings.siblings[i].elements[j],
                        self.siblings[i].elements[j],
                    );
                }
            }

            wires.wires.assign(pw, self.depth);
        }
    }
}
