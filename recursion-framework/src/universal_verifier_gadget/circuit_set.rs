use std::collections::HashMap;

use plonky2::{
    field::extension::Extendable,
    hash::{
        hash_types::{HashOut, HashOutTarget, MerkleCapTarget, RichField},
        merkle_proofs::MerkleProofTarget,
        merkle_tree::{MerkleCap, MerkleTree},
    },
    iop::{
        target::{BoolTarget, Target},
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, VerifierCircuitTarget},
        config::{AlgebraicHasher, GenericConfig, GenericHashOut, Hasher},
    },
    util::log2_ceil,
};
use serde::{Deserialize, Serialize};

use crate::serialization::{deserialize, deserialize_vec, serialize, serialize_vec};

use super::CIRCUIT_SET_CAP_HEIGHT;
use anyhow::{Error, Result};

/// get the list of targets composing a `MerkleCapTarget`
pub(crate) fn merkle_cap_to_targets(merkle_cap: &MerkleCapTarget) -> Vec<Target> {
    merkle_cap.0.iter().flat_map(|h| h.elements).collect()
}

/// Set of targets employed to prove that the circuit employed to generate a proof being recursively
/// verified belongs to the set of circuits whose proofs can be verified with the universal verifier
/// bound to such a set
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct CircuitSetMembershipTargets {
    #[serde(serialize_with = "serialize", deserialize_with = "deserialize")]
    merkle_proof_target: MerkleProofTarget,
    #[serde(serialize_with = "serialize_vec", deserialize_with = "deserialize_vec")]
    leaf_index_bits: Vec<BoolTarget>,
}

/// The target employed to represent the set of circuits whose proofs can be verified with the
/// universal verifier bound to such a set
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct CircuitSetTarget(
    #[serde(serialize_with = "serialize", deserialize_with = "deserialize")] MerkleCapTarget,
);

impl CircuitSetTarget {
    pub(crate) fn build_target<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        Self(builder.add_virtual_cap(CIRCUIT_SET_CAP_HEIGHT))
    }

    pub(crate) fn to_targets(&self) -> Vec<Target> {
        merkle_cap_to_targets(&self.0)
    }

    pub(crate) fn from_circuit_set_digest<
        F: RichField + Extendable<D>,
        H: Hasher<F, Hash = HashOut<F>>,
        C: GenericConfig<D, Hasher = H, F = F>,
        const D: usize,
    >(
        builder: &mut CircuitBuilder<F, D>,
        digest: CircuitSetDigest<F, C, D>,
    ) -> Self {
        Self(builder.constant_merkle_cap(&digest.0))
    }

    pub(crate) fn set_target<
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F>,
        const D: usize,
    >(
        &self,
        pw: &mut PartialWitness<F>,
        digest: &CircuitSetDigest<F, C, D>,
    ) where
        C::Hasher: AlgebraicHasher<F>,
    {
        pw.set_cap_target(&self.0, &digest.0);
    }

    /// Enforce that `circuit_digest_target` is a leaf in the merkle-tree
    /// with root `circuit_set_target`
    pub(crate) fn check_circuit_digest_membership<
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F>,
        const D: usize,
    >(
        builder: &mut CircuitBuilder<F, D>,
        circuit_set_target: &Self,
        circuit_digest_target: &HashOutTarget,
        num_circuit_digests: usize,
    ) -> CircuitSetMembershipTargets
    where
        C::Hasher: AlgebraicHasher<F>,
    {
        let full_tree_height = log2_ceil(num_circuit_digests);
        let height = full_tree_height - CIRCUIT_SET_CAP_HEIGHT;
        let mpt = MerkleProofTarget {
            siblings: builder.add_virtual_hashes(height),
        };
        let leaf_index_bits = (0..height)
            .map(|_| builder.add_virtual_bool_target_safe())
            .collect::<Vec<_>>();

        builder.verify_merkle_proof_to_cap::<C::Hasher>(
            circuit_digest_target.elements.to_vec(),
            leaf_index_bits.as_slice(),
            &circuit_set_target.0,
            &mpt,
        );

        CircuitSetMembershipTargets {
            merkle_proof_target: mpt,
            leaf_index_bits,
        }
    }
    /// Returns the number of targets employed for `CircuitSetTarget`
    pub(crate) fn num_targets<F: RichField + Extendable<D>, const D: usize>(
        config: CircuitConfig,
    ) -> usize {
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let target = CircuitSetTarget::build_target(&mut builder);
        target.to_targets().len()
    }
}

/// check in the circuit that the circuit digest in `verifier_data` is correctly computed from
/// `verifier_data.constants_sigmas_cap` and the degree bits of the circuit
pub(crate) fn check_circuit_digest_target<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
>(
    builder: &mut CircuitBuilder<F, D>,
    verifier_data: &VerifierCircuitTarget,
    degree_bits: usize,
) where
    C::Hasher: AlgebraicHasher<F>,
{
    let cap_targets = merkle_cap_to_targets(&verifier_data.constants_sigmas_cap);
    // we assume the circuit was generated without a domain generator
    let domain_separator_target = builder
        .constant_hash(C::Hasher::hash_pad(&vec![]))
        .elements
        .to_vec();
    let degree_target = vec![builder.constant(F::from_canonical_usize(degree_bits))];
    let cap_hash = builder.hash_n_to_hash_no_pad::<C::Hasher>(
        [cap_targets, domain_separator_target, degree_target].concat(),
    );
    builder.connect_hashes(verifier_data.circuit_digest, cap_hash);
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(bound = "")]
/// Data structure employed by the recursion framework to store and manage the set of circuits whose proofs
/// can be verified with the universal verifier bound to such a set
pub(crate) struct CircuitSet<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
> {
    circuit_digests_to_leaf_indexes: HashMap<Vec<F>, usize>,
    #[serde(serialize_with = "serialize", deserialize_with = "deserialize")]
    mt: MerkleTree<F, C::Hasher>,
}

impl<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize> CircuitSet<F, C, D>
where
    C::Hasher: AlgebraicHasher<F>,
    [(); C::Hasher::HASH_SIZE]:,
{
    pub(crate) fn build_circuit_set(circuit_digests: Vec<<C::Hasher as Hasher<F>>::Hash>) -> Self {
        let (circuit_digests_to_leaf_indexes, mut leaves): (HashMap<Vec<F>, usize>, Vec<_>) =
            circuit_digests
                .iter()
                .enumerate()
                .map(|(index, hash)| {
                    let hash_to_fes = hash.to_vec();
                    ((hash_to_fes, index), hash.to_vec())
                })
                .unzip();

        let num_leaves_padded: usize = 1 << log2_ceil(leaves.len());
        leaves.resize_with(num_leaves_padded, || vec![F::ZERO]);

        Self {
            circuit_digests_to_leaf_indexes,
            mt: MerkleTree::<F, C::Hasher>::new(leaves, CIRCUIT_SET_CAP_HEIGHT),
        }
    }

    fn leaf_index(&self, digest: &[F]) -> Option<usize> {
        self.circuit_digests_to_leaf_indexes.get(digest).cloned()
    }

    /// set a `CircuitSetMembershipTargets` to prove membership of `circuit_digest` in the set of
    /// circuits whose proofs can be verified with the universal verifier bound to such a set
    pub(crate) fn set_circuit_membership_target(
        &self,
        pw: &mut PartialWitness<F>,
        membership_target: &CircuitSetMembershipTargets,
        circuit_digest: <C::Hasher as Hasher<F>>::Hash,
    ) -> Result<()> {
        // compute merkle proof for `circuit_digest`
        let leaf_index = self
            .leaf_index(circuit_digest.to_vec().as_slice())
            .ok_or(Error::msg("circuit digest not found"))?;

        let merkle_proof = self.mt.prove(leaf_index);

        // set leaf index bits targets with the little-endian bit decomposition of leaf_index
        for (i, bool_target) in membership_target.leaf_index_bits.iter().enumerate() {
            let mask = (1 << i) as usize;
            pw.set_bool_target(*bool_target, (leaf_index & mask) != 0);
        }
        // set merkle proof target
        assert_eq!(
            merkle_proof.len(),
            membership_target.merkle_proof_target.siblings.len()
        );
        for (&mp, &mpt) in merkle_proof
            .siblings
            .iter()
            .zip(membership_target.merkle_proof_target.siblings.iter())
        {
            pw.set_hash_target(mpt, mp);
        }

        Ok(())
    }

    pub(crate) fn circuit_set_size(&self) -> usize {
        self.circuit_digests_to_leaf_indexes.len()
    }
}

/// A short representation (e.g., a digest) of the set of circuits whose proofs can be verified with the
/// universal verifier bound to such a set; this should represent values assignable to a `CircuitSetTarget`
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct CircuitSetDigest<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
>(MerkleCap<F, C::Hasher>);

impl<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>
    CircuitSetDigest<F, C, D>
where
    C::Hasher: AlgebraicHasher<F>,
{
    pub fn flatten(&self) -> Vec<F> {
        self.0.flatten()
    }
}

impl<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize> Default
    for CircuitSetDigest<F, C, D>
where
    [(); C::Hasher::HASH_SIZE]:,
{
    fn default() -> Self {
        Self(MerkleCap(
            (0..(1 << CIRCUIT_SET_CAP_HEIGHT))
                .map(|_| {
                    <<C as GenericConfig<D>>::Hasher as Hasher<F>>::Hash::from_bytes(
                        &[0u8; <<C as GenericConfig<D>>::Hasher as Hasher<F>>::HASH_SIZE],
                    )
                })
                .collect::<Vec<_>>(),
        ))
    }
}

impl<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>
    From<&CircuitSet<F, C, D>> for CircuitSetDigest<F, C, D>
{
    fn from(circuit_set: &CircuitSet<F, C, D>) -> Self {
        Self(circuit_set.mt.cap.clone())
    }
}

#[cfg(test)]
mod tests {
    use crate::framework::tests::check_panic;

    use super::*;
    use plonky2::field::types::Sample;
    use plonky2::plonk::config::PoseidonGoldilocksConfig;

    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    #[test]
    fn test_circuit_set_gadgets() {
        const NUM_ELEMENTS: usize = 42;

        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        let circuit_set_target = CircuitSetTarget::build_target(&mut builder);
        let element_targets = builder.add_virtual_hashes(NUM_ELEMENTS);
        let circuit_membership_targets = element_targets
            .iter()
            .map(|t| {
                CircuitSetTarget::check_circuit_digest_membership::<F, C, D>(
                    &mut builder,
                    &circuit_set_target,
                    t,
                    NUM_ELEMENTS,
                )
            })
            .collect::<Vec<_>>();
        builder.register_public_inputs(&circuit_set_target.to_targets());

        let circuit = builder.build::<C>();

        let elements = (0..NUM_ELEMENTS)
            .map(|_| {
                let hash_input = vec![F::rand(); 4];
                <C as GenericConfig<D>>::Hasher::hash_no_pad(hash_input.as_slice())
            })
            .collect::<Vec<_>>();

        let circuit_set = CircuitSet::<F, C, D>::build_circuit_set(elements);

        let circuit_set_digest = CircuitSetDigest::<F, C, D>::from(&circuit_set);

        let prove_circuit = |circuit_set: &CircuitSet<F, C, D>| {
            let mut pw = PartialWitness::<F>::new();
            let elements = circuit_set.circuit_digests_to_leaf_indexes.keys();
            circuit_set_target.set_target(&mut pw, &circuit_set_digest);
            element_targets
                .iter()
                .zip(circuit_membership_targets.iter().zip(elements))
                .for_each(|(&el_t, (membership_t, el))| {
                    let el = HashOut::from_vec(el.clone());
                    pw.set_hash_target(el_t, el);
                    circuit_set
                        .set_circuit_membership_target(&mut pw, membership_t, el)
                        .unwrap()
                });

            circuit.prove(pw)
        };

        let proof = prove_circuit(&circuit_set).unwrap();

        assert_eq!(&proof.public_inputs, &circuit_set_digest.flatten());

        circuit.verify(proof).unwrap();

        let elements = (0..NUM_ELEMENTS)
            .map(|_| {
                let hash_input = vec![F::rand(); 4];
                <C as GenericConfig<D>>::Hasher::hash_no_pad(hash_input.as_slice())
            })
            .collect::<Vec<_>>();

        let wrong_circuit_set = CircuitSet::<F, C, D>::build_circuit_set(elements);

        check_panic!(
            || prove_circuit(&wrong_circuit_set).unwrap(),
            "circuit set membership didn't fail when employing wrong circuit set"
        );
    }

    #[test]
    fn test_target_serialization() {
        const NUM_ELEMENTS: usize = 42;

        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        let circuit_set_target = CircuitSetTarget::build_target(&mut builder);
        let element_targets = builder.add_virtual_hashes(NUM_ELEMENTS);
        let circuit_membership_targets = element_targets
            .iter()
            .map(|t| {
                CircuitSetTarget::check_circuit_digest_membership::<F, C, D>(
                    &mut builder,
                    &circuit_set_target,
                    t,
                    NUM_ELEMENTS,
                )
            })
            .collect::<Vec<_>>();

        // test serialization of `CircuitSetTarget`
        let encoded = bincode::serialize(&circuit_set_target).unwrap();
        let decoded_target: CircuitSetTarget = bincode::deserialize(&encoded).unwrap();

        assert_eq!(circuit_set_target, decoded_target);

        // test serialization of `CircuitSetMembershipTargets`
        let encoded = bincode::serialize(&circuit_membership_targets).unwrap();
        let decoded_targets: Vec<CircuitSetMembershipTargets> =
            bincode::deserialize(&encoded).unwrap();

        assert_eq!(circuit_membership_targets, decoded_targets);
    }

    #[test]
    fn test_circuit_set_serialization() {
        const NUM_ELEMENTS: usize = 42;
        let elements = (0..NUM_ELEMENTS)
            .map(|_| {
                let hash_input = vec![F::rand(); 4];
                <C as GenericConfig<D>>::Hasher::hash_no_pad(hash_input.as_slice())
            })
            .collect::<Vec<_>>();

        let circuit_set = CircuitSet::<F, C, D>::build_circuit_set(elements);

        let circuit_set_digest = CircuitSetDigest::<F, C, D>::from(&circuit_set);

        // test serialization of `CircuitSet`
        let encoded = bincode::serialize(&circuit_set).unwrap();
        let decoded_set: CircuitSet<F, C, D> = bincode::deserialize(&encoded).unwrap();

        assert_eq!(circuit_set, decoded_set);

        // test serialization of `CircuitSetDigest`
        let encoded = bincode::serialize(&circuit_set_digest).unwrap();
        let decoded_digest: CircuitSetDigest<F, C, D> = bincode::deserialize(&encoded).unwrap();

        assert_eq!(circuit_set_digest, decoded_digest);
    }
}
