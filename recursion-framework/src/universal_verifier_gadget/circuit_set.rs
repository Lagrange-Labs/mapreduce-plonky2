use std::collections::HashMap;

use plonky2::{field::extension::Extendable, hash::{hash_types::{HashOutTarget, MerkleCapTarget, RichField}, 
    merkle_proofs::MerkleProofTarget, merkle_tree::{MerkleCap, MerkleTree}}, iop::{target::{BoolTarget, Target}, witness::{PartialWitness, WitnessWrite}}, 
    plonk::{circuit_builder::CircuitBuilder, circuit_data::{CircuitConfig, VerifierCircuitTarget}, config::{AlgebraicHasher, GenericConfig, GenericHashOut, Hasher}}, 
    util::log2_ceil
};

use super::CIRCUIT_SET_CAP_HEIGHT;
use anyhow::{Result, Error};

// get the list of targets composing a `MerkleCapTarget`
pub(crate) fn merkle_cap_to_targets(merkle_cap: &MerkleCapTarget) -> Vec<Target> {
    merkle_cap.0.iter().flat_map(|h| h.elements).collect()
}

// Set of targets employed to prove that the circuit employed to generate a proof being aggregated
// by `MergeCircuit` belongs to the set of circuits that can be aggregated by the `MergeCircuit`
// itself
#[derive(Debug)]
pub(crate) struct CircuitSetMembershipTargets {
    merkle_proof_target: MerkleProofTarget,
    leaf_index_bits: Vec<BoolTarget>,
}

// The target employed to represent the set of circuits that can be aggregated by the `MergeCircuit`
pub(crate) struct CircuitSetTarget(MerkleCapTarget);

impl CircuitSetTarget {
    pub(crate) fn build_target<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        Self(builder.add_virtual_cap(CIRCUIT_SET_CAP_HEIGHT))
    }

    pub(crate) fn to_targets(&self) -> Vec<Target> {
        merkle_cap_to_targets(&self.0)
    }

    // Enforce that `circuit_digest_target` is a leaf in the merkle-tree
    // with root `circuit_set_target`
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
        assert!(full_tree_height >= CIRCUIT_SET_CAP_HEIGHT, "CIRCUIT_SET_CAP_HEIGHT={} is too high: it should be no greater than ceil(log2(num_leaves)) = {}", CIRCUIT_SET_CAP_HEIGHT, full_tree_height);
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
}


pub(crate) fn num_targets_for_circuit_set<F: RichField + Extendable<D>, const D: usize>(
    config: CircuitConfig,
) -> usize {
    let mut builder = CircuitBuilder::<F, D>::new(config);
    let target = CircuitSetTarget::build_target(&mut builder);
    target.to_targets().len()
}

// check in the circuit that the circuit digest in `verifier_data` is correctly computed from
// `verifier_data.constants_sigmas_cap` and the degree bits of the circuit
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

// Data structure employed by the recursion framework to store and manage the set of circuits that can
// be verified with the universal verifier
pub(crate) struct CircuitSet<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize> {
    circuit_digests_to_leaf_indexes: HashMap<Vec<F>, usize>,
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

    // set a `CircuitSetMembershipTargets` to prove membership of `circuit_digest` in the set of
    // circuits that can be aggregated by the `MergeCircuit`
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
}

// A short representation (e.g., a digest) of the set of circuits that can be aggregated by
// `MergeCircuit`; this should represent values assignable to a `CircuitSetTarget`
#[derive(Debug, Clone)]
pub(crate) struct CircuitSetDigest<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
>(MerkleCap<F, C::Hasher>);

impl<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>
    CircuitSetDigest<F, C, D>
where
    C::Hasher: AlgebraicHasher<F>,
{
    pub(crate) fn set_circuit_set_target(
        &self,
        pw: &mut PartialWitness<F>,
        target: &CircuitSetTarget,
    ) {
        pw.set_cap_target(&target.0, &self.0);
    }

    pub(crate) fn flatten(&self) -> Vec<F> {
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