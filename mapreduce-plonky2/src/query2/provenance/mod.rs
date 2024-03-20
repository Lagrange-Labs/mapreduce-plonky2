//! LPN State & Block DB provenance

use std::iter;

use plonky2::{
    field::extension::Extendable,
    hash::{
        hash_types::{HashOut, HashOutTarget, RichField, NUM_HASH_OUT_ELTS},
        poseidon::PoseidonHash,
    },
    iop::{
        target::{BoolTarget, Target},
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::circuit_builder::CircuitBuilder,
};

use crate::{
    array::Array,
    keccak::{OutputHash, PACKED_HASH_LEN},
    query2::epilogue::{Provenance, PublicInputs},
};

#[cfg(test)]
mod tests;

/// The witnesses of [ProvenanceCircuit].
#[derive(Debug, Clone)]
pub struct ProvenanceWires {
    /// The merkle root of the path opening.
    pub state_root: HashOutTarget,
    /// The siblings that opens to `state_root`.
    pub siblings: Vec<HashOutTarget>,
    /// The boolean flags to describe the path. `true` equals right; `false` equals left.
    pub positions: Vec<BoolTarget>,
    /// The block hash as stored in the leaf of the block db.
    pub block_hash: OutputHash,
}

/// The provenance db circuit
#[derive(Debug, Clone)]
pub struct ProvenanceCircuit<const L: usize, F: RichField> {
    state_root: HashOut<F>,
    siblings: Vec<HashOut<F>>,
    positions: Vec<bool>,
    block_hash: Array<F, PACKED_HASH_LEN>,
}

impl<const L: usize, F: RichField> ProvenanceCircuit<L, F> {
    pub fn new(
        state_root: HashOut<F>,
        siblings: Vec<HashOut<F>>,
        positions: Vec<bool>,
        block_hash: Array<F, PACKED_HASH_LEN>,
    ) -> Self {
        Self {
            state_root,
            siblings,
            positions,
            block_hash,
        }
    }

    pub fn build<const D: usize>(
        cb: &mut CircuitBuilder<F, D>,
        db_proof: &PublicInputs<Target, Provenance, L>,
    ) -> ProvenanceWires
    where
        F: Extendable<D>,
    {
        let a = db_proof.smart_contract_address();
        let x = db_proof.user_address();
        let m = db_proof.mapping_slot();
        let s = db_proof.length_slot();
        let c = db_proof.root();
        let b = db_proof.block_number();
        let b_min = db_proof.min_block_number();
        let b_max = db_proof.max_block_number();
        let r = db_proof.range();
        let digest = db_proof.digest();

        // FIXME the optimized version without the length slot is unimplemented
        // https://www.notion.so/lagrangelabs/Encoding-Specs-ccaa31d1598b4626860e26ac149705c4?pvs=4#fe2b40982352464ba39164cf4b41d301
        let state_leaf = a
            .arr
            .iter()
            .map(|t| t.0)
            .chain(iter::once(m))
            .chain(iter::once(s))
            .chain(c.elements.iter().copied())
            .collect();

        let mut state_root = cb.hash_n_to_hash_no_pad::<PoseidonHash>(state_leaf);

        // FIXME what is the depth of the merkle tree?
        let (siblings, positions): (Vec<_>, Vec<_>) = (0..L)
            .map(|_| {
                let pos = cb.add_virtual_bool_target_safe();
                let sibling = cb.add_virtual_hash();

                let mut left = HashOutTarget::from_partial(&[], cb.zero());
                let mut right = HashOutTarget::from_partial(&[], cb.zero());

                for i in 0..NUM_HASH_OUT_ELTS {
                    left.elements[i] = cb.select(pos, state_root.elements[i], sibling.elements[i]);
                    right.elements[i] = cb.select(pos, sibling.elements[i], state_root.elements[i]);
                }

                let preimage = left
                    .elements
                    .iter()
                    .chain(right.elements.iter())
                    .copied()
                    .collect();

                state_root = cb.hash_n_to_hash_no_pad::<PoseidonHash>(preimage);

                (sibling, pos)
            })
            .unzip();

        // FIXME optimized version unimplemented
        // https://www.notion.so/lagrangelabs/Encoding-Specs-ccaa31d1598b4626860e26ac149705c4?pvs=4#5e8e6f06e2554b0caee4904258cbbca2
        let block_hash = OutputHash::new(cb);
        let block_leaf = iter::once(b)
            .chain(block_hash.arr.iter().map(|a| a.0))
            .collect();
        let block_leaf_hash = cb.hash_n_to_hash_no_pad::<PoseidonHash>(block_leaf);

        let one = cb.one();
        cb.connect(r, one);

        PublicInputs::<Target, Provenance, L>::register(
            cb,
            b,
            r,
            &block_leaf_hash,
            b_min,
            b_max,
            &a,
            &x,
            m,
            s,
            &digest,
        );

        ProvenanceWires {
            state_root,
            siblings,
            positions,
            block_hash,
        }
    }

    pub fn assign(&self, pw: &mut PartialWitness<F>, wires: &ProvenanceWires) {
        wires
            .state_root
            .elements
            .iter()
            .zip(self.state_root.elements.iter())
            .for_each(|(&w, &v)| pw.set_target(w, v));

        wires
            .siblings
            .iter()
            .map(|s| s.elements.iter())
            .flatten()
            .zip(self.siblings.iter().map(|s| s.elements.iter()).flatten())
            .for_each(|(&w, &v)| pw.set_target(w, v));

        wires
            .positions
            .iter()
            .map(|p| p.target)
            .zip(self.positions.iter())
            .for_each(|(w, &v)| pw.set_target(w, F::from_bool(v)));

        wires
            .block_hash
            .arr
            .iter()
            .map(|h| h.0)
            .zip(self.block_hash.arr.iter())
            .for_each(|(w, &v)| pw.set_target(w, v));
    }
}
