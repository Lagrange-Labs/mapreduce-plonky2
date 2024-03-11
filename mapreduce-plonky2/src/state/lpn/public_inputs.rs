//! Intermediate node circuit of Merkle tree

use core::array;

use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOutTarget, RichField, NUM_HASH_OUT_ELTS},
    iop::target::Target,
    plonk::circuit_builder::CircuitBuilder,
};
use plonky2_crypto::u32::arithmetic_u32::U32Target;

use crate::{
    keccak::{OutputHash, PACKED_HASH_LEN},
    state::lpn::LeafWires,
};

/// The public inputs for the leaf circuit.
///
/// # Attributes
///
/// The inner attributes are, in order:
///
/// - C: Merkle root of this node represented by `H("LEAF" || node)`
/// - H: Blockchain header hash
/// - N: Block index
/// - PREV_H: Blockchain header hash of the parent block
///
/// The elements of `node` are, in order:
///
/// - A: Smart contract address
/// - C: Merkle root of the storage database
/// - S: Storage slot of the variable holding the length
/// - M: Storage slot of the mapping
#[derive(Clone, Debug)]
pub struct PublicInputs<'a, T: Clone> {
    pub(crate) proof_inputs: &'a [T],
}

impl<'a> PublicInputs<'a, Target> {
    /// Registers the public inputs into the circuit builder.
    pub fn register<F, const D: usize>(b: &mut CircuitBuilder<F, D>, wires: &LeafWires)
    where
        F: RichField + Extendable<D>,
    {
        b.register_public_inputs(&wires.root.elements);
        wires.block_header.register_as_input(b);
        b.register_public_input(wires.block_number.0);
        wires.prev_block_header.register_as_input(b);
    }

    /// Returns the root hash.
    pub fn root(&self) -> HashOutTarget {
        let data = self.root_data();
        array::from_fn(|i| data[i]).into()
    }

    /// Returns the block header hash.
    pub fn block_header(&self) -> OutputHash {
        let data = self.block_header_data();
        array::from_fn(|i| U32Target(data[i])).into()
    }

    /// Returns the block number.
    pub fn block_number(&self) -> U32Target {
        U32Target(self.block_number_data())
    }

    /// Returns the previous block header hash.
    pub fn prev_block_header(&self) -> OutputHash {
        let data = self.prev_block_header_data();
        array::from_fn(|i| U32Target(data[i])).into()
    }
}

impl<'a, T: Copy> PublicInputs<'a, T> {
    pub(crate) const C_LEN: usize = NUM_HASH_OUT_ELTS;
    pub(crate) const H_LEN: usize = PACKED_HASH_LEN;
    pub(crate) const N_LEN: usize = 1;
    pub(crate) const PREV_H_LEN: usize = PACKED_HASH_LEN;
    pub(crate) const TOTAL_LEN: usize = Self::C_LEN + Self::H_LEN + Self::N_LEN + Self::PREV_H_LEN;

    pub(crate) const C_IDX: usize = 0;
    pub(crate) const H_IDX: usize = Self::C_IDX + Self::C_LEN;
    pub(crate) const N_IDX: usize = Self::H_IDX + Self::H_LEN;
    pub(crate) const PREV_H_IDX: usize = Self::N_IDX + Self::N_LEN;

    /// Creates a representation of the public inputs from the provided slice.
    ///
    /// # Panics
    ///
    /// This function will panic if the length of the provided slice is smaller than
    /// [Self::TOTAL_LEN].
    pub fn from_slice(arr: &'a [T]) -> Self {
        assert_eq!(
            arr.len(),
            Self::TOTAL_LEN,
            "The public inputs slice of the leaf circuit must match the expected length."
        );

        Self { proof_inputs: arr }
    }

    /// Returns the elements of the node root data.
    pub fn root_data(&self) -> &[T] {
        &self.proof_inputs[Self::C_IDX..Self::C_IDX + Self::C_LEN]
    }

    /// Returns the elements of the block header data.
    pub fn block_header_data(&self) -> &[T] {
        &self.proof_inputs[Self::H_IDX..Self::H_IDX + Self::H_LEN]
    }

    /// Returns the element representation of the storage slot of the variable holding the length.
    pub fn block_number_data(&self) -> T {
        self.proof_inputs[Self::N_IDX]
    }

    /// Returns the header hash of the previous block.
    pub fn prev_block_header_data(&self) -> &[T] {
        &self.proof_inputs[Self::PREV_H_IDX..Self::PREV_H_IDX + Self::PREV_H_LEN]
    }
}

#[cfg(test)]
mod tests {
    use plonky2::{
        field::{goldilocks_field::GoldilocksField, types::Field},
        hash::{hashing::hash_n_to_hash_no_pad, poseidon::PoseidonPermutation},
    };

    use super::*;
    use crate::state::BlockLinkingPublicInputs;

    impl<'a, F: RichField> PublicInputs<'a, F> {
        /// Writes the parts of the block liking public inputs into the provided target array.
        pub fn block_linking_into_target<'b>(
            target: &mut [F; PublicInputs::<()>::TOTAL_LEN],
            pi: &'b BlockLinkingPublicInputs<'b, F>,
        ) {
            let len = 1 + pi.a().len() + pi.merkle_root().len() + pi.s().len() + pi.m().len();
            let mut node = Vec::with_capacity(len);
            node.push(F::ONE); // "LEAF"
            node.extend_from_slice(pi.a());
            node.extend_from_slice(pi.merkle_root());
            node.extend_from_slice(pi.s());
            node.extend_from_slice(pi.m());
            let root = hash_n_to_hash_no_pad::<F, PoseidonPermutation<F>>(&node);

            target[Self::C_IDX..Self::C_IDX + Self::C_LEN].copy_from_slice(&root.elements);
            target[Self::H_IDX..Self::H_IDX + Self::H_LEN].copy_from_slice(pi.block_hash());
            target[Self::N_IDX..Self::N_IDX + Self::N_LEN].copy_from_slice(pi.s());
            target[Self::PREV_H_IDX..Self::PREV_H_IDX + Self::PREV_H_LEN]
                .copy_from_slice(pi.prev_block_hash());
        }
    }

    #[test]
    fn public_inputs_data_correspond_to_block_linking_pi_structure() {
        let h = [GoldilocksField::from_canonical_u64(1); BlockLinkingPublicInputs::<()>::H_LEN];
        let n = [GoldilocksField::from_canonical_u64(2); BlockLinkingPublicInputs::<()>::N_LEN];
        let prev_h =
            [GoldilocksField::from_canonical_u64(3); BlockLinkingPublicInputs::<()>::PREV_H_LEN];
        let a = [GoldilocksField::from_canonical_u64(4); BlockLinkingPublicInputs::<()>::A_LEN];
        let d = [GoldilocksField::from_canonical_u64(5); BlockLinkingPublicInputs::<()>::D_LEN];
        let m = [GoldilocksField::from_canonical_u64(6); BlockLinkingPublicInputs::<()>::M_LEN];
        let s = [GoldilocksField::from_canonical_u64(7); BlockLinkingPublicInputs::<()>::S_LEN];
        let c = [GoldilocksField::from_canonical_u64(8); BlockLinkingPublicInputs::<()>::C_LEN];

        let mut target = [GoldilocksField::ZERO; BlockLinkingPublicInputs::<()>::TOTAL_LEN];
        BlockLinkingPublicInputs::parts_into_target(
            &mut target,
            &h,
            &n,
            &prev_h,
            &a,
            &d,
            &m,
            &s,
            &c,
        );
        let block_linking = BlockLinkingPublicInputs::from_slice(&target);

        let mut target = [GoldilocksField::ZERO; PublicInputs::<()>::TOTAL_LEN];
        PublicInputs::block_linking_into_target(&mut target, &block_linking);
        let pi = PublicInputs::from_slice(&target);

        assert_eq!(pi.block_header_data(), &h);
        assert_eq!(pi.block_number_data(), s[0]);
        assert_eq!(pi.prev_block_header_data(), &prev_h);
    }
}
