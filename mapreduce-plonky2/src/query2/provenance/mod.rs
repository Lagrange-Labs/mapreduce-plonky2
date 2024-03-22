//! LPN State & Block DB provenance

use std::iter;

use plonky2::{
    field::{goldilocks_field::GoldilocksField, types::Field},
    hash::{
        hash_types::{HashOut, HashOutTarget, RichField},
        merkle_proofs::MerkleProofTarget,
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
    query2::storage::public_inputs::PublicInputs as StorageInputs,
    query2::{Address, AddressTarget},
};

use super::aggregation::AggregationPublicInputs;

#[cfg(test)]
pub(crate) mod tests;

/// The witnesses of [ProvenanceCircuit].
#[derive(Debug, Clone)]
pub struct ProvenanceWires {
    /// Smart contract address (unpacked)
    pub smart_contract_address: AddressTarget,
    /// Mapping of the storage slot
    pub mapping_slot: Target,
    /// Length of the storage slot
    pub length_slot: Target,
    /// Block number
    pub block_number: Target,
    /// Block number minimum range
    pub block_number_min: Target,
    /// Block number maximum range
    pub block_number_max: Target,
    /// Aggregated range
    pub range: Target,
    /// The merkle root of the opening.
    pub state_root: HashOutTarget,
    /// The siblings that opens to `state_root`.
    pub siblings: MerkleProofTarget,
    /// The boolean flags to describe the path. `true` equals right; `false` equals left.
    pub positions: Vec<BoolTarget>,
    /// The block hash as stored in the leaf of the block db.
    pub block_hash: OutputHash,
}

/// The provenance db circuit
///
/// # Arguments
///
/// - [StorageInputs]
///
/// # Witnesses
///
/// - `A` Smart contract address
/// - `M` Mapping slot
/// - `S` Length of the slot
/// - `B` Block number
/// - `B_MIN` Minimum block number
/// - `B_MAX` Maximum block number
/// - `R` Aggregated range
/// - `Z` State root of the leaf opening
/// - `P` Siblings path from leaf hash to `Z`
/// - `T` Little-endian positions flags for the merkle opening path
/// - `Y` Aggregated storage digest
/// - `H` Block hash as stored in the leaf of the block db
///
/// # Public Inputs
///
/// - `B` Block number
/// - `R` Aggregated range
/// - `C` Block leaf hash
/// - `B_MIN` Minimum block number
/// - `B_MAX` Maximum block number
/// - `A` Smart contract address
/// - `X` User/Owner address
/// - `M` Mapping slot
/// - `S` Length of the slot
/// - `Y` Aggregated storage digest
///
/// # Circuit
///
/// 1. `state_leaf := Poseidon(A || M || S || C)`
/// 2. Open the Merkle path `(P, T)` from `state_leaf` to `Z`
/// 3. `C := Poseidon(B || H || Z)`
/// 4. `R == 1`
#[derive(Debug, Clone)]
pub struct ProvenanceCircuit<const DEPTH: usize, const L: usize, F: RichField> {
    smart_contract_address: Address<F>,
    mapping_slot: F,
    length_slot: F,
    block_number: F,
    block_number_min: F,
    block_number_max: F,
    state_root: HashOut<F>,
    siblings: Vec<HashOut<F>>,
    positions: Vec<bool>,
    block_hash: Array<F, PACKED_HASH_LEN>,
}

impl<const DEPTH: usize, const L: usize, F: RichField> ProvenanceCircuit<DEPTH, L, F> {
    /// Creates a new instance of the provenance circuit with the provided witness values.
    pub fn new(
        smart_contract_address: Address<F>,
        mapping_slot: F,
        length_slot: F,
        block_number: F,
        block_number_min: F,
        block_number_max: F,
        state_root: HashOut<F>,
        siblings: Vec<HashOut<F>>,
        positions: Vec<bool>,
        block_hash: Array<F, PACKED_HASH_LEN>,
    ) -> Self {
        Self {
            smart_contract_address,
            mapping_slot,
            length_slot,
            block_number,
            block_number_min,
            block_number_max,
            state_root,
            siblings,
            positions,
            block_hash,
        }
    }

    /// Builds the circuit wires with virtual targets.
    pub fn build(
        cb: &mut CircuitBuilder<GoldilocksField, 2>,
        storage_proof: &StorageInputs<Target>,
    ) -> ProvenanceWires {
        let x = storage_proof.owner();
        let c = storage_proof.root();
        let digest = storage_proof.digest();

        let a = AddressTarget::new(cb);
        let m = cb.add_virtual_target();
        let s = cb.add_virtual_target();
        let b = cb.add_virtual_target();
        let b_min = cb.add_virtual_target();
        let b_max = cb.add_virtual_target();
        let r = cb.constant(GoldilocksField::ONE);

        let (siblings, positions): (Vec<_>, Vec<_>) = (0..DEPTH)
            .map(|_| {
                let pos = cb.add_virtual_bool_target_safe();
                let sibling = cb.add_virtual_hash();

                (sibling, pos)
            })
            .unzip();
        let siblings = MerkleProofTarget { siblings };

        // FIXME the optimized version without the length slot is unimplemented
        // https://www.notion.so/lagrangelabs/Encoding-Specs-ccaa31d1598b4626860e26ac149705c4?pvs=4#fe2b40982352464ba39164cf4b41d301
        let state_leaf = a
            .arr
            .iter()
            .copied()
            .chain(iter::once(m))
            .chain(iter::once(s))
            .chain(c.elements.iter().copied())
            .collect();

        let state_root = cb.add_virtual_hash();
        cb.verify_merkle_proof::<PoseidonHash>(
            state_leaf,
            positions.as_slice(),
            state_root,
            &siblings,
        );

        // FIXME optimized version unimplemented
        // https://www.notion.so/lagrangelabs/Encoding-Specs-ccaa31d1598b4626860e26ac149705c4?pvs=4#5e8e6f06e2554b0caee4904258cbbca2
        let block_hash = OutputHash::new(cb);
        let block_leaf = iter::once(b)
            .chain(block_hash.arr.iter().map(|a| a.0))
            .chain(state_root.elements.iter().copied())
            .collect();
        let block_leaf_hash = cb.hash_n_to_hash_no_pad::<PoseidonHash>(block_leaf);

        AggregationPublicInputs::<_, L>::register(cb, b, r, &block_leaf_hash, &a, &x, m, s, digest);

        ProvenanceWires {
            smart_contract_address: a,
            mapping_slot: m,
            length_slot: s,
            block_number: b,
            block_number_min: b_min,
            block_number_max: b_max,
            range: r,
            state_root,
            siblings,
            positions,
            block_hash,
        }
    }

    /// Assigns the instance witness values to the provided wires.
    pub fn assign(&self, pw: &mut PartialWitness<F>, wires: &ProvenanceWires) {
        wires
            .smart_contract_address
            .arr
            .iter()
            .zip(self.smart_contract_address.arr.iter())
            .for_each(|(&w, &v)| pw.set_target(w, v));

        pw.set_target(wires.mapping_slot, self.mapping_slot);
        pw.set_target(wires.length_slot, self.length_slot);
        pw.set_target(wires.block_number, self.block_number);
        pw.set_target(wires.block_number_min, self.block_number_min);
        pw.set_target(wires.block_number_max, self.block_number_max);

        wires
            .state_root
            .elements
            .iter()
            .zip(self.state_root.elements.iter())
            .for_each(|(&w, &v)| pw.set_target(w, v));

        wires
            .siblings
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
