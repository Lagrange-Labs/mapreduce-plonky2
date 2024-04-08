use std::array::from_fn as create_array;

use itertools::Itertools;
use plonky2::{
    field::{goldilocks_field::GoldilocksField, types::Field},
    hash::hash_types::HashOutTarget,
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::circuit_builder::CircuitBuilder,
};
use plonky2_ecgfp5::gadgets::curve::CircuitBuilderEcGFp5;

use serde::{Deserialize, Serialize};

use crate::{
    block::{empty_merkle_root, public_inputs::PublicInputs as BlockDBPublicInputs},
    group_hashing::CircuitBuilderGroupHashing,
    query2::block::BlockPublicInputs as BlockQueryPublicInputs,
    types::{PackedMappingKeyTarget, PACKED_MAPPING_KEY_LEN},
    utils::{greater_than_or_equal_to, less_than, less_than_or_equal_to},
};

use super::RevelationPublicInputs;

#[derive(Serialize, Deserialize)]
pub(crate) struct RevelationWires<const L: usize> {
    // poor support of const generics arrays in serde - use that external crate
    #[serde(with = "serde_arrays")]
    pub raw_keys: [PackedMappingKeyTarget; L],
    pub num_entries: Target,
    pub min_block_number: Target,
    pub max_block_number: Target,
}

#[derive(Clone, Debug)]
pub struct RevelationCircuit<const L: usize> {
    pub(crate) packed_keys: [[u32; PACKED_MAPPING_KEY_LEN]; L],
    pub(crate) num_entries: u8,
    pub(crate) query_min_block_number: usize,
    pub(crate) query_max_block_number: usize,
}
impl<const L: usize> RevelationCircuit<L> {
    pub fn build<const MAX_DEPTH: usize>(
        b: &mut CircuitBuilder<GoldilocksField, 2>,
        db_proof: BlockDBPublicInputs<Target>,
        root_proof: BlockQueryPublicInputs<Target>,
    ) -> RevelationWires<L> {
        let t = b._true();
        // Create the empty root constant matching the given MAX_DEPTH of the Poseidon storage tree
        let empty_root = HashOutTarget::from_vec(
            empty_merkle_root::<GoldilocksField, 2, MAX_DEPTH>()
                .elements
                .into_iter()
                .map(|x| b.constant(x))
                .collect_vec(),
        );

        // The raw mapping keys are given as witness, we then pack them to prove they are
        // the same value inserted in the digests accross the computation graph
        // we then cast them to the query specific, i.e. NFT ID < 2^32
        // remember values are encoded using big endian and left padded
        let packed_ids: [PackedMappingKeyTarget; L] =
            create_array(|_| PackedMappingKeyTarget::new(b));
        let nft_ids = create_array(|i| packed_ids[i].last());
        // We add a witness mentionning how many entries we have in the output array
        // The reason we have this witness is because "0" can be a valid NFT ID so
        // we can not use the "0" value to signal "an empty value".
        // Given that we trust already the prover to correctly prove inclusion of the right
        // number of entries (i.e. we don't enforce the LIMIT/OFFSET SQL ops yet), it doesn't
        // introduce any additional assumption in the circuit.
        let num_entries = b.add_virtual_target();

        let min_block_number = b.add_virtual_target();
        let max_block_number = b.add_virtual_target();

        let p0 = b.curve_zero();
        let mut digests = Vec::with_capacity(L);
        for i in 0..L {
            let p = b.map_to_curve_point(&packed_ids[i].to_targets().arr);
            let it = b.constant(GoldilocksField::from_canonical_usize(i));
            let should_be_included = less_than(b, it, num_entries, 8);
            // also check if values are unique, i.e. we expect values in sorted order so we just check
            // diff is positive.
            if i > 0 {
                let previous = nft_ids[i - 1];
                let curr = nft_ids[i];
                let ordered = less_than(b, previous.0, curr.0, 32);
                let should_be_ordered = b.select(should_be_included, ordered.target, t.target);
                b.connect(should_be_ordered, t.target);
            }
            digests.push(b.curve_select(should_be_included, p, p0));
        }
        let d = b.add_curve_point(&digests);

        // Assert the digest computed corresponds to all the nft ids aggregated up to now
        b.connect_curve_points(d, root_proof.digest());
        // Assert the roots of the query and the block db are the same
        b.connect_hashes(root_proof.root(), db_proof.root());
        b.connect_hashes(db_proof.init_root(), empty_root);

        let min_bound = b.sub(root_proof.block_number(), root_proof.range());

        // Comment from tests:
        // query_min >= min_block during aggregation
        // query_max <= max_block during aggregation

        // It seems that if min_block == query_min and max_block == query_max,
        // then subtracting the range(interpreted as the number of blocks)
        // from the max_block goes 1 below the min_block_number.

        // Add 1 to the min_bound
        let one = b.one();
        let min_bound_plus_1 = b.add(min_bound, one);

        let t = b._true();
        // TODO: check the bit count, 32 ought to be enough?
        let correct_min = greater_than_or_equal_to(b, min_bound_plus_1, min_block_number, 32);
        let correct_max = less_than_or_equal_to(b, root_proof.block_number(), max_block_number, 32);
        b.connect(correct_min.target, t.target);
        b.connect(correct_max.target, t.target);

        // transform the generic mapping value into a packed user address
        // 32 bytes -> 8 u32, 20 bytes -> 5 u32
        // Just take the last 5 u32 !
        // (values are always left_pad32(big_endian(value)) in the leaf LPN)
        let user_address_packed = root_proof
            .user_address()
            .take_last::<GoldilocksField, 2, 5>();

        RevelationPublicInputs::<Target, L>::register(
            b,
            root_proof.block_number(),
            root_proof.range(),
            min_block_number,
            max_block_number,
            &root_proof.smart_contract_address(),
            &user_address_packed,
            root_proof.mapping_slot(),
            root_proof.mapping_slot_length(),
            &nft_ids,
            db_proof.original_block_header(),
        );

        RevelationWires {
            raw_keys: packed_ids,
            num_entries,
            min_block_number,
            max_block_number,
        }
    }

    pub fn assign(&self, pw: &mut PartialWitness<GoldilocksField>, wires: &RevelationWires<L>) {
        wires
            .raw_keys
            .iter()
            .zip(self.packed_keys.iter())
            .for_each(|(wire, packed)| wire.assign_from_data(pw, packed));
        pw.set_target(
            wires.num_entries,
            GoldilocksField::from_canonical_u8(self.num_entries),
        );
        pw.set_target(
            wires.min_block_number,
            GoldilocksField::from_canonical_usize(self.query_min_block_number),
        );
        pw.set_target(
            wires.max_block_number,
            GoldilocksField::from_canonical_usize(self.query_max_block_number),
        );
    }
}
