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

use crate::{
    block::{empty_merkle_root, public_inputs::PublicInputs as BlockPublicInputs},
    group_hashing::CircuitBuilderGroupHashing,
    query2::aggregation::AggregationPublicInputs,
    types::{MappingKeyTarget, PackedMappingKeyTarget, MAPPING_KEY_LEN},
    utils::{greater_than_or_equal_to, less_than, less_than_or_equal_to},
};

use super::RevelationPublicInputs;

pub(crate) struct RevelationWires<const L: usize> {
    pub raw_keys: [MappingKeyTarget; L],
    pub num_entries: Target,
    pub min_block_number: Target,
    pub max_block_number: Target,
}

#[derive(Clone, Debug)]
pub(crate) struct RevelationCircuit<const L: usize> {
    pub(crate) raw_keys: [[u8; MAPPING_KEY_LEN]; L],
    pub(crate) num_entries: u8,
    pub(crate) query_min_block_number: usize,
    pub(crate) query_max_block_number: usize,
}
impl<const L: usize> RevelationCircuit<L> {
    pub fn build<const MAX_DEPTH: usize>(
        b: &mut CircuitBuilder<GoldilocksField, 2>,
        db_proof: BlockPublicInputs<Target>,
        root_proof: AggregationPublicInputs<Target>,
    ) -> RevelationWires<L> {
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
        let ys: [MappingKeyTarget; L] = create_array(|_| MappingKeyTarget::new(b));
        let packed_ids: [PackedMappingKeyTarget; L] = create_array(|i| ys[i].convert_u8_to_u32(b));
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
            digests.push(b.curve_select(should_be_included, p, p0));
        }
        let d = b.add_curve_point(&digests);

        // Assert the digest computed corresponds to all the nft ids aggregated up to now
        b.connect_curve_points(d, root_proof.digest());
        // Assert the roots of the query and the block db are the same
        b.connect_hashes(root_proof.root(), db_proof.root());
        b.connect_hashes(db_proof.init_root(), empty_root);
        b.connect_curve_points(d, root_proof.digest());
        let min_bound = b.sub(root_proof.block_number(), root_proof.range());

        let t = b._true();
        // TODO: check the bit count, 32 ought to be enough?
        let correct_min = greater_than_or_equal_to(b, min_bound, min_block_number, 32);
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
            raw_keys: ys,
            num_entries,
            min_block_number,
            max_block_number,
        }
    }

    pub fn assign(&self, pw: &mut PartialWitness<GoldilocksField>, wires: &RevelationWires<L>) {
        wires
            .raw_keys
            .iter()
            .zip(self.raw_keys.iter())
            .for_each(|(wire, bytes)| wire.assign_bytes(pw, bytes));
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
