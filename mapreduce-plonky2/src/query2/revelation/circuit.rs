use std::array::from_fn as create_array;

use itertools::Itertools;
use plonky2::{
    field::{goldilocks_field::GoldilocksField, types::Field},
    iop::{
        target::{BoolTarget, Target},
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::circuit_builder::CircuitBuilder,
};
use plonky2_ecgfp5::gadgets::curve::CircuitBuilderEcGFp5;

use crate::{
    block::public_inputs::PublicInputs as BlockPublicInputs,
    group_hashing::CircuitBuilderGroupHashing,
    query2::{aggregation::AggregationPublicInputs, EWordTarget},
    types::{MappingKeyTarget, PackedMappingKeyTarget, MAPPING_KEY_LEN},
    utils::{greater_than, greater_than_or_equal_to, less_than, less_than_or_equal_to},
};

use super::RevelationPublicInputs;

/// Returns true if e1 is greater than e2
fn greater_than_eword(
    b: &mut CircuitBuilder<GoldilocksField, 2>,
    e1: EWordTarget,
    e2: EWordTarget,
) -> BoolTarget {
    let gt_neqs = e1
        .iter()
        .zip(e2.iter())
        .map(|(&e1i, &e2i)| {
            let gt = greater_than(b, e1i, e2i, 32);
            let eq = b.is_equal(e1i, e2i);
            (gt, b.not(eq))
        })
        .collect_vec();
    let mut is_lesser_than = b._false();
    let mut is_greater_than = b._false();
    for (gt, neq) in gt_neqs {
        (is_greater_than, is_lesser_than) = (
            {
                // /lesser_than ∧ cmp
                let consider = b.not(is_lesser_than);
                let new_greater_than = b.and(consider, gt);
                b.or(is_greater_than, new_greater_than)
            },
            {
                // /greater_than ∧ /cmp
                let maybe_greater_than = b.or(is_greater_than, gt);
                let maybe_greater_than = b.and(maybe_greater_than, neq);
                let new_lesser_than = b.not(maybe_greater_than);
                b.or(is_lesser_than, new_lesser_than)
            },
        );
    }

    is_greater_than
}

pub struct RevelationWires<const L: usize> {
    raw_keys: [MappingKeyTarget; L],
    num_entries: Target,
}

#[derive(Clone, Debug)]
pub struct RevelationCircuit<const L: usize> {
    raw_keys: [[u8; MAPPING_KEY_LEN]; L],
    num_entries: u8,
}
impl<const L: usize> RevelationCircuit<L> {
    pub fn build(
        b: &mut CircuitBuilder<GoldilocksField, 2>,
        db_proof: BlockPublicInputs<Target>,
        root_proof: AggregationPublicInputs<Target>,
    ) -> RevelationWires<L> {
        let zero = b.zero();
        // The raw mapping keys are given as witness, we then pack them to prove they are
        // the same value inserted in the digests accross the computation graph
        // we then cast them to the query specific, i.e. NFT ID < 2^32
        // remember values are encoded using big endian and left padded
        let ys: [MappingKeyTarget; L] = create_array(|i| MappingKeyTarget::new(b));
        let packed_ids: [PackedMappingKeyTarget; L] = create_array(|i| ys[i].convert_u8_to_u32(b));
        let nft_ids = create_array(|i| packed_ids[i].last());
        // We add a witness mentionning how many entries we have in the output array
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

        // Assert the roots & digests are the same
        b.connect_hashes(root_proof.root(), db_proof.root());
        b.connect_curve_points(d, root_proof.digest());

        let min_bound = b.sub(root_proof.block_number(), root_proof.range());

        // TODO: check the bit count, 32 ought to be enough?
        greater_than_or_equal_to(b, min_bound, min_block_number, 32);
        less_than_or_equal_to(b, root_proof.block_number(), max_block_number, 32);

        RevelationPublicInputs::<Target, L>::register(
            b,
            root_proof.block_number(),
            root_proof.range(),
            &root_proof.root(),
            min_block_number,
            max_block_number,
            &root_proof.smart_contract_address(),
            &root_proof.user_address(),
            root_proof.mapping_slot(),
            &nft_ids,
            db_proof.block_header(),
        );

        RevelationWires {
            raw_keys: ys,
            num_entries,
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
    }
}
