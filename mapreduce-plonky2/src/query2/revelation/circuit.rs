use itertools::Itertools;
use plonky2::{
    field::{extension::Extendable, goldilocks_field::GoldilocksField},
    hash::hash_types::RichField,
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
    query2::{aggregation::AggregationPublicInputs, EWord, EWordTarget, EWORD_LEN},
    utils::{
        convert_u8_targets_to_u32, greater_than, greater_than_or_equal_to, less_than_or_equal_to,
    },
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
                let eq = b.not(neq);
                let maybe_greater_than = b.or(is_greater_than, gt);
                let maybe_greater_than = b.or(maybe_greater_than, eq);
                let new_lesser_than = b.not(maybe_greater_than);
                b.or(is_lesser_than, new_lesser_than)
            },
        );
    }

    is_greater_than
}

pub struct RevelationWires {
    db_proof: Vec<Target>,
    root_proof: Vec<Target>,
    ys: Vec<EWordTarget>,
    min_block_number: Target,
    max_block_number: Target,
}

#[derive(Clone, Debug)]
pub struct RevelationCircuit<F, const L: usize> {
    pub(crate) db_proof: Vec<F>,
    pub(crate) root_proof: Vec<F>,
    pub(crate) ys: [EWord<F>; L],
    pub(crate) min_block_number: F,
    pub(crate) max_block_number: F,
}
impl<F: RichField, const L: usize> RevelationCircuit<F, L> {
    pub fn build(b: &mut CircuitBuilder<GoldilocksField, 2>) -> RevelationWires {
        let zero = b.zero();

        let db_proof_io = b.add_virtual_targets(BlockPublicInputs::<Target>::TOTAL_LEN);
        let db_proof = BlockPublicInputs::<Target>::from(db_proof_io.as_slice());
        let root_proof_io =
            b.add_virtual_targets(AggregationPublicInputs::<Target, L>::total_len());
        let root_proof = AggregationPublicInputs::<Target, L>::from(root_proof_io.as_slice());
        let ys = (0..L)
            .map(|_| b.add_virtual_target_arr::<EWORD_LEN>())
            .collect_vec();

        let min_block_number = b.add_virtual_target();
        let max_block_number = b.add_virtual_target();

        let p0 = b.curve_zero();
        let mut digests = Vec::with_capacity(L);
        for y in ys.iter() {
            let p = b.map_to_curve_point(y);
            let y_summed = y.iter().copied().reduce(|ax, x| b.add(ax, x)).unwrap();
            let y_is_zero = b.is_equal(y_summed, zero);
            digests.push(b.curve_select(y_is_zero, p0, p));
        }
        let d = b.add_curve_point(&digests);

        // Assert the roots & digests are the same
        b.connect_hashes(root_proof.root(), db_proof.root());
        b.connect_curve_points(d, root_proof.digest());

        let min_bound = b.sub(root_proof.block_number(), root_proof.range());

        // TODO: check the bit count, 32 ought to be enough?
        greater_than_or_equal_to(b, min_bound, min_block_number, 32);
        less_than_or_equal_to(b, root_proof.block_number(), max_block_number, 32);

        for i in 0..L - 1 {
            // 1 if OK, 0 else
            let cmp = greater_than_eword(b, ys[i + 1], ys[i]);

            // // 0 if OK, 1 else
            let inv_cmp = b.not(cmp);

            // mask padding, 0 if OK, 1 else
            // assume that the sum will not *exactly* cycle back to 0
            let mask = ys[i].iter().copied().reduce(|ax, x| b.add(ax, x)).unwrap();
            let r = b.mul(mask, inv_cmp.target);
            b.assert_zero(r);
        }

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
            root_proof.mapping_slot_length(),
            &ys,
            db_proof.block_header(),
        );

        RevelationWires {
            db_proof: db_proof_io,
            root_proof: root_proof_io,
            ys,
            min_block_number,
            max_block_number,
        }
    }

    pub fn assign(&self, pw: &mut PartialWitness<F>, wires: &RevelationWires) {
        pw.set_target_arr(&wires.db_proof, &self.db_proof);
        pw.set_target_arr(&wires.root_proof, &self.root_proof);
        for (i, eword) in wires.ys.iter().enumerate() {
            pw.set_target_arr(eword, self.ys[i].as_slice());
        }
        pw.set_target(wires.min_block_number, self.min_block_number);
        pw.set_target(wires.max_block_number, self.max_block_number);
    }
}
