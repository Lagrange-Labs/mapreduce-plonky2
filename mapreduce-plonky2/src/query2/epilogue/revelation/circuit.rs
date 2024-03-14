use itertools::Itertools;
use plonky2::{
    field::goldilocks_field::GoldilocksField,
    iop::{
        target::{BoolTarget, Target},
        witness::PartialWitness,
    },
    plonk::circuit_builder::CircuitBuilder,
};
use plonky2_ecgfp5::gadgets::curve::CircuitBuilderEcGFp5;

use crate::{
    block::public_inputs::PublicInputs as BlockPublicInputs,
    group_hashing::CircuitBuilderGroupHashing,
    query2::epilogue::{aggregation::AggregationPublicInputs, EWordTarget, EWORD_LEN},
    utils::{greater_than, greater_than_or_equal_to, less_than_or_equal_to},
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

pub struct RevelationWires;
#[derive(Clone)]
pub struct RevelationCircuit<const L: usize>;
impl<const L: usize> RevelationCircuit<L> {
    pub fn build(
        b: &mut CircuitBuilder<GoldilocksField, 2>,
        db_proof: BlockPublicInputs<Target>,
        root_proof: AggregationPublicInputs<Target, L>,
        ys: &[EWordTarget],
    ) -> RevelationWires {
        let zero = b.zero();

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

        for i in 0..L {
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
            &ys,
            db_proof.block_header(),
        );

        RevelationWires {}
    }

    pub fn assign(&self, _: &mut PartialWitness<GoldilocksField>, _: &RevelationWires) {}
}
