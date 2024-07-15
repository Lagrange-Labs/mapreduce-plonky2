use std::{
    iter::{once, repeat},
    mem::variant_count,
};

use ethers::types::U256;
use itertools::Itertools;
use mp2_common::{
    array::{Targetable, ToField},
    poseidon::{empty_poseidon_hash, H},
    types::CBuilder,
    u256::UInt256Target,
    utils::{ToFields, ToTargets},
    CHasher, F,
};
use plonky2::{
    field::types::{Field, PrimeField64},
    hash::{
        hash_types::{HashOut, HashOutTarget, RichField},
        hashing::hash_n_to_hash_no_pad,
    },
    iop::target::Target,
    plonk::config::{GenericHashOut, Hasher},
    util::log2_ceil,
};

pub enum Identifiers {
    Extraction(Extraction),
    Operations(Operation),
    Output(Output),
    AggregationOperations(AggregationOperation),
    // TODO
}

impl Identifiers {
    pub fn offset(&self) -> usize {
        match self {
            &Identifiers::Extraction(_) => 0,
            &Identifiers::Operations(_) => {
                Identifiers::Extraction(Extraction::default()).offset()
                    + variant_count::<Extraction>()
            }
            &Identifiers::Output(_) => {
                Identifiers::Operations(Operation::default()).offset()
                    + variant_count::<Operation>()
            }
            &Identifiers::AggregationOperations(_) => {
                Identifiers::Output(Output::default()).offset() + variant_count::<Output>()
            }
        }
    }
    pub fn position(&self) -> usize {
        let offset = self.offset();
        offset
            + match self {
                Identifiers::Extraction(e) => *e as usize,
                Identifiers::Operations(o) => *o as usize,
                Identifiers::Output(o) => *o as usize,
                Identifiers::AggregationOperations(ao) => *ao as usize,
            }
    }
    pub(crate) fn prefix_id_hash(&self, elements: Vec<F>) -> HashOut<F> {
        let inputs: Vec<_> = once(self.to_field()).chain(elements).collect();
        H::hash_no_pad(&inputs)
    }
    pub(crate) fn prefix_id_hash_circuit(
        &self,
        b: &mut CBuilder,
        elements: Vec<Target>,
    ) -> HashOutTarget {
        let inputs = once(b.constant(self.to_field())).chain(elements).collect();
        b.hash_n_to_hash_no_pad::<CHasher>(inputs)
    }
}

impl<F: RichField> ToField<F> for Identifiers {
    fn to_field(&self) -> F {
        F::from_canonical_usize(self.position())
    }
}

#[derive(Clone, Debug, Copy, Default)]
pub enum Extraction {
    #[default]
    Column,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Default)]
/// Set of constant identifiers employed in the
/// computational hash, which is a compact representation
/// of the query being proven by the query circuits
pub enum Operation {
    #[default]
    AddOp,
    SubOp,
    MulOp,
    DivOp,
    ModOp,
    LessThanOp,
    EqOp,
    NeOp,
    GreaterThanOp,
    LessThanOrEqOp,
    GreaterThanOrEqOp,
    AndOp,
    OrOp,
    NotOp,
    XorOp,
}

impl<F: RichField> ToField<F> for Operation {
    fn to_field(&self) -> F {
        F::from_canonical_usize(self.index())
    }
}

type HashPermutation = <CHasher as Hasher<F>>::Permutation;

impl Operation {
    pub fn index(&self) -> usize {
        *self as usize
    }

    pub fn offset() -> usize {
        Identifiers::Operations(Self::default()).offset()
    }
    pub(crate) fn basic_operation_hash(
        input_hash: &[HashOut<F>],
        constant_operand: U256,
        placeholder_ids: [F; 2],
        first_selector: F,
        second_selector: F,
        op_selector: F,
    ) -> HashOut<F> {
        let constant_operand_hash =
            hash_n_to_hash_no_pad::<_, HashPermutation>(&constant_operand.to_fields());
        let first_placeholder_hash =
            hash_n_to_hash_no_pad::<_, HashPermutation>(&[placeholder_ids[0]]);
        let second_placeholder_hash =
            hash_n_to_hash_no_pad::<_, HashPermutation>(&[placeholder_ids[1]]);
        let num_inputs = input_hash.len();
        let first_hash = match first_selector.to_canonical_u64() as usize {
            a if a < num_inputs => input_hash[a],
            a if a == num_inputs => constant_operand_hash,
            a if a == num_inputs + 1 => first_placeholder_hash,
            a if a == num_inputs + 2 => second_placeholder_hash,
            a => panic!(
                "sampled second input selector too big: max {}, sampled {}",
                num_inputs + 2,
                a
            ),
        };
        let second_hash = match second_selector.to_canonical_u64() as usize {
            a if a < num_inputs => input_hash[a],
            a if a == num_inputs => constant_operand_hash,
            a if a == num_inputs + 1 => first_placeholder_hash,
            a if a == num_inputs + 2 => second_placeholder_hash,
            a => panic!(
                "sampled second input selector too big: max {}, sampled {}",
                num_inputs + 2,
                a
            ),
        };
        let op_hash_identifier = F::from_canonical_usize(Operation::offset()) + op_selector;
        hash_n_to_hash_no_pad::<_, HashPermutation>(
            &once(op_hash_identifier)
                .chain(first_hash.to_vec())
                .chain(second_hash.to_vec())
                .collect_vec(),
        )
    }

    pub(crate) fn basic_operation_hash_circuit(
        b: &mut CBuilder,
        input_hash: &[HashOutTarget],
        constant_operand: &UInt256Target,
        placeholder_ids: [Target; 2],
        first_selector: Target,
        second_selector: Target,
        op_selector: Target,
    ) -> HashOutTarget {
        let constant_operand_hash =
            b.hash_n_to_hash_no_pad::<CHasher>(constant_operand.to_targets());
        let first_placeholder_id_hash =
            b.hash_n_to_hash_no_pad::<CHasher>(vec![placeholder_ids[0]]);
        let second_placeholder_id_hash =
            b.hash_n_to_hash_no_pad::<CHasher>(vec![placeholder_ids[1]]);
        // Compute the vector of computational hashes associated to each entry in `possible_input_values`.
        // The vector is padded to the next power of 2 to safely use `random_access_hash` gadget
        let pad_len = 1 << log2_ceil(input_hash.len() + 3); // length of the padded vector of computational hashes
        let empty_poseidon_hash = b.constant_hash(*empty_poseidon_hash()); // employed for padding
        let possible_input_hash = input_hash
            .iter()
            .chain(
                [
                    constant_operand_hash,
                    first_placeholder_id_hash,
                    second_placeholder_id_hash,
                ]
                .iter(),
            )
            .cloned()
            .chain(repeat(empty_poseidon_hash))
            .take(pad_len)
            .collect_vec();
        assert!(
            possible_input_hash.len() <= 64,
            "random access gadget works only for arrays with at most 64 elements"
        );
        let first_input_hash = b.random_access_hash(first_selector, possible_input_hash.clone());
        let second_input_hash = b.random_access_hash(second_selector, possible_input_hash);
        let op_offset = b.constant(F::from_canonical_usize(Operation::offset()));
        let operation_identifier = b.add(op_offset, op_selector);
        b.hash_n_to_hash_no_pad::<CHasher>(
            // this should be an identifier accross all identifiers
            once(operation_identifier)
                .chain(first_input_hash.to_targets())
                .chain(second_input_hash.to_targets())
                .collect(),
        )
    }
}

#[derive(Clone, Debug, Copy, Default)]
pub enum Output {
    #[default]
    Aggregation,
    NoAggregation,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Default)]
pub enum AggregationOperation {
    #[default]
    IdOp,
    SumOp,
}
