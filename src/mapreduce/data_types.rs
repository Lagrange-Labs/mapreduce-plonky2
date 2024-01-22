use plonky2::{field::extension::Extendable, hash::hash_types::RichField, plonk::circuit_builder::CircuitBuilder, iop::{target::{Target, BoolTarget}, witness::{WitnessWrite, PartialWitness}}};
use plonky2_crypto::u32::{arithmetic_u32::{CircuitBuilderU32, U32Target}, witness::WitnessU32};


/// An instance of Data knows how to allocate targets for itself in CircuitBuilder and
/// set targets for itself in PartialWitness. By setting the appropriate types for
/// Value and WireTarget, atomic elements like (bool, BoolTarget) or larger structures
/// like ([u32; 8], HashTarget) can implement Data.
trait Data {
    type Value;
    type WireTarget: Clone;

    fn create_target<F: RichField + Extendable<D>, const D: usize>(builder: &mut CircuitBuilder<F, D>) -> Self::WireTarget;
    fn set_target<F: RichField>(target: Self::WireTarget, value: Self::Value, pw: &mut PartialWitness<F>);
}

#[derive(Clone)]
pub struct Bool;

impl Data for Bool {
    type Value = bool;
    type WireTarget = BoolTarget;

    fn create_target<F: RichField + Extendable<D>, const D: usize>(builder: &mut CircuitBuilder<F, D>) -> Self::WireTarget {
        builder.add_virtual_bool_target_unsafe()
    }

    fn set_target<F: RichField>(target: Self::WireTarget, value: Self::Value, pw: &mut PartialWitness<F>) {
        pw.set_bool_target(target, value)
    }
}

#[derive(Clone)]
pub struct U8;

impl Data for U8 {
    type Value = u8;
    type WireTarget = Target;

    fn create_target<F: RichField + Extendable<D>, const D: usize>(builder: &mut CircuitBuilder<F, D>) -> Self::WireTarget {
        builder.add_virtual_target()
    }

    fn set_target<F: RichField>(target: Self::WireTarget, value: Self::Value, pw: &mut PartialWitness<F>) {
        pw.set_target(target, F::from_canonical_u8(value))
    }
}

#[derive(Clone)]
pub struct U32;

impl Data for U32 {
    type Value = u32;
    type WireTarget = U32Target;

    fn create_target<F: RichField + Extendable<D>, const D: usize>(builder: &mut CircuitBuilder<F, D>) -> Self::WireTarget {
        builder.add_virtual_u32_target()
    }

    fn set_target<F: RichField>(target: Self::WireTarget, value: Self::Value, pw: &mut PartialWitness<F>) {
        pw.set_u32_target(target, value)
    }
}

#[derive(Clone)]
pub struct U64;

impl Data for U64 {
    type Value = u64;
    type WireTarget = Target;

    fn create_target<F: RichField + Extendable<D>, const D: usize>(builder: &mut CircuitBuilder<F, D>) -> Self::WireTarget {
        builder.add_virtual_target()
    }

    fn set_target<F: RichField>(target: Self::WireTarget, value: Self::Value, pw: &mut PartialWitness<F>) {
        pw.set_target(target, F::from_canonical_u64(value))
    }
}

#[derive(Clone, Debug)]
pub enum Tree<T> {
    Leaf(T),
    Node(Vec<Tree<T>>),
}

// Flattens the tree into an iterator
impl<T> IntoIterator for Tree<T> {
    type Item = T;
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        match self {
            Tree::Leaf(l) => vec![l].into_iter(),
            Tree::Node(v) => v.into_iter().flat_map(|tree| tree.into_iter()).collect::<Vec<_>>().into_iter(),
        }
    }
}


impl<T: Data> Tree<T> {
    fn create_targets<F: RichField + Extendable<D>, const D: usize>(&self, builder: &mut CircuitBuilder<F, D>) -> Tree<T::WireTarget> {
        match self {
            Tree::Leaf(_) => Tree::Leaf(T::create_target(builder)),
            Tree::Node(trees) => Tree::Node(trees.iter().map(|tree| tree.create_targets(builder)).collect()), 
        }
    }

    fn set_targets<F: RichField>(targets: Tree<T::WireTarget>, values: Tree<T::Value>, pw: &mut PartialWitness<F>) {
        targets
            .into_iter()
            .zip(values.into_iter())
            .for_each(|(t, v)| 
                T::set_target(t, v, pw)
            )
    }
}

mod test {
    use anyhow::Result;
    use plonky2::field::types::Field;
    use plonky2::iop::target::Target;
    use plonky2::iop::wire::Wire;
    use plonky2::iop::witness::PartialWitness;
    use plonky2::plonk::circuit_builder::CircuitBuilder;
    use plonky2::plonk::circuit_data::CircuitConfig;
    use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};

    use crate::mapreduce::data_types::Tree;
    use crate::mapreduce::data_types::U64;

    #[test]
    fn test_allocate_data_tree() -> Result<()> {
        let item = Tree::Leaf(U64);
        let count = Tree::Leaf(U64);
        let pair = Tree::Node(vec![item, count]);
        let items = Tree::Node(vec![pair; 10]);

        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let targets = items.create_targets(&mut builder);

        Ok(())
    }
}
