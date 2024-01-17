use plonky2::{field::extension::Extendable, hash::hash_types::RichField, plonk::circuit_builder::CircuitBuilder, iop::target::{Target, BoolTarget}};
use plonky2_crypto::u32::arithmetic_u32::{CircuitBuilderU32, U32Target};

use super::Data;

/// An item of a data set that can be represented by a fixed-length array of field elements
// pub trait DataItem {
//     // TODO:
//     // consider making a struct that bookkeeps DataItems and their associated Targets
//     // in a HashMap or similar

//     /// An instance of DataItem must provide a function that retrieves or computes
//     /// the values that will be added to the witness
//     fn get_values<F>(&self) -> Vec<F>
//     where
//         F: RichField;

//     /// An instance of DataItem must provide a function returning a closure that creates
//     /// the targets that will added to the circuit
//     fn create_targets<F, const D: usize>(&self) -> impl Fn(&mut CircuitBuilder<F, D>) -> Vec<Target>
//     where
//         F: RichField + Extendable<D>;
    
//     fn len(&self) -> usize;
// }



/// A DataItem is an arbitrary tree whose leaves are field elements.
#[derive(Clone)]
pub enum DataItem<F: RichField> {
    Bool(F),
    U32(F),
    U64(F), 
    DataVector(Vec<DataItem<F>>),
}

impl<F> DataItem<F> {
    fn create_targets<const D: usize>(self, builder: &mut CircuitBuilder<F, D>) -> TargetItem
    where
        F: RichField + Extendable<D>
    {
        match self {
            Bool => TargetItem::Bool(builder.add_virtual_bool_target_unsafe()),
            U32 => TargetItem::U32(builder.add_virtual_u32_target()),
            U64 => TargetItem::U64(builder.add_virtual_target()),
            DataItem::DataVector(vec) => TargetItem::TargetVector(vec.iter().map(|item| item.create_targets(builder)).collect()),
        }
    }
}

impl<F> Data for DataItem<F>{}

/// A TargetItem is an arbitrary tree whose leaves are targets.
pub enum TargetItem {
    Bool(BoolTarget),
    U32(U32Target),
    U64(Target),
    TargetVector(Vec<TargetItem>),
}