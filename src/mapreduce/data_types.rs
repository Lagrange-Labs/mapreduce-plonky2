use plonky2::{
    field::extension::Extendable, hash::hash_types::RichField,
};

use super::DataItem;

#[derive(Clone)]
pub struct PublicU64(pub u64);

impl<F, const D: usize> DataItem<F, D> for PublicU64
where
    F: RichField + Extendable<D>,
{
    fn encode(&self) -> Vec<F> {
        vec![F::from_canonical_u64(self.0)]
    }
}

struct PublicByteString(Vec<u8>);

impl<F, const D: usize> DataItem<F, D> for PublicByteString
where
    F: RichField + Extendable<D>,
{
    fn encode(&self) -> Vec<F> {
        self.0.iter().map(|b| F::from_canonical_u8(*b)).collect()
    }
}
