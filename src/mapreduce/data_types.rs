use plonky2::hash::hash_types::RichField;

use super::DataItem;

#[derive(Clone)]
pub struct PublicU64(pub u64);

impl DataItem for PublicU64
{
    fn encode<F: RichField>(&self) -> Vec<F> {
        vec![F::from_canonical_u64(self.0)]
    }

    fn len(&self) -> usize {
        1
    }
}