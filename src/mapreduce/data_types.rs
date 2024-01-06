use plonky2::{
    field::extension::Extendable, hash::hash_types::RichField, iop::target::Target,
    plonk::circuit_builder::CircuitBuilder,
};

use super::DataItem;

#[derive(Clone)]
pub struct PublicU64(pub u64);

impl DataItem for PublicU64 {
    fn encode<F: RichField + Extendable<D>, const D: usize>(&self) -> Vec<F> {
        vec![F::from_canonical_u64(self.0)]
    }

    fn decode<F: RichField + Extendable<D>, const D: usize>(list: Vec<F>) -> Self {
        assert!(list.len() == 1);
        Self(F::to_canonical_u64(&list[0]))
    }

    fn allocate<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> Vec<Target> {
        builder.constants(&self.encode())
    }
}
