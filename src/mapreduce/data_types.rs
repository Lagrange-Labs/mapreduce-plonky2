use plonky2::{
    field::extension::Extendable, hash::hash_types::RichField, iop::target::Target,
    plonk::circuit_builder::CircuitBuilder,
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

    fn decode(list: Vec<F>) -> Self {
        assert!(list.len() == 1);
        Self(F::to_canonical_u64(&list[0]))
    }

    fn allocate(&self, builder: &mut CircuitBuilder<F, D>) -> Vec<Target> {
        let cons = builder.constants(&self.encode());
        builder.register_public_inputs(&cons);
        cons
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

    fn decode(list: Vec<F>) -> Self {
        let bytes: Vec<u8> = list
            .iter()
            .map(|e| F::to_canonical_u64(e).try_into().unwrap())
            .collect();
        PublicByteString(bytes)
    }

    fn allocate(&self, builder: &mut CircuitBuilder<F, D>) -> Vec<Target> {
        let cons = builder.constants(&self.encode());
        builder.register_public_inputs(&cons);
        cons
    }
}
