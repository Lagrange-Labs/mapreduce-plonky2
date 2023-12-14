use plonky2::{iop::target::Target, hash::hash_types::RichField, field::extension::Extendable, plonk::circuit_builder::CircuitBuilder};

use super::Data;

#[derive(Clone)]
pub struct PublicInputU64(pub u64);

impl Data for PublicInputU64 {
    type Encoded = Target;

    fn encode<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self::Encoded {
        let target = builder.constant(F::from_canonical_u64(self.0));
        builder.register_public_input(target);
        target
    }
}


#[derive(Clone)]
pub struct VecPublicInputU64(Vec<u64>);

impl Data for VecPublicInputU64 {
    type Encoded = Vec<Target>;

    fn encode<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self::Encoded {
        let targets: Vec<Target> = self.0.iter()
            .map(|x| builder.constant(F::from_canonical_u64(*x)))
            .collect();
        targets.iter().for_each(|target| builder.register_public_input(*target));
        targets
    }
}