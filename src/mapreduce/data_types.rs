#[derive(Clone)]
struct PublicInputU64(u64);

impl Data for PublicInputU64 {
    type Encoded = Target;

    fn encode<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> Target {
        let target = builder.constant(F::from_canonical_u64(self.x));
        builder.register_public_input(target);
        target
    }
}