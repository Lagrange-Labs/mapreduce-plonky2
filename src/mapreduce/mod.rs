mod data_types;
mod ops;
mod sum;

// /// An item of a data set that can be represented by a fixed-length array of field elements
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

// fn add_reduce_constraints_and_witnesses<F, C, const D: usize>(
//     &self,
//     inputs: &[R::Input],
//     builder: &mut CircuitBuilder<F, D>,
//     pw: &mut PartialWitness<F>,
// ) -> R::Input
// where
//     F: RichField + Extendable<D>,
//     C: Fn(&mut CircuitBuilder<F, D>, &mut PartialWitness<F>) -> M::Output,
// {
//     if inputs.len() == 1 {
//         // put neutral on the right
//         // is this *always* ok ?
//         self.reduce.add_constraints_and_witnesses::<C, F, D>(
//             &inputs[0],
//             &self.reduce.neutral()
//         )(builder, pw)
//     } else {
//         let (left_half, right_half) = inputs.split_at(inputs.len() / 2);
//         let left = self.add_reduce_constraints_and_witnesses::<C, F, D>(left_half, builder, pw);
//         let right = self.add_reduce_constraints_and_witnesses::<C, F, D>(right_half, builder, pw);
//         let out = self.reduce.add_constraints_and_witnesses::<C, F, D>(&left, &right)(builder, pw);
//         out
//     }
// }

// fn add_map_constraints_and_witnesses<F, C, const D: usize>(
//     &self,
//     inputs: &[M::Input],
//     builder: &mut CircuitBuilder<F, D>,
//     pw: &mut PartialWitness<F>,
// ) -> Vec<M::Output>
// where
//     F: RichField + Extendable<D>,
//     C: Fn(&mut CircuitBuilder<F, D>, &mut PartialWitness<F>) -> M::Output,

// {
//     inputs.iter()
//         .map(|i|
//             self.map.add_constraints_and_witnesses::<C,F,D>(i)(builder, pw)
//         ).collect()
// }

// fn add_constraints_and_witnesses<F, C, const D: usize>(
//     &self,
//     inputs: &[M::Input],
//     builder: &mut CircuitBuilder<F, D>,
//     pw: &mut PartialWitness<F>,
// ) -> R::Input
// where
//     F: RichField + Extendable<D>,
//     C: Fn(&mut CircuitBuilder<F, D>, &mut PartialWitness<F>) -> M::Output,
// {
//     let map_outs: Vec<M::Output> = inputs
//         .iter()
//         .map(|i|
//             self.map.add_constraints_and_witnesses::<C, F, D>(i)(builder, pw)
//         ).collect();

//     self.add_reduce_constraints_and_witnesses(&map_outs, builder, pw)
// }
