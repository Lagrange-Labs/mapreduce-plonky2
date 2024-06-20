use plonky2::{
    field::{goldilocks_field::GoldilocksField, types::Field},
    iop::{target::Target, witness::PartialWitness},
    plonk::circuit_builder::CircuitBuilder,
};

use crate::{contract_extraction, values_extraction};

#[derive(Debug, Clone)]
pub struct BaseCircuit {}

#[derive(Debug, Clone)]
pub struct BaseWires {}

impl BaseCircuit {
    fn build(
        b: &mut CircuitBuilder<GoldilocksField, 2>,
        block_pi: &[Target],
        contract_pi: &[Target],
        value_pi: &[Target],
    ) -> BaseWires {
        // TODO: homogeinize the public inputs structs
        let value_pi = values_extraction::PublicInputs::<Target>::new(value_pi);
        //let contract_pi = contract_extraction::PublicInputs::<Target>::from_slice(contract_pi);

        let minus_one = b.constant(GoldilocksField::NEG_ONE);
        b.connect(value_pi.mpt_key().pointer, minus_one);
        BaseWires {}
    }

    fn assign(&self, pw: &mut PartialWitness<GoldilocksField>, wires: &BaseWires) {}
}

#[cfg(test)]
mod test {
    use super::*;
    use anyhow::Result;
    use contract_extraction::build_circuits_params;
    use mp2_common::{
        mpt_sequential::MPTKeyWire,
        types::GFp,
        utils::{FromBytes, IntTargetWriter, Packer},
    };
    use mp2_test::{
        circuit::{run_circuit, setup_circuit, UserCircuit},
        utils::random_vector,
    };
    use plonky2::{
        field::types::Sample,
        hash::hash_types::HashOut,
        iop::witness::WitnessWrite,
        plonk::config::{GenericConfig, GenericHashOut, PoseidonGoldilocksConfig},
    };
    use plonky2_ecgfp5::curve::curve::WeierstrassPoint;
    use std::array::from_fn as create_array;
    use values_extraction::public_inputs::tests::new_extraction_public_inputs;

    pub const D: usize = 2;
    pub type C = PoseidonGoldilocksConfig;
    pub type F = <C as GenericConfig<D>>::F;

    #[derive(Clone, Debug)]
    struct TestBaseCircuit {
        values_pi: Vec<GFp>,
        circuit: BaseCircuit,
    }

    struct TestBaseWires {
        values_pi: Vec<Target>,
        base: BaseWires,
    }

    impl UserCircuit<GoldilocksField, 2> for TestBaseCircuit {
        type Wires = TestBaseWires;
        fn build(c: &mut CircuitBuilder<GoldilocksField, 2>) -> Self::Wires {
            let block_pi = vec![];
            let contract_pi = vec![];
            let values_pi =
                c.add_virtual_targets(values_extraction::PublicInputs::<Target>::TOTAL_LEN);
            let base_wires = BaseCircuit::build(c, &block_pi, &contract_pi, &values_pi);
            TestBaseWires {
                base: base_wires,
                values_pi,
            }
        }
        fn prove(&self, pw: &mut PartialWitness<GoldilocksField>, wires: &Self::Wires) {
            pw.set_target_arr(&wires.values_pi, self.values_pi.as_ref());
            self.circuit.assign(pw, &wires.base);
        }
    }

    #[test]
    fn final_simple_value() -> Result<()> {
        //let block_pi = vec![];
        //let contract_pi = vec![];

        let value_h = HashOut::<GFp>::rand().to_bytes().pack();
        let key = random_vector(64);
        let ptr = usize::max_value();
        let dv = WeierstrassPoint::from_random_bytes()?;
        let dm = WeierstrassPoint::from_random_bytes()?;
        let n = 10;
        let values_pi = new_extraction_public_inputs(&value_h, &key, ptr, &dv, &dm, n);

        let test_circuit = TestBaseCircuit {
            values_pi,
            circuit: BaseCircuit {},
        };
        run_circuit::<F, D, C, _>(test_circuit);
        Ok(())
    }
}
