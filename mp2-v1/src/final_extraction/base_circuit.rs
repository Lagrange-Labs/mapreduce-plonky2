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
    use mp2_common::{
        mpt_sequential::MPTKeyWire,
        utils::{FromBytes, Packer},
    };
    use mp2_test::{circuit::UserCircuit, utils::random_vector};
    use plonky2::{field::types::Sample, hash::hash_types::HashOut, plonk::config::GenericHashOut};
    use plonky2_ecgfp5::curve::curve::WeierstrassPoint;
    use values_extraction::public_inputs::tests::new_extraction_public_inputs;

    #[derive(Clone, Debug)]
    struct TestBaseCircuit {
        key_nibbles: Vec<u8>,
        key_ptr: usize,
        circuit: BaseCircuit,
    }

    struct TestBaseWires {
        key: MPTKeyWire,
        base: BaseWires,
    }

    impl UserCircuit<GoldilocksField, 2> for TestBaseCircuit {
        type Wires = TestBaseWires;
        fn build(c: &mut CircuitBuilder<GoldilocksField, 2>) -> Self::Wires {
            let key = MPTKeyWire::new(c);
            let block_pi = vec![];
            let contract_pi = vec![];
            let values_pi = vec![];
            let base_wires = BaseCircuit::build(c, &block_pi, &contract_pi, &values_pi);
            TestBaseWires {
                key,
                base: base_wires,
            }
        }
        fn prove(&self, pw: &mut PartialWitness<GoldilocksField>, wires: &Self::Wires) {
            wires.key.assign(
                pw,
                &self.key_nibbles.clone().try_into().unwrap(),
                self.key_ptr,
            );
            self.circuit.assign(pw, &wires.base);
        }
    }

    #[test]
    fn final_simple_value() -> Result<()> {
        let block_pi = vec![];
        let contract_pi = vec![];
        let value_h = HashOut::rand().to_bytes().pack();
        let key = random_vector(64);
        let ptr = 0;
        let dv = WeierstrassPoint::from_random_bytes()?;
        let dm = WeierstrassPoint::from_random_bytes()?;
        let n = 10;
        let value_i = new_extraction_public_inputs(&value_h, &key, ptr, &dv, &dm, n);
        Ok(())
    }
}
