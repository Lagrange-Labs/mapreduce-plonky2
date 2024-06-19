//! Circuits for v1 of Lagrange Proof Network (LPN)

// Add this to allow generic const expressions, e.g. `PAD_LEN(NODE_LEN)`.
#![feature(generic_const_exprs)]

use mp2_common::mpt_sequential::PAD_LEN;

pub const MAX_BRANCH_NODE_LEN: usize = 532;
pub const MAX_BRANCH_NODE_LEN_PADDED: usize = PAD_LEN(532);
/// rlp( rlp(max key 32b) + rlp(max value 32b) ) + 1 for compact encoding
/// see test_len()
pub const MAX_EXTENSION_NODE_LEN: usize = 69;
pub const MAX_EXTENSION_NODE_LEN_PADDED: usize = PAD_LEN(69);
pub const MAX_LEAF_NODE_LEN: usize = MAX_EXTENSION_NODE_LEN;

pub mod api;
pub mod contract_extraction;
pub mod length_extraction;
pub mod values_extraction;

#[test]
fn foo() {
    run::<272, 272>();

    // defs & imports

    fn run<const INPUT_LEN: usize, const CIRCUIT_LEN: usize>() {
        let input = vec![0xfa; INPUT_LEN];

        let output = keccak256(&input);
        let output_packed: Vec<_> = convert_u8_to_u32_slice(&output)
            .into_iter()
            .map(GFp::from_canonical_u32)
            .collect();

        let circuit: FooCircuit<CIRCUIT_LEN> = FooCircuit { input };
        let proof =
            run_circuit::<GFp, D, PoseidonGoldilocksConfig, FooCircuit<CIRCUIT_LEN>>(circuit);

        assert_eq!(proof.public_inputs, output_packed);
    }

    use std::array;

    use mp2_common::{
        array::{Array, Vector, VectorWire},
        keccak::{InputData, KeccakCircuit, KeccakWires, PACKED_HASH_LEN},
        mpt_sequential::PAD_LEN,
        types::{CBuilder, GFp},
        utils::{convert_u8_to_u32_slice, keccak256},
        D,
    };
    use mp2_test::circuit::{run_circuit, UserCircuit};
    use plonky2::{
        field::types::Field,
        iop::{target::Target, witness::PartialWitness},
        plonk::config::PoseidonGoldilocksConfig,
    };

    #[derive(Debug, Clone)]
    pub struct FooWires<const INPUT_LEN: usize> {
        pub input: VectorWire<Target, INPUT_LEN>,
        pub wires: KeccakWires<INPUT_LEN>,
    }

    #[derive(Debug, Clone)]
    pub struct FooCircuit<const INPUT_LEN: usize> {
        pub input: Vec<u8>,
    }

    impl<const INPUT_LEN: usize> UserCircuit<GFp, D> for FooCircuit<INPUT_LEN> {
        type Wires = FooWires<INPUT_LEN>;

        fn build(cb: &mut CBuilder) -> Self::Wires {
            let input = VectorWire::new(cb);

            input.assert_bytes(cb);

            let wires = KeccakCircuit::hash_vector(cb, &input);
            let output: [_; PACKED_HASH_LEN] = array::from_fn(|i| wires.output_array[i].0);

            cb.register_public_inputs(&output);

            FooWires { input, wires }
        }

        fn prove(&self, pw: &mut PartialWitness<GFp>, wires: &Self::Wires) {
            let input = Vector::from_vec(&self.input).unwrap();

            wires.input.assign(pw, &input);

            KeccakCircuit::<INPUT_LEN>::assign(pw, &wires.wires, &InputData::Assigned(&input));
        }
    }
}
