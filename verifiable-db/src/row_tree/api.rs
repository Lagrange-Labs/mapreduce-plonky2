use anyhow::{bail, Result};
use ethers::types::U256;
use mp2_common::{default_config, proof::ProofWithVK, C, D, F};
use recursion_framework::{
    circuit_builder::{CircuitWithUniversalVerifier, CircuitWithUniversalVerifierBuilder},
    framework::{prepare_recursive_circuit_for_circuit_set as p, RecursiveCircuits},
};

use crate::cells_tree;

use super::{
    full_node::{self, FullNodeCircuit},
    leaf::{self, LeafCircuit},
    partial_node::{self, PartialNodeCircuit},
    IndexTuple,
};

pub struct Parameters {
    leaf: CircuitWithUniversalVerifier<F, C, D, 0, leaf::RecursiveLeafWires>,
    full: CircuitWithUniversalVerifier<
        F,
        C,
        D,
        { full_node::NUM_CHILDREN },
        full_node::RecursiveFullWires,
    >,
    partial: CircuitWithUniversalVerifier<
        F,
        C,
        D,
        { partial_node::NUM_CHILDREN },
        partial_node::RecursivePartialWires,
    >,
    row_set: RecursiveCircuits<F, C, D>,
}

const ROW_IO_LEN: usize = super::public_inputs::TOTAL_LEN;
const CELL_IO_LEN: usize = cells_tree::PublicInputs::<F>::TOTAL_LEN;

impl Parameters {
    pub fn build(cells_set: &RecursiveCircuits<F, C, D>) -> Self {
        const ROW_CIRCUIT_SET_SIZE: usize = 3;
        let builder = CircuitWithUniversalVerifierBuilder::<F, D, ROW_IO_LEN>::new::<C>(
            default_config(),
            ROW_CIRCUIT_SET_SIZE,
        );

        let leaf_circuit = builder.build_circuit(cells_set.clone());
        let full_circuit = builder.build_circuit(cells_set.clone());
        let partial_circuit = builder.build_circuit(cells_set.clone());

        let circuits = vec![p(&leaf_circuit), p(&full_circuit), p(&partial_circuit)];
        let circuit_set = RecursiveCircuits::<F, C, D>::new(circuits);
        Self {
            leaf: leaf_circuit,
            full: full_circuit,
            partial: partial_circuit,
            row_set: circuit_set,
        }
    }

    pub fn generate_proof(&self, input: CircuitInput) -> Result<Vec<u8>> {
        match input {
            CircuitInput::Leaf {
                witness,
                cells_proof,
            } => self.generate_leaf_proof(witness, cells_proof),
            CircuitInput::Full {
                witness,
                left_proof,
                right_proof,
                cells_proof,
            } => self.generate_full_proof(witness, left_proof, right_proof, cells_proof),
            CircuitInput::Partial {
                witness,
                child_proof,
                is_child_left,
                cells_proof,
            } => self.generate_partial_proof(witness, child_proof, is_child_left, cells_proof),
        }
    }

    fn generate_leaf_proof(
        &self,
        witness: LeafCircuit,
        cells_proof: CellsProof,
    ) -> Result<Vec<u8>> {
        let (p, cells_set) = cells_proof;
        let cells_proof = ProofWithVK::deserialize(&p)?;
        let leaf = leaf::RecursiveLeafInput {
            witness,
            cells_proof,
            cells_set,
        };
        let proof = self.row_set.generate_proof(&self.leaf, [], [], leaf)?;
        ProofWithVK::new(proof, self.leaf.circuit_data().verifier_only.clone()).serialize()
    }

    fn generate_full_proof(
        &self,
        witness: FullNodeCircuit,
        left_proof: Vec<u8>,
        right_proof: Vec<u8>,
        cells_proof: CellsProof,
    ) -> Result<Vec<u8>> {
        let (p, cells_set) = cells_proof;
        let cells_proof = ProofWithVK::deserialize(&p)?;
        let full = full_node::RecursiveFullInput {
            witness,
            cells_proof,
            cells_set,
        };
        let (left_proof, left_vd) = ProofWithVK::deserialize(&left_proof)?.into();
        let (right_proof, right_vd) = ProofWithVK::deserialize(&right_proof)?.into();
        let proof = self.row_set.generate_proof(
            &self.full,
            [left_proof, right_proof],
            [&left_vd, &right_vd],
            full,
        )?;
        ProofWithVK::new(proof, self.leaf.circuit_data().verifier_only.clone()).serialize()
    }

    fn generate_partial_proof(
        &self,
        witness: PartialNodeCircuit,
        child_proof: Vec<u8>,
        is_child_left: bool,
        cells_proof: CellsProof,
    ) -> Result<Vec<u8>> {
        let (p, cells_set) = cells_proof;
        let cells_proof = ProofWithVK::deserialize(&p)?;
        let partial = partial_node::RecursivePartialInput {
            witness,
            cells_proof,
            cells_set,
        };
        let (child_proof, child_vd) = ProofWithVK::deserialize(&child_proof)?.into();
        let proof =
            self.row_set
                .generate_proof(&self.partial, [child_proof], [&child_vd], partial)?;
        ProofWithVK::new(proof, self.leaf.circuit_data().verifier_only.clone()).serialize()
    }
}

///  A wrapper type around the information needed for all three cases
///  of the  rows circuits
type CellsProof = (Vec<u8>, RecursiveCircuits<F, C, D>);

/// Enum holding all the inputs necessary to generate
/// rows tree related proofs
enum CircuitInput {
    Leaf {
        witness: leaf::LeafCircuit,
        cells_proof: CellsProof,
    },
    Full {
        witness: full_node::FullNodeCircuit,
        left_proof: Vec<u8>,
        right_proof: Vec<u8>,
        cells_proof: CellsProof,
    },
    Partial {
        witness: partial_node::PartialNodeCircuit,
        child_proof: Vec<u8>,
        is_child_left: bool,
        cells_proof: CellsProof,
    },
}

impl CircuitInput {
    fn leaf(
        identifier: F,
        value: U256,
        cells_proof: Vec<u8>,
        cells_set: &RecursiveCircuits<F, C, D>,
    ) -> Result<Self> {
        let circuit = LeafCircuit::new(IndexTuple::new(identifier, value));
        Ok(CircuitInput::Leaf {
            witness: circuit,
            cells_proof: (cells_proof, cells_set.clone()),
        })
    }
    pub fn full(
        identifier: F,
        value: U256,
        left_proof: Vec<u8>,
        right_proof: Vec<u8>,
        cells_proof: Vec<u8>,
        cells_set: &RecursiveCircuits<F, C, D>,
    ) -> Result<Self> {
        let circuit = FullNodeCircuit::from(IndexTuple::new(identifier, value));
        Ok(CircuitInput::Full {
            witness: circuit,
            left_proof,
            right_proof,
            cells_proof: (cells_proof, cells_set.clone()),
        })
    }
    pub fn partial(
        identifier: F,
        value: U256,
        is_child_left: bool,
        child_proof: Vec<u8>,
        cells_proof: Vec<u8>,
        cells_set: &RecursiveCircuits<F, C, D>,
    ) -> Result<Self> {
        let tuple = IndexTuple::new(identifier, value);
        let witness = PartialNodeCircuit::new(tuple, is_child_left);
        Ok(CircuitInput::Partial {
            witness,
            child_proof,
            is_child_left,
            cells_proof: (cells_proof, cells_set.clone()),
        })
    }
}

#[cfg(test)]
mod test {
    use crate::row_tree::public_inputs::PublicInputs;

    use super::*;
    use full_node::test::weierstrass_to_point;
    use mp2_common::{
        group_hashing::map_to_curve_point,
        poseidon::{empty_poseidon_hash, H},
        utils::ToFields,
        F,
    };
    use plonky2::{
        field::types::Sample,
        hash::{
            hash_types::HashOut, hashing::hash_n_to_hash_no_pad, poseidon::PoseidonPermutation,
        },
        plonk::{
            circuit_data::VerifierOnlyCircuitData, config::Hasher, proof::ProofWithPublicInputs,
        },
    };
    use plonky2_ecgfp5::curve::curve::Point;
    use rand::{thread_rng, Rng};
    use recursion_framework::framework_testing::TestingRecursiveCircuits;

    struct TestParams {
        cells_test: TestingRecursiveCircuits<F, C, D, CELL_IO_LEN>,
        params: Parameters,
        // always using the same cells_proof at each  row node
        // to save on test time
        cells_proof: ProofWithPublicInputs<F, C, D>,
        cells_vk: VerifierOnlyCircuitData<C, D>,
        leaf1: IndexTuple,
        leaf2: IndexTuple,
        full: IndexTuple,
        partial: IndexTuple,
    }

    impl TestParams {
        fn build() -> Result<Self> {
            let cells_test = TestingRecursiveCircuits::<F, C, D, CELL_IO_LEN>::default();
            let params = Parameters::build(cells_test.get_recursive_circuit_set());
            let cells_pi = Self::rand_cells_pi();
            let cells_proof =
                cells_test.generate_input_proofs::<1>([cells_pi.clone().try_into().unwrap()])?;
            let cells_vk = cells_test.verifier_data_for_input_proofs::<1>()[0].clone();
            //  leaf1 - leaf2  =>  full_node => partial_node
            let mut rng = thread_rng();
            let identifier = F::rand();
            let v1 = U256::from(rng.gen::<[u8; 32]>());
            let v_full = v1 + U256::from(10);
            let v2 = v_full + U256::from(10);
            let v_partial = v2 + U256::from(10); // full is left child of partial

            Ok(TestParams {
                cells_test,
                params,
                cells_proof: cells_proof[0].clone(),
                cells_vk,
                leaf1: IndexTuple::new(identifier, v1),
                leaf2: IndexTuple::new(identifier, v2),
                full: IndexTuple::new(identifier, v_full),
                partial: IndexTuple::new(identifier, v_partial),
            })
        }

        fn cells_pi(&self) -> cells_tree::PublicInputs<F> {
            cells_tree::PublicInputs::from_slice(&self.cells_proof.public_inputs)
        }
        fn cells_proof_vk(&self) -> ProofWithVK {
            ProofWithVK::new(self.cells_proof.clone(), self.cells_vk.clone())
        }

        fn rand_cells_pi() -> Vec<F> {
            // generate cells tree input and fake proof
            let cells_hash = HashOut::rand().to_fields();
            let cells_digest = Point::rand().to_weierstrass().to_fields();
            let cells_pi = cells_tree::PublicInputs::new(&cells_hash, &cells_digest).to_vec();
            cells_pi
        }
    }

    #[test]
    fn test_rows_tree_api() -> Result<()> {
        env_logger::init();
        log::info!("Generating parameters");
        let params = TestParams::build()?;
        log::info!("Generating leaf proof 1");
        let leaf1 = generate_leaf_proof(&params, &params.leaf1)?;
        log::info!("Generating leaf proof 2");
        let leaf2 = generate_leaf_proof(&params, &params.leaf2)?;
        let children_proof = [leaf1.clone(), leaf2.clone()];
        log::info!("Generating full proof (from leaf 1 and leaf 2)");
        let full_proof = generate_full_proof(&params, children_proof)?;
        Ok(())
    }

    fn generate_partial_proof(
        p: &TestParams,
        tuple: IndexTuple,
        is_left: bool,
        child_proof: Vec<u8>,
    ) -> Result<Vec<u8>> {
        let input = CircuitInput::partial(
            tuple.index_identifier,
            tuple.index_value,
            is_left,
            child_proof.clone(),
            p.cells_proof_vk().serialize()?,
            p.cells_test.get_recursive_circuit_set(),
        )?;
        let proof = p.params.generate_proof(input)?;
        let pi = ProofWithVK::deserialize(&proof)?.proof.public_inputs;
        let pi = PublicInputs::from_slice(&pi);
        let child_proof = ProofWithVK::deserialize(&child_proof)?;
        let child_pi = PublicInputs::from_slice(&child_proof.proof.public_inputs);
        {
            let child_min = child_pi.min_value_u256();
            let child_max = child_pi.max_value_u256();
            let (min, max) = match is_left {
                true => {
                    assert_eq!(U256::from(child_min), pi.min_value_u256());
                    assert_eq!(tuple.index_value, pi.max_value_u256());
                    (pi.min_value_u256(), tuple.index_value)
                }
                false => {
                    assert_eq!(tuple.index_value, pi.min_value_u256());
                    assert_eq!(U256::from(child_min), pi.max_value_u256());
                    (tuple.index_value, pi.min_value_u256())
                }
            };

            let child_hash = child_pi.root_hash_hashout();
            let empty_hash = empty_poseidon_hash();
            let input_hash = match is_left {
                true => [child_hash.to_fields(), empty_hash.to_fields()].concat(),
                false => [empty_hash.to_fields(), child_hash.to_fields()].concat(),
            };
            let inputs = input_hash
                .iter()
                .chain(min.to_fields().iter())
                .chain(max.to_fields().iter())
                .chain(tuple.to_fields().iter())
                .chain(p.cells_pi().h_raw().iter())
                .cloned()
                .collect::<Vec<_>>();
            let hash = H::hash_no_pad(&inputs);
            assert_eq!(hash, pi.root_hash_hashout());
            // child_proof.DR + D(cells_proof.DC + D(index_id || index_value)) as DR
            let inner = map_to_curve_point(&tuple.to_fields());
            let cells_point = weierstrass_to_point(&p.cells_pi().digest_point());
            let inner2 = inner + cells_point;
            let outer = map_to_curve_point(&inner2.to_weierstrass().to_fields());
            let child_d = weierstrass_to_point(&child_pi.rows_digest_field());
            let res = child_d + outer;
            assert_eq!(res.to_weierstrass(), pi.rows_digest_field());
        }
        Ok(vec![])
    }

    fn generate_full_proof(p: &TestParams, child_proof: [Vec<u8>; 2]) -> Result<Vec<u8>> {
        let tuple = p.full.clone();
        let input = CircuitInput::full(
            tuple.index_identifier,
            tuple.index_value,
            child_proof[0].to_vec(),
            child_proof[1].to_vec(),
            p.cells_proof_vk().serialize()?,
            p.cells_test.get_recursive_circuit_set(),
        )?;
        let left_proof = ProofWithVK::deserialize(&child_proof[0])?;
        let left_pi = PublicInputs::from_slice(&left_proof.proof.public_inputs);
        let right_proof = ProofWithVK::deserialize(&child_proof[1])?;
        let right_pi = PublicInputs::from_slice(&right_proof.proof.public_inputs);
        assert!(left_pi.max_value_u256() < tuple.index_value);
        assert!(tuple.index_value < right_pi.min_value_u256());
        let proof = p.params.generate_proof(input)?;
        let pi = ProofWithVK::deserialize(&proof)?.proof.public_inputs;
        let pi = PublicInputs::from_slice(&pi);
        {
            // H(left_child_hash,right_child_hash,min,max,index_identifier,index_value,cells_tree_hash)
            // min coming from left
            // max coming from right
            let inputs: Vec<_> = left_pi
                .root_hash_hashout()
                .to_fields()
                .iter()
                .chain(right_pi.root_hash_hashout().to_fields().iter())
                .chain(left_pi.min_value_u256().to_fields().iter())
                .chain(right_pi.max_value_u256().to_fields().iter())
                .chain(tuple.to_fields().iter())
                .chain(p.cells_pi().h_raw().iter())
                .cloned()
                .collect();
            let exp_hash = H::hash_no_pad(&inputs);
            assert_eq!(pi.root_hash_hashout(), exp_hash);

            {
                // expose p1.DR + p2.DR + D(p.DC + D(index_id || index_value)) as DR
                let inner = map_to_curve_point(&tuple.to_fields());
                let cells_point = weierstrass_to_point(&p.cells_pi().digest_point());
                let inner2 = inner + cells_point;
                let outer = map_to_curve_point(&inner2.to_weierstrass().to_fields());
                let left_d = weierstrass_to_point(&left_pi.rows_digest_field());
                let right_d = weierstrass_to_point(&right_pi.rows_digest_field());
                let result = left_d + right_d + outer;
                assert_eq!(pi.rows_digest_field(), result.to_weierstrass());
            }
        }
        Ok(proof)
    }

    fn generate_leaf_proof(p: &TestParams, tuple: &IndexTuple) -> Result<Vec<u8>> {
        let cells_pi = p.cells_pi();
        //  generate row leaf proof
        let input = CircuitInput::leaf(
            tuple.index_identifier,
            tuple.index_value,
            p.cells_proof_vk().serialize()?,
            p.cells_test.get_recursive_circuit_set(),
        )?;

        let proof = p.params.generate_proof(input)?;
        let pi = ProofWithVK::deserialize(&proof)
            .unwrap()
            .proof
            .public_inputs;
        let pi = PublicInputs::from_slice(&pi);
        let tuple = tuple.clone();
        {
            let empty_hash = empty_poseidon_hash();
            // H(left_child_hash,right_child_hash,min,max,index_identifier,index_value,cells_tree_hash)
            let inputs: Vec<_> = empty_hash
                .to_fields()
                .iter()
                .chain(empty_hash.to_fields().iter())
                .chain(tuple.index_value.to_fields().iter())
                .chain(tuple.index_value.to_fields().iter())
                .chain(tuple.to_fields().iter())
                .chain(cells_pi.h_raw().iter())
                .cloned()
                .collect();
            let exp_hash = H::hash_no_pad(&inputs);
            assert_eq!(pi.root_hash_hashout(), exp_hash);
        }
        {
            // expose p1.DR + p2.DR + D(p.DC + D(index_id || index_value)) as DR
            let cells_point = weierstrass_to_point(&cells_pi.digest_point());
            let inner = map_to_curve_point(&tuple.to_fields());
            let inner2 = inner + cells_point;
            let outer = map_to_curve_point(&inner2.to_weierstrass().to_fields());
            assert_eq!(outer.to_weierstrass(), pi.rows_digest_field());
        }
        Ok(proof)
    }
}
