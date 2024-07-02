//! This circuit is employed when the new node is inserted as the right child of
//! an existing node (or if there is no existing node, which happens for the
//! first block number).

use super::{compute_index_digest, public_inputs::PublicInputs};
use crate::{extraction::ExtractionPI, row_tree};
use anyhow::Result;
use mp2_common::{
    default_config,
    group_hashing::CircuitBuilderGroupHashing,
    poseidon::{empty_poseidon_hash, hash_to_int_target},
    proof::ProofWithVK,
    public_inputs::PublicInputCommon,
    types::CBuilder,
    utils::{SliceConnector, ToTargets},
    CHasher, C, D, F,
};
use mp2_v1::final_extraction;
use plonky2::{
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{circuit_builder::CircuitBuilder, proof::ProofWithPublicInputsTarget},
};
use recursion_framework::{
    circuit_builder::CircuitLogicWires,
    framework::{
        RecursiveCircuits, RecursiveCircuitsVerifierGagdet, RecursiveCircuitsVerifierTarget,
    },
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::{iter, marker::PhantomData};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct LeafWires {
    index_identifier: Target,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct LeafCircuit {
    /// Identifier of the block number column
    pub(crate) index_identifier: F,
}

impl LeafCircuit {
    fn build<E>(b: &mut CBuilder, extraction_pi: &[Target], rows_tree_pi: &[Target]) -> LeafWires
    where
        E: ExtractionPI,
    {
        let index_identifier = b.add_virtual_target();

        let extraction_pi = E::from_slice(extraction_pi);
        let rows_tree_pi = row_tree::PublicInputs::<Target>::from_slice(rows_tree_pi);

        // in our case, the extraction proofs extracts from the blockchain and sets
        // the block number as the primary index
        let index_value = extraction_pi.primary_index_value();

        // Enforce that the data extracted from the blockchain is the same as the data
        // employed to build the rows tree for this node.
        b.connect_slice(
            &extraction_pi.digest_value(),
            &rows_tree_pi.rows_digest().to_targets(),
        );

        // Compute the hash of table metadata, to be exposed as public input to prove to
        // the verifier that we extracted the correct storage slots and we place the data
        // in the expected columns of the constructed tree; we add also the identifier
        // of the block number column to the table metadata.
        // metadata_hash = H(extraction_proof.DM || block_id)
        let inputs = extraction_pi
            .digest_metadata()
            .into_iter()
            .chain(iter::once(index_identifier))
            .collect();
        let metadata_hash = b.hash_n_to_hash_no_pad::<CHasher>(inputs).elements;

        // Compute the order-agnostic digest of this node of the block tree.
        // node_digest = HashToInt(H(index_identifier || index_value)) * rows_tree_proof.DR
        let inputs = iter::once(index_identifier)
            .chain(index_value.iter().cloned())
            .collect();
        let node_digest = compute_index_digest(b, inputs, rows_tree_pi.rows_digest());

        // Compute hash of the inserted node
        // node_min = block_number
        // node_max = block_number
        // H_new = H(H("") || H("") || node_min || node_max || block_id || block_number || rows_tree_proof.H)
        let empty_hash = b.constant_hash(*empty_poseidon_hash()).to_targets();
        let inputs = empty_hash
            .iter()
            .chain(empty_hash.iter())
            .chain(index_value.iter()) // node_min
            .chain(index_value.iter()) // node_max
            .chain(iter::once(&index_identifier))
            .chain(index_value.iter())
            .chain(rows_tree_pi.h)
            .cloned()
            .collect();
        let h_new = b.hash_n_to_hash_no_pad::<CHasher>(inputs).to_targets();

        // Register the public inputs.
        PublicInputs::new(
            &h_new,
            &empty_hash,
            &index_value, // node_min
            &index_value, // node_max
            &index_value,
            &extraction_pi.commitment(),
            &extraction_pi.prev_commitment(),
            &metadata_hash,
            &node_digest.to_targets(),
        )
        .register(b);

        LeafWires { index_identifier }
    }

    /// Assign the wireswhere E: ExtractionPI.
    fn assign(&self, pw: &mut PartialWitness<F>, wires: &LeafWires) {
        pw.set_target(wires.index_identifier, self.index_identifier);
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct RecursiveLeafWires<E>
where
    E: ExtractionPI,
{
    leaf_wires: LeafWires,
    extraction_verifier: RecursiveCircuitsVerifierTarget<D>,
    rows_tree_verifier: RecursiveCircuitsVerifierTarget<D>,
    _p: PhantomData<E>,
}

#[derive(Clone, Debug)]
pub(crate) struct RecursiveLeafInput {
    pub(crate) witness: LeafCircuit,
    pub(crate) extraction_proof: ProofWithVK,
    pub(crate) rows_tree_proof: ProofWithVK,
    pub(crate) extraction_set: RecursiveCircuits<F, C, D>,
    pub(crate) rows_tree_set: RecursiveCircuits<F, C, D>,
}

impl<E> CircuitLogicWires<F, D, 0> for RecursiveLeafWires<E>
where
    E: ExtractionPI,
{
    // Final extraction circuit set + rows tree circuit set
    type CircuitBuilderParams = (RecursiveCircuits<F, C, D>, RecursiveCircuits<F, C, D>);

    type Inputs = RecursiveLeafInput;

    const NUM_PUBLIC_INPUTS: usize = PublicInputs::<Target>::TOTAL_LEN;

    fn circuit_logic(
        builder: &mut CircuitBuilder<F, D>,
        _verified_proofs: [&ProofWithPublicInputsTarget<D>; 0],
        builder_parameters: Self::CircuitBuilderParams,
    ) -> Self {
        const EXTRACTION_IO: usize = final_extraction::PublicInputs::<Target>::TOTAL_LEN;
        const ROWS_TREE_IO: usize = row_tree::PublicInputs::<Target>::TOTAL_LEN;

        let extraction_verifier = RecursiveCircuitsVerifierGagdet::<F, C, D, EXTRACTION_IO>::new(
            default_config(),
            &builder_parameters.0,
        );
        let extraction_verifier = extraction_verifier.verify_proof_in_circuit_set(builder);
        let extraction_pi = extraction_verifier.get_public_input_targets::<F, EXTRACTION_IO>();

        let rows_tree_verifier = RecursiveCircuitsVerifierGagdet::<F, C, D, ROWS_TREE_IO>::new(
            default_config(),
            &builder_parameters.1,
        );
        let rows_tree_verifier = rows_tree_verifier.verify_proof_in_circuit_set(builder);
        let rows_tree_pi = rows_tree_verifier.get_public_input_targets::<F, ROWS_TREE_IO>();

        let leaf_wires = LeafCircuit::build::<E>(builder, extraction_pi, rows_tree_pi);

        RecursiveLeafWires {
            leaf_wires,
            extraction_verifier,
            rows_tree_verifier,
            _p: PhantomData,
        }
    }

    fn assign_input(&self, inputs: Self::Inputs, pw: &mut PartialWitness<F>) -> Result<()> {
        inputs.witness.assign(pw, &self.leaf_wires);

        let (proof, vd) = inputs.extraction_proof.into();
        self.extraction_verifier
            .set_target(pw, &inputs.extraction_set, &proof, &vd)?;

        let (proof, vd) = inputs.rows_tree_proof.into();
        self.rows_tree_verifier
            .set_target(pw, &inputs.rows_tree_set, &proof, &vd)
    }
}

#[cfg(test)]
pub mod tests {
    use super::{
        super::tests::{random_extraction_pi, random_rows_tree_pi},
        *,
    };
    use ethers::prelude::U256;
    use mp2_common::{
        poseidon::{hash_to_int_value, H},
        utils::{Fieldable, ToFields},
    };
    use mp2_test::{
        circuit::{run_circuit, UserCircuit},
        utils::weierstrass_to_point,
    };
    use plonky2::{
        field::types::{Field, Sample},
        hash::hash_types::HashOut,
        plonk::config::Hasher,
    };
    use plonky2_ecgfp5::curve::{curve::Point, scalar_field::Scalar};
    use rand::{thread_rng, Rng};

    pub fn compute_expected_hash(
        extraction_pi: &final_extraction::PublicInputs<F>,
        identifier: F,
    ) -> HashOut<F> {
        let inputs: Vec<_> = extraction_pi
            .digest_metadata_raw()
            .iter()
            .cloned()
            .chain(iter::once(identifier))
            .collect();
        H::hash_no_pad(&inputs)
    }

    pub fn compute_expected_set_digest(
        identifier: F,
        value: Vec<F>,
        rows_tree_pi: row_tree::PublicInputs<F>,
    ) -> Point {
        let inputs: Vec<_> = iter::once(identifier)
            .chain(value.iter().cloned())
            .collect();
        let hash = H::hash_no_pad(&inputs);
        let int = hash_to_int_value(hash);
        let scalar = Scalar::from_noncanonical_biguint(int);
        let point = rows_tree_pi.rows_digest_field();
        let point = weierstrass_to_point(&point);
        point * scalar
    }
    type TestPI = crate::extraction::test::PublicInputs<Target>;
    #[derive(Clone, Debug)]
    struct TestLeafCircuit<'a> {
        c: LeafCircuit,
        extraction_pi: &'a [F],
        rows_tree_pi: &'a [F],
    }

    impl<'a> UserCircuit<F, D> for TestLeafCircuit<'a> {
        // Leaf node wires + extraction public inputs + rows tree public inputs
        type Wires = (LeafWires, Vec<Target>, Vec<Target>);

        fn build(b: &mut CBuilder) -> Self::Wires {
            let extraction_pi =
                b.add_virtual_targets(final_extraction::PublicInputs::<Target>::TOTAL_LEN);
            let rows_tree_pi = b.add_virtual_targets(row_tree::PublicInputs::<Target>::TOTAL_LEN);

            let leaf_wires = LeafCircuit::build::<TestPI>(b, &extraction_pi, &rows_tree_pi);

            (leaf_wires, extraction_pi, rows_tree_pi)
        }

        fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
            self.c.assign(pw, &wires.0);

            assert_eq!(
                wires.1.len(),
                final_extraction::PublicInputs::<Target>::TOTAL_LEN
            );
            pw.set_target_arr(&wires.1, self.extraction_pi);

            assert_eq!(wires.2.len(), row_tree::PublicInputs::<Target>::TOTAL_LEN);
            pw.set_target_arr(&wires.2, self.rows_tree_pi);
        }
    }

    #[test]
    fn test_block_index_leaf_circuit() {
        let mut rng = thread_rng();

        let block_id = rng.gen::<u32>().to_field();
        let block_number = U256(rng.gen::<[u64; 4]>());

        let row_digest = Point::sample(&mut rng).to_weierstrass().to_fields();
        let extraction_pi = &random_extraction_pi(&mut rng, block_number, &row_digest);
        let rows_tree_pi = &random_rows_tree_pi(&mut rng, &row_digest);

        let test_circuit = TestLeafCircuit {
            c: LeafCircuit {
                index_identifier: block_id,
            },
            extraction_pi,
            rows_tree_pi,
        };

        let proof = run_circuit::<F, D, C, _>(test_circuit);
        let pi = PublicInputs::from_slice(&proof.public_inputs);
        let extraction_pi = final_extraction::PublicInputs::from_slice(extraction_pi);
        let rows_tree_pi = row_tree::PublicInputs::from_slice(rows_tree_pi);

        let empty_hash = empty_poseidon_hash();
        let block_number = extraction_pi.block_number_raw();

        // Check new hash
        {
            let inputs: Vec<_> = empty_hash
                .elements
                .iter()
                .chain(empty_hash.elements.iter())
                .chain(block_number) // node_min
                .chain(block_number) // node_max
                .chain(iter::once(&block_id))
                .chain(block_number)
                .chain(rows_tree_pi.h)
                .cloned()
                .collect();
            let exp_hash = H::hash_no_pad(&inputs);

            assert_eq!(pi.h_new, exp_hash.elements);
        }
        // Check old hash
        {
            assert_eq!(pi.h_old, empty_hash.elements);
        }
        // Check minimum block number
        {
            assert_eq!(pi.min, block_number);
        }
        // Check maximum block number
        {
            assert_eq!(pi.max, block_number);
        }
        // Check block number
        {
            assert_eq!(pi.block_number, block_number);
        }
        // Check block hash
        {
            assert_eq!(pi.block_hash, extraction_pi.block_hash_raw());
        }
        // Check previous block hash
        {
            assert_eq!(pi.prev_block_hash, extraction_pi.prev_block_hash_raw());
        }
        // Check metadata hash
        {
            let exp_hash = compute_expected_hash(&extraction_pi, block_id);
            assert_eq!(pi.metadata_digest, exp_hash.elements);
        }
        // Check new node digest
        {
            let exp_digest =
                compute_expected_set_digest(block_id, block_number.to_vec(), rows_tree_pi);
            assert_eq!(pi.new_node_digest_point(), exp_digest.to_weierstrass());
        }
    }
}
