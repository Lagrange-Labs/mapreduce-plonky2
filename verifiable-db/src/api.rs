//! Main APIs and related structures

use crate::{
    block_tree, cells_tree,
    extraction::{ExtractionPI, ExtractionPIWrap},
    ivc,
    query::{self, api::Parameters as QueryParams, PI_LEN as QUERY_PI_LEN},
    revelation::{
        self, api::Parameters as RevelationParams, NUM_QUERY_IO, PI_LEN as REVELATION_PI_LEN,
    },
    row_tree::{self},
};
use anyhow::Result;
use log::info;
use mp2_common::{
    default_config,
    poseidon::H,
    proof::{serialize_proof, ProofWithVK},
    serialization::{deserialize, serialize},
    C, D, F,
};
use plonky2::{
    iop::witness::PartialWitness,
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitData, VerifierOnlyCircuitData},
        config::{Hasher, PoseidonGoldilocksConfig},
    },
};
use recursion_framework::framework::{
    RecursiveCircuits, RecursiveCircuitsVerifierGagdet, RecursiveCircuitsVerifierTarget,
};
use serde::{Deserialize, Serialize};

/// Set of inputs necessary to generate proofs for each circuit employed in the verifiable DB stage of LPN
pub enum CircuitInput {
    /// Cells tree construction input
    CellsTree(cells_tree::CircuitInput),
    RowsTree(row_tree::CircuitInput),
    BlockTree(block_tree::CircuitInput),
    IVC(ivc::CircuitInput),
}

/// Parameters defining all the circuits employed for the verifiable DB stage of LPN
#[derive(Serialize, Deserialize)]
#[serde(bound = "")]
pub struct PublicParameters<E: ExtractionPIWrap>
where
    [(); E::PI::TOTAL_LEN]:,
{
    cells_tree: cells_tree::PublicParameters,
    rows_tree: row_tree::PublicParameters,
    block_tree: block_tree::PublicParameters<E>,
    ivc: ivc::PublicParameters,
}

impl<E: ExtractionPIWrap> PublicParameters<E>
where
    [(); E::PI::TOTAL_LEN]:,
{
    pub fn get_params_info(&self) -> Result<Vec<u8>> {
        let params_info = ParamsInfo {
            preprocessing_circuit_set: self.ivc.get_circuit_set().clone(),
            preprocessing_vk: self.ivc.get_ivc_circuit_data().verifier_only.clone(),
        };
        Ok(bincode::serialize(&params_info)?)
    }
}

/// Instantiate the circuits employed for the verifiable DB stage of LPN, and return their corresponding parameters.
pub fn build_circuits_params<E: ExtractionPIWrap>(
    extraction_set: &RecursiveCircuits<F, C, D>,
) -> PublicParameters<E>
where
    [(); E::PI::TOTAL_LEN]:,
{
    log::info!("Building cells_tree parameters...");
    let cells_tree = cells_tree::build_circuits_params();
    log::info!("Building row tree parameters...");
    let rows_tree = row_tree::PublicParameters::build(cells_tree.vk_set());
    log::info!("Building block tree parameters...");
    let block_tree = block_tree::PublicParameters::build(extraction_set, rows_tree.set_vk());
    log::info!("Building IVC parameters...");
    let ivc = ivc::PublicParameters::build(block_tree.set_vk());
    log::info!("All parameters built!");

    PublicParameters {
        cells_tree,
        rows_tree,
        block_tree,
        ivc,
    }
}

/// Generate a proof for a circuit in the set of circuits employed in the
/// verifiable DB stage of LPN, employing `CircuitInput` to specify for which
/// circuit the proof should be generated.
pub fn generate_proof<E: ExtractionPIWrap>(
    params: &PublicParameters<E>,
    input: CircuitInput,
    extraction_set: &RecursiveCircuits<F, C, D>,
) -> Result<Vec<u8>>
where
    [(); E::PI::TOTAL_LEN]:,
{
    match input {
        CircuitInput::CellsTree(input) => params.cells_tree.generate_proof(input),
        CircuitInput::RowsTree(input) => params
            .rows_tree
            .generate_proof(input, params.cells_tree.vk_set().clone()),
        CircuitInput::BlockTree(input) => {
            params
                .block_tree
                .generate_proof(input, extraction_set, params.rows_tree.set_vk())
        }
        CircuitInput::IVC(input) => params.ivc.generate_proof(input, params.block_tree.set_vk()),
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
struct ParamsInfo {
    preprocessing_circuit_set: RecursiveCircuits<F, C, D>,
    #[serde(serialize_with = "serialize", deserialize_with = "deserialize")]
    preprocessing_vk: VerifierOnlyCircuitData<C, D>,
}

type WrapC = PoseidonGoldilocksConfig;

#[derive(Serialize, Deserialize)]
/// Wrapper circuit around the different type of revelation circuits we expose. Reason we need one is to be able
/// to always keep the same succinct wrapper circuit and Groth16 circuit regardless of the end result we submit
/// onchain.
pub struct WrapCircuitParams<
    const MAX_NUM_OUTPUTS: usize,
    const MAX_NUM_ITEMS_PER_OUTPUT: usize,
    const MAX_NUM_PLACEHOLDERS: usize,
> {
    query_verifier_wires: RecursiveCircuitsVerifierTarget<D>,
    #[serde(serialize_with = "serialize", deserialize_with = "deserialize")]
    circuit_data: CircuitData<F, WrapC, D>,
}

impl<
        const MAX_NUM_OUTPUTS: usize,
        const MAX_NUM_ITEMS_PER_OUTPUT: usize,
        const MAX_NUM_PLACEHOLDERS: usize,
    > WrapCircuitParams<MAX_NUM_OUTPUTS, MAX_NUM_ITEMS_PER_OUTPUT, MAX_NUM_PLACEHOLDERS>
where
    [(); REVELATION_PI_LEN::<MAX_NUM_OUTPUTS, MAX_NUM_ITEMS_PER_OUTPUT, MAX_NUM_PLACEHOLDERS>]:,
    [(); <H as Hasher<F>>::HASH_SIZE]:,
{
    pub fn build(revelation_circuit_set: &RecursiveCircuits<F, C, D>) -> Self {
        let mut builder = CircuitBuilder::new(default_config());
        let verifier_gadget = RecursiveCircuitsVerifierGagdet::<
            F,
            C,
            D,
            {
                REVELATION_PI_LEN::<MAX_NUM_OUTPUTS, MAX_NUM_ITEMS_PER_OUTPUT, MAX_NUM_PLACEHOLDERS>
            },
        >::new(default_config(), revelation_circuit_set);
        let query_verifier_wires = verifier_gadget.verify_proof_in_circuit_set(&mut builder);
        // expose public inputs of verifier proof as public inputs
        let verified_proof_pi = query_verifier_wires.get_public_input_targets::<F, {
            REVELATION_PI_LEN::<MAX_NUM_OUTPUTS, MAX_NUM_ITEMS_PER_OUTPUT, MAX_NUM_PLACEHOLDERS>
        }>();
        builder.register_public_inputs(verified_proof_pi);
        let circuit_data = builder.build();

        Self {
            query_verifier_wires,
            circuit_data,
        }
    }

    pub fn generate_proof(
        &self,
        revelation_circuit_set: &RecursiveCircuits<F, C, D>,
        query_proof: &ProofWithVK,
    ) -> Result<Vec<u8>> {
        let (proof, vd) = query_proof.into();
        let mut pw = PartialWitness::new();
        self.query_verifier_wires
            .set_target(&mut pw, revelation_circuit_set, proof, vd)?;
        let proof = self.circuit_data.prove(pw)?;
        serialize_proof(&proof)
    }

    pub fn circuit_data(&self) -> &CircuitData<F, WrapC, D> {
        &self.circuit_data
    }
}

#[derive(Serialize, Deserialize)]
pub struct QueryParameters<
    const MAX_NUM_COLUMNS: usize,
    const MAX_NUM_PREDICATE_OPS: usize,
    const MAX_NUM_RESULT_OPS: usize,
    const MAX_NUM_OUTPUTS: usize,
    const MAX_NUM_ITEMS_PER_OUTPUT: usize,
    const MAX_NUM_PLACEHOLDERS: usize,
> where
    [(); MAX_NUM_COLUMNS + MAX_NUM_RESULT_OPS]:,
    [(); MAX_NUM_ITEMS_PER_OUTPUT - 1]:,
    [(); NUM_QUERY_IO::<MAX_NUM_ITEMS_PER_OUTPUT>]:,
    [(); 2 * (MAX_NUM_PREDICATE_OPS + MAX_NUM_RESULT_OPS)]:,
{
    query_params: QueryParams<
        MAX_NUM_COLUMNS,
        MAX_NUM_PREDICATE_OPS,
        MAX_NUM_RESULT_OPS,
        MAX_NUM_ITEMS_PER_OUTPUT,
    >,
    revelation_params: RevelationParams<
        MAX_NUM_OUTPUTS,
        MAX_NUM_ITEMS_PER_OUTPUT,
        MAX_NUM_PLACEHOLDERS,
        { 2 * (MAX_NUM_PREDICATE_OPS + MAX_NUM_RESULT_OPS) },
    >,
    wrap_circuit:
        WrapCircuitParams<MAX_NUM_OUTPUTS, MAX_NUM_ITEMS_PER_OUTPUT, MAX_NUM_PLACEHOLDERS>,
}

#[derive(Serialize, Deserialize)]
pub enum QueryCircuitInput<
    const MAX_NUM_COLUMNS: usize,
    const MAX_NUM_PREDICATE_OPS: usize,
    const MAX_NUM_RESULT_OPS: usize,
    const MAX_NUM_OUTPUTS: usize,
    const MAX_NUM_ITEMS_PER_OUTPUT: usize,
    const MAX_NUM_PLACEHOLDERS: usize,
> where
    [(); 2 * (MAX_NUM_PREDICATE_OPS + MAX_NUM_RESULT_OPS)]:,
{
    Query(
        query::api::CircuitInput<
            MAX_NUM_COLUMNS,
            MAX_NUM_PREDICATE_OPS,
            MAX_NUM_RESULT_OPS,
            MAX_NUM_ITEMS_PER_OUTPUT,
        >,
    ),
    Revelation(
        revelation::api::CircuitInput<
            MAX_NUM_OUTPUTS,
            MAX_NUM_ITEMS_PER_OUTPUT,
            MAX_NUM_PLACEHOLDERS,
            { 2 * (MAX_NUM_PREDICATE_OPS + MAX_NUM_RESULT_OPS) },
        >,
    ),
}

impl<
        const MAX_NUM_COLUMNS: usize,
        const MAX_NUM_PREDICATE_OPS: usize,
        const MAX_NUM_RESULT_OPS: usize,
        const MAX_NUM_OUTPUTS: usize,
        const MAX_NUM_ITEMS_PER_OUTPUT: usize,
        const MAX_NUM_PLACEHOLDERS: usize,
    >
    QueryParameters<
        MAX_NUM_COLUMNS,
        MAX_NUM_PREDICATE_OPS,
        MAX_NUM_RESULT_OPS,
        MAX_NUM_OUTPUTS,
        MAX_NUM_ITEMS_PER_OUTPUT,
        MAX_NUM_PLACEHOLDERS,
    >
where
    [(); MAX_NUM_COLUMNS + MAX_NUM_RESULT_OPS]:,
    [(); MAX_NUM_ITEMS_PER_OUTPUT - 1]:,
    [(); NUM_QUERY_IO::<MAX_NUM_ITEMS_PER_OUTPUT>]:,
    [(); 2 * (MAX_NUM_PREDICATE_OPS + MAX_NUM_RESULT_OPS)]:,
    [(); QUERY_PI_LEN::<MAX_NUM_ITEMS_PER_OUTPUT>]:,
    [(); REVELATION_PI_LEN::<MAX_NUM_OUTPUTS, MAX_NUM_ITEMS_PER_OUTPUT, MAX_NUM_PLACEHOLDERS>]:,
{
    /// Build `QueryParameters` from serialized `ParamsInfo` of `PublicParamaters`
    pub fn build_params(preprocessing_params_info: &[u8]) -> Result<Self> {
        let params_info: ParamsInfo = bincode::deserialize(preprocessing_params_info)?;
        let query_params = QueryParams::build();
        info!("Building the revelation circuit parameters...");
        let revelation_params = RevelationParams::build(
            query_params.get_circuit_set(),
            &params_info.preprocessing_circuit_set,
            &params_info.preprocessing_vk,
        );
        info!("Building the final wrapping circuit parameters...");
        let wrap_circuit = WrapCircuitParams::build(revelation_params.get_circuit_set());
        info!("All QUERY parameters built !");
        Ok(Self {
            query_params,
            revelation_params,
            wrap_circuit,
        })
    }

    pub fn generate_proof(
        &self,
        input: QueryCircuitInput<
            MAX_NUM_COLUMNS,
            MAX_NUM_PREDICATE_OPS,
            MAX_NUM_RESULT_OPS,
            MAX_NUM_OUTPUTS,
            MAX_NUM_ITEMS_PER_OUTPUT,
            MAX_NUM_PLACEHOLDERS,
        >,
    ) -> Result<Vec<u8>> {
        match input {
            QueryCircuitInput::Query(input) => self.query_params.generate_proof(input),
            QueryCircuitInput::Revelation(input) => {
                let proof = self
                    .revelation_params
                    .generate_proof(input, self.query_params.get_circuit_set())?;
                self.wrap_circuit.generate_proof(
                    self.revelation_params.get_circuit_set(),
                    &ProofWithVK::deserialize(&proof)?,
                )
            }
        }
    }

    pub fn final_proof_circuit_data(&self) -> &CircuitData<F, WrapC, D> {
        &self.wrap_circuit.circuit_data
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use plonky2::plonk::proof::ProofWithPublicInputs;
    use std::{fs::File, io::BufReader};

    // Constants associating with test data.
    const MAX_NUM_COLUMNS: usize = 20;
    const MAX_NUM_PREDICATE_OPS: usize = 20;
    const MAX_NUM_RESULT_OPS: usize = 20;
    const MAX_NUM_OUTPUTS: usize = 3;
    const MAX_NUM_ITEMS_PER_OUTPUT: usize = 5;
    const MAX_NUM_PLACEHOLDERS: usize = 10;

    // This is only used for testing on local.
    #[ignore]
    #[test]
    fn test_local_proof_verification() {
        const QUERY_PARAMS_FILE_PATH: &str = "test_data/query_params.bin";
        const QUERY_PROOF_FILE_PATH: &str = "test_data/revelation";

        // Load the query parameters.
        let file = File::open(QUERY_PARAMS_FILE_PATH).unwrap();
        let reader = BufReader::new(file);
        let query_params: QueryParameters<
            MAX_NUM_COLUMNS,
            MAX_NUM_PREDICATE_OPS,
            MAX_NUM_RESULT_OPS,
            MAX_NUM_OUTPUTS,
            MAX_NUM_ITEMS_PER_OUTPUT,
            MAX_NUM_PLACEHOLDERS,
        > = bincode::deserialize_from(reader).unwrap();

        // Load the query proof.
        let file = File::open(QUERY_PROOF_FILE_PATH).unwrap();
        let reader = BufReader::new(file);
        let proof: ProofWithPublicInputs<F, WrapC, D> = bincode::deserialize_from(reader).unwrap();

        query_params
            .wrap_circuit
            .circuit_data()
            .verify(proof)
            .unwrap();
    }
}
