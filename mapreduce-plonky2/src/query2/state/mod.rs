//! LPN State & Block DB provenance
use std::iter;

use ethers::types::Address;
use itertools::Itertools;
use plonky2::{
    field::{goldilocks_field::GoldilocksField, types::Field},
    hash::{
        hash_types::{HashOut, RichField},
        merkle_proofs::MerkleProofTarget,
        poseidon::PoseidonHash,
    },
    iop::{
        target::{BoolTarget, Target},
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{circuit_builder::CircuitBuilder, circuit_data::CircuitData, config::GenericHashOut},
};
use recursion_framework::{
    circuit_builder::{
        CircuitLogicWires, CircuitWithUniversalVerifier, CircuitWithUniversalVerifierBuilder,
    },
    framework::{
        RecursiveCircuits, RecursiveCircuitsVerifierGagdet, RecursiveCircuitsVerifierTarget,
    },
    serialization::{deserialize, serialize},
};
use serde::{Deserialize, Serialize};

use crate::{
    api::{default_config, ProofWithVK, C, D, F},
    array::Array,
    keccak::{OutputHash, PACKED_HASH_LEN},
    merkle_tree::StateTreeWires,
    query2::storage::public_inputs::PublicInputs as StorageInputs,
    types::{HashOutput, PackedAddressTarget as PackedSCAddressTarget},
    utils::{Packer, ToFields},
};

use super::{
    block::{BlockPublicInputs, BLOCK_CIRCUIT_SET_SIZE},
    PackedSCAddress,
};
use anyhow::Result;

#[cfg(test)]
pub(crate) mod tests;

/// The witnesses of [ProvenanceCircuit].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateWires<const MAX_DEPTH: usize> {
    /// Smart contract address (unpacked)
    pub smart_contract_address: PackedSCAddressTarget,
    /// Mapping of the storage slot
    pub mapping_slot: Target,
    /// Length of the storage slot
    pub length_slot: Target,
    /// Block number
    pub block_number: Target,
    /// Range of the query
    pub range: Target,
    #[serde(serialize_with = "serialize", deserialize_with = "deserialize")]
    /// The siblings that opens to the state tree.
    pub siblings: MerkleProofTarget,
    #[serde(serialize_with = "serialize", deserialize_with = "deserialize")]
    /// The boolean flags to describe the path. `true` equals right; `false` equals left.
    pub positions: Vec<BoolTarget>,
    /// The block hash as stored in the leaf of the block db.
    pub block_hash: OutputHash,
    /// The merkle root of the opening.
    pub state_tree: StateTreeWires<MAX_DEPTH>,
}

/// The provenance db circuit
///
/// # Arguments
///
/// - [StorageInputs]
///
/// # Witnesses
///
/// - `A` Smart contract address
/// - `M` Mapping slot
/// - `S` Length of the slot
/// - `B` Block number
/// - `B_MIN` Minimum block number
/// - `B_MAX` Maximum block number
/// - `R` Aggregated range
/// - `Z` State root of the leaf opening
/// - `P` Siblings path from leaf hash to `Z`
/// - `T` Little-endian positions flags for the merkle opening path
/// - `Y` Aggregated storage digest
/// - `H` Block hash as stored in the leaf of the block db
///
/// # Public Inputs
///
/// - `B` Block number
/// - `R` Aggregated range
/// - `C` Block leaf hash
/// - `B_MIN` Minimum block number
/// - `B_MAX` Maximum block number
/// - `A` Smart contract address (packed in u32)
/// - `X` User/Owner address (packed in u32)
/// - `M` Mapping slot
/// - `S` Length of the slot
/// - `Y` Aggregated storage digest
///
/// # Circuit
///
/// 1. `state_leaf := Poseidon(A || M || S || C)`
/// 2. Open the Merkle path `(P, T)` from `state_leaf` to `Z`
/// 3. `C := Poseidon(B || H || Z)`
/// 4. `R == 1`
///
/// `MAX_DEPTH` is the maximum depth of the state tree in LPN database.
#[derive(Debug, Clone)]
pub struct StateCircuit<const MAX_DEPTH: usize, F: RichField> {
    smart_contract_address: PackedSCAddress<F>,
    mapping_slot: F,
    length_slot: F,
    block_number: F,
    depth: F,
    siblings: Vec<HashOut<F>>,
    positions: Vec<bool>,
    block_hash: Array<F, PACKED_HASH_LEN>,
}

impl<const MAX_DEPTH: usize, F: RichField> StateCircuit<MAX_DEPTH, F> {
    /// Creates a new instance of the provenance circuit with the provided witness values.
    pub fn new(
        smart_contract_address: PackedSCAddress<F>,
        mapping_slot: F,
        length_slot: F,
        block_number: F,
        depth: F,
        siblings: Vec<HashOut<F>>,
        positions: Vec<bool>,
        block_hash: Array<F, PACKED_HASH_LEN>,
    ) -> Self {
        Self {
            smart_contract_address,
            mapping_slot,
            length_slot,
            block_number,
            depth,
            siblings,
            positions,
            block_hash,
        }
    }

    /// Builds the circuit wires with virtual targets. It takes as argument
    /// the public inputs of the storage root proof.
    pub fn build(
        cb: &mut CircuitBuilder<GoldilocksField, 2>,
        storage_proof: &StorageInputs<Target>,
    ) -> StateWires<MAX_DEPTH> {
        let x = storage_proof.owner();
        let c = storage_proof.root();
        let digest = storage_proof.digest();

        let a = PackedSCAddressTarget::new(cb);
        let m = cb.add_virtual_target();
        let s = cb.add_virtual_target();
        let b = cb.add_virtual_target();
        let r = cb.constant(GoldilocksField::ONE);

        let (siblings, positions): (Vec<_>, Vec<_>) = (0..MAX_DEPTH)
            .map(|_| {
                let pos = cb.add_virtual_bool_target_safe();
                let sibling = cb.add_virtual_hash();

                (sibling, pos)
            })
            .unzip();
        let siblings = MerkleProofTarget { siblings };

        // FIXME the optimized version without the length slot is unimplemented
        // https://www.notion.so/lagrangelabs/Encoding-Specs-ccaa31d1598b4626860e26ac149705c4?pvs=4#fe2b40982352464ba39164cf4b41d301
        // Currently = H(pack_u32(address) || mapping_slot || length_slot || storageRoot)
        let state_leaf: Vec<_> = a
            .to_targets()
            .arr
            .into_iter()
            .chain(iter::once(m))
            .chain(iter::once(s))
            .chain(c.elements.iter().copied())
            .collect();

        let state_tree = StateTreeWires::build(cb, state_leaf.as_slice(), &siblings, &positions);

        // FIXME optimized version unimplemented
        // https://www.notion.so/lagrangelabs/Encoding-Specs-ccaa31d1598b4626860e26ac149705c4?pvs=4#5e8e6f06e2554b0caee4904258cbbca2
        let block_hash = OutputHash::new(cb);
        let block_leaf = iter::once(b)
            .chain(block_hash.to_targets().arr)
            .chain(state_tree.root.elements.iter().copied())
            .collect();
        let block_leaf_hash = cb.hash_n_to_hash_no_pad::<PoseidonHash>(block_leaf);

        BlockPublicInputs::register(cb, b, r, &block_leaf_hash, &a, &x, m, s, digest);

        StateWires {
            smart_contract_address: a,
            mapping_slot: m,
            length_slot: s,
            block_number: b,
            range: r,
            siblings,
            positions,
            block_hash,
            state_tree,
        }
    }

    /// Assigns the instance witness values to the provided wires.
    pub fn assign(&self, pw: &mut PartialWitness<F>, wires: &StateWires<MAX_DEPTH>) {
        wires.state_tree.assign(pw, self.depth);

        wires
            .smart_contract_address
            .assign(pw, &self.smart_contract_address.arr);

        pw.set_target(wires.mapping_slot, self.mapping_slot);
        pw.set_target(wires.length_slot, self.length_slot);
        pw.set_target(wires.block_number, self.block_number);

        wires
            .siblings
            .siblings
            .iter()
            .flat_map(|s| s.elements.iter())
            .zip(self.siblings.iter().flat_map(|s| s.elements.iter()))
            .for_each(|(&w, &v)| pw.set_target(w, v));

        wires
            .positions
            .iter()
            .map(|p| p.target)
            .zip(self.positions.iter())
            .for_each(|(w, &v)| pw.set_target(w, F::from_bool(v)));

        wires
            .block_hash
            .arr
            .iter()
            .map(|h| h.0)
            .zip(self.block_hash.arr.iter())
            .for_each(|(w, &v)| pw.set_target(w, v));
    }
}

#[derive(Serialize, Deserialize)]
pub(crate) struct StateRecursiveWires<const MAX_DEPTH: usize> {
    state_wires: StateWires<MAX_DEPTH>,
    storage_verifier: RecursiveCircuitsVerifierTarget<D>,
}

const NUM_STORAGE_INPUTS: usize = StorageInputs::<Target>::TOTAL_LEN;
const NUM_IO: usize = BlockPublicInputs::<Target>::total_len();
//ToDo: decide if we want it as a const generic parameter
const MAX_DEPTH: usize = 0;

impl CircuitLogicWires<F, D, 0> for StateRecursiveWires<MAX_DEPTH> {
    type CircuitBuilderParams = RecursiveCircuitsVerifierGagdet<F, C, D, NUM_STORAGE_INPUTS>;

    type Inputs = CircuitInputsInternal;

    const NUM_PUBLIC_INPUTS: usize = NUM_IO;

    fn circuit_logic(
        builder: &mut CircuitBuilder<F, D>,
        _verified_proofs: [&plonky2::plonk::proof::ProofWithPublicInputsTarget<D>; 0],
        builder_parameters: Self::CircuitBuilderParams,
    ) -> Self {
        let storage_verifier = builder_parameters.verify_proof_in_circuit_set(builder);
        let storage_pi = StorageInputs::from_slice(
            storage_verifier.get_public_input_targets::<F, NUM_STORAGE_INPUTS>(),
        );

        let state_wires = StateCircuit::<MAX_DEPTH, F>::build(builder, &storage_pi);

        Self {
            state_wires,
            storage_verifier,
        }
    }

    fn assign_input(&self, inputs: Self::Inputs, pw: &mut PartialWitness<F>) -> Result<()> {
        inputs.api_inputs.state_input.assign(pw, &self.state_wires);
        let (proof, vd) = (&inputs.api_inputs.storage_proof).into();
        self.storage_verifier
            .set_target(pw, &inputs.storage_circuit_set, proof, vd)
    }
}

#[derive(Serialize, Deserialize)]
pub struct Parameters {
    circuit: CircuitWithUniversalVerifier<F, C, D, 0, StateRecursiveWires<MAX_DEPTH>>,
}
/// Set of inputs necessary to generate a proof for the state circuit
pub struct CircuitInputsInternal {
    api_inputs: CircuitInput,
    storage_circuit_set: RecursiveCircuits<F, C, D>,
}

impl CircuitInputsInternal {
    pub(crate) fn new(
        state_input: StateCircuit<MAX_DEPTH, F>,
        storage_proof: ProofWithVK,
        storage_circuit_set: &RecursiveCircuits<F, C, D>,
    ) -> Self {
        Self {
            api_inputs: CircuitInput {
                state_input,
                storage_proof,
            },
            storage_circuit_set: storage_circuit_set.clone(),
        }
    }

    pub(crate) fn from_circuit_input(
        input: CircuitInput,
        storage_circuit_set: &RecursiveCircuits<F, C, D>,
    ) -> Self {
        Self {
            api_inputs: input,
            storage_circuit_set: storage_circuit_set.clone(),
        }
    }
}
/// Inputs to be provided to the publicly exposed query API in order to generate a proof for the
/// state circuit
pub struct CircuitInput {
    state_input: StateCircuit<MAX_DEPTH, F>,
    storage_proof: ProofWithVK,
}

impl CircuitInput {
    pub fn new(
        smart_contract_address: Address,
        mapping_slot: u32,
        length_slot: u32,
        block_number: u32,
        depth: u32,
        siblings: &[HashOutput; MAX_DEPTH],
        positions: &[bool; MAX_DEPTH],
        block_hash: HashOutput,
        storage_proof: Vec<u8>,
    ) -> Result<Self> {
        let smart_contract_address =
            PackedSCAddress::try_from(smart_contract_address.as_bytes().pack().to_fields())?;
        let mapping_slot = F::from_canonical_u32(mapping_slot);
        let length_slot = F::from_canonical_u32(length_slot);
        let block_number = F::from_canonical_u32(block_number);
        let depth = F::from_canonical_u32(depth);
        let siblings = siblings
            .iter()
            .map(|hash| HashOut::from_bytes(hash.as_slice()))
            .collect_vec();
        let positions = positions.to_vec();
        let block_hash = Array::<F, PACKED_HASH_LEN>::try_from(block_hash.pack().to_fields())?;
        Ok(Self {
            state_input: StateCircuit::new(
                smart_contract_address,
                mapping_slot,
                length_slot,
                block_number,
                depth,
                siblings,
                positions,
                block_hash,
            ),
            storage_proof: ProofWithVK::deserialize(&storage_proof)?,
        })
    }
}

impl Parameters {
    pub(crate) fn build(storage_circuit_set: &RecursiveCircuits<F, C, D>) -> Self {
        let verifier_gadget =
            RecursiveCircuitsVerifierGagdet::new(default_config(), storage_circuit_set);
        let circuit_builder = CircuitWithUniversalVerifierBuilder::<F, D, NUM_IO>::new::<C>(
            default_config(),
            BLOCK_CIRCUIT_SET_SIZE,
        );
        let circuit = circuit_builder.build_circuit(verifier_gadget);

        Self { circuit }
    }

    pub(crate) fn generate_proof(
        &self,
        block_circuit_set: &RecursiveCircuits<F, C, D>,
        input: CircuitInputsInternal,
    ) -> Result<Vec<u8>> {
        let proof = block_circuit_set.generate_proof(&self.circuit, [], [], input)?;
        ProofWithVK::serialize(&(proof, self.circuit.circuit_data().verifier_only.clone()).into())
    }

    pub(crate) fn circuit_data(&self) -> &CircuitData<F, C, D> {
        self.circuit.circuit_data()
    }

    pub(crate) fn verify_proof(&self, proof: &[u8]) -> Result<()> {
        let proof = ProofWithVK::deserialize(proof)?;
        let (proof, _) = proof.into();
        self.circuit.circuit_data().verify(proof)
    }
}
