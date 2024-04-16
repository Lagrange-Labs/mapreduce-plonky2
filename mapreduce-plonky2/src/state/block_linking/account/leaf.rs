use ethers::types::H160;
use plonky2::{
    field::types::Field,
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::VerifierCircuitData,
        proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget},
    },
};
use recursion_framework::{
    circuit_builder::CircuitLogicWires,
    serialization::{deserialize, serialize},
};
use serde::{Deserialize, Serialize};

use crate::{
    api::verify_proof_fixed_circuit,
    array::{Array, Vector, VectorWire},
    keccak::{InputData, KeccakCircuit, KeccakWires, OutputByteHash},
    mpt_sequential::{Circuit as MPTCircuit, MPTKeyWire, MAX_LEAF_VALUE_LEN, PAD_LEN},
    rlp::decode_fixed_list,
    storage::PublicInputs as StorageInputs,
    types::{AddressTarget, ADDRESS_LEN},
    utils::{find_index_subvector, less_than},
};

use super::public_inputs::PublicInputs;
use anyhow::{Error, Result};

/// Keccak input padded length for address
const INPUT_PADDED_ADDRESS_LEN: usize = PAD_LEN(ADDRESS_LEN);

pub(crate) struct LeafCircuit<const NODE_LEN: usize> {
    contract_address: H160,
    /// The offset of storage root hash located in RLP encoded account node
    storage_root_offset: usize,
    node: Vec<u8>,
}
#[derive(Serialize, Deserialize)]
struct LeafWires<const NODE_LEN: usize>
where
    [(); PAD_LEN(NODE_LEN)]:,
{
    /// The contract address
    pub(super) contract_address: AddressTarget,
    /// The keccak wires computed from contract address, which is set to the
    /// state MPT root hash
    keccak_contract_address: KeccakWires<INPUT_PADDED_ADDRESS_LEN>,
    /// The offset of storage MPT root hash located in RLP encoded account node
    pub(crate) storage_root_offset: Target,
    node: VectorWire<Target, { PAD_LEN(NODE_LEN) }>,
    root: KeccakWires<{ PAD_LEN(NODE_LEN) }>,
}

type F = super::F;
type C = super::C;
const D: usize = super::D;

impl<const NODE_LEN: usize> LeafCircuit<NODE_LEN>
where
    [(); PAD_LEN(NODE_LEN)]:,
{
    fn build(cb: &mut CircuitBuilder<F, D>, storage_pi: &[Target]) -> LeafWires<NODE_LEN> {
        let zero = cb.zero();
        let t = cb._true();
        let contract_address = Array::new(cb);

        let storage_root_offset = cb.add_virtual_target();

        let node = VectorWire::<Target, { PAD_LEN(NODE_LEN) }>::new(cb);
        // always ensure theThanks all node is bytes at the beginning
        node.assert_bytes(cb);

        // Calculate the keccak hash of contract address, and use it as the
        // state MPT root hash.
        let mut arr = [cb.zero(); INPUT_PADDED_ADDRESS_LEN];
        arr[..ADDRESS_LEN].copy_from_slice(&contract_address.arr);
        let bytes_to_keccak = &VectorWire::<Target, INPUT_PADDED_ADDRESS_LEN> {
            real_len: cb.constant(F::from_canonical_usize(ADDRESS_LEN)),
            arr: Array { arr },
        };
        let keccak_contract_address = KeccakCircuit::hash_vector(cb, bytes_to_keccak);
        let expected_mpt_key =
            MPTKeyWire::init_from_u32_targets(cb, &keccak_contract_address.output_array);

        let leaf_hash = KeccakCircuit::<{ PAD_LEN(NODE_LEN) }>::hash_vector(cb, &node);
        // small optimization here as we only need to decode two items for a leaf, since we know it's a leaf
        let leaf_headers = decode_fixed_list::<_, _, 2>(cb, &node.arr.arr, zero);
        let (new_key, _, is_leaf) = MPTCircuit::<1, NODE_LEN>::advance_key_leaf_or_extension::<
            _,
            _,
            _,
            MAX_LEAF_VALUE_LEN,
        >(cb, &node.arr, &expected_mpt_key, &leaf_headers);
        cb.connect(t.target, is_leaf.target);

        let packed_address = contract_address.convert_u8_to_u32(cb); // always register the packed version

        let storage_pi = StorageInputs::from(storage_pi);
        PublicInputs::register(
            cb,
            &new_key,
            &packed_address,
            storage_pi.mapping_slot(),
            storage_pi.length_slot(),
            &leaf_hash.output_array,
            &storage_pi.digest(),
            &storage_pi.merkle_root(),
        );
        /* Verify the account node includes the hash of storage MPT root. */

        // Verify the offset of storage MPT root hash is within range. We use 7
        // bits for the range check since the account node is composed by
        // [nonce (U64), balance (U256), storage_hash (H256), code_hash (H256)]
        // and it has 104 bytes.
        let within_range = less_than(cb, storage_root_offset, node.real_len, 7);
        cb.connect(within_range.target, t.target);

        // Verify the account node includes the storage MPT root hash.
        let expected_storage_root: OutputByteHash = node.arr.extract_array(cb, storage_root_offset);
        expected_storage_root
            .convert_u8_to_u32(cb)
            .enforce_equal(cb, &storage_pi.mpt_root());

        LeafWires {
            contract_address,
            keccak_contract_address,
            storage_root_offset,
            node,
            root: leaf_hash,
        }
    }

    /// Assign the wires.
    fn assign(&self, pw: &mut PartialWitness<F>, wires: &LeafWires<NODE_LEN>) -> Result<()> {
        // Assign the contract address.
        wires
            .contract_address
            .assign(pw, &self.contract_address.0.map(F::from_canonical_u8));

        // Assign the keccak value of contract address.
        KeccakCircuit::<{ PAD_LEN(ADDRESS_LEN) }>::assign(
            pw,
            &wires.keccak_contract_address,
            &InputData::Assigned(
                &Vector::from_vec(&self.contract_address.0)
                    .expect("Cannot create vector input for keccak contract address"),
            ),
        );

        // Assign the offset of storage MPT root hash located in RLP encoded
        // account node.
        pw.set_target(
            wires.storage_root_offset,
            F::from_canonical_usize(self.storage_root_offset),
        );

        let pad_node =
            Vector::<u8, { PAD_LEN(NODE_LEN) }>::from_vec(&self.node).expect("invalid node given");
        wires.node.assign(pw, &pad_node);
        KeccakCircuit::<{ PAD_LEN(NODE_LEN) }>::assign(
            pw,
            &wires.root,
            &InputData::Assigned(&pad_node),
        );

        Ok(())
    }
}

const NUM_IO: usize = PublicInputs::<Target>::TOTAL_LEN;

#[derive(Serialize, Deserialize)]
pub(crate) struct LeafRecursiveWires<const NODE_LEN: usize>
where
    [(); PAD_LEN(NODE_LEN)]:,
{
    leaf_wires: LeafWires<NODE_LEN>,
    #[serde(serialize_with = "serialize", deserialize_with = "deserialize")]
    storage_proof: ProofWithPublicInputsTarget<D>,
}

pub(crate) struct LeafInput<const NODE_LEN: usize> {
    leaf_input: LeafCircuit<NODE_LEN>,
    storage_proof: ProofWithPublicInputs<F, C, D>,
}

impl<const NODE_LEN: usize> LeafInput<NODE_LEN> {
    pub(crate) fn new(
        contract_address: H160,
        node: Vec<u8>,
        storage_proof: ProofWithPublicInputs<F, C, D>,
    ) -> Result<Self> {
        // Find the storage root hash from account node.
        let storage_pi = StorageInputs::from(&storage_proof.public_inputs);
        let storage_root_bytes = storage_pi.mpt_root_value();
        let storage_root_offset = find_index_subvector(&node, &storage_root_bytes.0)
            .ok_or(Error::msg("storage root not found in node"))?;
        Ok(Self {
            leaf_input: LeafCircuit {
                contract_address,
                storage_root_offset,
                node,
            },
            storage_proof,
        })
    }
}

// Leaf circuit does not need to verify any proof of account circuit set, so the number of
// verifiers for `CircuitLogicWires` is 0
impl<const NODE_LEN: usize> CircuitLogicWires<F, D, 0> for LeafRecursiveWires<NODE_LEN>
where
    [(); PAD_LEN(NODE_LEN)]:,
{
    type CircuitBuilderParams = VerifierCircuitData<F, C, D>;

    type Inputs = LeafInput<NODE_LEN>;

    const NUM_PUBLIC_INPUTS: usize = NUM_IO;

    fn circuit_logic(
        builder: &mut CircuitBuilder<F, D>,
        _: [&ProofWithPublicInputsTarget<D>; 0],
        builder_parameters: Self::CircuitBuilderParams,
    ) -> Self {
        let storage_proof = verify_proof_fixed_circuit(builder, &builder_parameters);
        let leaf_wires = LeafCircuit::<NODE_LEN>::build(builder, &storage_proof.public_inputs);
        LeafRecursiveWires {
            leaf_wires,
            storage_proof,
        }
    }

    fn assign_input(&self, inputs: Self::Inputs, pw: &mut PartialWitness<F>) -> Result<()> {
        pw.set_proof_with_pis_target(&self.storage_proof, &inputs.storage_proof);
        inputs.leaf_input.assign(pw, &self.leaf_wires)
    }
}
