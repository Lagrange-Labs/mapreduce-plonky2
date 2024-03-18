use anyhow::Result;
use plonky2::plonk::{
    circuit_data::VerifierOnlyCircuitData,
    config::{GenericConfig, PoseidonGoldilocksConfig},
    proof::ProofWithPublicInputs,
};
use recursion_framework::serialization::{deserialize, serialize};
use serde::{Deserialize, Serialize};

pub use crate::storage::{
    self,
    length_extract::{self},
    lpn, mapping,
};

// TODO: put every references here. remove one from mapping
pub(crate) const D: usize = 2;
pub(crate) type C = PoseidonGoldilocksConfig;
pub(crate) type F = <C as GenericConfig<D>>::F;

pub enum CircuitInput {
    Mapping(mapping::CircuitInput),
    LengthExtract(storage::length_extract::CircuitInput),
    Storage(lpn::Input),
}

#[derive(Serialize, Deserialize)]
pub struct PublicParameters {
    mapping: mapping::PublicParameters,
    length_extract: length_extract::PublicParameters,
    lpn_storage: lpn::PublicParameters,
}

pub fn build_circuits_params() -> PublicParameters {
    PublicParameters {
        mapping: mapping::build_circuits_params(),
        length_extract: length_extract::PublicParameters::build(),
        lpn_storage: lpn::PublicParameters::build(),
    }
}

pub fn generate_proof(params: &PublicParameters, input: CircuitInput) -> Result<Vec<u8>> {
    match input {
        CircuitInput::Mapping(mapping_input) => {
            mapping::generate_proof(&params.mapping, mapping_input)
        }
        CircuitInput::LengthExtract(length_extract_input) => {
            params.length_extract.generate(length_extract_input)
        }
        CircuitInput::Storage(storage_input) => params.lpn_storage.generate_proof(storage_input),
    }
}

/// ProofWithVK is a generic struct holding a child proof and its associated verification key.
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub(crate) struct ProofWithVK {
    pub(crate) proof: ProofWithPublicInputs<F, C, D>,
    #[serde(serialize_with = "serialize", deserialize_with = "deserialize")]
    pub(crate) vk: VerifierOnlyCircuitData<C, D>,
}

impl ProofWithVK {
    pub(crate) fn serialize(&self) -> Result<Vec<u8>> {
        let buff = bincode::serialize(&self)?;
        Ok(buff)
    }

    pub(crate) fn deserialize(buff: &[u8]) -> Result<Self> {
        let s = bincode::deserialize(buff)?;
        Ok(s)
    }
}

impl
    From<(
        ProofWithPublicInputs<F, C, D>,
        VerifierOnlyCircuitData<C, D>,
    )> for ProofWithVK
{
    fn from(
        (proof, vk): (
            ProofWithPublicInputs<F, C, D>,
            VerifierOnlyCircuitData<C, D>,
        ),
    ) -> Self {
        ProofWithVK { proof, vk }
    }
}

#[cfg(test)]
mod test {
    use std::sync::Arc;

    use eth_trie::{EthTrie, MemoryDB, Trie};
    use plonky2::field::goldilocks_field::GoldilocksField;
    use plonky2::field::types::Field;

    use crate::{api::ProofWithVK, eth::StorageSlot, utils::test::random_vector};

    #[test]
    fn test_mapping() {
        let memdb = Arc::new(MemoryDB::new(true));
        let mut trie = EthTrie::new(memdb.clone());

        let key1 = [1; 20].to_vec();
        let val1 = [2; 32].to_vec();
        let slot1 = StorageSlot::Mapping(key1.clone(), 0);
        let mpt_key1 = slot1.mpt_key();

        let key2 = [3; 20].to_vec();
        let val2 = [4; 32].to_vec();
        let slot2 = StorageSlot::Mapping(key2.clone(), 0);
        let mpt_key2 = slot2.mpt_key();

        trie.insert(&mpt_key1, &val1).unwrap();
        trie.insert(&mpt_key2, &val2).unwrap();
        trie.root_hash().unwrap();

        let proof1 = trie.get_proof(&mpt_key1).unwrap();
        let proof2 = trie.get_proof(&mpt_key2).unwrap();

        assert_eq!(proof1.len(), 2);
        assert_eq!(proof2.len(), 2);
        assert_eq!(proof1[0], proof2[0]);
        assert!(rlp::decode_list::<Vec<u8>>(&proof1[0]).len() == 17);
        use crate::storage::mapping::{self};
        println!("Generating params...");
        let params = mapping::api::build_circuits_params();
        println!("Proving leaf 1...");

        let leaf_input1 = mapping::CircuitInput::new_leaf(proof1[1].clone(), 0, key1);
        let leaf_proof1 = mapping::api::generate_proof(&params, leaf_input1).unwrap();
        {
            let lp = ProofWithVK::deserialize(&leaf_proof1).unwrap();
            let pub1 = mapping::PublicInputs::from(&lp.proof.public_inputs);
            let (_, ptr) = pub1.mpt_key_info();
            assert_eq!(ptr, GoldilocksField::ZERO);
        }

        println!("Proving leaf 2...");

        let leaf_input2 = mapping::CircuitInput::new_leaf(proof2[1].clone(), 0, key2);

        let leaf_proof2 = mapping::api::generate_proof(&params, leaf_input2).unwrap();

        println!("Proving branch...");

        let branch_input = mapping::api::CircuitInput::new_branch(
            proof1[0].clone(),
            vec![leaf_proof1, leaf_proof2],
            //vec![leaf_proof1],
        );

        mapping::api::generate_proof(&params, branch_input).unwrap();
    }
}
