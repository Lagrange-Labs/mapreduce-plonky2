use plonky2::{
    iop::witness::PartialWitness,
    plonk::{circuit_builder::CircuitBuilder, circuit_data::CircuitData},
};

mod circuit;
pub(crate) mod public_inputs;

use anyhow::Result;
use mp2_common::{
    default_config,
    proof::serialize_proof,
    serialization::{deserialize, serialize},
    C, D, F,
};
use serde::{Deserialize, Serialize};

pub use public_inputs::PublicInputs;
pub struct CircuitInput(Vec<u8>);
impl CircuitInput {
    pub fn from_block_header(rlp_header: Vec<u8>) -> Self {
        Self(rlp_header)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PublicParameters {
    #[serde(serialize_with = "serialize", deserialize_with = "deserialize")]
    circuit_data: CircuitData<F, C, D>,
    wires: circuit::BlockWires,
}

/// Returns the parameters necessary to prove block extraction circuits
pub fn build_circuits_params() -> PublicParameters {
    PublicParameters::build()
}

impl PublicParameters {
    pub fn build() -> Self {
        let config = default_config();
        let mut cb = CircuitBuilder::new(config);
        let wires = circuit::BlockCircuit::build(&mut cb);
        let cd = cb.build();
        Self {
            circuit_data: cd,
            wires,
        }
    }

    pub fn generate_proof(&self, block_header: CircuitInput) -> Result<Vec<u8>> {
        let input = circuit::BlockCircuit::new(block_header.0)?;
        let mut pw = PartialWitness::new();
        input.assign(&mut pw, &self.wires);
        let proof = self.circuit_data.prove(pw)?;
        serialize_proof(&proof)
    }

    pub fn circuit_data(&self) -> &CircuitData<F, C, D> {
        &self.circuit_data
    }
}

#[cfg(test)]
mod test {
    use alloy::{
        eips::BlockNumberOrTag,
        primitives::U256,
        providers::{Provider, ProviderBuilder},
    };
    use anyhow::Result;
    use mp2_common::{
        eth::Rlpable,
        proof::deserialize_proof,
        utils::{Endianness, FromFields, Packer, ToFields},
        C, D, F,
    };
    use mp2_test::eth::get_sepolia_url;

    use crate::block_extraction::{public_inputs::PublicInputs, PublicParameters};
    #[tokio::test]
    async fn test_api() -> Result<()> {
        let params = PublicParameters::build();
        let url = get_sepolia_url();
        let provider = ProviderBuilder::new().on_http(url.parse().unwrap());
        let block_number = BlockNumberOrTag::Latest;
        let block = provider
            .get_block_by_number(block_number, true.into())
            .await
            .unwrap()
            .unwrap();

        let rlp_headers = super::CircuitInput::from_block_header(block.rlp());
        let proof = params.generate_proof(rlp_headers)?;
        // check public inputs
        let proof = deserialize_proof::<F, C, D>(&proof)?;
        let pi = PublicInputs::from_slice(&proof.public_inputs);
        assert_eq!(
            pi.block_hash_raw(),
            block.block_hash().pack(Endianness::Little).to_fields()
        );
        // sanity check to know we generate the hash the same way as what is included in headers
        assert_eq!(
            pi.block_hash_raw(),
            block
                .header
                .hash
                // XXX unclear why that fails when one removes the ".0" since we access things
                // directly underneath when calling pack directly or using as_slice, both fail.
                // XXX unclear why it is needed here but not for previous hash...
                .0
                .pack(Endianness::Little)
                .to_fields(),
        );
        assert_eq!(
            pi.prev_block_hash_raw(),
            block
                .header
                .parent_hash
                .pack(Endianness::Little)
                .to_fields(),
        );
        assert_eq!(
            U256::from_fields(pi.block_number_raw()),
<<<<<<< HEAD
            U256::from(block.header.number),
=======
            U256::from(block.header.number)
>>>>>>> 6072e82 (test with receipts encoding)
        );
        assert_eq!(
            pi.state_root_raw(),
            block.header.state_root.pack(Endianness::Little).to_fields(),
        );
        Ok(())
    }
}
