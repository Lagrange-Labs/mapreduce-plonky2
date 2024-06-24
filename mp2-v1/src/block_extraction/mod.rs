use plonky2::{
    iop::witness::PartialWitness,
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitData, VerifierCircuitData},
    },
    util::serialization::gate_serialization::default,
};

mod circuit;
mod public_inputs;

use anyhow::Result;
use mp2_common::{
    serialization::{deserialize, serialize},
    C, D, F,
};
use serde::{Deserialize, Serialize};

use crate::api::{default_config, serialize_proof};
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
}

#[cfg(test)]
mod test {
    use anyhow::Result;
    use ethers::{
        providers::{Http, Middleware, Provider},
        types::{BlockNumber, U256, U64},
    };
    use mp2_common::{
        eth::BlockUtil,
        u256::U256PubInputs,
        utils::{Endianness, Packer, ToFields},
        C, D, F,
    };
    use mp2_test::eth::get_sepolia_url;

    use crate::{
        api::deserialize_proof,
        block_extraction::{public_inputs::PublicInputs, PublicParameters},
    };
    #[tokio::test]
    async fn test_api() -> Result<()> {
        let params = PublicParameters::build();
        let url = get_sepolia_url();
        let provider = Provider::<Http>::try_from(url).unwrap();
        let block_number = BlockNumber::Latest;
        let block = provider.get_block(block_number).await.unwrap().unwrap();

        let rlp_headers = CircuitInput::from_block_header(block.rlp());
        let proof = params.generate_proof(rlp_headers)?;
        // check public inputs
        let proof = deserialize_proof::<F, C, D>(&proof)?;
        let pi = PublicInputs::from_slice(&proof.public_inputs);
        assert_eq!(
            pi.block_hash_raw(),
            block
                .hash
                .unwrap()
                .as_bytes()
                .pack(Endianness::Little)
                .to_fields(),
        );
        assert_eq!(
            pi.prev_block_hash_raw(),
            block
                .parent_hash
                .as_bytes()
                .pack(Endianness::Little)
                .to_fields(),
        );
        assert_eq!(
            U256::from(U256PubInputs::try_from(pi.block_number_raw())?),
            U256::from(block.number.unwrap().as_ref()[0])
        );
        assert_eq!(
            pi.state_root_raw(),
            block
                .state_root
                .as_bytes()
                .pack(Endianness::Little)
                .to_fields(),
        );
        Ok(())
    }
}
