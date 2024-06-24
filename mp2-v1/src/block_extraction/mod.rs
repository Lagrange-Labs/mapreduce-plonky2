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

#[derive(Debug, Serialize, Deserialize)]
pub struct Parameters {
    #[serde(serialize_with = "serialize", deserialize_with = "deserialize")]
    circuit_data: CircuitData<F, C, D>,
    wires: circuit::BlockWires,
}

impl Parameters {
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

    pub fn generate_proof(&self, block_header: Vec<u8>) -> Result<Vec<u8>> {
        let input = circuit::BlockCircuit::new(block_header)?;
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
        types::BlockNumber,
    };
    use mp2_common::eth::BlockUtil;
    use mp2_test::eth::get_sepolia_url;

    use crate::block_extraction::Parameters;
    #[tokio::test]
    async fn test_api() -> Result<()> {
        let params = Parameters::build();
        let url = get_sepolia_url();
        let provider = Provider::<Http>::try_from(url).unwrap();
        let block_number = BlockNumber::Latest;
        let block = provider.get_block(block_number).await.unwrap().unwrap();

        let rlp_headers = block.rlp();
        params.generate_proof(rlp_headers).unwrap();
        Ok(())
    }
}
