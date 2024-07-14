use plonky2::{
    iop::witness::PartialWitness,
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitData, VerifierCircuitData},
    },
    util::serialization::gate_serialization::default,
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
        rpc::types::BlockTransactionsKind,
    };
    use anyhow::Result;
    use mp2_common::{
        eth::BlockUtil,
        proof::deserialize_proof,
        u256::U256PubInputs,
        utils::{keccak256, Endianness, FromFields, Packer, ToFields},
        C, D, F,
    };
    use mp2_test::eth::get_sepolia_url;

    use crate::block_extraction::{public_inputs::PublicInputs, PublicParameters};
    #[tokio::test]
    async fn test_api() -> Result<()> {
        let params = PublicParameters::build();
        println!("parameters built");
        let url = get_sepolia_url();
        let provider = ProviderBuilder::new().on_http(url.parse().unwrap());
        let bn = provider.get_block_number().await.unwrap();
        // first do it on the previous block header to fetch its hash, and then fetch the next one
        // to compare the hashes computed by ethers and the one we compute manually.
        let block_number = BlockNumberOrTag::Number(bn - 1);
        let block = provider
            .get_block(block_number.into(), BlockTransactionsKind::Hashes)
            .await
            .unwrap()
            .unwrap();
        println!(" first block fetched");
        let prev_block_hash = block
            .header
            .parent_hash
            .0
            .pack(Endianness::Little)
            .to_fields();

        let rlp_headers = super::CircuitInput::from_block_header(block.rlp());
        let proof = params.generate_proof(rlp_headers)?;
        println!(" proof generation done");
        // check public inputs
        let proof = deserialize_proof::<F, C, D>(&proof)?;
        let pi = PublicInputs::from_slice(&proof.public_inputs);
        let block_hash_manual = keccak256(&block.rlp()).pack(Endianness::Little).to_fields();
        assert_eq!(pi.block_hash_raw(), block_hash_manual);

        assert_eq!(
            pi.block_hash_raw(),
            block
                .header
                .hash
                .unwrap()
                .pack(Endianness::Little)
                .to_fields(),
        );

        assert_eq!(pi.prev_block_hash_raw(), prev_block_hash);
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
            U256::from(block.header.number.unwrap()),
        );
        assert_eq!(
            pi.state_root_raw(),
            block.header.state_root.pack(Endianness::Little).to_fields(),
        );
        let next_block = provider
            .get_block_by_number(BlockNumberOrTag::Number(bn), true)
            .await
            .unwrap()
            .unwrap();
        let next_previous_hash = next_block
            .header
            .parent_hash
            .pack(Endianness::Little)
            .to_fields();
        assert_eq!(block_hash_manual, next_previous_hash);

        Ok(())
    }
}
