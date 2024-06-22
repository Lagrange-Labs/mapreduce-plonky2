use ethers::types::Address;
use mp2_common::{
    group_hashing::map_to_curve_point,
    utils::{Endianness, Packer, ToFields},
};
use plonky2_ecgfp5::curve::curve::Point as Digest;

mod api;
mod branch;
mod extension;
mod leaf;
mod public_inputs;

pub fn compute_metadata_digest(contract_addr: Address) -> Digest {
    let packed_contract_address: Vec<_> = contract_addr.0.pack(Endianness::Big).to_fields();

    map_to_curve_point(&packed_contract_address)
}

pub use api::{build_circuits_params, generate_proof, CircuitInput, PublicParameters};
pub use public_inputs::PublicInputs;
