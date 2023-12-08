#![warn(missing_docs)]
#![feature(generic_const_exprs)]

use plonky2::plonk::{
    circuit_data::{CommonCircuitData, VerifierOnlyCircuitData},
    proof::ProofWithPublicInputs,
};

mod eth;
mod hash;
mod rlp;
mod transaction;
mod utils;
mod benches;

/// Bundle containing the raw proof, the verification key, and some common data
/// necessary for prover and verifier.
pub(crate) type ProofTuple<F, C, const D: usize> = (
    ProofWithPublicInputs<F, C, D>,
    VerifierOnlyCircuitData<C, D>,
    CommonCircuitData<F, D>,
);
