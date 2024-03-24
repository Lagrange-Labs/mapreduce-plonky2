//! Compile Go functions and export to Rust

mod compile;
mod prove;
mod verify;

pub use compile::compile_and_generate_assets;
pub use prove::{init_prover, prove};
pub use verify::{init_verifier, verify};

mod go {
    use std::os::raw::c_char;

    extern "C" {
        /// Compile and generate asset files from circuit data to the specified
        /// dir. The generated files are `r1cs.bin`, `pk.bin` and `vk.bin`.
        pub fn CompileAndGenerateAssets(
            common_circuit_data: *const c_char,
            verifier_only_circuit_data: *const c_char,
            proof_with_public_inputs: *const c_char,
            dst_asset_dir: *const c_char,
        ) -> *const c_char;

        /// Initialize the prover. The asset dir must include `r1cs.bin` and
        /// `pk.bin`.
        pub fn InitProver(asset_dir: *const c_char) -> *const c_char;

        /// Generate the proof from data. The InitProver function must be called
        /// before.
        pub fn Prove(
            verifier_only_circuit_data: *const c_char,
            proof_with_public_inputs: *const c_char,
        ) -> (*const c_char, *const c_char);

        /// Initialize the verifier. The asset dir must include `vk.bin`.
        pub fn InitVerifier(asset_dir: *const c_char) -> *const c_char;

        /// Verify the proof. Return true if it's verified successfully, false
        /// otherwise.
        pub fn Verify(proof: *const c_char) -> *const c_char;

        /// Free the C String returned from Go to Rust.
        pub fn FreeString(s: *const c_char);
    }
}
