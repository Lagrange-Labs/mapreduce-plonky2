//! Copied and modified from [snark-verifier](https://github.com/privacy-scaling-explorations/snark-verifier).

mod executor;
mod utils;

pub use executor::deploy_and_call;
pub use utils::compile_solidity;
