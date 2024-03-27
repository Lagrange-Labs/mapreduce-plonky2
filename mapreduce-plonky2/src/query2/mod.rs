//! The module implementing the required mechanisms for ‶Query 2″
//! https://www.notion.so/lagrangelabs/Cryptographic-Documentation-85adb821f18647b2a3dc65efbe144981?pvs=4#fa3f5d23a7724d0699a04f72bbec2a16

use crate::{array::Array, types::PACKED_ADDRESS_LEN as PACKED_SC_ADDRESS_LEN};

pub mod api;
pub mod block;
pub mod revelation;
pub mod state;
pub mod storage;

pub use api::{CircuitInput, PublicParameters};
#[cfg(test)]
mod tests;

pub(crate) type PackedSCAddress<F> = Array<F, PACKED_SC_ADDRESS_LEN>;
