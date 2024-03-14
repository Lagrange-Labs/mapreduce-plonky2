//! The module implementing the required mechanisms for ‶Query 2″
//! https://www.notion.so/lagrangelabs/Cryptographic-Documentation-85adb821f18647b2a3dc65efbe144981?pvs=4#fa3f5d23a7724d0699a04f72bbec2a16

use plonky2::iop::target::Target;

use crate::array::Array;
mod full_inner;
mod leaf;
mod partial_inner;
mod public_inputs;
#[cfg(test)]
mod tests;

// TODO: use 32B for address for now, see later if we prefer 20B
type AddressTarget = Array<Target, 32>;
