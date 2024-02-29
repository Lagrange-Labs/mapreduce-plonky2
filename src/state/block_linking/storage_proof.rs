//! This is the public inputs of previous storage proof, it's considered as
//! inputs of the current state proving process.

use crate::{keccak::OutputHash, utils::convert_u32_fields_to_u8_vec};
use ethers::types::{H160, H256};
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::circuit_builder::CircuitBuilder,
};
use plonky2_crypto::u32::arithmetic_u32::U32Target;
use std::array;

/// The previous storage public inputs are composed of:
/// - `D` Digest of all the values processed
/// - `C1` MPT root of blockchain storage trie
/// - `C2` Merkle root of LPN’s storage database (Merkle Tree)
/// - `A` Address of smart contract
/// - `M` Storage slot of the mapping
/// - `S` Storage slot of the variable holding the length
/// D = 5*2+1, C1 = C2 = 8, A = 5, M = 8, S = 1
pub const D_IDX: usize = 0;
pub const C1_IDX: usize = 11;
pub const C2_IDX: usize = 19;
pub const A_IDX: usize = 27;
pub const M_IDX: usize = 32;
pub const S_IDX: usize = 33;
pub const STORAGE_INPUT_LEN: usize = 34;

/// The public input values of previous storage proof
#[derive(Clone, Debug)]
pub struct StorageInputs<T> {
    pub inner: [T; STORAGE_INPUT_LEN],
}

/// Common functions
impl<T> StorageInputs<T> {
    pub fn mpt_root(&self) -> &[T] {
        &self.inner[C1_IDX..C2_IDX]
    }

    pub fn merkle_root(&self) -> &[T] {
        &self.inner[C2_IDX..A_IDX]
    }

    pub fn d(&self) -> &[T] {
        &self.inner[D_IDX..C1_IDX]
    }

    pub fn a(&self) -> &[T] {
        &self.inner[A_IDX..M_IDX]
    }

    pub fn m(&self) -> &[T] {
        &self.inner[M_IDX..S_IDX]
    }

    pub fn s(&self) -> &[T] {
        &self.inner[S_IDX..]
    }
}

pub type StorageInputsWires = StorageInputs<Target>;

impl StorageInputsWires {
    /// Get the hash target of storage MPT root (C1).
    pub fn mpt_root_target(&self) -> OutputHash {
        let data = self.mpt_root();
        array::from_fn(|i| U32Target(data[i])).into()
    }
}

/// The storage input gadget
impl<F> StorageInputs<F>
where
    F: RichField,
{
    /// Build for circuit.
    pub fn build<const D: usize>(cb: &mut CircuitBuilder<F, D>) -> StorageInputsWires
    where
        F: Extendable<D>,
    {
        StorageInputs {
            inner: array::from_fn(|_| cb.add_virtual_target()),
        }
    }

    /// Assign the wires.
    pub fn assign(&self, pw: &mut PartialWitness<F>, wires: &StorageInputsWires) {
        self.inner
            .iter()
            .zip(wires.inner)
            .for_each(|(value, target)| pw.set_target(target, *value));
    }

    /// Get the contract address (A).
    pub fn contract_address(&self) -> H160 {
        // The contract address is packed as [u32; 5] in public inputs. This
        // code converts it to [u8; 20] as H160.
        let bytes = convert_u32_fields_to_u8_vec(self.a());

        H160(bytes.try_into().unwrap())
    }

    /// Get the hash value of storage MPT root (C1).
    pub fn mpt_root_value(&self) -> H256 {
        // The root hash is packed as [u32; 8] in public inputs. This code
        // converts it to [u8; 32] as H256.
        let bytes = convert_u32_fields_to_u8_vec(&self.mpt_root());

        H256(bytes.try_into().unwrap())
    }
}
