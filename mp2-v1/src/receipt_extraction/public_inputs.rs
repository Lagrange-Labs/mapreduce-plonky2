//! Public inputs for Receipt Extraction circuits

use mp2_common::{
    keccak::{OutputHash, PACKED_HASH_LEN},
    mpt_sequential::ReceiptKeyWire,
    public_inputs::{PublicInputCommon, PublicInputRange},
    types::{CBuilder, CURVE_TARGET_LEN},
};
use plonky2::hash::hash_types::{HashOutTarget, NUM_HASH_OUT_ELTS};

use plonky2_ecgfp5::gadgets::curve::{CircuitBuilderEcGFp5, CurveTarget};

/// The maximum length of a transaction index in a block in nibbles.
/// Theoretically a block can have up to 1428 transactions in Ethereum, which takes 3 bytes to represent.
const MAX_INDEX_NIBBLES: usize = 6;
// Contract extraction public Inputs:
/// - `H : [8]F` : packed node hash
const H_RANGE: PublicInputRange = 0..PACKED_HASH_LEN;
/// - `K : [6]F` : Length of the transaction index in nibbles
const K_RANGE: PublicInputRange = H_RANGE.end..H_RANGE.end + MAX_INDEX_NIBBLES;
/// `T : F` pointer in the MPT indicating portion of the key already traversed (from 6 → 0)
const T_RANGE: PublicInputRange = K_RANGE.end..K_RANGE.end + 1;
/// - `DV : Digest[F]` : value digest of all rows to extract
const DV_RANGE: PublicInputRange = T_RANGE.end..T_RANGE.end + CURVE_TARGET_LEN;
/// - `DM : Digest[F]` : metadata digest to extract
const DM_RANGE: PublicInputRange = DV_RANGE.end..DV_RANGE.end + NUM_HASH_OUT_ELTS;

/// Public inputs for contract extraction
#[derive(Clone, Debug)]
pub struct PublicInputArgs<'a> {
    /// The hash of the node
    pub(crate) h: &'a OutputHash,
    /// The MPT key
    pub(crate) k: &'a ReceiptKeyWire,
    /// Digest of the values
    pub(crate) dv: CurveTarget,
    /// The poseidon hash of the metadata
    pub(crate) dm: HashOutTarget,
}

impl<'a> PublicInputCommon for PublicInputArgs<'a> {
    const RANGES: &'static [PublicInputRange] = &[H_RANGE, K_RANGE, T_RANGE, DV_RANGE, DM_RANGE];

    fn register_args(&self, cb: &mut CBuilder) {
        self.generic_register_args(cb)
    }
}

impl<'a> PublicInputArgs<'a> {
    /// Create a new public inputs.
    pub fn new(
        h: &'a OutputHash,
        k: &'a ReceiptKeyWire,
        dv: CurveTarget,
        dm: HashOutTarget,
    ) -> Self {
        Self { h, k, dv, dm }
    }
}

impl<'a> PublicInputArgs<'a> {
    pub fn generic_register_args(&self, cb: &mut CBuilder) {
        self.h.register_as_public_input(cb);
        self.k.register_as_input(cb);
        cb.register_curve_public_input(self.dv);
        cb.register_public_inputs(&self.dm.elements);
    }

    pub fn digest_value(&self) -> CurveTarget {
        self.dv
    }

    pub fn digest_metadata(&self) -> HashOutTarget {
        self.dm
    }
}
