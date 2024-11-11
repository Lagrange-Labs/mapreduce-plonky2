//! Public inputs for Receipt Extraction circuits

use mp2_common::{
    array::Array,
    keccak::{OutputHash, PACKED_HASH_LEN},
    mpt_sequential::ReceiptKeyWire,
    public_inputs::{PublicInputCommon, PublicInputRange},
    types::{CBuilder, GFp, GFp5, CURVE_TARGET_LEN},
    utils::{convert_point_to_curve_target, convert_slice_to_curve_point, FromTargets},
};

use plonky2::{
    field::{extension::FieldExtension, types::Field},
    iop::target::Target,
};
use plonky2_ecgfp5::{
    curve::curve::WeierstrassPoint,
    gadgets::curve::{CircuitBuilderEcGFp5, CurveTarget},
};

/// The maximum length of a transaction index in a block in nibbles.
/// Theoretically a block can have up to 1428 transactions in Ethereum, which takes 2 bytes to represent.
const MAX_INDEX_NIBBLES: usize = 4;
// Contract extraction public Inputs:
/// - `H : [8]F` : packed node hash
const H_RANGE: PublicInputRange = 0..PACKED_HASH_LEN;
/// - `K : [4]F` : Length of the transaction index in nibbles
const K_RANGE: PublicInputRange = H_RANGE.end..H_RANGE.end + MAX_INDEX_NIBBLES;
/// `T : F` pointer in the MPT indicating portion of the key already traversed (from 4 → 0)
const T_RANGE: PublicInputRange = K_RANGE.end..K_RANGE.end + 1;
/// - `DV : Digest[F]` : value digest of all rows to extract
const DV_RANGE: PublicInputRange = T_RANGE.end..T_RANGE.end + CURVE_TARGET_LEN;
/// - `DM : Digest[F]` : metadata digest to extract
const DM_RANGE: PublicInputRange = DV_RANGE.end..DV_RANGE.end + CURVE_TARGET_LEN;

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
    pub(crate) dm: CurveTarget,
}

impl<'a> PublicInputCommon for PublicInputArgs<'a> {
    const RANGES: &'static [PublicInputRange] = &[H_RANGE, K_RANGE, T_RANGE, DV_RANGE, DM_RANGE];

    fn register_args(&self, cb: &mut CBuilder) {
        self.generic_register_args(cb)
    }
}

impl<'a> PublicInputArgs<'a> {
    /// Create a new public inputs.
    pub fn new(h: &'a OutputHash, k: &'a ReceiptKeyWire, dv: CurveTarget, dm: CurveTarget) -> Self {
        Self { h, k, dv, dm }
    }
}

impl<'a> PublicInputArgs<'a> {
    pub fn generic_register_args(&self, cb: &mut CBuilder) {
        self.h.register_as_public_input(cb);
        self.k.register_as_input(cb);
        cb.register_curve_public_input(self.dv);
        cb.register_curve_public_input(self.dm);
    }

    pub fn digest_value(&self) -> CurveTarget {
        self.dv
    }

    pub fn digest_metadata(&self) -> CurveTarget {
        self.dm
    }
}

/// Public inputs wrapper of any proof generated in this module
#[derive(Clone, Debug)]
pub struct PublicInputs<'a, T> {
    pub(crate) proof_inputs: &'a [T],
}

impl PublicInputs<'_, Target> {
    /// Get the merkle hash of the subtree this proof has processed.
    pub fn root_hash_target(&self) -> OutputHash {
        OutputHash::from_targets(self.root_hash_info())
    }

    /// Get the MPT key defined over the public inputs.
    pub fn mpt_key(&self) -> ReceiptKeyWire {
        let (key, ptr) = self.mpt_key_info();
        ReceiptKeyWire {
            key: Array {
                arr: std::array::from_fn(|i| key[i]),
            },
            pointer: ptr,
        }
    }

    /// Get the values digest defined over the public inputs.
    pub fn values_digest_target(&self) -> CurveTarget {
        convert_point_to_curve_target(self.values_digest_info())
    }

    /// Get the metadata digest defined over the public inputs.
    pub fn metadata_digest_target(&self) -> CurveTarget {
        convert_point_to_curve_target(self.metadata_digest_info())
    }
}

impl PublicInputs<'_, GFp> {
    /// Get the merkle hash of the subtree this proof has processed.
    pub fn root_hash(&self) -> Vec<u32> {
        let hash = self.root_hash_info();
        hash.iter().map(|t| t.0 as u32).collect()
    }

    /// Get the values digest defined over the public inputs.
    pub fn values_digest(&self) -> WeierstrassPoint {
        let (x, y, is_inf) = self.values_digest_info();

        WeierstrassPoint {
            x: GFp5::from_basefield_array(std::array::from_fn::<GFp, 5, _>(|i| x[i])),
            y: GFp5::from_basefield_array(std::array::from_fn::<GFp, 5, _>(|i| y[i])),
            is_inf: is_inf.is_nonzero(),
        }
    }

    /// Get the metadata digest defined over the public inputs.
    pub fn metadata_digest(&self) -> WeierstrassPoint {
        let (x, y, is_inf) = self.metadata_digest_info();

        WeierstrassPoint {
            x: GFp5::from_basefield_array(std::array::from_fn::<GFp, 5, _>(|i| x[i])),
            y: GFp5::from_basefield_array(std::array::from_fn::<GFp, 5, _>(|i| y[i])),
            is_inf: is_inf.is_nonzero(),
        }
    }
}

impl<'a, T: Copy> PublicInputs<'a, T> {
    pub(crate) const TOTAL_LEN: usize = DM_RANGE.end;

    pub fn new(proof_inputs: &'a [T]) -> Self {
        Self { proof_inputs }
    }

    pub fn root_hash_info(&self) -> &[T] {
        &self.proof_inputs[H_RANGE]
    }

    pub fn mpt_key_info(&self) -> (&[T], T) {
        let key = &self.proof_inputs[K_RANGE];
        let ptr = self.proof_inputs[T_RANGE.start];

        (key, ptr)
    }

    pub fn values_digest_info(&self) -> ([T; 5], [T; 5], T) {
        convert_slice_to_curve_point(&self.proof_inputs[DV_RANGE])
    }

    pub fn metadata_digest_info(&self) -> ([T; 5], [T; 5], T) {
        convert_slice_to_curve_point(&self.proof_inputs[DM_RANGE])
    }
}
