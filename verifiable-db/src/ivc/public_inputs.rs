use ethers::types::U256;
use mp2_common::{
    keccak::PACKED_HASH_LEN,
    public_inputs::{PublicInputCommon, PublicInputRange},
    types::CURVE_TARGET_LEN,
    u256::{self, U256PubInputs, UInt256Target},
    utils::{FromFields, FromTargets, ToTargets},
    F,
};
use plonky2::{
    hash::hash_types::{HashOut, HashOutTarget, NUM_HASH_OUT_ELTS},
    iop::target::Target,
};
use plonky2_ecgfp5::{curve::curve::WeierstrassPoint, gadgets::curve::CurveTarget};

/// -  H: new (Merkle) root
/// - `DM` : metadata hash representing the extraction of the data from storage slots and insertion in the expected columns of the table being built
/// - `DV` : order-agnostic digest of the block tree, useful in case we want to build another index tree with a different index column
/// - **IVC Information - specific to blockchain:**
///     - `$z_0$`: first block number inserted (as u256, represented by  8 32-bit limbs)
///     - `$z_i$` : last block number inserted (as u256, represented by  8 32-bit limbs)
///     - `$O_{z_i}$`: original (blockchain) header hash of the last block inserted
pub struct PublicInputs<T> {
    h: Vec<T>,
    dm: Vec<T>,
    dv: Vec<T>,
    z0: Vec<T>,
    zi: Vec<T>,
    o: Vec<T>,
}

const INDEX_LEN: usize = u256::NUM_LIMBS;
const H_RANGE: PublicInputRange = 0..NUM_HASH_OUT_ELTS;
const DM_RANGE: PublicInputRange = H_RANGE.end..H_RANGE.end + CURVE_TARGET_LEN;
const DV_RANGE: PublicInputRange = DM_RANGE.end..DM_RANGE.end + CURVE_TARGET_LEN;
const Z0_RANGE: PublicInputRange = DV_RANGE.end..DV_RANGE.end + INDEX_LEN;
const ZI_RANGE: PublicInputRange = Z0_RANGE.end..Z0_RANGE.end + INDEX_LEN;
const O_RANGE: PublicInputRange = ZI_RANGE.end..ZI_RANGE.end + PACKED_HASH_LEN;

impl PublicInputCommon for PublicInputs<Target> {
    const RANGES: &'static [PublicInputRange] =
        &[H_RANGE, DM_RANGE, DV_RANGE, Z0_RANGE, ZI_RANGE, O_RANGE];

    fn register_args(&self, cb: &mut mp2_common::types::CBuilder) {
        cb.register_public_inputs(&self.h);
        cb.register_public_inputs(&self.dm);
        cb.register_public_inputs(&self.dv);
        cb.register_public_inputs(&self.z0);
        cb.register_public_inputs(&self.zi);
        cb.register_public_inputs(&self.o);
    }
}

impl<T: Clone> PublicInputs<T> {
    pub(crate) const TOTAL_LEN: usize = O_RANGE.end;
    pub fn new(
        h: Vec<T>,
        dm: Vec<T>,
        dv: Vec<T>,
        z0: Vec<T>,
        zi: Vec<T>,
        original_hash: Vec<T>,
    ) -> Self {
        assert_eq!(h.len(), H_RANGE.len());
        assert_eq!(dm.len(), DM_RANGE.len());
        assert_eq!(dv.len(), DV_RANGE.len());
        assert_eq!(z0.len(), Z0_RANGE.len());
        assert_eq!(zi.len(), ZI_RANGE.len());
        assert_eq!(original_hash.len(), O_RANGE.len());

        Self {
            h,
            dm,
            dv,
            z0,
            zi,
            o: original_hash,
        }
    }
    pub fn from_slice(s: &[T]) -> Self {
        assert!(s.len() >= Self::TOTAL_LEN);
        Self {
            h: s[H_RANGE].to_vec(),
            dm: s[DM_RANGE].to_vec(),
            dv: s[DV_RANGE].to_vec(),
            z0: s[Z0_RANGE].to_vec(),
            zi: s[ZI_RANGE].to_vec(),
            o: s[O_RANGE].to_vec(),
        }
    }

    pub fn original_hash(&self) -> Vec<T> {
        self.o.clone()
    }
}

impl PublicInputs<Target> {
    pub fn merkle_hash(&self) -> HashOutTarget {
        HashOutTarget {
            elements: self.h.clone().try_into().unwrap(),
        }
    }

    pub fn z0(&self) -> UInt256Target {
        UInt256Target::from_targets(&self.z0)
    }
    pub fn zi(&self) -> UInt256Target {
        UInt256Target::from_targets(&self.zi)
    }

    pub fn metadata_set_digest(&self) -> CurveTarget {
        CurveTarget::from_targets(&self.dm)
    }

    pub fn value_set_digest(&self) -> CurveTarget {
        CurveTarget::from_targets(&self.dv)
    }

    pub fn block_hash(&self) -> Vec<Target> {
        self.o.to_targets()
    }
}

impl PublicInputs<F> {
    pub fn root_hash(&self) -> HashOut<F> {
        HashOut {
            elements: self.h.clone().try_into().unwrap(),
        }
    }

    pub fn metadata_set_digest_point(&self) -> WeierstrassPoint {
        WeierstrassPoint::from_fields(&self.dm)
    }

    pub fn value_set_digest_point(&self) -> WeierstrassPoint {
        WeierstrassPoint::from_fields(&self.dv)
    }
    pub fn z0_u256(&self) -> U256 {
        U256::from(U256PubInputs::try_from(self.z0.as_slice()).unwrap())
    }

    pub fn zi_u256(&self) -> U256 {
        U256::from(U256PubInputs::try_from(self.zi.as_slice()).unwrap())
    }

    pub fn to_vec(&self) -> Vec<F> {
        let mut res = vec![];
        res.extend(&self.h);
        res.extend(&self.dm);
        res.extend(&self.dv);
        res.extend(&self.z0);
        res.extend(&self.zi);
        res.extend(&self.original_hash());
        res
    }
}
