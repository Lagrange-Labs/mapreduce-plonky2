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
use std::array::from_fn as create_array;

/// -  H: new (Merkle) root
/// - `DM` : metadata hash representing the extraction of the data from storage slots and insertion in the expected columns of the table being built.
/// It's represented as a hash since more efficient to pass along in public inputs.
/// - `DV` : order-agnostic digest of the block tree, useful in case we want to build another index tree with a different index column
/// - **IVC Information - specific to blockchain:**
///     - `$z_0$`: first block number inserted (as u256, represented by  8 32-bit limbs)
///     - `$z_i$` : last block number inserted (as u256, represented by  8 32-bit limbs)
///     - `$O_{z_i}$`: original (blockchain) header hash of the last block inserted
pub struct PublicInputs<'a, T> {
    h: &'a [T],
    dm: &'a [T],
    dv: &'a [T],
    z0: &'a [T],
    zi: &'a [T],
    o: &'a [T],
}

const INDEX_LEN: usize = u256::NUM_LIMBS;
const H_RANGE: PublicInputRange = 0..NUM_HASH_OUT_ELTS;
const DM_RANGE: PublicInputRange = H_RANGE.end..H_RANGE.end + NUM_HASH_OUT_ELTS;
const DV_RANGE: PublicInputRange = DM_RANGE.end..DM_RANGE.end + CURVE_TARGET_LEN;
const Z0_RANGE: PublicInputRange = DV_RANGE.end..DV_RANGE.end + INDEX_LEN;
const ZI_RANGE: PublicInputRange = Z0_RANGE.end..Z0_RANGE.end + INDEX_LEN;
const O_RANGE: PublicInputRange = ZI_RANGE.end..ZI_RANGE.end + PACKED_HASH_LEN;

impl<'a> PublicInputCommon for PublicInputs<'a, Target> {
    const RANGES: &'static [PublicInputRange] =
        &[H_RANGE, DM_RANGE, DV_RANGE, Z0_RANGE, ZI_RANGE, O_RANGE];

    fn register_args(&self, cb: &mut mp2_common::types::CBuilder) {
        cb.register_public_inputs(self.h);
        cb.register_public_inputs(self.dm);
        cb.register_public_inputs(self.dv);
        cb.register_public_inputs(self.z0);
        cb.register_public_inputs(self.zi);
        cb.register_public_inputs(self.o);
    }
}

impl<'a, T: Clone> PublicInputs<'a, T> {
    pub(crate) const TOTAL_LEN: usize = O_RANGE.end;
    pub fn new(
        h: &'a [T],
        dm: &'a [T],
        dv: &'a [T],
        z0: &'a [T],
        zi: &'a [T],
        original_hash: &'a [T],
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
    pub fn from_slice(s: &'a [T]) -> Self {
        assert!(s.len() >= Self::TOTAL_LEN);
        Self {
            h: &s[H_RANGE],
            dm: &s[DM_RANGE],
            dv: &s[DV_RANGE],
            z0: &s[Z0_RANGE],
            zi: &s[ZI_RANGE],
            o: &s[O_RANGE],
        }
    }

    pub fn original_hash_raw(&self) -> &[T] {
        self.o
    }

    pub fn metadata_hash(&self) -> &[T] {
        self.dm
    }
}

impl<'a> PublicInputs<'a, Target> {
    pub fn merkle_hash(&self) -> HashOutTarget {
        HashOutTarget {
            elements: self.h.try_into().unwrap(),
        }
    }

    pub fn z0(&self) -> UInt256Target {
        UInt256Target::from_targets(self.z0)
    }
    pub fn zi(&self) -> UInt256Target {
        UInt256Target::from_targets(self.zi)
    }

    pub fn value_set_digest(&self) -> CurveTarget {
        CurveTarget::from_targets(self.dv)
    }

    pub fn block_hash(&self) -> Vec<Target> {
        self.o.to_targets()
    }
}

impl<'a> PublicInputs<'a, F> {
    pub fn merkle_root_hash_fields(&self) -> HashOut<F> {
        HashOut {
            elements: self.h.try_into().unwrap(),
        }
    }

    pub fn value_set_digest_point(&self) -> WeierstrassPoint {
        WeierstrassPoint::from_fields(self.dv)
    }
    pub fn z0_u256(&self) -> U256 {
        U256::from_fields(self.z0)
    }

    pub fn zi_u256(&self) -> U256 {
        U256::from_fields(self.zi)
    }

    pub fn block_hash_fields(&self) -> [F; PACKED_HASH_LEN] {
        create_array(|i| self.o[i])
    }

    pub fn to_vec(&self) -> Vec<F> {
        let mut res = vec![];
        res.extend(self.h);
        res.extend(self.metadata_hash());
        res.extend(self.dv);
        res.extend(self.z0);
        res.extend(self.zi);
        res.extend(self.original_hash_raw());
        res
    }
}

#[cfg(test)]
mod tests {

    use mp2_common::{utils::ToFields, C, D};
    use mp2_test::{
        circuit::{run_circuit, UserCircuit},
        utils::random_vector,
    };
    use plonky2::{
        field::types::Sample,
        iop::witness::{PartialWitness, WitnessWrite},
        plonk::circuit_builder::CircuitBuilder,
    };
    use plonky2_ecgfp5::curve::curve::Point;

    use super::*;

    #[derive(Clone, Debug)]
    struct TestPICircuit<'a> {
        exp_pi: &'a [F],
    }

    impl<'a> UserCircuit<F, D> for TestPICircuit<'a> {
        type Wires = Vec<Target>;

        fn build(b: &mut CircuitBuilder<F, D>) -> Self::Wires {
            let pi = b.add_virtual_targets(PublicInputs::<Target>::TOTAL_LEN);
            PublicInputs::from_slice(&pi).register(b);

            pi
        }

        fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
            pw.set_target_arr(wires, self.exp_pi);
        }
    }

    #[test]
    fn test_block_insertion_public_inputs() {
        let hash = HashOut::<F>::rand().to_fields();
        let md_hash = HashOut::<F>::rand().to_fields();
        let dv = Point::rand().to_fields();
        let [z0, zi] = [U256::from(10).to_fields(), U256::from(11).to_fields()];
        let original_hash = random_vector::<u32>(PACKED_HASH_LEN).to_fields();
        let pi = PublicInputs::<F>::new(&hash, &md_hash, &dv, &z0, &zi, &original_hash);
        let test_circuit = TestPICircuit {
            exp_pi: &pi.to_vec(),
        };
        let proof = run_circuit::<F, D, C, _>(test_circuit);

        assert_eq!(&proof.public_inputs, &pi.to_vec());
        assert_eq!(pi.to_vec().len(), super::PublicInputs::<Target>::TOTAL_LEN);
    }
}
