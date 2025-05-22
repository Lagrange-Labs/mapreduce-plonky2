//! Public inputs for Contract Extraction circuits

use crate::{CBuilder, OutputHash, F as GFp};
use mp2_common::{
    array::Array,
    keccak::PACKED_HASH_LEN,
    mpt_sequential::MPTKeyWire,
    public_inputs::{PublicInputCommon, PublicInputRange},
    rlp::MAX_KEY_NIBBLE_LEN,
    types::CURVE_TARGET_LEN,
    utils::{FromFields, FromTargets},
};
use plonky2::iop::target::Target;
use plonky2_ecgfp5::{curve::curve::WeierstrassPoint, gadgets::curve::CurveTarget};
use std::{array, iter};

// Contract extraction public Inputs:
// - `H : [8]F` : packed block hash
// - `DM : Digest[F]` : metadata digest to extract
// - `K : [64]F` : MPT key derived for this contract
// - `T : F` : pointer of the MPT key
// - `S : [8]F` : packed hash of the storage trie root of this contract
const H_RANGE: PublicInputRange = 0..PACKED_HASH_LEN;
const DM_RANGE: PublicInputRange = H_RANGE.end..H_RANGE.end + CURVE_TARGET_LEN;
const K_RANGE: PublicInputRange = DM_RANGE.end..DM_RANGE.end + MAX_KEY_NIBBLE_LEN;
const T_RANGE: PublicInputRange = K_RANGE.end..K_RANGE.end + 1;
const S_RANGE: PublicInputRange = T_RANGE.end..T_RANGE.end + PACKED_HASH_LEN;

/// Public inputs for contract extraction
#[derive(Clone, Debug)]
pub struct PublicInputs<'a, T> {
    pub(crate) h: &'a [T],
    pub(crate) dm: &'a [T],
    pub(crate) k: &'a [T],
    pub(crate) t: &'a T,
    pub(crate) s: &'a [T],
}

impl PublicInputCommon for PublicInputs<'_, Target> {
    const RANGES: &'static [PublicInputRange] = &[H_RANGE, DM_RANGE, K_RANGE, T_RANGE, S_RANGE];

    fn register_args(&self, cb: &mut CBuilder) {
        cb.register_public_inputs(self.h);
        cb.register_public_inputs(self.dm);
        cb.register_public_inputs(self.k);
        cb.register_public_input(*self.t);
        cb.register_public_inputs(self.s);
    }
}

impl PublicInputs<'_, GFp> {
    /// Get the metadata point.
    pub fn metadata_point(&self) -> WeierstrassPoint {
        WeierstrassPoint::from_fields(self.dm)
    }
    pub fn root_hash_field(&self) -> Vec<u32> {
        let hash = self.h_raw();
        hash.iter().map(|t| t.0 as u32).collect()
    }
}

impl<'a> PublicInputs<'a, Target> {
    /// Create a new public inputs.
    pub fn new(
        h: &'a [Target],
        dm: &'a [Target],
        k: &'a [Target],
        t: &'a Target,
        s: &'a [Target],
    ) -> Self {
        Self { h, dm, k, t, s }
    }

    /// Get the merkle hash of the subtree this proof has processed.
    pub fn root_hash(&self) -> OutputHash {
        OutputHash::from_targets(self.h)
    }

    /// Get the MPT key defined over the public inputs.
    pub fn mpt_key(&self) -> MPTKeyWire {
        let key = self.k;
        let pointer = *self.t;

        MPTKeyWire {
            key: Array {
                arr: array::from_fn(|i| key[i]),
            },
            pointer,
        }
    }
    pub fn metadata_digest(&self) -> CurveTarget {
        CurveTarget::from_targets(self.dm)
    }

    pub fn storage_root(&self) -> OutputHash {
        OutputHash::from_targets(self.s)
    }
}

impl<'a, T: Copy> PublicInputs<'a, T> {
    /// Total length of the public inputs
    pub(crate) const TOTAL_LEN: usize = S_RANGE.end;

    /// Create from a slice.
    pub fn from_slice(pi: &'a [T]) -> Self {
        assert!(pi.len() >= Self::TOTAL_LEN);

        Self {
            h: &pi[H_RANGE],
            dm: &pi[DM_RANGE],
            k: &pi[K_RANGE],
            t: &pi[T_RANGE.start],
            s: &pi[S_RANGE],
        }
    }

    /// Combine to a vector.
    pub fn to_vec(&self) -> Vec<T> {
        self.h
            .iter()
            .chain(self.dm)
            .chain(self.k)
            .chain(iter::once(self.t))
            .chain(self.s)
            .cloned()
            .collect()
    }

    pub fn h_raw(&self) -> &'a [T] {
        self.h
    }

    pub fn dm_raw(&self) -> &'a [T] {
        self.dm
    }

    pub fn k_raw(&self) -> &'a [T] {
        self.k
    }

    pub fn t_raw(&self) -> &'a T {
        self.t
    }

    pub fn s_raw(&self) -> &'a [T] {
        self.s
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mp2_common::utils::{Fieldable, ToFields};
    use crate::{C, D, F};
    use mp2_test::{
        circuit::{run_circuit, UserCircuit},
        utils::random_vector,
    };
    use plonky2::{
        field::types::Sample,
        iop::{
            target::Target,
            witness::{PartialWitness, WitnessWrite},
        },
    };
    use plonky2_ecgfp5::curve::curve::Point;
    use rand::thread_rng;

    #[derive(Clone, Debug)]
    struct TestPICircuit<'a> {
        exp_pi: &'a [F],
    }

    impl UserCircuit<F, D> for TestPICircuit<'_> {
        type Wires = Vec<Target>;

        fn build(b: &mut CBuilder) -> Self::Wires {
            let pi = b.add_virtual_targets(PublicInputs::<Target>::TOTAL_LEN);
            PublicInputs::from_slice(&pi).register(b);

            pi
        }

        fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
            pw.set_target_arr(wires, self.exp_pi);
        }
    }

    #[test]
    fn test_contract_extraction_public_inputs() {
        let mut rng = thread_rng();

        // Prepare the public inputs.
        let h = &random_vector::<u32>(PACKED_HASH_LEN).to_fields();
        let dm = &Point::sample(&mut rng).to_weierstrass().to_fields();
        let k = &random_vector::<u8>(MAX_KEY_NIBBLE_LEN).to_fields();
        let t = &2_u8.to_field();
        let s = &random_vector::<u32>(PACKED_HASH_LEN).to_fields();
        let exp_pi = PublicInputs { h, dm, k, t, s };
        let exp_pi = &exp_pi.to_vec();

        let test_circuit = TestPICircuit { exp_pi };
        let proof = run_circuit::<F, D, C, _>(test_circuit);

        assert_eq!(&proof.public_inputs, exp_pi);
    }
}
