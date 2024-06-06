//! Public inputs for Contract Extraction circuits

use mp2_common::{
    array::Array,
    group_hashing::EXTENSION_DEGREE,
    keccak::{OutputHash, PACKED_HASH_LEN},
    mpt_sequential::MPTKeyWire,
    public_inputs::{PublicInputCommon, PublicInputRange},
    rlp::MAX_KEY_NIBBLE_LEN,
    types::{CBuilder, GFp, GFp5, CURVE_TARGET_LEN},
};
use plonky2::{
    field::{extension::FieldExtension, types::Field},
    iop::target::Target,
};
use plonky2_crypto::u32::arithmetic_u32::U32Target;
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
    pub(crate) dm: (&'a [T], &'a [T], &'a T),
    pub(crate) k: &'a [T],
    pub(crate) t: &'a T,
    pub(crate) s: &'a [T],
}

impl<'a> PublicInputCommon for PublicInputs<'a, Target> {
    const RANGES: &'static [PublicInputRange] = &[H_RANGE, DM_RANGE, K_RANGE, T_RANGE, S_RANGE];

    fn register_args(&self, cb: &mut CBuilder) {
        cb.register_public_inputs(self.h);
        cb.register_public_inputs(self.dm.0);
        cb.register_public_inputs(self.dm.1);
        cb.register_public_input(*self.dm.2);
        cb.register_public_inputs(self.k);
        cb.register_public_input(*self.t);
        cb.register_public_inputs(self.s);
    }
}

impl<'a> PublicInputs<'a, GFp> {
    /// Get the metadata point.
    pub fn metadata_point(&self) -> WeierstrassPoint {
        let x = array::from_fn::<_, EXTENSION_DEGREE, _>(|i| self.dm.0[i]);
        let y = array::from_fn::<_, EXTENSION_DEGREE, _>(|i| self.dm.1[i]);
        let is_inf = self.dm.2 == &GFp::ONE;

        WeierstrassPoint {
            x: GFp5::from_basefield_array(x),
            y: GFp5::from_basefield_array(y),
            is_inf,
        }
    }
}

impl<'a> PublicInputs<'a, Target> {
    /// Create a new public inputs.
    pub fn new(
        h: &'a [Target],
        dm: &'a CurveTarget,
        k: &'a [Target],
        t: &'a Target,
        s: &'a [Target],
    ) -> Self {
        let dm_x = &dm.0 .0[0].0[..];
        let dm_y = &dm.0 .0[1].0[..];
        let dm_is_inf = &dm.0 .1.target;

        Self {
            h,
            dm: (dm_x, dm_y, dm_is_inf),
            k,
            t,
            s,
        }
    }

    /// Get the merkle hash of the subtree this proof has processed.
    pub fn root_hash(&self) -> OutputHash {
        let hash = self.h;
        Array::<U32Target, PACKED_HASH_LEN>::from_array(array::from_fn(|i| U32Target(hash[i])))
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
}

impl<'a, T: Copy> PublicInputs<'a, T> {
    /// Total length of the public inputs
    pub(crate) const TOTAL_LEN: usize = S_RANGE.end;

    /// Create from a slice.
    pub fn from_slice(pi: &'a [T]) -> Self {
        Self {
            h: &pi[H_RANGE],
            dm: (
                &pi[DM_RANGE.start..DM_RANGE.start + CURVE_TARGET_LEN / 2],
                &pi[DM_RANGE.start + CURVE_TARGET_LEN / 2..DM_RANGE.end - 1],
                &pi[DM_RANGE.end - 1],
            ),
            k: &pi[K_RANGE],
            t: &pi[T_RANGE.start],
            s: &pi[S_RANGE],
        }
    }

    /// Combine to a vector.
    pub fn to_vec(&self) -> Vec<T> {
        self.h
            .iter()
            .chain(self.dm.0)
            .chain(self.dm.1)
            .chain(iter::once(self.dm.2))
            .chain(self.k)
            .chain(iter::once(self.t))
            .chain(self.s)
            .cloned()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mp2_common::{
        utils::{Fieldable, ToFields},
        C, D, F,
    };
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

    impl<'a> UserCircuit<F, D> for TestPICircuit<'a> {
        type Wires = Vec<Target>;

        fn build(b: &mut CBuilder) -> Self::Wires {
            let pi = b.add_virtual_targets(PublicInputs::<Target>::TOTAL_LEN);
            PublicInputs::from_slice(&pi).register(b);

            pi
        }

        fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
            pw.set_target_arr(&wires, self.exp_pi);
        }
    }

    #[test]
    fn test_contract_extraction_public_inputs() {
        let mut rng = thread_rng();

        // Prepare the public inputs.
        let h = &random_vector::<u32>(PACKED_HASH_LEN).to_fields();
        let dm = Point::sample(&mut rng).to_weierstrass();
        let dm_is_inf = if dm.is_inf { F::ONE } else { F::ZERO };
        let dm = (dm.x.0.as_slice(), dm.y.0.as_slice(), &dm_is_inf);
        let k = &random_vector::<u8>(64).to_fields();
        let t = &2_u8.to_field();
        let s = &random_vector::<u32>(PACKED_HASH_LEN).to_fields();
        let exp_pi = PublicInputs { h, dm, k, t, s };
        let exp_pi = &exp_pi.to_vec();

        let test_circuit = TestPICircuit { exp_pi };
        let proof = run_circuit::<F, D, C, _>(test_circuit);

        assert_eq!(&proof.public_inputs, exp_pi);
    }
}
