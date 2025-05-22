//! Public inputs for Extraction Leaf/Extension/Branch circuits

use crate::{CBuilder, GFp5, OutputHash, F as GFp};
use mp2_common::{
    array::Array,
    keccak::PACKED_HASH_LEN,
    mpt_sequential::MPTKeyWire,
    public_inputs::{PublicInputCommon, PublicInputRange},
    rlp::MAX_KEY_NIBBLE_LEN,
    types::CURVE_TARGET_LEN,
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
use std::array;

// Leaf/Extension/Branch node Public Inputs:
// - `H : [8]F` packed Keccak hash of the extension node
// - `K : [64]F` MPT key in nibbles (of *one* leaf under this subtree)
// - `T : F` pointer in the MPT indicating portion of the key already traversed (from 64 → 0)
// - `DV : Digest[F]` : Digest of the values accumulated in this subtree
//     - It can be an accumulation of *cell* digest or *rows* digest. The distinction is made in subsequent circuits.
// - `DM : Digest[F]` : Metadata digest (e.g. simple variable `D(identifier || slot)`)
// - `N : F` - Number of leaves extracted from this subtree
pub(crate) const H_RANGE: PublicInputRange = 0..PACKED_HASH_LEN;
pub(crate) const K_RANGE: PublicInputRange = H_RANGE.end..H_RANGE.end + MAX_KEY_NIBBLE_LEN;
pub(crate) const T_RANGE: PublicInputRange = K_RANGE.end..K_RANGE.end + 1;
pub(crate) const DV_RANGE: PublicInputRange = T_RANGE.end..T_RANGE.end + CURVE_TARGET_LEN;
pub(crate) const DM_RANGE: PublicInputRange = DV_RANGE.end..DV_RANGE.end + CURVE_TARGET_LEN;
pub(crate) const N_RANGE: PublicInputRange = DM_RANGE.end..DM_RANGE.end + 1;

/// Public inputs wrapper for registering
#[derive(Clone, Debug)]
pub struct PublicInputsArgs<'a> {
    pub(crate) h: &'a OutputHash,
    pub(crate) k: &'a MPTKeyWire,
    pub(crate) dv: CurveTarget,
    pub(crate) dm: CurveTarget,
    pub(crate) n: Target,
}

impl PublicInputCommon for PublicInputsArgs<'_> {
    const RANGES: &'static [PublicInputRange] =
        &[H_RANGE, K_RANGE, T_RANGE, DV_RANGE, DM_RANGE, N_RANGE];

    fn register_args(&self, cb: &mut CBuilder) {
        self.h.register_as_public_input(cb);
        self.k.register_as_input(cb);
        cb.register_curve_public_input(self.dv);
        cb.register_curve_public_input(self.dm);
        cb.register_public_input(self.n);
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
    pub fn mpt_key(&self) -> MPTKeyWire {
        let (key, ptr) = self.mpt_key_info();
        MPTKeyWire {
            key: Array {
                arr: array::from_fn(|i| key[i]),
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
            x: GFp5::from_basefield_array(array::from_fn::<GFp, 5, _>(|i| x[i])),
            y: GFp5::from_basefield_array(array::from_fn::<GFp, 5, _>(|i| y[i])),
            is_inf: is_inf.is_nonzero(),
        }
    }

    /// Get the metadata digest defined over the public inputs.
    pub fn metadata_digest(&self) -> WeierstrassPoint {
        let (x, y, is_inf) = self.metadata_digest_info();

        WeierstrassPoint {
            x: GFp5::from_basefield_array(array::from_fn::<GFp, 5, _>(|i| x[i])),
            y: GFp5::from_basefield_array(array::from_fn::<GFp, 5, _>(|i| y[i])),
            is_inf: is_inf.is_nonzero(),
        }
    }
}

impl<'a, T: Copy> PublicInputs<'a, T> {
    pub(crate) const TOTAL_LEN: usize = N_RANGE.end;

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

    pub fn metadata_digest_raw(&self) -> &[T] {
        &self.proof_inputs[DM_RANGE]
    }

    pub fn values_digest_info(&self) -> ([T; 5], [T; 5], T) {
        convert_slice_to_curve_point(&self.proof_inputs[DV_RANGE])
    }

    pub fn metadata_digest_info(&self) -> ([T; 5], [T; 5], T) {
        convert_slice_to_curve_point(self.metadata_digest_raw())
    }

    /// Return the number of leaves extracted from this subtree.
    pub fn n(&self) -> T {
        self.proof_inputs[N_RANGE][0]
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::{C, D, F};
    use mp2_common::mpt_sequential::MPTKeyWire;
    use mp2_test::{
        circuit::{run_circuit, UserCircuit},
        utils::random_vector,
    };
    use plonky2::{
        field::types::{Field, Sample},
        iop::{
            target::Target,
            witness::{PartialWitness, WitnessWrite},
        },
        plonk::circuit_builder::CircuitBuilder,
    };
    use plonky2_ecgfp5::{
        curve::curve::Point,
        gadgets::curve::{CurveTarget, PartialWitnessCurve},
    };
    use rand::thread_rng;
    use std::iter;

    pub(crate) fn new_extraction_public_inputs(
        h: &[u32],
        key: &[u8],
        ptr: usize,
        dv: &WeierstrassPoint,
        dm: &WeierstrassPoint,
        n: usize,
    ) -> Vec<GFp> {
        let mut arr = vec![];
        arr.extend_from_slice(
            &h.iter()
                .cloned()
                .map(GFp::from_canonical_u32)
                .collect::<Vec<_>>(),
        );
        arr.extend_from_slice(
            &key.iter()
                .cloned()
                .map(GFp::from_canonical_u8)
                .collect::<Vec<_>>(),
        );
        arr.push(match ptr {
            // hack to be able to construct a _final_ pointer value
            usize::MAX => GFp::NEG_ONE,
            _ => GFp::from_canonical_usize(ptr),
        });
        arr.extend_from_slice(
            &dv.x
                .0
                .iter()
                .chain(dv.y.0.iter())
                .cloned()
                .chain(iter::once(GFp::from_bool(dv.is_inf)))
                .collect::<Vec<_>>(),
        );
        arr.extend_from_slice(
            &dm.x
                .0
                .iter()
                .chain(dm.y.0.iter())
                .cloned()
                .chain(iter::once(GFp::from_bool(dm.is_inf)))
                .collect::<Vec<_>>(),
        );
        arr.push(GFp::from_canonical_usize(n));

        arr
    }

    #[derive(Clone, Debug)]
    struct TestPICircuit {
        h: Vec<u32>,
        key: Vec<u8>,
        ptr: usize,
        n: usize,
        dv: WeierstrassPoint,
        dm: WeierstrassPoint,
    }

    impl UserCircuit<F, D> for TestPICircuit {
        type Wires = (OutputHash, MPTKeyWire, CurveTarget, CurveTarget, Target);

        fn build(b: &mut CircuitBuilder<F, D>) -> Self::Wires {
            let h = OutputHash::new(b);
            let k = MPTKeyWire::new(b);
            let dv = b.add_virtual_curve_target();
            let dm = b.add_virtual_curve_target();
            let n = b.add_virtual_target();

            PublicInputsArgs {
                h: &h,
                k: &k,
                dv,
                dm,
                n,
            }
            .register(b);

            (h, k, dv, dm, n)
        }

        fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
            wires
                .0
                .assign(pw, &array::from_fn(|i| F::from_canonical_u32(self.h[i])));
            wires
                .1
                .assign(pw, &self.key.clone().try_into().unwrap(), self.ptr);
            pw.set_curve_target(wires.2, self.dv);
            pw.set_curve_target(wires.3, self.dm);
            pw.set_target(wires.4, F::from_canonical_usize(self.n));
        }
    }

    #[test]
    fn test_values_extraction_public_inputs() {
        let h = random_vector::<u32>(8);
        let key = random_vector::<u8>(64);
        let ptr = 2;
        let n = 4;

        let mut rng = thread_rng();
        let dv = Point::sample(&mut rng).to_weierstrass();
        let dm = Point::sample(&mut rng).to_weierstrass();

        let circuit = TestPICircuit {
            h: h.clone(),
            key: key.clone(),
            ptr,
            dv,
            dm,
            n,
        };
        let proof = run_circuit::<F, D, C, _>(circuit);
        let pi = PublicInputs::new(&proof.public_inputs);

        assert_eq!(pi.root_hash(), h);
        {
            let (found_key, found_ptr) = pi.mpt_key_info();
            let key: Vec<_> = key.iter().cloned().map(F::from_canonical_u8).collect();
            let ptr = F::from_canonical_usize(ptr);
            assert_eq!(found_key, key);
            assert_eq!(found_ptr, ptr);
        }
        assert_eq!(pi.values_digest(), dv);
        assert_eq!(pi.metadata_digest(), dm);
        assert_eq!(pi.n(), F::from_canonical_usize(n));
    }
}
