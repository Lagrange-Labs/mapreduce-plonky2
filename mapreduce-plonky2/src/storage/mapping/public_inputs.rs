use std::array::from_fn as create_array;

use plonky2::{
    field::{
        extension::{quintic::QuinticExtension, FieldExtension},
        goldilocks_field::GoldilocksField,
        types::Field,
    },
    iop::target::{BoolTarget, Target},
    plonk::circuit_builder::CircuitBuilder,
};
use plonky2_crypto::u32::arithmetic_u32::U32Target;
use plonky2_ecgfp5::{
    curve::curve::WeierstrassPoint,
    gadgets::{
        base_field::QuinticExtensionTarget,
        curve::{CircuitBuilderEcGFp5, CurveTarget},
    },
};

use crate::{
    array::Array,
    keccak::{OutputHash, PACKED_HASH_LEN},
    mpt_sequential::MPTKeyWire,
    rlp::MAX_KEY_NIBBLE_LEN,
    utils::{convert_point_to_curve_target, convert_slice_to_curve_point},
};
// This is a wrapper around an array of targets set as public inputs
// of any proof generated in this module. They all share the same
// structure.
// `K` Full key for a leaf inside this subtree
// `T` Index of the part “processed” on the full key
// `S`  storage slot of the mapping
// `n` number of items seen so far up to this node
// `C` MPT root (of the current node)
// `D` Accumulator digest of the values
#[derive(Clone, Debug)]
pub struct PublicInputs<'a, T: Clone> {
    pub(crate) proof_inputs: &'a [T],
}

impl<'a> PublicInputs<'a, Target> {
    pub fn register(
        b: &mut CircuitBuilder<GoldilocksField, 2>,
        key: &MPTKeyWire,
        slot: Target,
        n: Target,
        c: &OutputHash,
        d: &CurveTarget,
    ) {
        b.register_curve_public_input(*d);
        key.register_as_input(b);
        b.register_public_input(slot);
        b.register_public_input(n);
        c.register_as_public_input(b);
    }
    /// Returns the MPT key defined over the public inputs
    pub fn mpt_key(&self) -> MPTKeyWire {
        let (key, ptr) = self.mpt_key_info();
        MPTKeyWire {
            key: Array {
                arr: create_array(|i| key[i]),
            },
            pointer: ptr,
        }
    }
    /// Returns the accumulator digest defined over the public inputs
    // TODO: move that to ecgfp5 repo
    pub fn accumulator(&self) -> CurveTarget {
        convert_point_to_curve_target(self.accumulator_info())
    }

    /// Returns the merkle hash C of the subtree this proof has processed.
    pub fn root_hash(&self) -> OutputHash {
        let hash = self.root_hash_info();
        Array::<U32Target, PACKED_HASH_LEN>::from_array(create_array(|i| U32Target(hash[i])))
    }
}
impl<'a> PublicInputs<'a, GoldilocksField> {
    /// Returns the accumulator digest defined over the public inputs
    pub fn accumulator(&self) -> WeierstrassPoint {
        // TODO: put that in ecgfp5 crate publicly
        pub(crate) type GFp5 = QuinticExtension<GoldilocksField>;
        let ptr = Self::D_IDX;
        let (x, y, is_inf) = self.accumulator_info();
        WeierstrassPoint {
            x: GFp5::from_basefield_array(create_array::<GoldilocksField, 5, _>(|i| x[i])),
            y: GFp5::from_basefield_array(create_array::<GoldilocksField, 5, _>(|i| y[i])),
            is_inf: is_inf.is_nonzero(),
        }
    }
    // Returns in packed representation
    pub fn root_hash(&self) -> Vec<u32> {
        let hash = self.root_hash_info();
        hash.iter().map(|t| t.0 as u32).collect()
    }
    #[cfg(test)]
    pub fn create_public_inputs_arr(
        key: &[u8],
        ptr: usize,
        slot: usize,
        n: usize,
        c: &[u32], // packed hash
        d: &WeierstrassPoint,
    ) -> Vec<GoldilocksField> {
        let mut arr = vec![];
        arr.extend_from_slice(&d.x.0.iter().chain(&d.y.0).cloned().collect::<Vec<_>>());
        arr.push(if d.is_inf {
            GoldilocksField::ONE
        } else {
            GoldilocksField::ZERO
        });
        arr.extend_from_slice(
            &key.iter()
                .map(|x| GoldilocksField::from_canonical_u8(*x))
                .collect::<Vec<_>>(),
        );
        arr.push(GoldilocksField::from_canonical_usize(ptr));
        arr.push(GoldilocksField::from_canonical_usize(slot));
        arr.push(GoldilocksField::from_canonical_usize(n));
        arr.extend_from_slice(
            &c.iter()
                .map(|x| GoldilocksField::from_canonical_u32(*x))
                .collect::<Vec<_>>(),
        );
        arr
    }
}
impl<'a, T: Copy> PublicInputs<'a, T> {
    pub(crate) const D_IDX: usize = 0; // 5F for each coordinates + 1 bool flag
    pub(crate) const KEY_IDX: usize = 11; // 64 nibbles
    pub(crate) const T_IDX: usize = 75; // 1 index
    pub(crate) const S_IDX: usize = 76; // 1 index
    pub(crate) const N_IDX: usize = 77; // 1 index
    pub(crate) const C_IDX: usize = 78; // packed hash = 8 U32-F elements
    pub(crate) const EXTENSION: usize = 5;
    pub(crate) const TOTAL_LEN: usize = Self::C_IDX + 8;
    pub fn from(arr: &'a [T]) -> Self {
        Self { proof_inputs: arr }
    }

    // small utility function to transform a list of target to a curvetarget.
    pub(super) fn accumulator_info(&self) -> ([T; 5], [T; 5], T) {
        convert_slice_to_curve_point(&self.proof_inputs[Self::D_IDX..])
    }
    pub(crate) fn mpt_key_info(&self) -> (&[T], T) {
        let key_range = Self::KEY_IDX..Self::KEY_IDX + MAX_KEY_NIBBLE_LEN;
        let key = &self.proof_inputs[key_range];
        let ptr_range = Self::T_IDX..Self::T_IDX + 1;
        let ptr = self.proof_inputs[ptr_range][0];
        (key, ptr)
    }
    pub(crate) fn root_hash_info(&self) -> &[T] {
        // poseidon merkle root hash is 4 F elements
        let hash_range = Self::C_IDX..Self::C_IDX + PACKED_HASH_LEN;
        &self.proof_inputs[hash_range]
    }
    /// Returns the mapping slot used to prove the derivation of the
    /// MPT keys
    pub fn mapping_slot(&self) -> T {
        self.proof_inputs[Self::S_IDX]
    }
    /// Returns the number of mapping leaf entries seen so
    /// far up to the givne node.
    pub fn n(&self) -> T {
        self.proof_inputs[Self::N_IDX]
    }
}

#[cfg(test)]
mod test {
    use plonky2::field::types::Field;
    use plonky2::{
        iop::{
            target::Target,
            witness::{PartialWitness, WitnessWrite},
        },
        plonk::{
            circuit_builder::CircuitBuilder,
            config::{GenericConfig, PoseidonGoldilocksConfig},
        },
    };
    use plonky2_crypto::u32::arithmetic_u32::U32Target;
    use plonky2_ecgfp5::gadgets::curve::CurveTarget;
    use std::array::from_fn as create_array;

    use crate::{
        array::Array,
        circuit::{test::run_circuit, UserCircuit},
        group_hashing::{map_to_curve_point, CircuitBuilderGroupHashing},
        keccak::PACKED_HASH_LEN,
        mpt_sequential::MPTKeyWire,
        utils::test::random_vector,
    };

    use super::PublicInputs;
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    #[derive(Clone, Debug)]
    struct TestPublicInputs {
        key: Vec<u8>,
        ptr: usize,
        slot: usize,
        n: usize,
        c: Vec<u32>,
    }

    impl UserCircuit<F, D> for TestPublicInputs {
        type Wires = (
            MPTKeyWire,
            Target,
            Target,
            Array<U32Target, PACKED_HASH_LEN>,
            CurveTarget,
        );
        fn build(b: &mut CircuitBuilder<F, D>) -> Self::Wires {
            let key = MPTKeyWire::new(b);
            let slot = b.add_virtual_target();
            let n = b.add_virtual_target();
            let c = Array::<U32Target, PACKED_HASH_LEN>::new(b);
            let one = b.one();
            let accumulator = b.map_to_curve_point(&[one]);
            PublicInputs::register(b, &key, slot, n, &c, &accumulator);
            (key, slot, n, c, accumulator)
        }

        fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
            wires
                .0
                .assign(pw, &self.key.clone().try_into().unwrap(), self.ptr);
            pw.set_target(wires.1, F::from_canonical_u64(self.slot as u64));
            pw.set_target(wires.2, F::from_canonical_u64(self.n as u64));
            wires.3.assign(
                pw,
                &create_array(|i| F::from_canonical_u64(self.c[i] as u64)),
            );
        }
    }
    #[test]
    fn test_public_inputs() {
        let p = map_to_curve_point(&[F::ONE]).to_weierstrass();
        let key = random_vector::<u8>(64);
        let ptr = 2;
        let slot = 3;
        let n = 4;
        let c = random_vector::<u32>(8);
        let test = TestPublicInputs {
            key: key.clone(),
            ptr,
            slot,
            n,
            c: c.clone(),
        };
        let proof = run_circuit::<F, D, C, _>(test);
        let pi = PublicInputs::<F>::from(&proof.public_inputs);
        {
            let (found_key, found_ptr) = pi.mpt_key_info();
            let key = key
                .iter()
                .cloned()
                .map(F::from_canonical_u8)
                .collect::<Vec<_>>();
            let ptr = F::from_canonical_usize(ptr);
            assert_eq!(found_key, key);
            assert_eq!(found_ptr, ptr);
        }
        {
            let found_slot = pi.mapping_slot();
            assert_eq!(found_slot, F::from_canonical_usize(slot));
        }
        {
            let found_n = pi.n();
            assert_eq!(found_n, F::from_canonical_usize(n));
        }
        {
            let found_c = pi.root_hash();
            assert_eq!(found_c, c);
        }
        {
            let found_p = pi.accumulator();
            assert_eq!(found_p, p);
        }
    }
}
