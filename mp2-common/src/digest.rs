use crate::group_hashing::{
    circuit_hashed_scalar_mul, cond_circuit_hashed_scalar_mul, cond_field_hashed_scalar_mul,
    field_hashed_scalar_mul, map_to_curve_point,
};
use crate::serialization::{deserialize, serialize};
use crate::types::CBuilder;
use crate::utils::ToFields;
use crate::{group_hashing::CircuitBuilderGroupHashing, utils::ToTargets};
use crate::{D, F};
use derive_more::{From, Into};
use plonky2::iop::target::BoolTarget;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2_ecgfp5::{
    curve::curve::Point,
    gadgets::curve::{CircuitBuilderEcGFp5, CurveTarget},
};
use serde::{Deserialize, Serialize};
pub type DigestTarget = CurveTarget;
pub type Digest = Point;

/// Whether the table's digest is composed of a single row, or multiple rows.
/// For example when extracting mapping entries in one single sweep of the MPT, the digest contains
/// multiple rows inside.
/// When extracting single variables on one sweep, there is only a single row contained in the
/// digest.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum TableDimension {
    /// Set to Single for types that only generate a single row at a given block. For example, a
    /// uint256 or a bytes32 will only generate a single row per block.
    Single,
    /// Set to Compound for types that
    /// * have multiple entries (like an mapping, unlike a single uin256 for example)
    /// * don't need or have an associated length slot to combine with
    /// It happens contracts don't have a length slot associated with the mapping
    /// like ERC20 and thus there is no proof circuits have looked at _all_ the entries
    /// due to limitations on EVM (there is no mapping.len()).
    Compound,
}

impl TableDimension {
    pub fn assign_wire(&self, pw: &mut PartialWitness<F>, wire: &TableDimensionWire) {
        match self {
            TableDimension::Single => pw.set_bool_target(wire.0, false),
            TableDimension::Compound => pw.set_bool_target(wire.0, true),
        }
    }

    pub fn conditional_row_digest(&self, digest: Digest) -> Digest {
        match self {
            TableDimension::Single => map_to_curve_point(&digest.to_fields()),
            TableDimension::Compound => digest,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, From, Into, Eq, PartialEq)]
pub struct TableDimensionWire(
    #[serde(serialize_with = "serialize", deserialize_with = "deserialize")] pub BoolTarget,
);

impl TableDimensionWire {
    pub fn conditional_row_digest(
        &self,
        c: &mut CircuitBuilder<F, D>,
        digest: CurveTarget,
    ) -> CurveTarget {
        let single = c.map_to_curve_point(&digest.to_targets());
        // if the table is a compound table, i.e. multiple rows accumulated in the digest, then
        // there is no need to apply digest one more time. On the other hand, if it is not
        // compounded, i.e. there is only a sum of cells digest, then we need to create the "row"
        // digest, thus applying the digest one more time.
        //
        // TableDimension::Single => false,
        // TableDimension::Compound => true,
        c.curve_select(self.0, digest, single)
    }
}

/// Generic struct that can either hold a digest in circuit (DigestTarget) or a digest outside
/// circuit, useful for testing.
#[derive(Clone, Debug)]
pub struct SplitDigest<T> {
    pub individual: T,
    pub multiplier: T,
}

pub type SplitDigestPoint = SplitDigest<Digest>;
pub type SplitDigestTarget = SplitDigest<DigestTarget>;

impl SplitDigestPoint {
    pub fn from_single_digest_point(digest: Digest, is_multiplier: bool) -> Self {
        let (ind, mult) = match is_multiplier {
            true => (Digest::NEUTRAL, digest),
            false => (digest, Digest::NEUTRAL),
        };
        Self {
            individual: ind,
            multiplier: mult,
        }
    }
    pub fn accumulate(&self, other: &Self) -> Self {
        Self {
            individual: other.individual + self.individual,
            multiplier: other.multiplier + self.multiplier,
        }
    }

    pub fn cond_combine_to_row_digest(&self) -> Digest {
        let base = map_to_curve_point(&self.individual.to_fields());
        let multiplier = map_to_curve_point(&self.multiplier.to_fields());
        cond_field_hashed_scalar_mul(self.is_merge_case(), multiplier, base)
    }
    pub fn is_merge_case(&self) -> bool {
        self.multiplier != Point::NEUTRAL
    }
    pub fn combine_to_row_digest(&self) -> Digest {
        field_hashed_scalar_mul(self.multiplier.to_fields(), self.individual)
    }
}

impl SplitDigestTarget {
    /// Returns true if the situation is the merging of two tables. i.e. the multiplier is not zero
    pub fn is_merge_case(&self, c: &mut CBuilder) -> BoolTarget {
        let zero = c.curve_zero();
        let is_simple = c.curve_eq(zero, self.multiplier);
        c.not(is_simple)
    }
    /// Returns a split digest depending if the given target should be a multiplier or not
    pub fn from_single_digest_target(
        c: &mut CBuilder,
        digest: DigestTarget,
        is_multiplier: BoolTarget,
    ) -> Self {
        let zero_curve = c.curve_zero();
        let digest_ind = c.curve_select(is_multiplier, zero_curve, digest);
        let digest_mult = c.curve_select(is_multiplier, digest, zero_curve);
        Self {
            individual: digest_ind,
            multiplier: digest_mult,
        }
    }
    /// aggregate the digest of the child proof in the right digest
    /// Returns the individual and multiplier digest
    pub fn accumulate(&self, c: &mut CBuilder, child_digest: &SplitDigestTarget) -> Self {
        let digest_ind = c.add_curve_point(&[child_digest.individual, self.individual]);
        let digest_mul = c.add_curve_point(&[child_digest.multiplier, self.multiplier]);
        Self {
            individual: digest_ind,
            multiplier: digest_mul,
        }
    }
    /// First compute the individual row digest of each component (i.e. digesting again to make a
    /// digest of a row). Then recombine the split and individual targets into a single one. It
    /// hashes the individual digest first as to look as a single table.
    /// NOTE: it takes care of looking if the multiplier is NEUTRAL. In this case, it simply
    /// returns the individual one. This is to accomodate for single table digest or "merged" table
    /// digest.
    pub fn cond_combine_to_row_digest(&self, b: &mut CBuilder) -> DigestTarget {
        let row_digest_ind = b.map_to_curve_point(&self.individual.to_targets());
        let row_digest_mul = b.map_to_curve_point(&self.multiplier.to_targets());
        let is_merge_case = self.is_merge_case(b);
        cond_circuit_hashed_scalar_mul(b, is_merge_case, row_digest_mul, row_digest_ind)
    }

    /// Recombine the split and individual target digest into a single one. It does NOT hashes the
    /// individual digest first since the individual digest is assumed to be a row digest already.
    /// E.g. this function is called at final extraction, when the digest of the value is already
    /// in the form of SUM Digest_row_i. So we don't need to do an additional digest.
    /// In the `cond_combine_to_row_digest`, we need since we are working at the row level and the
    /// digest of the proof is only `SUM Digest_column_j` so we need an additional digest on top.
    pub fn combine_to_digest(&self, b: &mut CBuilder) -> DigestTarget {
        circuit_hashed_scalar_mul(b, self.multiplier, self.individual)
    }
}

#[cfg(test)]
mod test {
    use crate::{types::CBuilder, utils::FromFields, C, D, F};

    use super::{
        Digest, DigestTarget, SplitDigest, SplitDigestPoint, SplitDigestTarget, TableDimension,
        TableDimensionWire,
    };
    use crate::utils::TryIntoBool;
    use mp2_test::circuit::{run_circuit, UserCircuit};
    use plonky2::{
        field::types::Sample,
        iop::{
            target::BoolTarget,
            witness::{PartialWitness, WitnessWrite},
        },
    };
    use plonky2_ecgfp5::{
        curve::curve::Point,
        gadgets::curve::{CircuitBuilderEcGFp5, PartialWitnessCurve},
    };

    #[derive(Clone, Debug)]
    struct TestSplitDigest {
        ind: Digest,
        mul: Digest,
    }

    struct TestSplitDigestTarget {
        ind: DigestTarget,
        mul: DigestTarget,
    }

    impl UserCircuit<F, D> for TestSplitDigest {
        type Wires = TestSplitDigestTarget;

        fn build(b: &mut CBuilder) -> Self::Wires {
            let d1 = b.add_virtual_curve_target();
            let d2 = b.add_virtual_curve_target();
            let sp = SplitDigestTarget {
                individual: d1,
                multiplier: d2,
            };
            let combined = sp.cond_combine_to_row_digest(b);
            let is_merge = sp.is_merge_case(b);
            b.register_public_input(is_merge.target);
            b.register_curve_public_input(combined);

            TestSplitDigestTarget { ind: d1, mul: d2 }
        }

        fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
            pw.set_curve_target(wires.ind, self.ind.to_weierstrass());
            pw.set_curve_target(wires.mul, self.mul.to_weierstrass());
        }
    }

    #[test]
    fn test_split_digest() {
        let cases = vec![
            TestSplitDigest {
                ind: Point::rand(),
                mul: Point::NEUTRAL,
            },
            TestSplitDigest {
                ind: Point::rand(),
                mul: Point::rand(),
            },
        ];

        for t in cases {
            let proof = run_circuit::<F, D, C, _>(t.clone());
            let sp = SplitDigestPoint {
                individual: t.ind,
                multiplier: t.mul,
            };
            let combined = sp.cond_combine_to_row_digest();
            // skipping the bool
            let found = Point::from_fields(&proof.public_inputs[1..]);
            assert_eq!(combined, found);

            let is_merge_case_circuit = proof.public_inputs[0]
                .try_into_bool()
                .expect("cant get bool");
            let is_merge_case_point = sp.is_merge_case();
            assert_eq!(is_merge_case_circuit, is_merge_case_point);
        }
    }

    #[derive(Clone, Debug)]
    struct TestTableDimension {
        digest: Digest,
        dimension: TableDimension,
    }

    struct TestTableDimensionWire {
        digest: DigestTarget,
        dimension: TableDimensionWire,
    }

    impl UserCircuit<F, D> for TestTableDimension {
        type Wires = TestTableDimensionWire;

        fn build(b: &mut CBuilder) -> Self::Wires {
            let digest = b.add_virtual_curve_target();
            let dimension: TableDimensionWire = b.add_virtual_bool_target_safe().into();
            let final_digest = dimension.conditional_row_digest(b, digest);
            b.register_curve_public_input(final_digest);

            TestTableDimensionWire { digest, dimension }
        }

        fn prove(&self, pw: &mut PartialWitness<F>, wires: &Self::Wires) {
            pw.set_curve_target(wires.digest, self.digest.to_weierstrass());
            self.dimension.assign_wire(pw, &wires.dimension);
        }
    }

    #[test]
    fn test_dimension_wire() {
        let cases = vec![TableDimension::Single, TableDimension::Compound];
        for dimension in cases {
            let circuit = TestTableDimension {
                digest: Point::rand(),
                dimension,
            };
            let proof = run_circuit::<F, D, C, _>(circuit.clone());
            let combined = Digest::from_fields(&proof.public_inputs);
            let expected = dimension.conditional_row_digest(circuit.digest);
            assert_eq!(combined, expected);
        }
    }
}
