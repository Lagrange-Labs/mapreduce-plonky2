use crate::assembler::{assemble_dynamic, DynamicCircuitPis};
use crate::isolator;
use crate::{
    symbols::FileContextProvider,
    utils::{parse_and_validate, ParsilSettings, PlaceholderSettings},
};
use alloy::primitives::U256;
use anyhow::Result;
use verifiable_db::query::universal_circuit::universal_circuit_inputs::Placeholders;

/// NOTE: queries that may bother us in the future
const CAREFUL: &[&str] = &[
    // What to do if b.t is longer than a.x?
    "SELECT x, (SELECT t AS tt FROM b) FROM a;",
    // Double aliasing
    "SELECT pipo.not_tt FROM (SELECT t AS tt FROM b) AS pipo (not_tt);",
];

#[test]
fn must_accept() -> Result<()> {
    let settings = ParsilSettings {
        context: FileContextProvider::from_file("tests/context.json")?,
        placeholders: PlaceholderSettings::with_freestanding(3),
    };

    for q in [
        // "SELECT 25",
        "SELECT AVG(foo), MIN(bar) FROM table2 WHERE block = 3",
        // "SELECT '0x1122334455667788990011223344556677889900112233445566778899001122'",
        // "SELECT '0x'",
        // "SELECT '1234567'",
        // "SELECT '0b01001'",
        // "SELECT '0o1234567'",
    ] {
        parse_and_validate(q, &settings)?;
    }
    Ok(())
}

#[test]
fn must_reject() {
    let settings = ParsilSettings {
        context: FileContextProvider::from_file("tests/context.json").unwrap(),
        placeholders: PlaceholderSettings::with_freestanding(3),
    };

    for q in [
        "SELECT foo, bar FROM table2 WHERE block = 3",
        "SELECT foo FROM table2 WHERE block IN (1, 2, 4)",
        "SELECT bar FROM table2 WHERE NOT block BETWEEN 12 AND 15",
        "SELECT a, c FROM table2 AS tt (a, b, c)",
        // Mixing aggregates and scalars
        "SELECT q, MIN(r) FROM pipo WHERE block = 3",
        // Bitwise operators unsupported
        "SELECT a & b FROM t",
        "SELECT a | b FROM t",
        "SELECT a ^ b FROM t",
        // *LIKE unsupported
        "SELECT x FROM t WHERE x LIKE 'adsf%'",
        "SELECT x FROM t WHERE x ILIKE 'adsf%'",
        // *LIKE unsupported
        "SELECT x->a FROM t",
        "SELECT x->>a FROM t",
        // No nested SELECTs
        "SELECT alpha FROM (SELECT pipo AS alpha FROM t)",
        // No mutating queries
        "INSERT 35 INTO t(x)",
        "CREATE TABLE t()",
        // No ALL/ANY
        "SELECT a FROM t WHERE a = ALL (SELECT b FROM u)",
        "SELECT a FROM t WHERE a < ANY (SELECT b FROM u)",
        // Too many ORDER BY
        "SELECT * FROM t ORDER BY a, b, c",
        // Too long
        "SELECT '0x11223344556677889900112233445566778899001122334455667788990011223'",
        // Unknown prefix
        "SELECT '0t11223344556677889900112233445566778899001122334455667788990011223'",
        // Invalid digit
        "SELECT '0o12345678'",
    ] {
        assert!(dbg!(parse_and_validate(q, &settings)).is_err())
    }
}

#[test]
fn must_resolve() -> Result<()> {
    let settings = ParsilSettings {
        context: FileContextProvider::from_file("tests/context.json")?,
        placeholders: PlaceholderSettings::with_freestanding(3),
    };
    for q in [
        // "SELECT foo FROM table2",
        // "SELECT foo FROM table2 WHERE bar < 3",
        // "SELECT foo, * FROM table2",
        "SELECT AVG(foo) FROM table2 WHERE block BETWEEN 43 and 68",
        // "SELECT foo, bar FROM table2 ORDER BY bar",
        // "SELECT foo, bar FROM table2 ORDER BY foo, bar",
    ] {
        parse_and_validate(q, &settings)?;
    }
    Ok(())
}

#[test]
fn ref_query() -> Result<()> {
    let settings = ParsilSettings {
        context: FileContextProvider::from_file("tests/context.json")?,
        placeholders: PlaceholderSettings::with_freestanding(2),
    };

    let q = "SELECT AVG(C1+C2/(C2*C3)), SUM(C1+C2), MIN(C1+$1), MAX(C4-2), AVG(C5) FROM T WHERE (C5 > 5 AND C1*C3 <= C4+C5 OR C3 == $2) AND C2 >= 75 AND C2 < 99";
    let query = parse_and_validate(q, &settings)?;
    Ok(())
}

#[test]
fn test_serde_circuit_pis() {
    let settings = ParsilSettings {
        context: FileContextProvider::from_file("tests/context.json").unwrap(),
        placeholders: PlaceholderSettings::with_freestanding(3),
    };

    let q = "SELECT AVG(foo) FROM table2";
    let query = parse_and_validate(q, &settings).unwrap();
    let pis = assemble_dynamic(
        &query,
        &settings,
        &Placeholders::new_empty(U256::from(10), U256::from(20)),
    )
    .unwrap();

    let serialized = serde_json::to_vec(&pis).unwrap();
    let deserialized: DynamicCircuitPis = serde_json::from_slice(&serialized).unwrap();

    assert_eq!(pis, deserialized);
}

#[test]
#[ignore = "wait for non-aggregation SELECT to come back"]
fn isolation() {
    fn isolated_to_string(q: &str, lo_sec: bool, hi_sec: bool) -> String {
        let settings = ParsilSettings {
            context: FileContextProvider::from_file("tests/context.json").unwrap(),
            placeholders: PlaceholderSettings::with_freestanding(3),
        };

        let mut query = parse_and_validate(q, &settings).unwrap();
        isolator::isolate_with(&mut query, &settings, lo_sec, hi_sec)
            .unwrap()
            .to_string()
    }

    assert_eq!(
        isolated_to_string(
            "SELECT * FROM table1 WHERE block BETWEEN 1 AND 5",
            false,
            false
        ),
        "SELECT * FROM table1 WHERE (block >= 1 AND block <= 5)"
    );

    // Drop references to other columns
    assert_eq!(
        isolated_to_string(
            "SELECT * FROM table2 WHERE block BETWEEN 1 AND 5 AND 3 = 4 OR bar = 5",
            false,
            false
        ),
        "SELECT * FROM table2 WHERE (block >= 1 AND block <= 5)"
    );

    // Drop sec. ind. references if it has no kown bounds.
    assert_eq!(
        isolated_to_string(
            "SELECT * FROM table2 WHERE block BETWEEN $MIN_BLOCK AND $MAX_BLOCK AND foo < 5",
            false,
            false
        ),
        "SELECT * FROM table2 WHERE (block >= $MIN_BLOCK AND block <= $MAX_BLOCK)"
    );

    // Drop sec.ind. < [...] if it has a defined higher bound
    assert_eq!(
        isolated_to_string(
            "SELECT * FROM table2 WHERE block BETWEEN $MIN_BLOCK AND $MAX_BLOCK AND foo < 5",
            true,
            false
        ),
        "SELECT * FROM table2 WHERE (block >= $MIN_BLOCK AND block <= $MAX_BLOCK)"
    );

    // Keep sec.ind. < [...] if it has a defined higher bound
    assert_eq!(
        isolated_to_string(
            "SELECT * FROM table2 WHERE block BETWEEN $MIN_BLOCK AND $MAX_BLOCK AND foo < 5",
            false,
            true
        ),
        "SELECT * FROM table2 WHERE (block >= $MIN_BLOCK AND block <= $MAX_BLOCK) AND foo < 5"
    );

    // Nicholas's example
    assert_eq!(
        isolated_to_string(
            "SELECT * FROM table2 WHERE block BETWEEN 5 AND 10 AND (foo = 4 OR foo = 15) AND bar = 12",
            false,
            false),
        "SELECT * FROM table2 WHERE (block >= 5 AND block <= 10)");
}
