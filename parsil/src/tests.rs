#![allow(clippy::single_element_loop)]
use crate::assembler::{assemble_dynamic, DynamicCircuitPis};
use crate::isolator;
use crate::utils::ParsilSettingsBuilder;
use crate::{
    symbols::FileContextProvider,
    utils::{parse_and_validate, ParsilSettings, PlaceholderSettings},
};
use alloy::primitives::U256;
use anyhow::Result;
use verifiable_db::query::universal_circuit::universal_circuit_inputs::Placeholders;

/// NOTE: queries that may bother us in the future
// CHORE: Remove this when relevant PR is merged
#[allow(dead_code)]
const CAREFUL: &[&str] = &[
    // What to do if b.t is longer than a.x?
    "SELECT x, (SELECT t AS tt FROM b) FROM a;",
    // Double aliasing
    "SELECT pipo.not_tt FROM (SELECT t AS tt FROM b) AS pipo (not_tt);",
];

const MAX_NUM_COLUMNS: usize = 10;
const MAX_NUM_PREDICATE_OPS: usize = 20;
const MAX_NUM_RESULT_OPS: usize = 20;
const MAX_NUM_ITEMS_PER_OUTPUT: usize = 10;
const MAX_NUM_OUTPUTS: usize = 5;

type TestFileContextProvider = FileContextProvider<
    MAX_NUM_COLUMNS,
    MAX_NUM_PREDICATE_OPS,
    MAX_NUM_RESULT_OPS,
    MAX_NUM_ITEMS_PER_OUTPUT,
    MAX_NUM_OUTPUTS,
>;

#[test]
fn must_accept() -> Result<()> {
    let settings = ParsilSettings {
        context: TestFileContextProvider::from_file("tests/context.json")?,
        placeholders: PlaceholderSettings::with_freestanding(3),
        limit: None,
        offset: None,
    };

    for q in [
        "SELECT foo FROM table2",
        "SELECT foo FROM table2 WHERE bar < 3",
        "SELECT foo, * FROM table2",
        "SELECT AVG(foo) FROM table2 WHERE block BETWEEN 43 and 68",
        // "SELECT 25",
        "SELECT AVG(foo), MIN(bar) FROM table2 WHERE block = 3",
        // "SELECT '0x1122334455667788990011223344556677889900112233445566778899001122'",
        // "SELECT '0x'",
        // "SELECT '1234567'",
        // "SELECT '0b01001'",
        // "SELECT '0o1234567'",
        "SELECT foo, bar FROM table2 WHERE block = 3",
        "SELECT foo FROM table2 WHERE block IN (1, 2, 4)",
        "SELECT bar FROM table2 WHERE NOT block BETWEEN 12 AND 15",
        "SELECT a, c FROM table2 AS tt (a, b, c)",
    ] {
        parse_and_validate(q, &settings)?;
    }
    Ok(())
}

#[test]
fn must_reject() {
    let settings = ParsilSettingsBuilder::default()
        .context(TestFileContextProvider::from_file("tests/context.json").unwrap())
        .placeholders(PlaceholderSettings::with_freestanding(3))
        .build()
        .unwrap();

    for q in [
        // No ORDER BY
        "SELECT foo, bar FROM table2 ORDER BY bar",
        "SELECT foo, bar FROM table2 ORDER BY foo, bar",
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
        // Too many items in SELECT
        "SELECT a+b, a-b, a, b, c*a, c+b, c<b, c-a, a+b+c, a*b+c, c, c*a-b FROM table2 AS tt (a,b,c)",
        // Too many operations in WHERE
        "SELECT a FROM table2 AS tt (a,b,c) WHERE c+b-c*(a+c)-75 < 42*(a-b*c+a*(b-c)) AND a*56 >= b+63 OR a < b AND (a-b)*(a+b) >= a*c+b-4",
        // Too many operations in SELECT
        "SELECT c+b-c*(a+c)-75 + 42*(a-b*c+a*(b-c)), a*56 >= b+63, a < b, (a-b)*(a+b) >= a*c+b-4 FROM table2 as tt (a,b,c)",
        // LIMIT
        "SELECT a+b FROM t LIMIT 10",
        "SELECT b*c FROM t LIMIT a",
        // OFFSET
        "SELECT a+b FROM t OFFSET 10",
        "SELECT b*c FROM t OFFSET $1",
    ] {
        assert!(dbg!(parse_and_validate(q, &settings)).is_err())
    }
}

#[test]
fn ref_query() -> Result<()> {
    let settings = ParsilSettingsBuilder::default()
        .context(TestFileContextProvider::from_file("tests/context.json").unwrap())
        .placeholders(PlaceholderSettings::with_freestanding(2))
        .build()
        .unwrap();

    let q = "SELECT AVG(C1+C2/(C2*C3)), SUM(C1+C2), MIN(C1+$1), MAX(C4-2), AVG(C5) FROM T WHERE (C5 > 5 AND C1*C3 <= C4+C5 OR C3 == $2) AND C2 >= 75 AND C2 < 99";
    let _query = parse_and_validate(q, &settings)?;
    Ok(())
}

#[test]
fn test_serde_circuit_pis() {
    let settings = ParsilSettingsBuilder::default()
        .context(TestFileContextProvider::from_file("tests/context.json").unwrap())
        .placeholders(PlaceholderSettings::with_freestanding(3))
        .build()
        .unwrap();

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
fn isolation() {
    fn isolated_to_string(q: &str, lo_sec: bool, hi_sec: bool) -> String {
        let settings = ParsilSettingsBuilder::default()
            .context(TestFileContextProvider::from_file("tests/context.json").unwrap())
            .placeholders(PlaceholderSettings::with_freestanding(3))
            .build()
            .unwrap();

        let query = parse_and_validate(q, &settings).unwrap();
        isolator::isolate_with(&query, &settings, lo_sec, hi_sec)
            .unwrap()
            .to_string()
    }

    assert_eq!(
        isolated_to_string(
            "SELECT * FROM table1 WHERE block BETWEEN 1 AND 5",
            false,
            false
        ),
        format!("SELECT * FROM table1 WHERE (block >= 1 AND block <= 5) LIMIT {MAX_NUM_OUTPUTS}")
    );

    // Drop references to other columns
    assert_eq!(
        isolated_to_string(
            "SELECT * FROM table2 WHERE block BETWEEN 1 AND 5 AND 3 = 4 OR bar = 5",
            false,
            false
        ),
        format!("SELECT * FROM table2 WHERE (block >= 1 AND block <= 5) LIMIT {MAX_NUM_OUTPUTS}")
    );

    // Drop sec. ind. references if it has no kown bounds.
    assert_eq!(
        isolated_to_string(
            "SELECT * FROM table2 WHERE block BETWEEN $MIN_BLOCK AND $MAX_BLOCK AND foo < 5",
            false,
            false
        ),
        format!("SELECT * FROM table2 WHERE (block >= $MIN_BLOCK AND block <= $MAX_BLOCK) LIMIT {MAX_NUM_OUTPUTS}")
    );

    // Drop sec.ind. < [...] if it has a defined higher bound
    assert_eq!(
        isolated_to_string(
            "SELECT * FROM table2 WHERE block BETWEEN $MIN_BLOCK AND $MAX_BLOCK AND foo < 5",
            true,
            false
        ),
        format!("SELECT * FROM table2 WHERE (block >= $MIN_BLOCK AND block <= $MAX_BLOCK) LIMIT {MAX_NUM_OUTPUTS}")
    );

    // Keep sec.ind. < [...] if it has a defined higher bound
    assert_eq!(
        isolated_to_string(
            "SELECT * FROM table2 WHERE block BETWEEN $MIN_BLOCK AND $MAX_BLOCK AND foo < 5",
            false,
            true
        ),
        format!("SELECT * FROM table2 WHERE (block >= $MIN_BLOCK AND block <= $MAX_BLOCK) AND foo < 5 LIMIT {MAX_NUM_OUTPUTS}")
    );

    // Nicholas's example
    assert_eq!(
        isolated_to_string(
            "SELECT * FROM table2 WHERE block BETWEEN 5 AND 10 AND (foo = 4 OR foo = 15) AND bar = 12",
            false,
            false),
        format!("SELECT * FROM table2 WHERE (block >= 5 AND block <= 10) LIMIT {MAX_NUM_OUTPUTS}")
    );
}
