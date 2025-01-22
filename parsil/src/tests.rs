#![allow(clippy::single_element_loop)]
use crate::assembler::{assemble_dynamic, assemble_static, DynamicCircuitPis};
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
fn prim_index_bounds() -> Result<()> {
    fn check(query: &str) -> Result<()> {
        let settings = ParsilSettings {
            context: TestFileContextProvider::from_file("tests/context.json")?,
            placeholders: PlaceholderSettings::with_freestanding(3),
            limit: None,
            offset: None,
        };
        let query = parse_and_validate(query, &settings)?;
        assemble_static(&query, &settings).map(|_| ())
    }

    assert!(check(
        "SELECT pipo FROM table1 WHERE block = $1 OR block BETWEEN $MIN_BLOCK AND $MAX_BLOCK;"
    )
    .is_err());
    assert!(check(
        "SELECT pipo FROM table1 WHERE block = pipo + 5 OR block BETWEEN $MIN_BLOCK AND $MAX_BLOCK"
    )
    .is_err());
    assert!(
        check("SELECT pipo FROM table1 WHERE block = pipo + 5 AND block BETWEEN 10 AND 15")
            .is_err()
    );
    assert!(check(
        "SELECT pipo FROM table1 WHERE block = pipo + 5 AND block BETWEEN $MIN_BLOCK AND $MAX_BLOCK"
    )
    .is_ok());
    assert!(check(
        "SELECT pipo FROM table1 WHERE block = pipo + 5 AND block BETWEEN $MIN_BLOCK AND $1"
    )
    .is_err());
    assert!(check("SELECT pipo FROM table1 WHERE block < MAX_BLOCK").is_err());
    assert!(check("SELECT pipo FROM table1 WHERE block > $MIN_BLOCK").is_err());
    assert!(
        check("SELECT pipo FROM table1 WHERE block < $MAX_BLOCK AND block > $MIN_BLOCK").is_err()
    );
    assert!(
        check("SELECT pipo FROM table1 WHERE block <= $MAX_BLOCK AND block >= $MIN_BLOCK").is_ok()
    );
    assert!(
        check("SELECT pipo FROM table1 WHERE block >= $MIN_BLOCK AND block <= $MAX_BLOCK").is_ok()
    );
    assert!(
        check("SELECT pipo FROM table1 WHERE block >= $MAX_BLOCK AND block <= $MIN_BLOCK").is_err()
    );
    Ok(())
}

#[test]
fn must_accept() -> Result<()> {
    let settings = ParsilSettings {
        context: TestFileContextProvider::from_file("tests/context.json")?,
        placeholders: PlaceholderSettings::with_freestanding(3),
        limit: None,
        offset: None,
    };

    for q in [
        "SELECT foo FROM table2 WHERE block BETWEEN $MIN_BLOCK AND $MAX_BLOCK",
        "SELECT foo FROM table2 WHERE bar < 3 AND block BETWEEN $MIN_BLOCK AND $MAX_BLOCK",
        "SELECT foo, * FROM table2 WHERE block BETWEEN $MIN_BLOCK AND $MAX_BLOCK",
        "SELECT AVG(foo) FROM table2 WHERE block BETWEEN $MIN_BLOCK and $MAX_BLOCK",
        // "SELECT 25",
        "SELECT AVG(foo), MIN(bar) FROM table2 WHERE block = 3 AND block BETWEEN $MIN_BLOCK AND $MAX_BLOCK",
        // "SELECT '0x1122334455667788990011223344556677889900112233445566778899001122'",
        // "SELECT '0x'",
        // "SELECT '1234567'",
        // "SELECT '0b01001'",
        // "SELECT '0o1234567'",
        "SELECT foo, bar FROM table2 WHERE block = 3 AND block BETWEEN $MIN_BLOCK AND $MAX_BLOCK",
        "SELECT foo FROM table2 WHERE block IN (1, 2, 4) AND block BETWEEN $MIN_BLOCK AND $MAX_BLOCK",
        "SELECT bar FROM table2 WHERE NOT block BETWEEN 12 AND 15 AND block BETWEEN $MIN_BLOCK AND $MAX_BLOCK",
        "SELECT a, c FROM table2 AS tt (a, b, c) WHERE a BETWEEN $MIN_BLOCK AND $MAX_BLOCK",
    ] {
        parse_and_validate(dbg!(q), &settings)?;
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

    let q = "SELECT AVG(C1+C2/(C2*C3)), SUM(C1+C2), MIN(C1+$1), MAX(C4-2), AVG(C5) FROM T WHERE block  BETWEEN $MIN_BLOCK AND $MAX_BLOCK AND (C5 > 5 AND C1*C3 <= C4+C5 OR C3 == $2) AND C2 >= 75 AND C2 < 99";
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
    fn isolated_to_string(q: &str, lo_sec: Option<U256>, hi_sec: Option<U256>) -> String {
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
            "SELECT * FROM table2 WHERE block BETWEEN $MIN_BLOCK AND $MAX_BLOCK",
            None,
            None
        ),
        format!("SELECT * FROM table2 WHERE table2.block >= $MIN_BLOCK AND table2.block <= $MAX_BLOCK LIMIT {MAX_NUM_OUTPUTS}")
    );

    // Drop references to other columns
    assert_eq!(
        isolated_to_string(
            "SELECT * FROM table2 WHERE (block BETWEEN $MIN_BLOCK AND $MAX_BLOCK) AND (3 = 4 OR bar = 5)",
            None,
            None
        ),
        format!("SELECT * FROM table2 WHERE table2.block >= $MIN_BLOCK AND table2.block <= $MAX_BLOCK LIMIT {MAX_NUM_OUTPUTS}")
    );

    // Drop sec. ind. references if it has no known bounds.
    assert_eq!(
        isolated_to_string(
            "SELECT * FROM table2 WHERE block BETWEEN $MIN_BLOCK AND $MAX_BLOCK AND foo < 5",
            None,
            None
        ),
        format!("SELECT * FROM table2 WHERE table2.block >= $MIN_BLOCK AND table2.block <= $MAX_BLOCK LIMIT {MAX_NUM_OUTPUTS}")
    );

    // Drop sec.ind. < [...] if it has a defined higher bound
    assert_eq!(
        isolated_to_string(
            "SELECT * FROM table2 WHERE block BETWEEN $MIN_BLOCK AND $MAX_BLOCK AND foo < 5",
            Some(U256::from(45)),
            None,
        ),
        format!("SELECT * FROM table2 WHERE table2.block >= $MIN_BLOCK AND table2.block <= $MAX_BLOCK AND table2.foo >= 45 LIMIT {MAX_NUM_OUTPUTS}")
    );

    // Keep sec.ind. < [...] if it has a defined higher bound
    assert_eq!(
        isolated_to_string(
            "SELECT * FROM table2 WHERE block BETWEEN $MIN_BLOCK AND $MAX_BLOCK AND foo < 5",
            None,
            Some(U256::from(4))
        ),
        format!("SELECT * FROM table2 WHERE table2.block >= $MIN_BLOCK AND table2.block <= $MAX_BLOCK AND table2.foo <= 4 LIMIT {MAX_NUM_OUTPUTS}")
    );

    // Both secondary index bounds
    assert_eq!(
        isolated_to_string(
            "SELECT * FROM table2 WHERE block BETWEEN $MIN_BLOCK AND $MAX_BLOCK AND foo = 50",
            Some(U256::from(45)),
            Some(U256::from(56))
        ),
        format!("SELECT * FROM table2 WHERE table2.block >= $MIN_BLOCK AND table2.block <= $MAX_BLOCK AND table2.foo >= 45 AND table2.foo <= 56 LIMIT {MAX_NUM_OUTPUTS}")
    );

    // Ignore any other primary index predicate
    assert_eq!(
        isolated_to_string(
            "SELECT * FROM table2 WHERE block BETWEEN $MIN_BLOCK AND $MAX_BLOCK AND block = 50",
            None,
            None
        ),
        format!("SELECT * FROM table2 WHERE table2.block >= $MIN_BLOCK AND table2.block <= $MAX_BLOCK LIMIT {MAX_NUM_OUTPUTS}")
    );

    // Nicholas's example
    assert_eq!(
        isolated_to_string(
            "SELECT * FROM table2 WHERE block BETWEEN $MIN_BLOCK AND $MAX_BLOCK AND (foo = 4 OR foo = 15) AND bar = 12",
            None,
            None),
        format!("SELECT * FROM table2 WHERE table2.block >= $MIN_BLOCK AND table2.block <= $MAX_BLOCK LIMIT {MAX_NUM_OUTPUTS}")
    );
}
