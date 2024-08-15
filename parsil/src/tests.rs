use anyhow::Result;

use crate::{check, resolve::resolve, symbols::FileContextProvider, utils::ParsilSettings};

/// NOTE: queries that may bother us in the future
const CAREFUL: &[&str] = &[
    // What to do if b.t is longer than a.x?
    "SELECT x, (SELECT t AS tt FROM b) FROM a;",
    // Double aliasing
    "SELECT pipo.not_tt FROM (SELECT t AS tt FROM b) AS pipo (not_tt);",
];

#[test]
fn must_accept() -> Result<()> {
    for q in [
        "SELECT 25",
        "SELECT q, r FROM pipo WHERE block = 3",
        "SELECT AVG(q), MIN(r) FROM pipo WHERE block = 3",
        "SELECT q FROM pipo WHERE block IN (1, 2, 4)",
        "SELECT q FROM pipo WHERE NOT block BETWEEN 12 AND 15",
        "SELECT foo, 39, bar FROM table2 AS tt (a, b)",
        "SELECT '0x1122334455667788990011223344556677889900112233445566778899001122'",
        "SELECT '0x'",
        "SELECT '1234567'",
        "SELECT '0b01001'",
        "SELECT '0o1234567'",
    ] {
        check(q)?;
    }
    Ok(())
}

#[test]
fn must_reject() {
    for q in [
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
        assert!(dbg!(check(q)).is_err())
    }
}

#[test]
fn must_resolve() -> Result<()> {
    for q in [
        "SELECT foo FROM table2",
        "SELECT foo FROM table2 WHERE bar < 3",
        "SELECT foo, * FROM table2",
        "SELECT AVG(foo) FROM table2 WHERE block BETWEEN 43 and 68",
        "SELECT foo, bar FROM table2 ORDER BY bar",
        "SELECT foo, bar FROM table2 ORDER BY foo, bar",
    ] {
        let ctx = FileContextProvider::from_file("tests/context.json")?;
        let query = check(q)?;
        resolve(&query, ctx, ParsilSettings::default())?;
    }
    Ok(())
}

#[test]
fn ref_query() -> Result<()> {
    let q = "SELECT AVG(C1+C2/(C2*C3)), SUM(C1+C2), MIN(C1+$1), MAX(C4-2), AVG(C5) FROM T WHERE (C5 > 5 AND C1*C3 <= C4+C5 OR C3 == $2) AND C2 >= 75 AND C2 < 99";
    let query = check(q)?;
    let ctx = FileContextProvider::from_file("tests/context.json")?;
    let exposed = resolve(&query, ctx, ParsilSettings::default())?;
    Ok(())
}
