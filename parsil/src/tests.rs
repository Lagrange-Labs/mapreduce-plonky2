use anyhow::Result;

use crate::prepare;

#[test]
fn must_accept() -> Result<()> {
    for q in [
        "SELECT 25",
        "SELECT q FROM pipo WHERE block = 3",
        "SELECT q FROM pipo WHERE block IN (1, 2, 4)",
        "SELECT q FROM pipo WHERE NOT block BETWEEN 12 AND 15",
    ] {
        prepare(q)?;
    }
    Ok(())
}

#[test]
fn must_reject() {
    for q in [
        // Funcalls unsupported
        "SELECT q FROM t WHERE SOME_FUNC(q)",
        // Bitwise operators unsupported
        "SELECT a & b FROM t WHERE SOME_FUNC(q)",
        "SELECT a | b FROM t WHERE SOME_FUNC(q)",
        "SELECT a ^ b FROM t WHERE SOME_FUNC(q)",
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
    ] {
        assert!(dbg!(prepare(q)).is_err())
    }
}
