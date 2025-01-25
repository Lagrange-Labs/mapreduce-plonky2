# Changelog

## [1.2.0] - 2025-01-25

[2f7d631](2f7d6319369d0814fb411bfa7555d53270f209fc)...[1a80b39](1a80b397567a088b7aa30455692e0294976144ba)

### Features



- Add primary index bracketing check (#433)


### Bug Fixes



- Add mp2 git version (#434)

- Info -> trace


### Refactor



- Add methods to `UpdatePlan` API (#436)


### Miscellaneous Tasks



- Add PR linting (#439)

- Add a release pipeline (#440)


## [1.1.3] - 2025-01-15

[77fa458](77fa458c7d136cdea2db4637d0031facfe7d38d7)...[2f7d631](2f7d6319369d0814fb411bfa7555d53270f209fc)

### Bug Fixes



- Do not crash on missing predicate (#428)


## [1.1.2] - 2025-01-09

[cc50651](cc506517584e5bec940fcf0ce150395f6f365f48)...[77fa458](77fa458c7d136cdea2db4637d0031facfe7d38d7)

### Refactor



- Make ryhope use its dedicated error type (#424)


### Build



- Pin rust version (#426)


### Chroe



- Update dependencies (#411)


## [1.1.1] - 2024-11-15

[4255ab1](4255ab177fc6e7d5c1f4be55f62b1a380295b134)...[cc50651](cc506517584e5bec940fcf0ce150395f6f365f48)

### Features



- Tabular SELECT Queries Without Aggregation Functions (#373)


## [1.1.0] - 2024-11-07

### Features



- Prove all tx in a block (#6)

- Implement 16-arity digest circuit (#37)

- Implement map-to-curve and group-hashing functions (#42)

- Add length-match circuit to prove the previous length and mapping entries proofs has the same length value (#82)

- Link state proof with block (#53)

- Mapping length extraction (#83)

- Add digest equivalence circuit for MPT and Merkle tree (#96)

- Add leaf node circuit (#105)

- Add circuit to prove the correct updating of the block database (#102)

- Add intermediate node state circuit (#111)

- Add provenance circuit for storage db (#130)

- Add groth16-framework (#131)

- Query2 API (#143)

- Add variable depth merkle tree opening (#158)

- Add tests to `hash_maybe_swap` (#169)

- Add a function to init the Groth16 prover from bytes (#194)

- Add range assertion to pi register (#206)

- Add database extraction leaf length circuit (#209)

- Add branch check to extraction circuit (#211)

- Add API interface to length extraction (#216)

- Init integration-tests with Values Extraction (C.1) tests (#217)

- Add the circuits for Contract Extraction (C.3) (#218)

- Add integrated tests to length extraction circuit (#219)

- Integrate ryhope (#238)

- Row tree creation & proving (#241)

- Implement column extraction component for query circuit (#247)

- Implement the output component with no aggregation for query circuit (#251)

- Implement full node circuits for query aggregation (#254)

- Implement partial node circuits for query aggregation (#266)

- Implement child proven single path node circuit (#256)

- Add (try_)fetch_with_context_at (#273)

- Implement non-existence leaf circuit for query aggregation (#267)

- Implement query validation (#272)

- Implement subtree proven single path node circuit (#270)

- Add public inputs for construction circuits to build results tree (#275)

- Implement revelation circuit without results tree (#271)

- Results tree construction circuits (3.B) (#279)

- Implement record construction circuits (3.A) (#283)

- Ryhope PgSQL backend may be initialized from an existing pool (#305)

- Implement query validation & translation (#277)

- Implement secondary index bracketing (#323)

- Implement grouped transactions (#318)

- Everything and the kitchen sink (#328)

- Re-inject block in `generate_query_keys`

- Ensure safe typing of intermediate query formats

- Integrate core keys queries in parsil

- Improve error messages for rollbacks

- Clamp index tree core keys within their realm of existence (#354)

- Add `try_fetch_many_at`

- Live tree explorer (#363)

- Implement batched update trees (#375)

- Use `MAX_BIGINT` for alive nodes (#390)

- Add a way for tree aggregation to handle external data (#398)


### Bug Fixes



- Enforce no dulicate mapping entry for branch in MPT (#104)

- Block linking pi lengths (#113)

- Restrict the generated account-node length must be within a range of `128` (#114)

- Return verifier contract file path and save groth16 proof to file (optional) (#160)

- Return combined bytes from Groth16 prove function and verify in Solidity (#166)

- Drop the groth16 asset memory manually (#197)

- Cache logic

- Always commit initial staet, even if the tree is not touched.

- Always commit initial state, even if the tree is not touched.

- Erroneous cache interpretation at commit (#295)

- Update the revelation public inputs to align with Uint256 (part-1 of Groth16 integration) (#310)

- Make some testing functions public for using them in groth16-framework (part-2 of Groth16 integration) (#311)

- Erroneous initial cache status (#331)

- CEIL -> FLOOR

- Double-commit in PgSqlStorage

- Make tests build (#342)

- Escape ryhope columns (#341)

- Unify nomenclature

- Query injection shenanigans

- Tests

- Fetch payload from zkTables

- Forgotten

- Correctly handle Gt/Lt in secondary index bound computations (#356)

- Remove useless cast (#359)

- Set the epoch at which the wide lineages are computed (#360)

- SBBST lineage computation

- Small optimization

- Add local test for the Groth16 proof (#370)

- Add `QueryError` to verifier contract (#374)

- Differentiate between placeholder traversing and validation

- Better messages (#394)

- Missing .gitmodules


### Refactor



- Move ryhope into mapreduce-plonky2 (#259)

- Impose Debug on UpdateTree::K

- Better naming

- Split between visitor and mutator (#340)

- Compute cryptographic IDs in the QE (#349)


### Documentation



- Generate cargo docs on github pages (#303)


### Performance



- Implement batched fetch operations  (#379)


### Miscellaneous Tasks



- Fix many warnings (#165)

- Update CI runner (#215)

- Unify integrated tests (#228)

- Cleanup some clippy warnings

- Fix visibility warnings

- Anvil binary is required (#265)

- Remove dead code warnings (#263)

- Formatting

- Prune imports

- Fix lint `async_fn_in_trait` (#378)


### API



- Define standard method off-circuit/in-circuit for encoding leaves (#117)


### WiP



- Test custom placeholders in integrated test

- Still need to test


### Bug



- Fix the order issue in query2 verifier contract (#189)


### Build



- Update dependencies (#121)

- Enable more agressive optimizations (#258)

- Disable commit hooks

- Unify devenv

- Use a random PgSQL port on CI (#296)


### Debug



- Dump caches at rollback (#376)

- Logs


### Hack



- Refuse non-aggregated queries (#337)


### Utils



- : + rlp::  (#1)


<!-- generated by git-cliff -->
