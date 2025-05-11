# Changelog

## [2.1.1] - 2025-05-11

[Compare 1b23c63 ... c2df1e2](https://github.com/Lagrange-Labs/mapreduce-plonky2/compare/1b23c637f120352cae399ca329e5292d3354408f...c2df1e28f8bbbc17e46c3156c5945f4f1839bc3e)

### Miscellaneous Tasks



- Move PPs generation to worker - in [PR #488](https://github.com/Lagrange-Labs/mapreduce-plonky2/pull/488)

- Update dependencies - in [PR #487](https://github.com/Lagrange-Labs/mapreduce-plonky2/pull/487)

- Updates alloy dependency - in [PR #489](https://github.com/Lagrange-Labs/mapreduce-plonky2/pull/489)

## [2.1.0] - 2025-05-05

[Compare 1d7cf8a ... 1b23c63](https://github.com/Lagrange-Labs/mapreduce-plonky2/compare/1d7cf8acf76eda463609baafb678e81e3a61b20c...1b23c637f120352cae399ca329e5292d3354408f)

### Features

- *(parsil)* Ensure number of parameters matches the number of placeholders - in [PR #484](https://github.com/Lagrange-Labs/mapreduce-plonky2/pull/484)



- Ensure number of parameters matches the number of placeholders - in [PR #484](https://github.com/Lagrange-Labs/mapreduce-plonky2/pull/484)


### Bug Fixes

- *(ryhope)* Immutable `touched` method on merkle tree db - in [PR #463](https://github.com/Lagrange-Labs/mapreduce-plonky2/pull/463)



- Immutable `touched` method on merkle tree db - in [PR #463](https://github.com/Lagrange-Labs/mapreduce-plonky2/pull/463)

- Validate table & column names - in [PR #485](https://github.com/Lagrange-Labs/mapreduce-plonky2/pull/485)


### Miscellaneous Tasks



- Generate PPs after release PR is merged - in [PR #479](https://github.com/Lagrange-Labs/mapreduce-plonky2/pull/479)

- Ensure PPs generation is non-destructive - in [PR #480](https://github.com/Lagrange-Labs/mapreduce-plonky2/pull/480)

- Add Deserialize/Serialize for TableRow/OffChainRootOfTrust - in [PR #483](https://github.com/Lagrange-Labs/mapreduce-plonky2/pull/483)

- Add step to upload PPs to main account in release workflow - in [PR #481](https://github.com/Lagrange-Labs/mapreduce-plonky2/pull/481)


### Release



- V2.1.0 - in [PR #486](https://github.com/Lagrange-Labs/mapreduce-plonky2/pull/486)

## [2.0.0] - 2025-04-17

[Compare 9db80d8 ... 1d7cf8a](https://github.com/Lagrange-Labs/mapreduce-plonky2/compare/9db80d8fd4f10567e1c58c633c74af3c8c469f46...1d7cf8acf76eda463609baafb678e81e3a61b20c)

### Features



- New extraction features - in [PR #462](https://github.com/Lagrange-Labs/mapreduce-plonky2/pull/462)

- Provable commitment for off chain tables - in [PR #477](https://github.com/Lagrange-Labs/mapreduce-plonky2/pull/477)


### Bug Fixes

- *(ryhope)* Propagate an error in failed fetch to caller - in [PR #468](https://github.com/Lagrange-Labs/mapreduce-plonky2/pull/468)



- Propagate an error in failed fetch to caller - in [PR #468](https://github.com/Lagrange-Labs/mapreduce-plonky2/pull/468)

- Ryhope - handle and propagate DB conn errors - in [PR #469](https://github.com/Lagrange-Labs/mapreduce-plonky2/pull/469)

- Ensure max depth in scapegoat tree - in [PR #472](https://github.com/Lagrange-Labs/mapreduce-plonky2/pull/472)


### Refactor



- Async-ize more ryhope functions - in [PR #473](https://github.com/Lagrange-Labs/mapreduce-plonky2/pull/473)


### Miscellaneous Tasks



- Add a way to manually generate commit hash-indexed PPs - in [PR #475](https://github.com/Lagrange-Labs/mapreduce-plonky2/pull/475)

- Run PPs generation in devenv - in [PR #476](https://github.com/Lagrange-Labs/mapreduce-plonky2/pull/476)


### Release



- V2.0.0 - in [PR #478](https://github.com/Lagrange-Labs/mapreduce-plonky2/pull/478)

## [1.2.3] - 2025-03-18

[Compare f13b976 ... 9db80d8](https://github.com/Lagrange-Labs/mapreduce-plonky2/compare/f13b97656f4ac86b69d2a0a0be056673d207e932...9db80d8fd4f10567e1c58c633c74af3c8c469f46)

### Bug Fixes



- Do not crash on queries without cell tree - in [PR #466](https://github.com/Lagrange-Labs/mapreduce-plonky2/pull/466)


### Miscellaneous Tasks



- Add README - in [PR #457](https://github.com/Lagrange-Labs/mapreduce-plonky2/pull/457)


### Release



- V1.2.3 - in [PR #467](https://github.com/Lagrange-Labs/mapreduce-plonky2/pull/467)

## [1.2.2] - 2025-02-13

[Compare 196952f ... f13b976](https://github.com/Lagrange-Labs/mapreduce-plonky2/compare/196952fe435d637757dda2c02ac3f694eb57cd18...f13b97656f4ac86b69d2a0a0be056673d207e932)

### Bug Fixes



- Workflow syntax ([f8d604f](https://github.com/Lagrange-Labs/mapreduce-plonky2/commit/f8d604faf547613c3b0f773486249583810823c5))


### Miscellaneous Tasks



- Fix links in CHANGELOG ([3dab65b](https://github.com/Lagrange-Labs/mapreduce-plonky2/commit/3dab65b5c101a8380ff5f495fdbab81de9b08870))

- Simplify release PR comment - in [PR #449](https://github.com/Lagrange-Labs/mapreduce-plonky2/pull/449)

- Automatize PPs generation on major version bumps - in [PR #450](https://github.com/Lagrange-Labs/mapreduce-plonky2/pull/450)

- Update dependencies - in [PR #455](https://github.com/Lagrange-Labs/mapreduce-plonky2/pull/455)


### Release



- V1.2.2 - in [PR #456](https://github.com/Lagrange-Labs/mapreduce-plonky2/pull/456)

## [1.2.1] - 2025-01-28

[Compare 64269de ... 196952f](https://github.com/Lagrange-Labs/mapreduce-plonky2/compare/64269de918791c746baafd8a2aa1bcd6b894f26c...196952fe435d637757dda2c02ac3f694eb57cd18)

### Features



- Expose `verifiable_db` version - in [PR #447](https://github.com/Lagrange-Labs/mapreduce-plonky2/pull/447)


### Miscellaneous Tasks



- Fix commit links in CHANGELOG - in [PR #446](https://github.com/Lagrange-Labs/mapreduce-plonky2/pull/446)


### Release



- V1.2.1 - in [PR #448](https://github.com/Lagrange-Labs/mapreduce-plonky2/pull/448)

## [1.2.0] - 2025-01-27

[Compare 2f7d631 ... 64269de](https://github.com/Lagrange-Labs/mapreduce-plonky2/compare/2f7d6319369d0814fb411bfa7555d53270f209fc...64269de918791c746baafd8a2aa1bcd6b894f26c)

### Features



- Add primary index bracketing check - in [PR #433](https://github.com/Lagrange-Labs/mapreduce-plonky2/pull/433)


### Bug Fixes



- Add mp2 git version - in [PR #434](https://github.com/Lagrange-Labs/mapreduce-plonky2/pull/434)

- Info -> trace ([063277e](https://github.com/Lagrange-Labs/mapreduce-plonky2/commit/063277e67a5ba777efffb6f52d1c76e64933b997))


### Refactor



- Add methods to `UpdatePlan` API - in [PR #436](https://github.com/Lagrange-Labs/mapreduce-plonky2/pull/436)


### Miscellaneous Tasks



- Add PR linting - in [PR #439](https://github.com/Lagrange-Labs/mapreduce-plonky2/pull/439)

- Add a release pipeline ([a9e2b59](https://github.com/Lagrange-Labs/mapreduce-plonky2/commit/a9e2b59e64261e41f71244e5b196a1c48c6bc9e7))


### Release



- V1.2.0 - in [PR #445](https://github.com/Lagrange-Labs/mapreduce-plonky2/pull/445)

## [1.1.3] - 2025-01-15

[Compare 77fa458 ... 2f7d631](https://github.com/Lagrange-Labs/mapreduce-plonky2/compare/77fa458c7d136cdea2db4637d0031facfe7d38d7...2f7d6319369d0814fb411bfa7555d53270f209fc)

### Bug Fixes



- Do not crash on missing predicate - in [PR #428](https://github.com/Lagrange-Labs/mapreduce-plonky2/pull/428)

## [1.1.2] - 2025-01-09

[Compare cc50651 ... 77fa458](https://github.com/Lagrange-Labs/mapreduce-plonky2/compare/cc506517584e5bec940fcf0ce150395f6f365f48...77fa458c7d136cdea2db4637d0031facfe7d38d7)

### Refactor



- Make ryhope use its dedicated error type - in [PR #424](https://github.com/Lagrange-Labs/mapreduce-plonky2/pull/424)


### Build



- Pin rust version - in [PR #426](https://github.com/Lagrange-Labs/mapreduce-plonky2/pull/426)


### Chroe



- Update dependencies - in [PR #411](https://github.com/Lagrange-Labs/mapreduce-plonky2/pull/411)

## [1.1.1] - 2024-11-15

[Compare 4255ab1 ... cc50651](https://github.com/Lagrange-Labs/mapreduce-plonky2/compare/4255ab177fc6e7d5c1f4be55f62b1a380295b134...cc506517584e5bec940fcf0ce150395f6f365f48)

### Features



- Tabular SELECT Queries Without Aggregation Functions - in [PR #373](https://github.com/Lagrange-Labs/mapreduce-plonky2/pull/373)

## [1.1.0] - 2024-11-07

### Features



- Prove all tx in a block - in [PR #6](https://github.com/Lagrange-Labs/mapreduce-plonky2/pull/6)

- Implement 16-arity digest circuit - in [PR #37](https://github.com/Lagrange-Labs/mapreduce-plonky2/pull/37)

- Implement map-to-curve and group-hashing functions - in [PR #42](https://github.com/Lagrange-Labs/mapreduce-plonky2/pull/42)

- Add length-match circuit to prove the previous length and mapping entries proofs has the same length value - in [PR #82](https://github.com/Lagrange-Labs/mapreduce-plonky2/pull/82)

- Link state proof with block - in [PR #53](https://github.com/Lagrange-Labs/mapreduce-plonky2/pull/53)

- Mapping length extraction - in [PR #83](https://github.com/Lagrange-Labs/mapreduce-plonky2/pull/83)

- Add digest equivalence circuit for MPT and Merkle tree - in [PR #96](https://github.com/Lagrange-Labs/mapreduce-plonky2/pull/96)

- Add leaf node circuit - in [PR #105](https://github.com/Lagrange-Labs/mapreduce-plonky2/pull/105)

- Add circuit to prove the correct updating of the block database - in [PR #102](https://github.com/Lagrange-Labs/mapreduce-plonky2/pull/102)

- Add intermediate node state circuit - in [PR #111](https://github.com/Lagrange-Labs/mapreduce-plonky2/pull/111)

- Add provenance circuit for storage db - in [PR #130](https://github.com/Lagrange-Labs/mapreduce-plonky2/pull/130)

- Add groth16-framework - in [PR #131](https://github.com/Lagrange-Labs/mapreduce-plonky2/pull/131)

- Query2 API - in [PR #143](https://github.com/Lagrange-Labs/mapreduce-plonky2/pull/143)

- Add variable depth merkle tree opening - in [PR #158](https://github.com/Lagrange-Labs/mapreduce-plonky2/pull/158)

- Add tests to `hash_maybe_swap` - in [PR #169](https://github.com/Lagrange-Labs/mapreduce-plonky2/pull/169)

- Add a function to init the Groth16 prover from bytes - in [PR #194](https://github.com/Lagrange-Labs/mapreduce-plonky2/pull/194)

- Add range assertion to pi register - in [PR #206](https://github.com/Lagrange-Labs/mapreduce-plonky2/pull/206)

- Add database extraction leaf length circuit - in [PR #209](https://github.com/Lagrange-Labs/mapreduce-plonky2/pull/209)

- Add branch check to extraction circuit - in [PR #211](https://github.com/Lagrange-Labs/mapreduce-plonky2/pull/211)

- Add API interface to length extraction - in [PR #216](https://github.com/Lagrange-Labs/mapreduce-plonky2/pull/216)

- Init integration-tests with Values Extraction (C.1) tests - in [PR #217](https://github.com/Lagrange-Labs/mapreduce-plonky2/pull/217)

- Add the circuits for Contract Extraction (C.3) - in [PR #218](https://github.com/Lagrange-Labs/mapreduce-plonky2/pull/218)

- Add integrated tests to length extraction circuit - in [PR #219](https://github.com/Lagrange-Labs/mapreduce-plonky2/pull/219)

- Integrate ryhope - in [PR #238](https://github.com/Lagrange-Labs/mapreduce-plonky2/pull/238)

- Row tree creation & proving - in [PR #241](https://github.com/Lagrange-Labs/mapreduce-plonky2/pull/241)

- Implement column extraction component for query circuit - in [PR #247](https://github.com/Lagrange-Labs/mapreduce-plonky2/pull/247)

- Implement the output component with no aggregation for query circuit - in [PR #251](https://github.com/Lagrange-Labs/mapreduce-plonky2/pull/251)

- Implement full node circuits for query aggregation - in [PR #254](https://github.com/Lagrange-Labs/mapreduce-plonky2/pull/254)

- Implement partial node circuits for query aggregation - in [PR #266](https://github.com/Lagrange-Labs/mapreduce-plonky2/pull/266)

- Implement child proven single path node circuit - in [PR #256](https://github.com/Lagrange-Labs/mapreduce-plonky2/pull/256)

- Add (try_)fetch_with_context_at - in [PR #273](https://github.com/Lagrange-Labs/mapreduce-plonky2/pull/273)

- Implement non-existence leaf circuit for query aggregation - in [PR #267](https://github.com/Lagrange-Labs/mapreduce-plonky2/pull/267)

- Implement query validation - in [PR #272](https://github.com/Lagrange-Labs/mapreduce-plonky2/pull/272)

- Implement subtree proven single path node circuit - in [PR #270](https://github.com/Lagrange-Labs/mapreduce-plonky2/pull/270)

- Add public inputs for construction circuits to build results tree - in [PR #275](https://github.com/Lagrange-Labs/mapreduce-plonky2/pull/275)

- Implement revelation circuit without results tree - in [PR #271](https://github.com/Lagrange-Labs/mapreduce-plonky2/pull/271)

- Results tree construction circuits (3.B) - in [PR #279](https://github.com/Lagrange-Labs/mapreduce-plonky2/pull/279)

- Implement record construction circuits (3.A) - in [PR #283](https://github.com/Lagrange-Labs/mapreduce-plonky2/pull/283)

- Ryhope PgSQL backend may be initialized from an existing pool - in [PR #305](https://github.com/Lagrange-Labs/mapreduce-plonky2/pull/305)

- Implement query validation & translation - in [PR #277](https://github.com/Lagrange-Labs/mapreduce-plonky2/pull/277)

- Implement secondary index bracketing - in [PR #323](https://github.com/Lagrange-Labs/mapreduce-plonky2/pull/323)

- Implement grouped transactions - in [PR #318](https://github.com/Lagrange-Labs/mapreduce-plonky2/pull/318)

- Everything and the kitchen sink - in [PR #328](https://github.com/Lagrange-Labs/mapreduce-plonky2/pull/328)

- Re-inject block in `generate_query_keys` ([9f28195](https://github.com/Lagrange-Labs/mapreduce-plonky2/commit/9f281950ca365666ff9b2b08fe90b403d50de75a))

- Ensure safe typing of intermediate query formats ([31fc749](https://github.com/Lagrange-Labs/mapreduce-plonky2/commit/31fc74947c4f4c7b9052d3ede94700273122c0e2))

- Integrate core keys queries in parsil ([aa56826](https://github.com/Lagrange-Labs/mapreduce-plonky2/commit/aa56826fe48266e647a118b2ff78a7c55a43f13f))

- Improve error messages for rollbacks ([81470ac](https://github.com/Lagrange-Labs/mapreduce-plonky2/commit/81470ac5bcfa309164a297fec1652b2464c0712f))

- Clamp index tree core keys within their realm of existence - in [PR #354](https://github.com/Lagrange-Labs/mapreduce-plonky2/pull/354)

- Add `try_fetch_many_at` ([6996313](https://github.com/Lagrange-Labs/mapreduce-plonky2/commit/69963137af272e0c5b6bbc3f07de73468ec2e1c3))

- Live tree explorer - in [PR #363](https://github.com/Lagrange-Labs/mapreduce-plonky2/pull/363)

- Implement batched update trees - in [PR #375](https://github.com/Lagrange-Labs/mapreduce-plonky2/pull/375)

- Use `MAX_BIGINT` for alive nodes - in [PR #390](https://github.com/Lagrange-Labs/mapreduce-plonky2/pull/390)

- Add a way for tree aggregation to handle external data ([f3cc06d](https://github.com/Lagrange-Labs/mapreduce-plonky2/commit/f3cc06db1f901672e125ae31d709e215d14e9caf))


### Bug Fixes



- Enforce no dulicate mapping entry for branch in MPT - in [PR #104](https://github.com/Lagrange-Labs/mapreduce-plonky2/pull/104)

- Block linking pi lengths - in [PR #113](https://github.com/Lagrange-Labs/mapreduce-plonky2/pull/113)

- Restrict the generated account-node length must be within a range of `128` - in [PR #114](https://github.com/Lagrange-Labs/mapreduce-plonky2/pull/114)

- Return verifier contract file path and save groth16 proof to file (optional) - in [PR #160](https://github.com/Lagrange-Labs/mapreduce-plonky2/pull/160)

- Return combined bytes from Groth16 prove function and verify in Solidity - in [PR #166](https://github.com/Lagrange-Labs/mapreduce-plonky2/pull/166)

- Drop the groth16 asset memory manually - in [PR #197](https://github.com/Lagrange-Labs/mapreduce-plonky2/pull/197)

- Cache logic ([5ea2f1b](https://github.com/Lagrange-Labs/mapreduce-plonky2/commit/5ea2f1b1c3ac0cc94a9e37954e9f8933cc4d6fb3))

- Always commit initial staet, even if the tree is not touched. ([7f68e26](https://github.com/Lagrange-Labs/mapreduce-plonky2/commit/7f68e2672c1637a88a06e988d9749efef6b3da8f))

- Always commit initial state, even if the tree is not touched. - in [PR #289](https://github.com/Lagrange-Labs/mapreduce-plonky2/pull/289)

- Erroneous cache interpretation at commit - in [PR #295](https://github.com/Lagrange-Labs/mapreduce-plonky2/pull/295)

- Update the revelation public inputs to align with Uint256 (part-1 of Groth16 integration) - in [PR #310](https://github.com/Lagrange-Labs/mapreduce-plonky2/pull/310)

- Make some testing functions public for using them in groth16-framework (part-2 of Groth16 integration) - in [PR #311](https://github.com/Lagrange-Labs/mapreduce-plonky2/pull/311)

- Erroneous initial cache status - in [PR #331](https://github.com/Lagrange-Labs/mapreduce-plonky2/pull/331)

- CEIL -> FLOOR ([9593048](https://github.com/Lagrange-Labs/mapreduce-plonky2/commit/9593048448e9a65cb106726aa18cd61ee78c914a))

- Double-commit in PgSqlStorage ([c429943](https://github.com/Lagrange-Labs/mapreduce-plonky2/commit/c42994349a27db7ec485bce862d3b2bb902036e3))

- Make tests build - in [PR #342](https://github.com/Lagrange-Labs/mapreduce-plonky2/pull/342)

- Escape ryhope columns - in [PR #341](https://github.com/Lagrange-Labs/mapreduce-plonky2/pull/341)

- Unify nomenclature ([0a679f6](https://github.com/Lagrange-Labs/mapreduce-plonky2/commit/0a679f610667499807df4329ade1db557e8a14f7))

- Query injection shenanigans ([952f8c7](https://github.com/Lagrange-Labs/mapreduce-plonky2/commit/952f8c774f921a91c2003a2cb90bd5363f5b1954))

- Tests ([0d8ec89](https://github.com/Lagrange-Labs/mapreduce-plonky2/commit/0d8ec8985116e088f3155fb2f4dc704a917f4821))

- Fetch payload from zkTables ([1e492d1](https://github.com/Lagrange-Labs/mapreduce-plonky2/commit/1e492d1701c7adc7d6109d9a5beead38ef00ab5c))

- Forgotten ([4283eba](https://github.com/Lagrange-Labs/mapreduce-plonky2/commit/4283eba9b60dc6167256e01334b91b6d5c193d48))

- Correctly handle Gt/Lt in secondary index bound computations - in [PR #356](https://github.com/Lagrange-Labs/mapreduce-plonky2/pull/356)

- Remove useless cast - in [PR #359](https://github.com/Lagrange-Labs/mapreduce-plonky2/pull/359)

- Set the epoch at which the wide lineages are computed - in [PR #360](https://github.com/Lagrange-Labs/mapreduce-plonky2/pull/360)

- SBBST lineage computation ([8fecdb3](https://github.com/Lagrange-Labs/mapreduce-plonky2/commit/8fecdb36a2c573559df91d7a251681fcef35605b))

- Small optimization ([4e9c77f](https://github.com/Lagrange-Labs/mapreduce-plonky2/commit/4e9c77f3cc50b5831dd8ca7f66d7eb4e8ecd4aec))

- Add local test for the Groth16 proof - in [PR #370](https://github.com/Lagrange-Labs/mapreduce-plonky2/pull/370)

- Add `QueryError` to verifier contract - in [PR #374](https://github.com/Lagrange-Labs/mapreduce-plonky2/pull/374)

- Differentiate between placeholder traversing and validation ([46dbe78](https://github.com/Lagrange-Labs/mapreduce-plonky2/commit/46dbe78be71654ad16f3284535f678337ea41b1c))

- Better messages - in [PR #394](https://github.com/Lagrange-Labs/mapreduce-plonky2/pull/394)

- Missing .gitmodules ([62d7d0e](https://github.com/Lagrange-Labs/mapreduce-plonky2/commit/62d7d0e6bcd25e264486e01c6ee4621dec732d90))


### Refactor



- Move ryhope into mapreduce-plonky2 - in [PR #259](https://github.com/Lagrange-Labs/mapreduce-plonky2/pull/259)

- Impose Debug on UpdateTree::K ([c677ded](https://github.com/Lagrange-Labs/mapreduce-plonky2/commit/c677ded3fb000015cac2d71f5e32c9db91bf006f))

- Better naming ([0601f97](https://github.com/Lagrange-Labs/mapreduce-plonky2/commit/0601f9761b44b241170ceee3f5941b1bb1d87645))

- Split between visitor and mutator - in [PR #340](https://github.com/Lagrange-Labs/mapreduce-plonky2/pull/340)

- Compute cryptographic IDs in the QE - in [PR #349](https://github.com/Lagrange-Labs/mapreduce-plonky2/pull/349)


### Documentation



- Generate cargo docs on github pages - in [PR #303](https://github.com/Lagrange-Labs/mapreduce-plonky2/pull/303)


### Performance



- Implement batched fetch operations  - in [PR #379](https://github.com/Lagrange-Labs/mapreduce-plonky2/pull/379)


### Miscellaneous Tasks



- Fix many warnings - in [PR #165](https://github.com/Lagrange-Labs/mapreduce-plonky2/pull/165)

- Update CI runner - in [PR #215](https://github.com/Lagrange-Labs/mapreduce-plonky2/pull/215)

- Unify integrated tests - in [PR #228](https://github.com/Lagrange-Labs/mapreduce-plonky2/pull/228)

- Cleanup some clippy warnings ([1e8d089](https://github.com/Lagrange-Labs/mapreduce-plonky2/commit/1e8d089f4bd1b5ae3a6a22adab80974d2ff3b6b7))

- Fix visibility warnings ([5d65e63](https://github.com/Lagrange-Labs/mapreduce-plonky2/commit/5d65e639274d840e46bd9642f5ecfac55e771ff6))

- Anvil binary is required - in [PR #265](https://github.com/Lagrange-Labs/mapreduce-plonky2/pull/265)

- Remove dead code warnings - in [PR #263](https://github.com/Lagrange-Labs/mapreduce-plonky2/pull/263)

- Formatting ([95d84ba](https://github.com/Lagrange-Labs/mapreduce-plonky2/commit/95d84babfc8ec549b3ef40bb1076aa1c615f8260))

- Prune imports ([60263f7](https://github.com/Lagrange-Labs/mapreduce-plonky2/commit/60263f78fc5c9effb47c4c7131b8940d1ed565af))

- Fix lint `async_fn_in_trait` - in [PR #378](https://github.com/Lagrange-Labs/mapreduce-plonky2/pull/378)


### API



- Define standard method off-circuit/in-circuit for encoding leaves - in [PR #117](https://github.com/Lagrange-Labs/mapreduce-plonky2/pull/117)


### WiP



- Test custom placeholders in integrated test ([7ee2caa](https://github.com/Lagrange-Labs/mapreduce-plonky2/commit/7ee2caae21d3d8ef94284f3649aa0f6a641e8ffa))

- Still need to test ([4583491](https://github.com/Lagrange-Labs/mapreduce-plonky2/commit/45834916ceb77de44a278040e1ef3b63cb9a8f9c))


### Bug



- Fix the order issue in query2 verifier contract - in [PR #189](https://github.com/Lagrange-Labs/mapreduce-plonky2/pull/189)


### Build



- Update dependencies - in [PR #121](https://github.com/Lagrange-Labs/mapreduce-plonky2/pull/121)

- Enable more agressive optimizations - in [PR #258](https://github.com/Lagrange-Labs/mapreduce-plonky2/pull/258)

- Disable commit hooks ([b425461](https://github.com/Lagrange-Labs/mapreduce-plonky2/commit/b42546156aa6f59c8de4cf19a71dc0dfb9c8afd7))

- Unify devenv ([835901e](https://github.com/Lagrange-Labs/mapreduce-plonky2/commit/835901e6bb1d432e2fd395d0f71d156ac1783735))

- Use a random PgSQL port on CI - in [PR #296](https://github.com/Lagrange-Labs/mapreduce-plonky2/pull/296)


### Debug



- Dump caches at rollback - in [PR #376](https://github.com/Lagrange-Labs/mapreduce-plonky2/pull/376)

- Logs ([3a7efc0](https://github.com/Lagrange-Labs/mapreduce-plonky2/commit/3a7efc0c79c6001739ec8e5639f4343c446da975))


### Hack



- Refuse non-aggregated queries - in [PR #337](https://github.com/Lagrange-Labs/mapreduce-plonky2/pull/337)


### Utils



- : + rlp::  - in [PR #1](https://github.com/Lagrange-Labs/mapreduce-plonky2/pull/1)

<!-- generated by git-cliff -->
