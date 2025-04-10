# Zk-SQL Coprocessor Cryptographic Backend
This repo contains the cryptographic backend for the Lagrange ZK coprocessor. 

In a nutshell, Lagrange Zk-SQL coprocessor allows to:
- Create relational tables in the Lagrange verifiable DB, using data from an EVM compatible blockchain such as storage trie content, receipts (events), in a verifiable fashion. List of currently supported source of blockchain data can be found in this section 
- Run verifiable SQL queries over these tables. List of currently supported queries can be found in 
[this section](#currently-supported-queries)

## High-Level Proving Flow

The high-level flow to provably build a table in the verifiable DB is:

- An *extraction proof* is generated to compute a cryptographic accumulator of the data to be employed to create a table; in case of blockchain data, this requires to prove the accumulator was built from data found in on-chain data structures (e.g., storage MPT)
- A *table creation* proof is generated to actually build the tables in Lagrange verifiable DB; this proof is also checking that the data employed to build the table was the same data extracted by the extraction proof, hinging upon the cryptographic accumulator

The verifiable DB supporst also updates to the tables, and the *table creation* proof can be incrementally updated to prove the construction of the updated table. Note that the verifiable DB currently supports append-only updates: indeed, to allow querying over historical data, the DB is conceived as a time-series DB, and so each modification to the DB implies that a new row is added to the table with the current timestamp (e.g., the block number in case of blockchain data)

Once a table is created, queries can be provably run over the table. Running a query generates a proof of correct computation of the query results. This proof is then recursively composed with the *table creation proof*, generating the final proof of query execution. This final proof can then be wrapped in a Groth16 proof for cheap on-chain verification.

## Cryptographic Components
The proofs employed in Zk-SQL Coprocessor are generated with the [Plonky2 proving system](https://github.com/0xPolygonZero/plonky2), built and maintained by Polygon zero.

### Recursion Framework

The recursive proof composition is performed through a recursion framework, which is built on top of Plonky2 recursion but allows to compose proofs of some circuits together in an arbitrary fashion while still keeping the same verification key. More specifically, given a set of circuits with the same public inputs, the framework allows to:

- Generate a proof for any circuit in the set
- Recursively aggregate proofs of any circuit in the set, independently from how they were generated, and an arbitrary amount of times

The useful property of the recursion framework is that the verifier can use the same verification key to verify any proof generated with the recursion framework for a given set of circuits. On the other hand, the verification key for two different set of circuits will be different, and this prevents that a prover could use arbitrary circuits in place of the ones expected by the verifier. 

This property of the recursion framework allows to have a verification key for the proofs in Zk-SQL coprocessor which is independent from how many recursion steps were employed to generate a proof, or form which circuits were employed (as soon as they are in the same circuit set)

### Cryptographic Accumulator
As cryptographic accumulator, the Zk-SQL coprocessor relies upon a multi-set digest defined over the [Ecgfp5 ellyptic curve](https://github.com/pornin/ecgfp5), whose base field is the same native field of Plonky2 (i.e., Goldilocks), thus allowing an efficient arithmetization in Plonky2 circuits. The multi-set digest employed is described in [this paper, Section 5.2](https://eprint.iacr.org/2018/907.pdf). In a nutshell, the digest is a point over the Ecgfp5 curve, and the accumulator is computed as follows: 

- Each item to be accumulated is hashed with a ZK-friendly hash function and mapped to a curve point, which is the accumulator for that item
- 2 accumulators, each being a point on the curve, are accumulated by adding over the curve points

Since the accumulation operation is commutative and associative, this accumulator has the useful property of being order-agnostic, which means that the accumulator will be the same independently from the order employed to accumulate items.

## Currently Supported On-Chain Data Sources
Currently tables in Lagrange verifiable DB can be provably built from the following on-chain data:
- **Smart contract storage data**: the following types of Solidity variables are supported:

    - *Primitive types*: Unsigned integer variables (including `address` and `bool`) and `struct`
    - *Collection types*:
    
        - Mappings: `mapping(key => value)`, where `value` could be any supported *primitive type*
        - Mappings of mappings: `mapping(outer_key => mapping(inner_key => value))`, where `value` could be any supported *primitive type*
- **Events** (WiP)

## Currently Supported Queries
1. Queries returning in `SELECT` aggregation functions over expressions of columns. Supported aggregation functions are `SUM, COUNT, AVG, MIN, MAX`
2. Queries returning in `SELECT` a list of expressions of columns (e.g., `SELECT price+qty, block/owner FROM t WHERE ...`). Also `DISTINCT` keyword can be used in this type of queries, but not variants like `DISTINCT ON(column)`, i.e., `DISTINCT` can be applied only to all the items specified in `SELECT`, not on subsets. `LIMIT` and `OFFSET` can be specified in these queries
3. **IMPORTANT:** Similarly to some SQL backends, we don’t allow queries where aggregations functions and expressions of columns are both returned in `SELECT` (e.g., a query like `SELECT AVG(price), block+qty FROM T WHERE ...` is not allowed).
4. For expressions in the `SELECT` and `WHERE` clauses, we allow the following operations:
    1. Comparison operators (i.e., `<, >, >=, <=, ==, <>`)
    2. Boolean operators (i.e, `AND, OR, NOT, XOR`)
    3. `U256` Arithmetic operators (i.e., `+, -, *, /, %`)

## Content of the Repository
This repository contains several crates that provide all the required APIs to generate the proofs necessary to provably create tables in Lagrange verifiable DB and run queries over such tables. The most relevant APIs are found in these crates:

- `mp2-v1`: Provides the generic API to construct the proving parameters, as well as the circuits that allow to generate the *extraction proof*
- `verifiable-db`: Contains public APIs and the circuit implementations that allow to:
    
    - Create/update a table in the DB
    - Compute results of queries
- `groth16-framework`: Provides the APIs to generate the final Groth16 proof to be sent on-chain

## License
All crates in this repository are licensed under the conditions found in [the LICENSE file](LICENSE)

