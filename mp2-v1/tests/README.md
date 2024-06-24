## Integration test

## Local test contract

The local test contracts are organized by [Foundry](https://github.com/foundry-rs/foundry),
it must be installed as a prerequisite.

The test contracts are located in `mp2-v1/test-contracts`.

Run the below steps to regenerate the Rust bindings if the test contracts are updated:

- `make int_setup`: Install forge dependencies.
- `make int_bind`: Generate the integration test contract bindings. The generated binding source code is located in `mp2-v1/tests/common/bindings`.
