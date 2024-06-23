## Integration test

## Local test contract

The local test contracts are organized by [Foundry](https://github.com/foundry-rs/foundry),
it must be installed as a prerequisite.

The source code is located in `mp2-v1/test-contracts/src` and deployment code in `mp2-v1/test-contracts/script`.

Before running the integration test against the local test contracts on local, should make the below steps:

- Enter `mp2-v1` project folder.
- Run `make integration_init` to build the local test contracts.
- Run `make integration_start` to start `anvil` as a local test node, it runs with logs in block mode.
- Enter another CMD session and run `make integration_deploy` to deploy the contracts.
- Run `make integration_import` to initialize the contract data by calling its functions.

If you want to update the contract source code, should follow the below steps (e.g. Simple contract):

- Update the source code of Simple contract `mp2-v1/test-contracts/src/Simple.sol`.
- Run `make integration_init` to rebuild the contract.
- (Assume `anvil` has already been run for local test node) run `make integration_deploy` to redeploy it.
- Get the new contract address in the deployment message.
- Update the new contract address in `mp2-v1/test-contracts/data/init_simple.sh` (`SIMPLE_CONTRACT`).
- Run `make integration_import` to initialize the contract data of the new contract.
- Update the test case code in `mp2-v1/tests/common/cases/local_simple.rs` (`LOCAL_SIMPLE_ADDRESS`).
- Run the integration test with the new contract.
