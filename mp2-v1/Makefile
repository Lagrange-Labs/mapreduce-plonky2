# Foundry configuration file path
FOUNDRY_CONFIG=test-contracts/foundry.toml

# Anvil local RPC URL
ANVIL_RPC_URL=http://0.0.0.0:8545

# Anvil testing private key for signing the transcations
ANVIL_PRIVATE_KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80

# Deployment arguments for the test contracts
TEST_CONTRACT_DEPLOY_ARGS=--broadcast --rpc-url ${ANVIL_RPC_URL} --private-key ${ANVIL_PRIVATE_KEY}

fmt:
	cargo fmt
	FOUNDRY_CONFIG=${FOUNDRY_CONFIG} forge fmt

integration_init:
	FOUNDRY_CONFIG=${FOUNDRY_CONFIG} forge clean
	FOUNDRY_CONFIG=${FOUNDRY_CONFIG} forge install
	FOUNDRY_CONFIG=${FOUNDRY_CONFIG} forge build

integration_start:
	anvil

integration_deploy:
	FOUNDRY_CONFIG=${FOUNDRY_CONFIG} forge script DeploySimple ${TEST_CONTRACT_DEPLOY_ARGS}

integration_import:
	sh test-contracts/data/init_simple.sh
