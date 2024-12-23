# Integration test contract path
TEST_CONTRACT_PATH=test-contracts

# Integration test bindings folder
TEST_BINDINGS_FOLDER=bindings

# Integration test bindings module path
TEST_BINDINGS_MOD_PATH=tests/common/$(TEST_BINDINGS_FOLDER)

# Integration test bindings output path
TEST_BINDINGS_OUT_PATH=$(TEST_CONTRACT_PATH)/out/$(TEST_BINDINGS_FOLDER)

# Generate the integration test contract bindings.
bindings:

# Generate new bindings.
	forge install --root $(TEST_CONTRACT_PATH)
	forge bind --bindings-path $(TEST_BINDINGS_MOD_PATH) --alloy --module --root $(TEST_CONTRACT_PATH) --extra-output abi --overwrite
	cargo fmt


# Declare phony targets
.PHONY: bindings
