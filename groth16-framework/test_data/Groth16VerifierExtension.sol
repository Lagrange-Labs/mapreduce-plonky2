// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import {Verifier} from "./Verifier.sol";

// The query input struct passed into the processQuery function
struct QueryInput {
    // Query limit parameter
    uint32 limit;
    // Query offset parameter
    uint32 offset;
    // Minimum block number
    uint64 minBlockNumber;
    // Maximum block number
    uint64 maxBlockNumber;
    // Block hash
    bytes32 blockHash;
    // Computational hash
    bytes32 computationalHash;
    // User placeholder values
    bytes32[] userPlaceholders;
}

// The query output struct returned from the processQuery function
struct QueryOutput {
    // Total number of the all matching rows
    uint256 totalMatchedRows;
    // Returned rows of the current cursor
    bytes[] rows;
    // Query error, return NoError if none.
    QueryErrorCode error;
}

// Query errors
enum QueryErrorCode {
    // No error
    NoError,
    // A computation overflow error during the query process
    ComputationOverflow
}

contract Groth16VerifierExtension is Verifier {
    // Top 3 bits mask.
    uint256 constant TOP_THREE_BIT_MASK = ~(uint256(7) << 253);

    // Generic constants for the supported queries
    // TODO: These constants are possible to be changed depending on user queries exploration.
    // Once we know which queries users are mostly doing, we'll be able to modify these constants.
    // Maximum number of the results
    uint32 constant MAX_NUM_OUTPUTS = 3;
    // Maximum number of the items per result
    uint32 constant MAX_NUM_ITEMS_PER_OUTPUT = 5;
    // Maximum number of the placeholders
    uint32 constant MAX_NUM_PLACEHOLDERS = 10;

    // The start uint256 offset of the public inputs in calldata.
    // groth16_proof_number (8) + groth16_input_number (3)
    uint32 constant PI_OFFSET = 11;

    // These values are aligned and each is an uint256.
    // Block hash uint256 position in the public inputs
    uint32 constant BLOCK_HASH_POS = 0;
    // Flattened computational hash uint256 position
    uint32 constant COMPUTATIONAL_HASH_POS = BLOCK_HASH_POS + 1;
    // Placeholder values uint256 position
    uint32 constant PLACEHOLDER_VALUES_POS = COMPUTATIONAL_HASH_POS + 1;
    // Result values uint256 position
    uint32 constant RESULT_VALUES_POS = PLACEHOLDER_VALUES_POS + MAX_NUM_PLACEHOLDERS;

    // The remaining items of public inputs are saved in one uint256.
    // The uint256 offset of the last uint256 of public inputs in calldata.
    uint32 constant PI_REM_OFFSET = PI_OFFSET + RESULT_VALUES_POS + MAX_NUM_OUTPUTS * MAX_NUM_ITEMS_PER_OUTPUT;
    // Placeholder number uint32 position in the last uint256
    uint32 constant REM_NUM_PLACEHOLDERS_POS = 0;
    // Result number uint32 position
    uint32 constant REM_NUM_RESULTS_POS = 1;
    // Entry count (current result number) uint32 position
    uint32 constant REM_ENTRY_COUNT_POS = 2;
    // Overflow flag uint32 position
    uint32 constant REM_OVERFLOW_POS = 3;
    // Query limit uint32 position
    uint32 constant REM_QUERY_LIMIT_POS = 4;
    // Query offset uint32 position
    uint32 constant REM_QUERY_OFFSET_POS = 5;

    // The total byte length of public inputs
    uint32 constant PI_LEN = 32 * (PI_REM_OFFSET - PI_OFFSET) + (REM_QUERY_OFFSET_POS + 1) * 4;

    // The processQuery function does the followings:
    // 1. Parse the Groth16 proofs (8 uint256) and inputs (3 uint256) from the `data`
    //    argument, and call `verifyProof` function for Groth16 verification.
    // 2. Calculate sha256 on the public inputs, and set the top 3 bits of this hash to 0.
    //    Then ensure this hash value equals to the last Groth16 input (groth16_inputs[2]).
    // 3. Parse the items from public inputs, and check as expected for query.
    // 4. Parse and return the query output from public inputs.
    function processQuery(bytes32[] calldata data, QueryInput memory query)
        public
        view
        virtual
        returns (QueryOutput memory)
    {
        // 1. Groth16 verification
        uint256[3] memory groth16Inputs = verifyGroth16Proof(data);

        // 2. Ensure the sha256 of public inputs equals to the last Groth16 input.
        verifyPublicInputs(data, groth16Inputs);

        // 3. Ensure the items of public inputs equal as expected for query.
        QueryErrorCode error = verifyQuery(data, query);

        // 4. Parse and return the query output.
        return parseOutput(data, error);
    }

    // Parse the Groth16 proofs and inputs, do verification, and returns the Groth16 inputs.
    function verifyGroth16Proof(bytes32[] calldata data) internal view virtual returns (uint256[3] memory) {
        uint256[8] memory proofs;
        uint256[3] memory inputs;

        for (uint32 i = 0; i < 8; ++i) {
            proofs[i] = uint256(data[i]);
        }
        for (uint32 i = 0; i < 3; ++i) {
            inputs[i] = uint256(data[i + 8]);
        }

        // Ensure the sha256 hash equals to the last Groth16 input.
        require(inputs[0] == uint256(CIRCUIT_DIGEST), "The first Groth16 input must be equal to the circuit digest");

        // Verify the Groth16 proof.
        this.verifyProof(proofs, inputs);

        return inputs;
    }

    // Compute sha256 on the public inputs, and ensure it equals to the last Groth16 input.
    function verifyPublicInputs(bytes32[] calldata data, uint256[3] memory groth16Inputs) internal pure virtual {
        // Parse the public inputs from calldata.
        bytes memory pi = parsePublicInputs(data);

        // Calculate sha256.
        uint256 hash = uint256(sha256(pi));
        // Set the top 3 bits of the hash value to 0.
        hash = hash & TOP_THREE_BIT_MASK;

        // Require the sha256 equals to the last Groth16 input.
        require(
            hash == groth16Inputs[2], "The sha256 hash of public inputs must be equal to the last of the Groth16 inputs"
        );
    }

    // Parse the public inputs from calldata.
    function parsePublicInputs(bytes32[] calldata data) internal pure returns (bytes memory) {
        bytes memory pi = new bytes(PI_LEN);

        // The calldata is encoded as Bytes32.
        uint256 b32Len = PI_LEN / 32;
        for (uint256 i = 0; i < b32Len; ++i) {
            bytes32 b = data[PI_OFFSET + i];
            for (uint32 j = 0; j < 32; ++j) {
                pi[i * 32 + j] = bytes1(b[j]);
            }
        }
        bytes32 rem = data[PI_OFFSET + b32Len];
        for (uint32 i = 0; i < PI_LEN % 32; ++i) {
            pi[b32Len * 32 + i] = rem[i];
        }

        return pi;
    }

    // Verify the public inputs with the expected query.
    function verifyQuery(bytes32[] calldata data, QueryInput memory query)
        internal
        view
        virtual
        returns (QueryErrorCode)
    {
        // Retrieve the last Uint256 of public inputs.
        bytes32 rem = data[PI_REM_OFFSET];

        // Check the block hash and computational hash.
        bytes32 blockHash = convertToBlockHash(data[PI_OFFSET + BLOCK_HASH_POS]);
        verifyBlockHash(blockHash, query.blockHash);
        bytes32 computationalHash = data[PI_OFFSET + COMPUTATIONAL_HASH_POS];
        require(computationalHash == query.computationalHash, "Computational hash must equal as expected.");

        uint32 numPlaceholders = uint32(bytes4(rem << (REM_NUM_PLACEHOLDERS_POS * 32)));
        require(numPlaceholders <= MAX_NUM_PLACEHOLDERS, "Placeholder number cannot overflow.");
        require(
            // The first two placeholders are minimum and maximum block numbers.
            numPlaceholders == query.userPlaceholders.length + 2,
            "Placeholder number cannot overflow and must equal as expected."
        );
        // Check the minimum and maximum block numbers.
        require(
            uint256(data[PI_OFFSET + PLACEHOLDER_VALUES_POS]) == query.minBlockNumber,
            "The first placeholder must be the expected minimum block number."
        );
        require(
            uint256(data[PI_OFFSET + PLACEHOLDER_VALUES_POS + 1]) == query.maxBlockNumber,
            "The second placeholder must be the expected maximum block number."
        );
        // Check the user placeholders.
        for (uint256 i = 0; i < numPlaceholders - 2; ++i) {
            require(
                data[PI_OFFSET + PLACEHOLDER_VALUES_POS + 2 + i] == query.userPlaceholders[i],
                "The user placeholder must equal as expected."
            );
        }

        // TODO: Uncomment once limit and offset supported
        // Check the query limit and offset.
        // uint32 limit = uint32(bytes4(rem << (REM_QUERY_LIMIT_POS * 32)));
        // require(limit == query.limit, "Query limit must equal as expected.");
        // uint32 offset = uint32(bytes4(rem << (REM_QUERY_OFFSET_POS * 32)));
        // require(offset == query.offset, "Query offset must equal as expected.");

        // Throw an error if overflow.
        uint32 overflow = uint32(bytes4(rem << (REM_OVERFLOW_POS * 32)));
        if (overflow == 0) {
            return QueryErrorCode.NoError;
        }
        return QueryErrorCode.ComputationOverflow;
    }

    /// @notice verifies two blockhashed are equal
    /// @param blockHash the blockhash computed from the proof
    /// @param expectedBlockHash the expected blockhash, retrieved from the query
    /// @dev this function is virtual to allow for different implementations in different environments
    function verifyBlockHash(bytes32 blockHash, bytes32 expectedBlockHash) internal view virtual {
        require(blockHash == expectedBlockHash, "Block hash must equal as expected.");
    }

    // Parse the query output from the public inputs.
    function parseOutput(bytes32[] calldata data, QueryErrorCode error)
        internal
        pure
        virtual
        returns (QueryOutput memory)
    {
        bytes32 rem = data[PI_REM_OFFSET];

        // Retrieve total number of the matched rows.
        uint32 totalMatchedRows = uint32(bytes4(rem << (REM_ENTRY_COUNT_POS * 32)));

        // Retrieve the current result number.
        uint32 numResults = uint32(bytes4(rem << (REM_NUM_RESULTS_POS * 32)));
        require(numResults <= MAX_NUM_OUTPUTS, "Result number cannot overflow.");

        uint32 offset = PI_OFFSET + RESULT_VALUES_POS;
        bytes[] memory rows = new bytes[](numResults);

        for (uint32 i = 0; i < numResults; ++i) {
            uint256[] memory columns = new uint256[](MAX_NUM_ITEMS_PER_OUTPUT);
            for (uint32 j = 0; j < MAX_NUM_ITEMS_PER_OUTPUT; ++j) {
                columns[j] = uint256(data[offset + i * MAX_NUM_ITEMS_PER_OUTPUT + j]);
            }
            rows[i] = abi.encodePacked(columns);
        }

        QueryOutput memory output = QueryOutput({totalMatchedRows: totalMatchedRows, rows: rows, error: error});

        return output;
    }

    // Reverse the bytes of each Uint32 in block hash.
    // Since we pack to little-endian for each Uint32 in block hash.
    function convertToBlockHash(bytes32 original) internal pure returns (bytes32) {
        bytes32 result;
        for (uint256 i = 0; i < 8; ++i) {
            for (uint256 j = 0; j < 4; ++j) {
                result |= bytes32(original[i * 4 + j]) >> (8 * (i * 4 + 3 - j));
            }
        }

        return result;
    }
}
