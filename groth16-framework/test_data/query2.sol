// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import "./verifier.sol";

contract Query2 is Verifier {
    // byteLen(uint160) / 4
    uint32 constant PACKED_ADDRESS_LEN = 5;

    // byteLen(uint256) / 4
    uint32 constant PACKED_HASH_LEN = 8;

    // Top 3 bits mask.
    uint256 constant TOP_THREE_BIT_MASK = ~(uint256(7) << 253);

    // Set the number of the NFT IDs. Each ID is an uint32.
    uint32 constant L = 5;

    // The start bytes32 offset of plonky2 public inputs in the whole data.
    // groth16_proof_number (8) + groth16_input_number (3)
    uint32 constant PLONKY2_PI_BYTES32_OFFSET = 11;

    // The total length of the plonky2 public inputs. Each input value is
    // serialized as an uint64. It's related with both the full proof
    // serialization and the wrapped circuit code.
    uint32 constant PI_TOTAL_LEN = (L + 24) * 8;

    // The min block number offset in the plonky2 public inputs.
    uint32 constant PI_MIN_BLOCK_NUM_OFFSET = 2 * 8;

    // The max block number offset in the plonky2 public inputs.
    uint32 constant PI_MAX_BLOCK_NUM_OFFSET = PI_MIN_BLOCK_NUM_OFFSET + 8;

    // The contract address offset in the plonky2 public inputs.
    uint32 constant PI_CONTRACT_ADDR_OFFSET = PI_MAX_BLOCK_NUM_OFFSET + 8;

    // The user address offset in the plonky2 public inputs.
    uint32 constant PI_USER_ADDR_OFFSET = PI_CONTRACT_ADDR_OFFSET + PACKED_ADDRESS_LEN * 8;

    // The NFT IDS offset in the plonky2 public inputs.
    uint32 constant PI_NFT_IDS_OFFSET = 16 * 8;

    // The block hash offset in the plonky2 public inputs.
    uint32 constant PI_BLOCK_HASH_OFFSET = PI_NFT_IDS_OFFSET + L * 8;

    // The query struct used to check with the public inputs.
    struct Query {
        address contractAddress;
        address userAddress;
        address clientAddress;
        uint256 minBlockNumber;
        uint256 maxBlockNumber;
        bytes32 blockHash;
    }

    // This processQuery function does the followings:
    // 1. Parse the Groth16 proofs (8 uint256) and inputs (3 uint256) from the `data` argument, and
    //    call `verifyProof` function for Groth16 verification.
    // 2. Parse the plonky2 public inputs from the `data` argument.
    // 3. Calculate sha256 on the inputs to a hash value, and set the top 3 bits of this hash to 0.
    //    Then asset this hash value must be equal to the last Groth16 input (groth16_inputs[2]).
    // 4. Parse a Query instance from the plonky2 public inputs, and asset it must be equal to the
    //    expected `query` argument.
    // 5. Parse and return `L` NFT IDs (uint32) from the plonky2 public inputs.
    function processQuery(bytes32[] calldata data, Query memory query) public view returns (uint256[] memory) {
        // 1. Do Groth16 verification.
        uint256[3] memory groth16_inputs = verifyGroth16Proof(data);

        // 2. Parse the plonky2 public inputs.
        bytes memory pis = parsePlonky2Inputs(data);

        // 3. Assert the hash of plonky2 public inputs must be equal to the last Groth16 input.
        verifyPlonky2Inputs(pis, groth16_inputs);

        // 3. Asset the query in plonky2 public inputs must be equal to expected `query` argument.
        verifyQuery(pis, query);

        // 4. Parse and return the NFT IDs.
        return parseNftIds(pis);
    }

    // Parse the Groth16 proofs and inputs, and do verification. It returns the Groth16 inputs.
    function verifyGroth16Proof(bytes32[] calldata data) internal view returns (uint256[3] memory) {
        uint256[8] memory proofs;
        uint256[3] memory inputs;

        for (uint32 i = 0; i < 8; ++i) {
            proofs[i] = convertToU256(data[i]);
        }
        for (uint32 i = 0; i < 3; ++i) {
            inputs[i] = convertToU256(data[i + 8]);
        }

        // Require the sha256 hash equals to the last Groth16 input.
        require(inputs[0] == uint256(CIRCUIT_DIGEST), "The first Groth16 input must be equal to the circuit digest");

        // Do Groth16 verification.
        this.verifyProof(proofs, inputs);

        return inputs;
    }

    // Parse the plonky2 public inputs.
    function parsePlonky2Inputs(bytes32[] calldata data) internal pure returns (bytes memory) {
        bytes memory pis = new bytes(PI_TOTAL_LEN);

        uint32 bytes32_len = PI_TOTAL_LEN / 32;
        for (uint32 i = 0; i < bytes32_len; ++i) {
            bytes32 b = data[PLONKY2_PI_BYTES32_OFFSET + i];
            for (uint32 j = 0; j < 32; ++j) {
                pis[i * 32 + j] = bytes1(b[j]);
            }
        }

        // Set the remaining bytes.
        bytes32 remaining_data = data[PLONKY2_PI_BYTES32_OFFSET + bytes32_len];
        for (uint32 i = 0; i < PI_TOTAL_LEN % 32; ++i) {
            pis[bytes32_len * 32 + i] = remaining_data[i];
        }

        return pis;
    }

    // Calculate sha256 on the plonky2 inputs, and asset it must be equal to the last Groth16 input.
    function verifyPlonky2Inputs(bytes memory pis, uint256[3] memory groth16_inputs) internal pure {
        // Calculate sha256.
        bytes32 pis_hash_bytes = sha256(pis);
        uint256 pis_hash = uint256(pis_hash_bytes);

        // Set the top 3 bits of the hash value to 0.
        pis_hash = pis_hash & TOP_THREE_BIT_MASK;

        // Require the sha256 hash equals to the last Groth16 input.
        require(pis_hash == groth16_inputs[2], "The plonky2 public inputs hash must be equal to the last of the Groth16 inputs");
    }

    // Verify the plonky2 inputs with the expected Query instance.
    function verifyQuery(bytes memory pis, Query memory query) internal pure {
        uint32 min_block_number = convertToU32(pis, PI_MIN_BLOCK_NUM_OFFSET);
        require(
            min_block_number == query.minBlockNumber,
            "The parsed min block number must be equal to the expected one in query."
        );

        uint32 max_block_number = convertToU32(pis, PI_MAX_BLOCK_NUM_OFFSET);
        require(
            max_block_number == query.maxBlockNumber,
            "The parsed max block number must be equal to the expected one in query."
        );

        address contract_address = convertToAddress(pis, PI_CONTRACT_ADDR_OFFSET);
        require(
            contract_address == query.contractAddress,
            "The parsed contract address must be equal to the expected one in query."
        );

        address user_address = convertToAddress(pis, PI_USER_ADDR_OFFSET);
        require(
            user_address == query.userAddress,
            "The parsed user address must be equal to the expected one in query."
        );

        bytes32 block_hash = convertToHash(pis, PI_BLOCK_HASH_OFFSET);
        require(
            block_hash == query.blockHash,
            "The parsed block hash must be equal to the expected one in query."
        );
    }

    // Parse the `L` NFT IDs from the plonky2 public inputs.
    function parseNftIds(bytes memory pis) internal pure returns (uint256[] memory) {
        uint256[] memory nft_ids = new uint256[](L);
        for (uint32 i = 0; i < L; ++i) {
            nft_ids[i] = uint256(convertToLeftPaddingU32(pis, PI_NFT_IDS_OFFSET + i * 8));
        }

        return nft_ids;
    }

    // Convert a bytes32 to an uint256.
    function convertToU256(bytes32 b) internal pure returns (uint256) {
        uint256 result;
        for (uint32 i = 0; i < 32; i++) {
            result |= uint256(uint8(b[i])) << (8 * i);
        }

        return result;
    }

    // Convert to an uint32 from a memory offset.
    function convertToU32(bytes memory data, uint32 offset) internal pure returns (uint32) {
        uint32 result;
        for (uint32 i = 0; i < 4; ++i) {
            result |= uint32(uint8(data[i + offset])) << (8 * i);
        }

        return result;
    }

    // Convert to an uint32 of left padding from a memory offset.
    function convertToLeftPaddingU32(bytes memory data, uint32 offset) internal pure returns (uint32) {
        uint32 result;
        for (uint32 i = 0; i < 4; ++i) {
            result |= uint32(uint8(data[i + offset])) << (8 * (3 - i));
        }

        return result;
    }

    // Convert to an address from a memory offset.
    function convertToAddress(bytes memory pis, uint32 offset) internal pure returns (address) {
        uint160 result;
        for (uint32 i = 0; i < PACKED_ADDRESS_LEN; ++i) {
            result |= uint160(convertToLeftPaddingU32(pis, offset + i * 8)) << (32 * (PACKED_ADDRESS_LEN - 1 - i));
        }

        return address(result);
    }

    // Convert to a hash from a memory offset.
    function convertToHash(bytes memory pis, uint32 offset) internal pure returns (bytes32) {
        uint256 result;
        for (uint32 i = 0; i < PACKED_HASH_LEN; ++i) {
            result |= uint256(convertToLeftPaddingU32(pis, offset + i * 8)) << (32 * (PACKED_HASH_LEN - 1 - i));
        }

        return bytes32(result);
    }
}
