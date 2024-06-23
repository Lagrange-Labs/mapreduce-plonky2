// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Script.sol";
import "../src/Simple.sol";

contract DeploySimple is Script {
    function run() external {
        vm.startBroadcast();

        string memory saltMsg = "mp2-v1";
        bytes32 salt = keccak256(abi.encodePacked(saltMsg));

        // Get the bytecode of the contract.
        bytes memory bytecode = type(Simple).creationCode;
        bytecode = abi.encodePacked(bytecode, abi.encode(saltMsg));

        // Deploy the contract using CREATE2.
        address addr;
        assembly {
            addr := create2(0, add(bytecode, 0x20), mload(bytecode), salt)
            if iszero(extcodesize(addr)) { revert(0, 0) }
        }

        vm.stopBroadcast();
    }
}
