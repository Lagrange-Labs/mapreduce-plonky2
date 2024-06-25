// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

contract Simple {
    // Test simple slots (slot 0 - 3)
    bool public s1;
    uint256 public s2;
    string public s3;
    address public s4;

    // Test mapping slots (slot 4)
    mapping(address => uint256) public m1;

    // Test array (slot 5)
    uint256[] public arr1;

    // Set the simple slots.
    function setSimples(
        bool newS1,
        uint256 newS2,
        string memory newS3,
        address newS4
    ) public {
        s1 = newS1;
        s2 = newS2;
        s3 = newS3;
        s4 = newS4;
    }

    // Set a mapping slot by key and value.
    function setMapping(address key, uint256 value) public {
        m1[key] = value;
    }

    // Add a value to the array.
    function addToArray(uint256 value) public {
        arr1.push(value);
    }
}
