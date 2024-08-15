// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

contract Simple {
  enum MappingOperation {
      Deletion,
      Update,
      Insertion
    }

    struct MappingChange {
        uint256 key;
        address value;
        MappingOperation operation;
    }


    // Test simple slots (slot 0 - 3)
    bool public s1;
    uint256 public s2;
    string public s3;
    address public s4;

    // Test mapping slots (slot 4)
    mapping(uint256 => address) public m1;

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
    function setS2(uint256 newS2) public {
      s2 = newS2;
    }

    // Set a mapping slot by key and value.
    function setMapping(uint256 key, address value) public {
        m1[key] = value;
    }

    function changeMapping(MappingChange[] memory changes) public {
      for (uint256 i = 0; i < changes.length; i++) {
        if (changes[i].operation == MappingOperation.Deletion) {
          delete m1[changes[i].key];
        } else if (changes[i].operation == MappingOperation.Insertion || changes[i].operation == MappingOperation.Update) {
          setMapping(changes[i].key,changes[i].value);
        } 
      }
    }

    // Add a value to the array.
    function addToArray(uint256 value) public {
        arr1.push(value);
    }
}
