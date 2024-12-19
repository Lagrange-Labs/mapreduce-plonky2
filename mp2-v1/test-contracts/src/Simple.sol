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

    struct MappingStructChange {
        uint256 key;
        uint256 field1;
        uint128 field2;
        uint128 field3;
        MappingOperation operation;
    }

    struct MappingOfSingleValueMappingsChange {
        uint256 outerKey;
        uint256 innerKey;
        uint256 value;
        MappingOperation operation;
    }

    struct MappingOfStructMappingsChange {
        uint256 outerKey;
        uint256 innerKey;
        uint256 field1;
        uint128 field2;
        uint128 field3;
        MappingOperation operation;
    }

    struct LargeStruct {
        // This field should live in one EVM word
        uint256 field1;
        // Both these fields should live in the same EVM word
        uint128 field2;
        uint128 field3;
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

    // Test simple struct (slot 6)
    LargeStruct public simpleStruct;

    // Test mapping struct (slot 8)
    mapping(uint256 => LargeStruct) public structMapping;

    // Test mapping of single value mappings (slot 9)
    mapping(uint256 => mapping(uint256 => uint256))
        public mappingOfSingleValueMappings;

    // Test mapping of struct mappings (slot 10)
    mapping(uint256 => mapping(uint256 => LargeStruct))
        public mappingOfStructMappings;

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
            } else if (
                changes[i].operation == MappingOperation.Insertion ||
                changes[i].operation == MappingOperation.Update
            ) {
                setMapping(changes[i].key, changes[i].value);
            }
        }
    }

    // Add a value to the array.
    function addToArray(uint256 value) public {
        arr1.push(value);
    }

    // Set simple struct.
    function setSimpleStruct(LargeStruct calldata input) public {
        simpleStruct = input;
    }

    // Set mapping struct.
    function setMappingStruct(
        uint256 _key,
        uint256 _field1,
        uint128 _field2,
        uint128 _field3
    ) public {
        structMapping[_key] = LargeStruct(_field1, _field2, _field3);
    }

    // function changeMappingStruct(MappingStructChange[] memory changes) public {
    //     for (uint256 i = 0; i < changes.length; i++) {
    //         if (changes[i].operation == MappingOperation.Deletion) {
    //             delete structMapping[changes[i].key];
    //         } else if (
    //             changes[i].operation == MappingOperation.Insertion ||
    //             changes[i].operation == MappingOperation.Update
    //         ) {
    //             setMappingStruct(
    //                 changes[i].key,
    //                 changes[i].field1,
    //                 changes[i].field2,
    //                 changes[i].field3
    //             );
    //         }
    //     }
    // }

    function changeMapping(MappingStructChange[] memory changes) public {
        for (uint256 i = 0; i < changes.length; i++) {
            if (changes[i].operation == MappingOperation.Deletion) {
                delete structMapping[changes[i].key];
            } else if (
                changes[i].operation == MappingOperation.Insertion ||
                changes[i].operation == MappingOperation.Update
            ) {
                setMappingStruct(
                    changes[i].key,
                    changes[i].field1,
                    changes[i].field2,
                    changes[i].field3
                );
            }
        }
    }

    function changeMapping(
        MappingOfSingleValueMappingsChange[] memory changes
    ) public {
        for (uint256 i = 0; i < changes.length; i++) {
            if (changes[i].operation == MappingOperation.Deletion) {
                delete mappingOfSingleValueMappings[changes[i].outerKey][
                    changes[i].innerKey
                ];
            } else if (
                changes[i].operation == MappingOperation.Insertion ||
                changes[i].operation == MappingOperation.Update
            ) {
                setMappingOfSingleValueMappings(
                    changes[i].outerKey,
                    changes[i].innerKey,
                    changes[i].value
                );
            }
        }
    }

    function changeMapping(
        MappingOfStructMappingsChange[] memory changes
    ) public {
        for (uint256 i = 0; i < changes.length; i++) {
            if (changes[i].operation == MappingOperation.Deletion) {
                delete mappingOfStructMappings[changes[i].outerKey][
                    changes[i].innerKey
                ];
            } else if (
                changes[i].operation == MappingOperation.Insertion ||
                changes[i].operation == MappingOperation.Update
            ) {
                setMappingOfStructMappings(
                    changes[i].outerKey,
                    changes[i].innerKey,
                    changes[i].field1,
                    changes[i].field2,
                    changes[i].field3
                );
            }
        }
    }

    // Set mapping of single value mappings.
    function setMappingOfSingleValueMappings(
        uint256 outerKey,
        uint256 innerKey,
        uint256 value
    ) public {
        mappingOfSingleValueMappings[outerKey][innerKey] = value;
    }

    // function changeMappingOfSingleValueMappings(
    //     MappingOfSingleValueMappingsChange[] memory changes
    // ) public {
    //     for (uint256 i = 0; i < changes.length; i++) {
    //         if (changes[i].operation == MappingOperation.Deletion) {
    //             delete mappingOfSingleValueMappings[changes[i].outerKey][
    //                 changes[i].innerKey
    //             ];
    //         } else if (
    //             changes[i].operation == MappingOperation.Insertion ||
    //             changes[i].operation == MappingOperation.Update
    //         ) {
    //             setMappingOfSingleValueMappings(
    //                 changes[i].outerKey,
    //                 changes[i].innerKey,
    //                 changes[i].value
    //             );
    //         }
    //     }
    // }

    // Set mapping of struct mappings.
    function setMappingOfStructMappings(
        uint256 outerKey,
        uint256 innerKey,
        uint256 field1,
        uint128 field2,
        uint128 field3
    ) public {
        mappingOfStructMappings[outerKey][innerKey] = LargeStruct(
            field1,
            field2,
            field3
        );
    }

    // function changeMappingOfStructMappings(
    //     MappingOfStructMappingsChange[] memory changes
    // ) public {
    //     for (uint256 i = 0; i < changes.length; i++) {
    //         if (changes[i].operation == MappingOperation.Deletion) {
    //             delete mappingOfStructMappings[changes[i].outerKey][
    //                 changes[i].innerKey
    //             ];
    //         } else if (
    //             changes[i].operation == MappingOperation.Insertion ||
    //             changes[i].operation == MappingOperation.Update
    //         ) {
    //             setMappingOfStructMappings(
    //                 changes[i].outerKey,
    //                 changes[i].innerKey,
    //                 changes[i].field1,
    //                 changes[i].field2,
    //                 changes[i].field3
    //             );
    //         }
    //     }
    // }
}
