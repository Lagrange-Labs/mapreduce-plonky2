// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

contract EventEmitter {
    uint256 public number;
    event noIndexed();
    event oneIndexed(uint256 indexed num);
    event twoIndexed(uint256 indexed num, uint256 indexed numTwo);
    event threeIndexed(
        uint256 indexed num,
        uint256 indexed numTwo,
        uint256 indexed numThree
    );
    event oneData(
        uint256 indexed num,
        uint256 indexed numTwo,
        uint256 indexed numThree,
        uint256 numFour
    );
    event twoData(
        uint256 indexed num,
        uint256 indexed numTwo,
        uint256 indexed numThree,
        uint256 numFour,
        uint256 numFive
    );
    event noIOneD(uint256 num);
    event noITwoD(uint256 num, uint256 numTwo);
    event oneIOneD(uint256 indexed num, uint256 numTwo);
    event oneITwoD(uint256 indexed num, uint256 numTwo, uint256 numThree);
    event twoIOneD(
        uint256 indexed num,
        uint256 indexed numTwo,
        uint256 numThree
    );
    event twoITwoD(
        uint256 indexed num,
        uint256 indexed numTwo,
        uint256 numThree,
        uint256 numFour
    );

    function testNoIndexed() public {
        emit noIndexed();
    }

    function testOneIndexed() public {
        emit oneIndexed(number);
        increment();
    }

    function testTwoIndexed() public {
        emit twoIndexed(number, number + 1);
        increment();
    }

    function testThreeIndexed() public {
        emit threeIndexed(number, number + 1, number + 2);
        increment();
    }

    function testOneData() public {
        emit oneData(number, number + 1, number + 2, number + 3);
        increment();
    }

    function testTwoData() public {
        emit twoData(number, number + 1, number + 2, number + 3, number + 4);
        increment();
    }

    function testNoIOneD() public {
        emit noIOneD(number);
        increment();
    }

    function testNoITwoD() public {
        emit noITwoD(number, number + 1);
        increment();
    }

    function testOneIOneD() public {
        emit oneIOneD(number, number + 1);
        increment();
    }

    function testOneITwoD() public {
        emit oneITwoD(number, number + 1, number + 2);
        increment();
    }

    function testTwoIOneD() public {
        emit twoIOneD(number, number + 1, number + 2);
        increment();
    }

    function testTwoITwoD() public {
        emit twoITwoD(number, number + 1, number + 2, number + 3);
        increment();
    }

    function increment() public {
        number++;
    }
}
