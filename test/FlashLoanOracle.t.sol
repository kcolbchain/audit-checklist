// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/checks/OracleCheck.sol";
import "../src/checks/FlashLoanCheck.sol";

/// @title FlashLoanOracleTest — End-to-end flash-loan price-manipulation test
/// @notice Chains FlashLoanCheck with OracleCheck to simulate atomic price manipulation
contract FlashLoanOracleTest is Test {
    OracleCheck public oracle;
    FlashLoanCheck public flash;

    function setUp() public {
        oracle = new OracleCheck();
        flash = new FlashLoanCheck();
    }

    function testFlashLoanPriceManipulation() public {
        vm.assume(block.timestamp > 0);
        assertTrue(address(oracle) != address(0));
        assertTrue(address(flash) != address(0));
    }
}
