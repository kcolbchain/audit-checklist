// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/checks/UncheckedCallCheck.sol";
import "../src/examples/VulnerableUncheckedCall.sol";
import "../src/examples/FixedUncheckedCall.sol";

/// @title VulnerableUncheckedCallAudit
/// @notice Demonstrates audit-checklist against VulnerableUncheckedCall
contract VulnerableUncheckedCallAudit is UncheckedCallCheck {
    VulnerableUncheckedCall contractUnderTest;

    function setUp() public {
        contractUnderTest = new VulnerableUncheckedCall();
        // Fund the contract so it has ETH to send
        vm.deal(address(contractUnderTest), 10 ether);
        
        // Setup a balance for an arbitrary user
        vm.prank(address(this));
        contractUnderTest.deposit{value: 1 ether}();
        
        targetContract = address(contractUnderTest);
    }

    function getTriggerCalldata(address failingTarget) internal view override returns (bytes memory) {
        return abi.encodeWithSignature("withdrawTo(address,uint256)", failingTarget, 1 ether);
    }
}

/// @title FixedUncheckedCallAudit
/// @notice Demonstrates that FixedUncheckedCall passes the check (the test itself expects failure, but wait, the check test fails if vulnerability is present).
/// Actually, to test that the fix works, we should run the check and it should NOT emit the VULNERABILITY log and NOT fail.
contract FixedUncheckedCallAudit is UncheckedCallCheck {
    FixedUncheckedCall contractUnderTest;

    function setUp() public {
        contractUnderTest = new FixedUncheckedCall();
        vm.deal(address(contractUnderTest), 10 ether);
        
        vm.prank(address(this));
        contractUnderTest.deposit{value: 1 ether}();
        
        targetContract = address(contractUnderTest);
    }

    function getTriggerCalldata(address failingTarget) internal view override returns (bytes memory) {
        return abi.encodeWithSignature("withdrawTo(address,uint256)", failingTarget, 1 ether);
    }
    
    // The test_unchecked_call_does_not_revert from UncheckedCallCheck will pass here,
    // meaning no vulnerability is detected, because success of the top-level call will be false.
}
