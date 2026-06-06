// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/checks/UncheckedCallCheck.sol";
import "../src/examples/UncheckedCallExample.sol";

contract ExampleUncheckedCallAudit is UncheckedCallCheck {
    VulnerableUncheckedCall vulContract;

    function setUp() public {
        vulContract = new VulnerableUncheckedCall();
        targetContract = address(vulContract);
    }

    function getTriggerCalldata() internal pure override returns (bytes memory) {
        return abi.encodeWithSelector(VulnerableUncheckedCall.executeCall.selector);
    }

    function setupMockTarget(address mockAddress) internal override {
        vulContract.setExternal(mockAddress);
    }
}

contract ExampleFixedUncheckedCallAudit is UncheckedCallCheck {
    FixedUncheckedCall fixedContract;

    function setUp() public {
        fixedContract = new FixedUncheckedCall();
        targetContract = address(fixedContract);
    }

    function getTriggerCalldata() internal pure override returns (bytes memory) {
        return abi.encodeWithSelector(FixedUncheckedCall.executeCall.selector);
    }

    function setupMockTarget(address mockAddress) internal override {
        fixedContract.setExternal(mockAddress);
    }
}
