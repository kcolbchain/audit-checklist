// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "../src/checks/UncheckedLowLevelCallCheck.sol";
import "../src/examples/UncheckedLowLevelCallExamples.sol";

/// @notice Run with: forge test --match-path test/UncheckedLowLevelCall.t.sol -vvv
contract ExampleUncheckedLowLevelCallAudit is UncheckedLowLevelCallCheck {
    VulnerableUncheckedLowLevelCall vulnerable;
    RejectEther rejecter;

    function setUp() public {
        vulnerable = new VulnerableUncheckedLowLevelCall();
        rejecter = new RejectEther();
        targetContract = address(vulnerable);
    }

    function getUncheckedCallCalldata() internal view override returns (bytes memory) {
        return abi.encodeWithSignature("payout(address)", address(rejecter));
    }

    function test_vulnerable_contract_silently_discards_failed_call() public {
        vm.expectEmit(true, false, false, true);
        emit VulnerableUncheckedLowLevelCall.Paid(address(rejecter), 1 ether);

        vulnerable.payout{value: 1 ether}(address(rejecter));

        assertEq(address(rejecter).balance, 0, "recipient rejected the transfer");
        assertEq(address(vulnerable).balance, 1 ether, "funds remain stuck in caller");
    }
}

contract ExampleFixedLowLevelCallAudit is UncheckedLowLevelCallCheck {
    FixedLowLevelCall fixedCaller;
    RejectEther rejecter;

    function setUp() public {
        fixedCaller = new FixedLowLevelCall();
        rejecter = new RejectEther();
        targetContract = address(fixedCaller);
    }

    function getUncheckedCallCalldata() internal view override returns (bytes memory) {
        return abi.encodeWithSignature("payout(address)", address(rejecter));
    }

    function test_fixed_contract_reverts_on_failed_call() public {
        vm.expectRevert("low-level call failed");
        fixedCaller.payout{value: 1 ether}(address(rejecter));
    }
}
