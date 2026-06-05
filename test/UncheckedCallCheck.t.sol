// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/checks/UncheckedCallCheck.sol";
import "../src/examples/UncheckedCallExamples.sol";

contract FixedUncheckedCallAudit is UncheckedCallCheck {
    FixedUncheckedCallPayout payoutContract;

    function setUp() public {
        payoutContract = new FixedUncheckedCallPayout{value: 2 ether}();
        targetContract = address(payoutContract);
    }

    function getUncheckedCallCalldata(address revertingReceiver) internal pure override returns (bytes memory) {
        return abi.encodeWithSignature("payout(address)", payable(revertingReceiver));
    }
}

contract UncheckedCallExampleTest is Test {
    RevertingReceiver receiver;
    VulnerableUncheckedCallPayout vulnerable;
    FixedUncheckedCallPayout fixedPayout;

    function setUp() public {
        receiver = new RevertingReceiver();
        vulnerable = new VulnerableUncheckedCallPayout{value: 2 ether}();
        fixedPayout = new FixedUncheckedCallPayout{value: 2 ether}();
    }

    function test_vulnerable_payout_ignores_failed_low_level_call() public {
        vulnerable.payout(payable(address(receiver)));

        assertTrue(vulnerable.paid(address(receiver)), "receiver should be marked paid despite revert");
        assertEq(address(receiver).balance, 0, "receiver should not receive ETH");
        assertEq(address(vulnerable).balance, 2 ether, "funds should remain trapped");
    }

    function test_fixed_payout_reverts_when_low_level_call_fails() public {
        vm.expectRevert(FixedUncheckedCallPayout.PayoutFailed.selector);
        fixedPayout.payout(payable(address(receiver)));

        assertFalse(fixedPayout.paid(address(receiver)), "receiver should not be marked paid");
        assertEq(address(fixedPayout).balance, 2 ether, "funds should remain in contract after revert");
    }
}
