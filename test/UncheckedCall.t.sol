// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/examples/VulnerableUncheckedCall.sol";
import "../src/examples/FixedUncheckedCall.sol";

/// @title UncheckedCallTest — Foundry tests proving the unchecked call vulnerability
contract UncheckedCallTest is Test {
    VulnerableUncheckedCall vulnerable;
    FixedUncheckedCall fixed;

    /// @dev A contract that reverts on receive, simulating a failed ETH transfer
    contract RevertingReceiver {
        receive() external payable {
            revert("I reject all ETH");
        }
    }

    /// @dev A mock ERC-20 token that returns false on transfer
    contract MockFailingToken {
        function transfer(address, uint256) external pure returns (bool) {
            return false;
        }
    }

    /// @dev A mock ERC-20 token that reverts on transfer
    contract MockRevertingToken {
        function transfer(address, uint256) external pure returns (bool) {
            revert("token transfer failed");
        }
    }

    function setUp() public {
        vulnerable = new VulnerableUncheckedCall();
        fixed = new FixedUncheckedCall();
    }

    // -----------------------------------------------------------------
    // Test 1: Vulnerable contract silently loses funds on failed ETH send
    // -----------------------------------------------------------------
    function test_vulnerable_silent_failure() public {
        // User deposits 1 ETH
        vm.deal(address(this), 1 ether);
        vulnerable.deposit{value: 1 ether}();

        assertEq(vulnerable.balances(address(this)), 1 ether);

        // Deploy a contract that reverts on receive
        RevertingReceiver receiver = new RevertingReceiver();

        // Try to withdraw to the reverting receiver
        // The .call() fails silently (return value unchecked)
        vulnerable.withdraw(payable(address(receiver)), 1 ether);

        // BUG: transferComplete is set to true even though ETH was NOT sent!
        assertEq(vulnerable.transferComplete(), true);

        // BUG: balance was decremented but ETH was never received
        assertEq(vulnerable.balances(address(this)), 0 ether);
        // The receiver got 0 ETH (it reverted)
        assertEq(address(receiver).balance, 0 ether);
        // The vulnerable contract still holds the ETH (it was never sent)
        assertEq(address(vulnerable).balance, 1 ether);

        // PROOF: ETH is stuck in the contract — user lost their balance
        // without receiving anything.
    }

    // -----------------------------------------------------------------
    // Test 2: Fixed contract properly reverts on failed ETH send
    // -----------------------------------------------------------------
    function test_fixed_reverts_on_failure() public {
        // User deposits 1 ETH
        vm.deal(address(this), 1 ether);
        fixed.deposit{value: 1 ether}();

        RevertingReceiver receiver = new RevertingReceiver();

        // Withdraw should revert because the receiver rejects ETH
        vm.expectRevert("ETH transfer failed");
        fixed.withdraw(payable(address(receiver)), 1 ether);

        // Balance should remain unchanged
        assertEq(fixed.balances(address(this)), 1 ether);
        // transferComplete should still be false
        assertEq(fixed.transferComplete(), false);
    }

    // -----------------------------------------------------------------
    // Test 3: Fixed contract succeeds with valid receiver
    // -----------------------------------------------------------------
    function test_fixed_succeeds_with_valid_receiver() public {
        vm.deal(address(this), 1 ether);
        fixed.deposit{value: 1 ether}();

        address payable receiver = payable(makeAddr("receiver"));

        fixed.withdraw(receiver, 1 ether);

        assertEq(fixed.balances(address(this)), 0 ether);
        assertEq(receiver.balance, 1 ether);
        assertEq(fixed.transferComplete(), true);
    }

    // -----------------------------------------------------------------
    // Test 4: Vulnerable contract ignores failing token transfer
    // -----------------------------------------------------------------
    function test_vulnerable_ignores_failing_token() public {
        MockFailingToken token = new MockFailingToken();

        // Call transferToken — token.transfer returns false
        // Vulnerable code ignores the return value
        vulnerable.transferToken(address(token), makeAddr("recipient"), 100);

        // BUG: lastRecipient is set even though transfer failed
        assertEq(vulnerable.lastRecipient(), makeAddr("recipient"));
    }

    // -----------------------------------------------------------------
    // Test 5: Fixed contract reverts on failing token transfer
    // -----------------------------------------------------------------
    function test_fixed_reverts_on_failing_token() public {
        MockFailingToken token = new MockFailingToken();

        // Should revert because token returns false
        vm.expectRevert("token transfer returned false");
        fixed.transferToken(address(token), makeAddr("recipient"), 100);
    }

    // -----------------------------------------------------------------
    // Test 6: Fixed contract reverts on reverting token transfer
    // -----------------------------------------------------------------
    function test_fixed_reverts_on_reverting_token() public {
        MockRevertingToken token = new MockRevertingToken();

        vm.expectRevert("token call failed");
        fixed.transferToken(address(token), makeAddr("recipient"), 100);
    }
}
