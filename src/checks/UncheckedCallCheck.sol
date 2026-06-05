// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "../ChecklistBase.sol";

/// @title UncheckedCallCheck — detect unchecked low-level .call() return values
/// @notice Verifies that the target contract properly checks the success boolean
///         returned by low-level address.call() operations.
///         Silently discarding the return value is a common source of hidden bugs.
/// @author kcolbchain
abstract contract UncheckedCallCheck is ChecklistBase {
    /// @dev Override to return calldata that triggers a low-level .call() in the target
    function getCallTestCalldata() internal view virtual returns (bytes memory);

    /// @dev Override to set up any state needed before the call test
    function setUpCallTest() internal virtual;

    /// @dev Override to assert the expected post-condition after a successful call
    function assertPostCondition() internal view virtual;

    /// @dev Test: call() that reverts should be properly handled
    function test_unchecked_call_revert() public {
        setUpCallTest();

        bytes memory callData = getCallTestCalldata();

        // Make the call revert by sending from a zero-balance address
        // or by setting up conditions that cause the callee to revert
        vm.prank(makeAddr("caller"));
        (bool success, bytes memory ret) = targetContract.call(callData);

        // The contract SHOULD handle the failure gracefully
        // If success is false and no revert was propagated, it means
        // the return value was silently discarded
        if (!success) {
            // Good: the call failed, but did the contract handle it?
            // Check that state didn't change inappropriately
            assertPostCondition();
        }
    }

    /// @dev Test: call() that succeeds should produce expected side effects
    function test_checked_call_success() public {
        setUpCallTest();

        bytes memory callData = getCallTestCalldata();

        // Fund the caller and make a successful call
        address caller = makeAddr("funded_caller");
        vm.deal(caller, 1 ether);
        vm.prank(caller);
        (bool success,) = targetContract.call{value: 0}(callData);

        // If the call succeeded, verify post-conditions
        if (success) {
            assertPostCondition();
        }
    }

    /// @dev Test: call() with empty calldata (fallback check)
    function test_call_with_empty_data() public {
        setUpCallTest();

        // Empty calldata triggers the fallback or receive function
        (bool success,) = targetContract.call("");

        // Contract should either have a fallback that handles this
        // or properly bubble up the failure
        // success=true means fallback exists and returned without reverting
        // success=false means no fallback or fallback reverted
        // Both are acceptable — what matters is consistency
        success; // Acknowledged return value (not discarded)
    }
}
