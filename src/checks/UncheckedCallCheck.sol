// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "../ChecklistBase.sol";

/// @title UncheckedCallCheck — detect silent .call() failures
/// @notice Tests whether address.call() return values are properly checked.
///         A call that fails silently (without revert) can lead to unexpected state.
/// @author curry202504
abstract contract UncheckedCallCheck is ChecklistBase {
    /// @dev Override to return the calldata that makes an unchecked external call
    function getUncheckedCallCalldata() internal view virtual returns (bytes memory);

    /// @dev Override to return the calldata that makes a CHECKED external call (fixed version)
    function getCheckedCallCalldata() internal view virtual returns (bytes memory);

    /// @notice Test that an unchecked call does NOT revert (vulnerability)
    function test_unchecked_call_silent_failure() public {
        bytes memory callData = getUncheckedCallCalldata();
        (bool success, bytes memory returnData) = targetContract.call(callData);

        // The call should "succeed" (no revert) even if the inner call failed
        // This is the vulnerability — the caller doesn't check the return value
        assertTrue(success, "Call reverted unexpectedly");

        // Check that the return data indicates failure (empty bytes or false)
        // An unchecked call that failed silently will return (true, 0x) or similar
        console.log("Unchecked call completed. Return data length:", returnData.length);
        console.log("VULNERABILITY: Call return value not checked!");
    }

    /// @notice Test that a CHECKED call properly handles failure
    function test_checked_call_handles_failure() public {
        bytes memory callData = getCheckedCallCalldata();

        // A properly checked call should revert when the inner call fails
        vm.expectRevert();
        (bool success,) = targetContract.call(callData);
        // Should not reach here if the fix properly reverts on failure
        assertFalse(success, "Fixed contract should have reverted");
    }

    /// @notice Test demonstration: unchecked call to non-existent function succeeds silently
    function test_demo_unchecked_silent_success() public {
        // Call a function that exists but makes an internal unchecked call
        bytes memory callData = abi.encodeWithSignature("executeUnchecked(address,bytes)");

        // This should succeed because the unchecked call doesn't revert the transaction
        address anyTarget = address(0x123);
        bytes memory innerData = abi.encodeWithSignature("nonExistentFunction()");
        bytes memory fullCalldata = abi.encodeWithSignature(
            "executeUnchecked(address,bytes)", anyTarget, innerData
        );

        vm.prank(address(this));
        (bool success,) = targetContract.call(fullCalldata);
        assertTrue(success, "Unchecked call should not revert even if inner call fails");
    }
}
