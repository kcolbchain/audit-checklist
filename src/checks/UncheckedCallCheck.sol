// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "../ChecklistBase.sol";

/// @title UncheckedCallCheck — detect unchecked low-level call vulnerabilities
/// @notice Tests whether external calls verify the return success boolean.
///         We mock the target to always revert during the call.
/// @author kcolbchain
abstract contract UncheckedCallCheck is ChecklistBase {
    /// @dev Override to return the calldata that triggers the internal .call()
    function getTriggerCalldata() internal pure virtual returns (bytes memory);

    /// @dev Override to configure the target contract to point its low-level call to the mock address
    function setupMockTarget(address mockAddress) internal virtual;

    function test_unchecked_call_reverts() public {
        // We set up a mock contract that will revert on any call
        AlwaysRevertMock mock = new AlwaysRevertMock();
        
        // Setup the target so it calls the mock
        setupMockTarget(address(mock));

        // Call the trigger function. If it does NOT revert, it means it ignored the call failure!
        bytes memory trigger = getTriggerCalldata();
        (bool success,) = targetContract.call(trigger);

        if (success) {
            emit log(unicode"VULNERABILITY: Unchecked low-level call detected — function succeeded despite sub-call failing");
            fail();
        }
    }
}

contract AlwaysRevertMock {
    fallback() external payable {
        revert("AlwaysRevertMock: forced revert");
    }
    receive() external payable {
        revert("AlwaysRevertMock: forced revert");
    }
}
