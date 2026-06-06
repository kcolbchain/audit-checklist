// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "../ChecklistBase.sol";

/// @title UncheckedCallCheck
/// @notice Tests whether external calls properly handle failures. If a contract makes a low-level
///         call without checking the return value, it might continue execution under the false
///         assumption that the call succeeded, leading to inconsistencies or lost funds.
/// @author kcolbchain
abstract contract UncheckedCallCheck is ChecklistBase {
    /// @dev Override to return the calldata that triggers an external call to the provided `failingTarget`.
    ///      The target contract should attempt to send ETH or make a call to `failingTarget`.
    function getTriggerCalldata(address failingTarget) internal view virtual returns (bytes memory);

    function test_unchecked_call_does_not_revert() public {
        FailingReceiver receiver = new FailingReceiver();
        bytes memory callData = getTriggerCalldata(address(receiver));
        
        // Execute the target function. If the target contract doesn't check the return value
        // of its internal call to `receiver`, the top-level call will succeed.
        (bool success, ) = targetContract.call(callData);
        
        if (success) {
            emit log(unicode"VULNERABILITY: Unchecked call detected — transaction succeeded despite receiver reverting");
            fail();
        }
    }
}

/// @dev Helper contract that always reverts on receive() and fallback()
contract FailingReceiver {
    receive() external payable {
        revert("FailingReceiver: receive failed");
    }

    fallback() external payable {
        revert("FailingReceiver: fallback failed");
    }
}
