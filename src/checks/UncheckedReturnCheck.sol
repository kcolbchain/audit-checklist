// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "../ChecklistBase.sol";

/// @title UncheckedReturnCheck â€” detect unchecked return values of low-level calls
/// @notice Tests whether a failing low-level call reverts the transaction.
/// @author kcolbchain
abstract contract UncheckedReturnCheck is ChecklistBase {
    /// @dev Override to return the calldata that triggers the low-level call
    function getCallCalldata() internal view virtual returns (bytes memory);

    /// @dev Override to perform any required setup (e.g. depositing funds)
    function setupCallContext(address caller) internal virtual;

    function test_unchecked_return_value() public {
        // We use a receiver that always reverts
        RevertingReceiver receiver = new RevertingReceiver();
        
        setupCallContext(address(receiver));

        // The receiver calls the target contract
        bytes memory callData = getCallCalldata();
        
        vm.prank(address(receiver));
        (bool success,) = targetContract.call(callData);

        // If the call succeeds, it means the target didn't revert when the inner call failed.
        if (success) {
            emit log(unicode"VULNERABILITY: Unchecked return value â€” transaction succeeded despite inner call failure");
            fail();
        }
    }
}

contract RevertingReceiver {
    receive() external payable {
        revert("I always revert");
    }
    fallback() external payable {
        revert("I always revert");
    }
}
