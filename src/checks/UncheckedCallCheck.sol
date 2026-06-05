// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "../ChecklistBase.sol";

/// @title UncheckedCallCheck -- detect ignored low-level call failures
/// @notice Override `getUncheckedCallCalldata()` to call the function that
///         performs a low-level `.call()`. The check supplies a receiver that
///         always reverts; safe targets must bubble or handle that failure by
///         reverting the outer transaction.
/// @author kcolbchain
abstract contract UncheckedCallCheck is ChecklistBase {
    /// @dev Return calldata that makes the target call `revertingReceiver`.
    function getUncheckedCallCalldata(address revertingReceiver) internal view virtual returns (bytes memory);

    function test_low_level_call_reverts_on_failed_external_call() public {
        RevertingReceiver receiver = new RevertingReceiver();

        (bool success,) = targetContract.call(getUncheckedCallCalldata(address(receiver)));

        if (success) {
            emit log("VULNERABILITY: low-level call failure was ignored");
            emit log("The target continued after a callee reverted; check the .call() success boolean");
            fail();
        }
    }
}

/// @dev Receiver fixture that rejects ETH and arbitrary calls.
contract RevertingReceiver {
    receive() external payable {
        revert("receiver rejects ETH");
    }

    fallback() external payable {
        revert("receiver rejects call");
    }
}
