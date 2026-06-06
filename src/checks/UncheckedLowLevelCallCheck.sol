// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "../ChecklistBase.sol";

/// @title UncheckedLowLevelCallCheck -- detect discarded low-level call results
/// @notice Override `getUncheckedCallCalldata()` to point at a function that uses
///         `address.call`. The function should revert when the low-level call
///         fails. If it succeeds anyway, the success boolean is likely ignored.
/// @author kcolbchain
abstract contract UncheckedLowLevelCallCheck is ChecklistBase {
    /// @dev Calldata for the function that performs a low-level call.
    function getUncheckedCallCalldata() internal view virtual returns (bytes memory);

    function test_low_level_call_result_is_checked() public {
        (bool success,) = targetContract.call(getUncheckedCallCalldata());
        if (success) {
            emit log("VULNERABILITY: low-level call returned false but caller ignored the result");
            fail();
        }
    }
}
