// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Always rejects ETH so callers can exercise failed low-level calls.
contract RejectEther {
    receive() external payable {
        revert("reject ether");
    }
}

/// @notice DO NOT USE IN PRODUCTION. Deliberately ignores `.call()` success.
contract VulnerableUncheckedLowLevelCall {
    event Paid(address recipient, uint256 amount);

    function payout(address recipient) external payable {
        recipient.call{value: msg.value}("");
        emit Paid(recipient, msg.value);
    }
}

/// @notice Fixed counterpart that checks and reverts on failed low-level calls.
contract FixedLowLevelCall {
    event Paid(address recipient, uint256 amount);

    function payout(address recipient) external payable {
        (bool success,) = recipient.call{value: msg.value}("");
        require(success, "low-level call failed");
        emit Paid(recipient, msg.value);
    }
}
