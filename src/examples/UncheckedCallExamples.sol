// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title UncheckedCallExamples -- vulnerable and fixed low-level call examples
/// @notice These contracts demonstrate why low-level call return values must be checked.
contract VulnerableUncheckedCallPayout {
    mapping(address => bool) public paid;

    constructor() payable {}

    function payout(address payable recipient) external {
        (bool success,) = recipient.call{value: 1 ether}("");
        success;

        paid[recipient] = true;
    }
}

contract FixedUncheckedCallPayout {
    mapping(address => bool) public paid;

    error PayoutFailed();

    constructor() payable {}

    function payout(address payable recipient) external {
        (bool success,) = recipient.call{value: 1 ether}("");
        if (!success) {
            revert PayoutFailed();
        }

        paid[recipient] = true;
    }
}
