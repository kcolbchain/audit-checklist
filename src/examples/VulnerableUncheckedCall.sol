// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title VulnerableUncheckedCall
/// @notice Intentionally vulnerable contract for demonstrating unchecked low-level calls.
/// @author kcolbchain
contract VulnerableUncheckedCall {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    /// @notice Withdraws ETH to a specified address.
    /// @dev VULNERABLE: Does not check the return value of the low-level call.
    ///      If `to` reverts, the user's balance is still deducted, leading to lost funds.
    function withdrawTo(address to, uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        
        balances[msg.sender] -= amount;
        
        // BUG: Unchecked return value of low-level call
        to.call{value: amount}("");
    }
}
