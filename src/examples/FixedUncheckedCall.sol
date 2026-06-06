// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title FixedUncheckedCall
/// @notice Fixed version of VulnerableUncheckedCall that checks the return value.
/// @author kcolbchain
contract FixedUncheckedCall {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    /// @notice Withdraws ETH to a specified address.
    /// @dev FIXED: Properly checks the return value of the low-level call and reverts on failure.
    function withdrawTo(address to, uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        
        balances[msg.sender] -= amount;
        
        // FIXED: Check return value
        (bool success, ) = to.call{value: amount}("");
        require(success, "Transfer failed");
    }
}
