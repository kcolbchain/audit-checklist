// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title VulnerableUncheckedCall — example of silent .call() failure
/// @notice Demonstrates the vulnerability of not checking .call() return values
/// @author curry202504
contract VulnerableUncheckedCall {
    mapping(address => uint256) public balances;

    /// @dev VULNERABLE: Makes an external call without checking the return value
    function executeUnchecked(address target, bytes calldata data) external {
        // VULNERABILITY: return value not checked!
        target.call{value: 0}(data);
    }

    /// @dev VULNERABLE: Send ETH without checking return
    function withdrawUnchecked(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        balances[msg.sender] -= amount;
        // VULNERABILITY: .call return value not checked!
        (bool sent, ) = msg.sender.call{value: amount}("");
        // sent is discarded!
    }

    receive() external payable {
        balances[msg.sender] += msg.value;
    }
}

/// @title FixedCall — properly checks .call() return values
/// @notice Shows the correct way to handle external calls
/// @author curry202504
contract FixedCall {
    mapping(address => uint256) public balances;

    /// @dev FIXED: Checks the return value and reverts on failure
    function executeChecked(address target, bytes calldata data) external {
        (bool success, bytes memory returnData) = target.call{value: 0}(data);
        require(success, "External call failed");
        // returnData can be used for additional logic
    }

    /// @dev FIXED: Checks ETH transfer return value
    function withdrawChecked(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        balances[msg.sender] -= amount;
        (bool sent, ) = msg.sender.call{value: amount}("");
        require(sent, "ETH transfer failed");
    }

    receive() external payable {
        balances[msg.sender] += msg.value;
    }
}

    /// @dev Deposit ETH
    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }
