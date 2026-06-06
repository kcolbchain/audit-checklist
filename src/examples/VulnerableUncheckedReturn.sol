// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract VulnerableUncheckedReturn {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        balances[msg.sender] -= amount;
        
        // Vulnerable: unchecked return value
        msg.sender.call{value: amount}("");
    }
}
