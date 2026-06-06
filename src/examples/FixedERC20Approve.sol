// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract FixedERC20Approve {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    function approve(address spender, uint256 amount) external returns (bool) {
        // Mitigation: prevent changing from non-zero to non-zero
        require(amount == 0 || allowance[msg.sender][spender] == 0, "ERC20: approve from non-zero to non-zero");
        allowance[msg.sender][spender] = amount;
        return true;
    }
    
    function transferFrom(address sender, address recipient, uint256 amount) external returns (bool) {
        allowance[sender][msg.sender] -= amount;
        balanceOf[sender] -= amount;
        balanceOf[recipient] += amount;
        return true;
    }
}
