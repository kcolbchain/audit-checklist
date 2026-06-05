// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title VulnerableERC20Approval - ERC-20 fixture with unsafe approve overwrite
/// @notice DO NOT USE IN PRODUCTION. This token intentionally allows direct
///         non-zero to non-zero allowance changes, which demonstrates the
///         classic ERC-20 approval race.
/// @author kcolbchain
contract VulnerableERC20Approval {
    string public name = "Vulnerable Approval Token";
    string public symbol = "VAT";
    uint8 public constant decimals = 18;

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function approve(address spender, uint256 amount) public virtual returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        uint256 allowed = allowance[from][msg.sender];
        require(allowed >= amount, "insufficient allowance");
        require(balanceOf[from] >= amount, "insufficient balance");

        allowance[from][msg.sender] = allowed - amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}

/// @title SafeERC20Approval - fixture that supports delta-based allowance changes
/// @notice Rejects direct non-zero to non-zero approve changes and exposes
///         increase/decrease allowance helpers for safe adjustment.
contract SafeERC20Approval is VulnerableERC20Approval {
    mapping(address => mapping(address => bool)) public hasApprovedSpender;

    function approve(address spender, uint256 amount) public override returns (bool) {
        uint256 current = allowance[msg.sender][spender];
        require(!hasApprovedSpender[msg.sender][spender] || amount == 0, "use increase/decrease allowance");
        require(current == 0 || amount == 0, "use increase/decrease allowance");
        allowance[msg.sender][spender] = amount;
        if (amount > 0) {
            hasApprovedSpender[msg.sender][spender] = true;
        }
        return true;
    }

    function increaseAllowance(address spender, uint256 addedValue) external returns (bool) {
        hasApprovedSpender[msg.sender][spender] = true;
        allowance[msg.sender][spender] += addedValue;
        return true;
    }

    function decreaseAllowance(address spender, uint256 subtractedValue) external returns (bool) {
        uint256 current = allowance[msg.sender][spender];
        require(current >= subtractedValue, "decreased allowance below zero");
        allowance[msg.sender][spender] = current - subtractedValue;
        return true;
    }
}
