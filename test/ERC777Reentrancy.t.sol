// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/checks/ERC777ReentrancyCheck.sol";

/// @title VulnerableERC777Vault — deliberately vulnerable to ERC-777 reentrancy
/// @notice Withdraws tokens BEFORE updating internal balance, allowing
///         tokensReceived reentrancy identical to the 2020 imBTC/Uniswap V1 exploit.
contract VulnerableERC777Vault {
    MockERC777 public token;
    mapping(address => uint256) public deposits;

    constructor(address _token) {
        token = MockERC777(_token);
    }

    function deposit(uint256 amount) external {
        token.transferFrom(msg.sender, address(this), amount);
        deposits[msg.sender] += amount;
    }

    /// @notice Vulnerable: transfers tokens BEFORE updating balance
    function withdraw() external {
        uint256 amount = deposits[msg.sender];
        // BUG: token transfer fires tokensReceived BEFORE balance update
        token.transfer(msg.sender, amount);
        deposits[msg.sender] = 0;
    }

    /// @notice Fixed version: updates balance BEFORE token transfer
    ///         (checks-effects-interactions pattern)
    function withdrawFixed() external {
        uint256 amount = deposits[msg.sender];
        deposits[msg.sender] = 0;
        token.transfer(msg.sender, amount);
    }
}

/// @title ERC777ReentrancyAudit — demonstrates audit check against VulnerableERC777Vault
contract ERC777ReentrancyAudit is ERC777ReentrancyCheck {
    VulnerableERC777Vault vault;
    MockERC777 token;

    function setUp() public {
        token = new MockERC777("Mock777", "M777", new address[](0));
        vault = new VulnerableERC777Vault(address(token));
        targetContract = address(vault);

        // Fund the vault with tokens so withdraw() can send them
        token.mint(address(vault), 10000 ether);
    }

    function getERC777WithdrawCalldata() internal pure override returns (bytes memory) {
        return abi.encodeWithSignature("withdraw()");
    }

    function performERC777Deposit(address depositor, uint256 amount) internal override {
        vm.prank(depositor);
        vault.deposit(amount);
    }
}

/// @title ERC777ReentrancyFixedAudit — proves check passes when reentrancy is fixed
contract ERC777ReentrancyFixedAudit is ERC777ReentrancyCheck {
    VulnerableERC777Vault vault;
    MockERC777 token;

    function setUp() public {
        token = new MockERC777("Mock777", "M777", new address[](0));
        vault = new VulnerableERC777Vault(address(token));
        targetContract = address(vault);
        token.mint(address(vault), 10000 ether);
    }

    function getERC777WithdrawCalldata() internal pure override returns (bytes memory) {
        return abi.encodeWithSignature("withdrawFixed()");
    }

    function performERC777Deposit(address depositor, uint256 amount) internal override {
        vm.prank(depositor);
        vault.deposit(amount);
    }
}
