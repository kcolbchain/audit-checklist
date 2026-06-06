// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/checks/ERC20ApprovalRaceConditionCheck.sol";
import "../src/examples/VulnerableERC20.sol";

contract ERC20ApprovalRaceConditionTest is Test, ERC20ApprovalRaceConditionCheck {
    VulnerableERC20 public token;

    function setUp() public {
        token = new VulnerableERC20();
        targetContract = address(token);
        // Deal some tokens to this contract (the owner)
        token.mint(address(this), 1000 * 10**18);
    }

    function getERC20Address() internal view override returns (address) {
        return address(token);
    }

    function test_detect_vulnerability() public {
        // This should fail because the contract is vulnerable
        test_erc20_approval_race_condition();
    }
}
