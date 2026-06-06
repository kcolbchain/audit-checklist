// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/checks/ERC20ApprovalRaceCheck.sol";
import "../src/examples/VulnerableERC20Approve.sol";
import "../src/examples/FixedERC20Approve.sol";

contract ExampleERC20ApprovalRaceAudit is ERC20ApprovalRaceCheck {
    VulnerableERC20Approve public tokenContract;

    function setUp() public {
        tokenContract = new VulnerableERC20Approve();
        targetContract = address(tokenContract);
    }

    function test_detects_approve_race_condition() public {
        vm.expectRevert(); // fail() uses revert
        this.test_erc20_approve_race_condition();
    }
}

contract TestERC20ApprovalRaceFixed is ERC20ApprovalRaceCheck {
    FixedERC20Approve public tokenContract;

    function setUp() public {
        tokenContract = new FixedERC20Approve();
        targetContract = address(tokenContract);
    }

    function test_passes_approve_race_condition_fix() public {
        // This should pass without reverting because the fix rejects non-zero to non-zero updates
        this.test_erc20_approve_race_condition();
    }
}
