// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/checks/ERC20ApprovalRaceCheck.sol";
import "../src/examples/VulnerableERC20Approval.sol";

contract ExampleERC20ApprovalRaceAudit is ERC20ApprovalRaceCheck {
    VulnerableERC20Approval token;

    function setUp() public {
        token = new VulnerableERC20Approval();
        targetContract = address(token);
    }

    function seedOwnerBalance(address owner, uint256 amount) internal override {
        token.mint(owner, amount);
    }
}

contract SafeERC20ApprovalRaceAudit is ERC20ApprovalRaceCheck {
    SafeERC20Approval token;

    function setUp() public {
        token = new SafeERC20Approval();
        targetContract = address(token);
    }

    function seedOwnerBalance(address owner, uint256 amount) internal override {
        token.mint(owner, amount);
    }
}

contract ERC20ApprovalRaceTest is Test {
    function test_detects_direct_approve_race() public {
        ExampleERC20ApprovalRaceAudit audit = new ExampleERC20ApprovalRaceAudit();
        audit.setUp();

        vm.expectRevert();
        audit.test_erc20_approval_change_cannot_be_double_spent();
    }

    function test_safe_token_rejects_direct_nonzero_allowance_change() public {
        SafeERC20ApprovalRaceAudit audit = new SafeERC20ApprovalRaceAudit();
        audit.setUp();

        audit.test_erc20_approval_change_cannot_be_double_spent();
    }

    function test_decrease_allowance_prevents_front_run_second_spend() public {
        SafeERC20Approval token = new SafeERC20Approval();
        address owner = address(0xA11CE);
        address spender = address(0xB0B);
        address recipient = address(0xCAFE);

        token.mint(owner, 150 ether);

        vm.prank(owner);
        token.increaseAllowance(spender, 100 ether);

        vm.prank(spender);
        token.transferFrom(owner, recipient, 100 ether);

        vm.prank(owner);
        vm.expectRevert(bytes("decreased allowance below zero"));
        token.decreaseAllowance(spender, 50 ether);

        assertEq(token.balanceOf(recipient), 100 ether);
        assertEq(token.allowance(owner, spender), 0);
    }
}
