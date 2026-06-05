// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "../ChecklistBase.sol";

interface IERC20ApprovalRaceTarget {
    function approve(address spender, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function allowance(address owner, address spender) external view returns (uint256);
    function balanceOf(address account) external view returns (uint256);
}

/// @title ERC20ApprovalRaceCheck - detect unsafe non-zero allowance overwrites
/// @notice Models the classic ERC-20 approve race: an owner tries to lower a
///         non-zero allowance, the spender uses the old allowance first, and
///         then receives the new allowance as well. Tokens should prefer
///         increase/decrease allowance flows or reject direct non-zero to
///         non-zero approval changes.
/// @author kcolbchain
abstract contract ERC20ApprovalRaceCheck is ChecklistBase {
    function getApprovalOwner() internal view virtual returns (address) {
        return address(0xA11CE);
    }

    function getApprovalSpender() internal view virtual returns (address) {
        return address(0xB0B);
    }

    function getApprovalRecipient() internal view virtual returns (address) {
        return address(0xCAFE);
    }

    function getInitialApprovalAmount() internal view virtual returns (uint256) {
        return 100 ether;
    }

    function getReducedApprovalAmount() internal view virtual returns (uint256) {
        return 50 ether;
    }

    /// @dev Seed enough owner balance for the front-run old allowance spend
    ///      and the later reduced allowance spend.
    function seedOwnerBalance(address owner, uint256 amount) internal virtual;

    function test_erc20_approval_change_cannot_be_double_spent() public {
        IERC20ApprovalRaceTarget token = IERC20ApprovalRaceTarget(targetContract);
        address owner = getApprovalOwner();
        address spender = getApprovalSpender();
        address recipient = getApprovalRecipient();
        uint256 initialAmount = getInitialApprovalAmount();
        uint256 reducedAmount = getReducedApprovalAmount();

        require(initialAmount > reducedAmount, "initial must exceed reduced");
        seedOwnerBalance(owner, initialAmount + reducedAmount);

        vm.prank(owner);
        bool initialApproved = token.approve(spender, initialAmount);
        assertTrue(initialApproved, "initial approve failed");

        vm.prank(spender);
        bool oldAllowanceSpent = token.transferFrom(owner, recipient, initialAmount);
        assertTrue(oldAllowanceSpent, "spender could not spend initial allowance");

        vm.prank(owner);
        try token.approve(spender, reducedAmount) returns (bool reducedApproved) {
            if (!reducedApproved) {
                return;
            }
        } catch {
            return;
        }

        uint256 recipientBefore = token.balanceOf(recipient);
        vm.prank(spender);
        try token.transferFrom(owner, recipient, reducedAmount) returns (bool spentReduced) {
            if (spentReduced && token.balanceOf(recipient) > recipientBefore) {
                emit log_named_uint(
                    "VULNERABILITY: spender extracted extra allowance after approval race",
                    reducedAmount
                );
                assertLe(token.balanceOf(recipient), recipientBefore, "approval race allowed double spend");
            }
        } catch {
            return;
        }
    }
}
