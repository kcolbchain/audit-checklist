// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "../ChecklistBase.sol";

/// @title ReentrancyCheck — detect reentrancy vulnerabilities
/// @notice Tests whether external calls are made before state updates.
///         Override `getWithdrawCalldata()` to point at your contract's withdraw function.
/// @author kcolbchain
abstract contract ReentrancyCheck is ChecklistBase {
    /// @dev Override to return the calldata that triggers a withdrawal/transfer
    function getWithdrawCalldata() internal view virtual returns (bytes memory);

    /// @dev Override to return the amount to deposit for testing
    function getDepositValue() internal view virtual returns (uint256) {
        return 1 ether;
    }

    /// @dev Override to perform a deposit into the target contract
    function performDeposit(address depositor, uint256 amount) internal virtual;

    function test_reentrancy_on_withdraw() public {
        // Fund and deposit via attacker contract
        bytes memory withdrawCall = getWithdrawCalldata();
        address attacker = _deployReentrant(withdrawCall);

        uint256 depositAmount = getDepositValue();
        vm.deal(attacker, depositAmount);

        // Deposit as the attacker
        vm.prank(attacker);
        performDeposit(attacker, depositAmount);

        uint256 targetBalBefore = address(targetContract).balance;

        // Trigger the attack — attacker calls withdraw, which sends ETH,
        // which triggers receive(), which re-enters withdraw()
        vm.prank(attacker);
        ReentrantAttacker(payable(attacker)).attack();

        uint256 attackerBal = address(attacker).balance;
        // If attacker got more than deposited, reentrancy succeeded
        if (attackerBal > depositAmount) {
            emit log(unicode"VULNERABILITY: Reentrancy detected — attacker extracted more than deposited");
            fail();
        }
    }
}
