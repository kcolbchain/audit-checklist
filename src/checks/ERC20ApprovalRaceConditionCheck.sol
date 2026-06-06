// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "../ChecklistBase.sol";

/// @title ERC20ApprovalRaceConditionCheck — detect ERC-20 approve() race condition
/// @notice Tests whether the contract's approve() function is vulnerable to the front-running race condition.
///         Vulnerability: approve() allows an attacker to spend both the old and new allowance
///         if they front-run the transaction that changes the allowance.
/// @author kcolbchain
abstract contract ERC20ApprovalRaceConditionCheck is ChecklistBase {
    
    /// @dev Override to return the address of the ERC-20 token being tested
    function getERC20Address() internal view virtual returns (address);

    function test_erc20_approval_race_condition() public {
        address token = getERC20Address();
        address owner = address(this);
        address spender = makeAddr("spender");
        
        // Initial approval: 100 tokens
        uint256 oldAllowance = 100 * 10**18;
        uint256 newAllowance = 50 * 10**18;

        // 1. Owner approves spender for 100 tokens
        vm.prank(owner);
        (bool success1, ) = token.call(abi.encodeWithSignature("approve(address,uint256)", spender, oldAllowance));
        require(success1, "Initial approve failed");

        // 2. Owner decides to change allowance to 50 tokens
        // Spender sees this transaction in the mempool and front-runs it
        
        // Front-run: Spender spends the 100 tokens before the new approval is mined
        vm.prank(spender);
        (bool success2, ) = token.call(abi.encodeWithSignature("transferFrom(address,address,uint256)", owner, spender, oldAllowance));
        require(success2, "Front-run transferFrom failed");

        // 3. Owner's transaction to change allowance to 50 tokens is mined
        vm.prank(owner);
        (bool success3, ) = token.call(abi.encodeWithSignature("approve(address,uint256)", spender, newAllowance));
        require(success3, "Second approve failed");

        // 4. Spender spends the new 50 tokens
        vm.prank(spender);
        (bool success4, ) = token.call(abi.encodeWithSignature("transferFrom(address,address,uint256)", owner, spender, newAllowance));
        
        // If success4 is true, the spender was able to spend 150 tokens in total (old + new)
        if (success4) {
            emit log(unicode"VULNERABILITY: ERC-20 Approval Race Condition detected — spender spent both old and new allowance");
            emit log(unicode"Recommendation: Use increaseAllowance/decreaseAllowance or require allowance to be 0 before setting a new value.");
            fail();
        }
    }
}
