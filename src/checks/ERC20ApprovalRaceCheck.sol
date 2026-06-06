// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "../ChecklistBase.sol";

interface IERC20Approve {
    function approve(address spender, uint256 amount) external returns (bool);
    function allowance(address owner, address spender) external view returns (uint256);
}

/// @title ERC20ApprovalRaceCheck — detect ERC-20 approval race conditions
/// @notice Tests whether an ERC-20 token allows changing an allowance from non-zero to non-zero.
/// @author kcolbchain
abstract contract ERC20ApprovalRaceCheck is ChecklistBase {
    function test_erc20_approve_race_condition() public {
        IERC20Approve token = IERC20Approve(targetContract);
        
        address alice = address(0xA11CE);
        address bob = address(0xB0B);

        // First approval
        vm.prank(alice);
        token.approve(bob, 100);

        // Attempt to change approval from non-zero to non-zero
        vm.prank(alice);
        (bool success, ) = targetContract.call(abi.encodeWithSelector(token.approve.selector, bob, 50));

        // If the call succeeded and the allowance was actually updated, it's vulnerable.
        if (success) {
            uint256 newAllowance = token.allowance(alice, bob);
            if (newAllowance == 50) {
                emit log(unicode"VULNERABILITY: ERC-20 approval race condition detected — token allows changing non-zero allowance to non-zero");
                fail();
            }
        }
    }
}
