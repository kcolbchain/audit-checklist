// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "../ChecklistBase.sol";

/// @title ERC20ApprovalRaceCheck — detect ERC-20 approval race condition
/// @notice Tests whether an approval can be front-run to double spend.
/// @author kcolbchain
abstract contract ERC20ApprovalRaceCheck is ChecklistBase {
    /// @dev Override to return the calldata for approve(address,uint256)
    function getApproveCalldata(address spender, uint256 amount) internal view virtual returns (bytes memory);

    /// @dev Override to return the calldata for transferFrom(address,address,uint256)
    function getTransferFromCalldata(address from, address to, uint256 amount) internal view virtual returns (bytes memory);

    function test_erc20_approval_race_condition() public {
        address alice = address(0x1111);
        address bob = address(0x2222);

        // 1. Setup: Give Alice some tokens if needed (implementer should ensure Alice has balance in setUp)
        
        // 2. Alice approves Bob for 100
        vm.prank(alice);
        (bool success1, ) = targetContract.call(getApproveCalldata(bob, 100));
        require(success1, "Initial approve failed");

        // 3. Alice decides to change Bob's allowance to 50
        // Bob front-runs and spends the 100 first
        vm.prank(bob);
        (bool success2, ) = targetContract.call(getTransferFromCalldata(alice, bob, 100));
        require(success2, "Front-run transferFrom failed");

        // 4. Alice's new approval goes through
        vm.prank(alice);
        (bool success3, ) = targetContract.call(getApproveCalldata(bob, 50));
        require(success3, "Second approve failed");

        // 5. Bob spends the new 50
        vm.prank(bob);
        (bool success4, ) = targetContract.call(getTransferFromCalldata(alice, bob, 50));
        
        if (success4) {
            emit log(unicode"VULNERABILITY: ERC-20 Approval Race Condition detected — Bob spent 150 total.");
            fail();
        }
    }
}
