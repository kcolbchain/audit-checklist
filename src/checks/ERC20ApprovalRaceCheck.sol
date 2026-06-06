// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "../ChecklistBase.sol";

/// @title ERC20ApprovalRaceCheck
/// @notice Checks for the classic ERC20 approve race condition
/// @author kcolbchain
abstract contract ERC20ApprovalRaceCheck is ChecklistBase {
    /// @dev Override to return the calldata for `approve(spender, amount)`
    function getApproveCalldata(address spender, uint256 amount) internal pure virtual returns (bytes memory);

    /// @dev Override to return the calldata for `transferFrom(from, to, amount)`
    function getTransferFromCalldata(address from, address to, uint256 amount) internal pure virtual returns (bytes memory);

    /// @dev Run the race condition check
    function test_erc20_approval_race() public {
        address alice = address(0xA11CE);
        address bob = address(0xB0B); // attacker

        // Give Alice some initial tokens (assuming the test sets this up)
        _fundAlice(alice, 200);

        // 1. Alice approves Bob for 100
        vm.prank(alice);
        (bool s1,) = targetContract.call(getApproveCalldata(bob, 100));
        require(s1, "Approve 1 failed");

        // 2. Alice decides to change approval to 50
        // Bob sees the mempool tx and front-runs it by spending the 100 FIRST
        vm.prank(bob);
        (bool s2,) = targetContract.call(getTransferFromCalldata(alice, bob, 100));
        require(s2, "Front-run transfer failed");

        // 3. Alice's tx to change approval to 50 executes
        // This might revert if using decreaseAllowance mitigation and allowance is already 0
        vm.prank(alice);
        (bool s3,) = targetContract.call(getApproveCalldata(bob, 50));

        // 4. Bob then spends the new 50 approval (if step 3 succeeded)
        vm.prank(bob);
        (bool s4,) = targetContract.call(getTransferFromCalldata(alice, bob, 50));
        
        if (s3 && s4) {
            emit log(unicode"VULNERABILITY: ERC20 approval race condition detected. Bob spent 150 total despite approvals of 100 and 50.");
            fail();
        }
    }

    /// @dev Override to fund Alice with tokens for the test
    function _fundAlice(address alice, uint256 amount) internal virtual;
}
