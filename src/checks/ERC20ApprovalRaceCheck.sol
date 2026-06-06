// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "../ChecklistBase.sol";

/// @title ERC20ApprovalRaceCheck — detect ERC-20 approve() race condition
/// @notice Tests whether the contract is vulnerable to the classic ERC-20
///         approval race condition, where approve() can be front-run.
/// @author curry202504
abstract contract ERC20ApprovalRaceCheck is ChecklistBase {
    /// @dev Deploy the vulnerable token and return its address
    function deployVulnerableToken() internal virtual returns (address);

    /// @dev Deploy the FIXED token (using increaseAllowance) and return its address
    function deployFixedToken() internal virtual returns (address);

    /// @notice Demo: approve() race condition vulnerability
    function test_approval_race_vulnerability() public {
        address token = deployVulnerableToken();

        // Alice approves Bob to spend 100 tokens
        vm.prank(alice());
        _callToken(token, abi.encodeWithSignature("approve(address,uint256)", bob(), 100));

        // Bob front-runs Alice's new approve() tx (changing to 50)
        vm.prank(bob());
        _callToken(token, abi.encodeWithSignature("transferFrom(address,address,uint256)", alice(), bob(), 100));

        // Alice's transaction goes through: approve(Bob, 50)
        vm.prank(alice());
        _callToken(token, abi.encodeWithSignature("approve(address,uint256)", bob(), 50));

        // Bob now spends another 50 — total 150, while Alice only approved 50
        vm.prank(bob());
        _callToken(token, abi.encodeWithSignature("transferFrom(address,address,uint256)", alice(), bob(), 50));

        console.log("VULNERABILITY: Alice approved 50 but Bob spent 150!");
    }

    /// @notice Demo: FIXED version using increaseAllowance/decreaseAllowance
    function test_approval_race_fixed() public {
        address token = deployFixedToken();

        // Alice increases Bob's allowance to 100
        vm.prank(alice());
        _callToken(token, abi.encodeWithSignature("increaseAllowance(address,uint256)", bob(), 100));

        // Bob spends 100
        vm.prank(bob());
        _callToken(token, abi.encodeWithSignature("transferFrom(address,address,uint256)", alice(), bob(), 100));

        // Alice increases allowance to 50 — safe because increaseAllowance is atomic
        vm.prank(alice());
        _callToken(token, abi.encodeWithSignature("increaseAllowance(address,uint256)", bob(), 50));

        // Bob can only spend 50
        vm.prank(bob());
        _callToken(token, abi.encodeWithSignature("transferFrom(address,address,uint256)", alice(), bob(), 50));

        console.log("FIXED: increaseAllowance prevents race condition");
    }

    function alice() internal pure returns (address) {
        return address(0x1);
    }

    function bob() internal pure returns (address) {
        return address(0x2);
    }

    function _callToken(address token, bytes memory data) internal {
        (bool s,) = token.call(data);
        require(s, "Token call failed");
    }
}
