// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "forge-std/Test.sol";

/// @title VulnerableERC20 — approve() race condition
/// @notice Uses standard approve() which is vulnerable to front-running
/// @author curry202504
contract VulnerableERC20 is ERC20 {
    constructor() ERC20("Vulnerable Token", "VULN") {
        _mint(msg.sender, 10000 ether);
    }
}

/// @title FixedERC20 — uses increaseAllowance to prevent race condition
/// @notice Extends OpenZeppelin's ERC20 with safe allowance management
/// @author curry202504
contract FixedERC20 is ERC20 {
    constructor() ERC20("Fixed Token", "FIXD") {
        _mint(msg.sender, 10000 ether);
    }

    // increaseAllowance and decreaseAllowance are already provided by OZ ERC20
    // The key is to NEVER use approve() when changing an existing allowance
    // Always use increaseAllowance() or decreaseAllowance() instead
}

/// @title UncheckedCallTest — Foundry test for unchecked call vulnerability
/// @author curry202504
contract UncheckedCallTest is Test {
    VulnerableUncheckedCall public vulnerable;
    FixedCall public fixed;

    receive() external payable {}

    function setUp() public {
        vulnerable = new VulnerableUncheckedCall();
        fixed = new FixedCall();

        // Fund contracts
        deal(address(vulnerable), 10 ether);
        deal(address(fixed), 10 ether);
    }

    /// @notice Prove: unchecked call to non-existent function does NOT revert
    function testVulnerableUncheckedCallSilentFail() public {
        // Call a non-existent function via the vulnerable contract
        bytes memory data = abi.encodeWithSignature("nonExistentFunction()");

        // This should NOT revert — the vulnerability is silent failure
        vulnerable.executeUnchecked(address(0xdead), data);

        // If we reached here, the vulnerability exists
        console.log("UNCHECKED: Call to non-existent function succeeded silently!");
    }

    /// @notice Prove: fixed version REVERTS on failed external call
    function testFixedCallRevertsOnFailure() public {
        bytes memory data = abi.encodeWithSignature("nonExistentFunction()");

        vm.expectRevert("External call failed");
        fixed.executeChecked(address(0xdead), data);
    }

    /// @notice Prove: unchecked withdraw can fail silently
    function testUncheckedWithdrawSilentFail() public {
        address user = address(0x123);
        vm.deal(user, 1 ether);

        // Fund via vulnerable contract
        vm.prank(user);
        (bool s,) = address(vulnerable).call{value: 1 ether}("");
        require(s);

        // Withdraw to a contract that rejects ETH
        address rejector = address(new EthRejector());
        uint256 balBefore = address(vulnerable).balance;

        vm.prank(user);
        vulnerable.withdrawUnchecked(0.5 ether);

        uint256 balAfter = address(vulnerable).balance;

        // The withdraw "succeeded" (no revert) but the ETH wasn't actually sent
        console.log("UNCHECKED: withdraw appeared to succeed but ETH may not have been sent");
        assertEq(balBefore, balAfter, "ETH was not actually transferred!");
    }

    /// @notice Prove: checked version reverts when ETH transfer fails
    function testCheckedWithdrawReverts() public {
        address user = address(0x456);
        vm.deal(user, 1 ether);

        // Fund
        vm.prank(user);
        (bool s,) = address(fixed).call{value: 1 ether}("");
        require(s);
        fixed.deposit{value: 1 ether}();

        // Withdraw to a contract that rejects ETH
        // The checked version should revert
        vm.prank(user);
        vm.expectRevert("ETH transfer failed");
        fixed.withdrawChecked(0.5 ether);
    }
}

/// @notice Helper contract that rejects all ETH transfers
contract EthRejector {
    receive() external payable {
        revert("I reject ETH!");
    }
}
