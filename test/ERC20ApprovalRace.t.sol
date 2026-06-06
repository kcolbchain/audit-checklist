// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/checks/ERC20ApprovalRaceCheck.sol";
import "../src/examples/ERC20ApprovalRaceExample.sol";

contract ExampleERC20ApprovalRaceAudit is ERC20ApprovalRaceCheck {
    VulnerableERC20Approval vulContract;

    function setUp() public {
        vulContract = new VulnerableERC20Approval();
        targetContract = address(vulContract);
    }

    function getApproveCalldata(address spender, uint256 amount) internal pure override returns (bytes memory) {
        return abi.encodeWithSelector(VulnerableERC20Approval.approve.selector, spender, amount);
    }

    function getTransferFromCalldata(address from, address to, uint256 amount) internal pure override returns (bytes memory) {
        return abi.encodeWithSelector(VulnerableERC20Approval.transferFrom.selector, from, to, amount);
    }

    function _fundAlice(address alice, uint256 amount) internal override {
        vulContract.mint(alice, amount);
    }
}

contract ExampleFixedERC20ApprovalRaceAudit is ERC20ApprovalRaceCheck {
    FixedERC20Approval fixedContract;

    function setUp() public {
        fixedContract = new FixedERC20Approval();
        targetContract = address(fixedContract);
    }

    function getApproveCalldata(address spender, uint256 amount) internal pure override returns (bytes memory) {
        if (amount == 100) {
            return abi.encodeWithSelector(FixedERC20Approval.approve.selector, spender, amount);
        } else if (amount == 50) {
            // Mitigation: use decreaseAllowance instead of approve
            return abi.encodeWithSelector(FixedERC20Approval.decreaseAllowance.selector, spender, 50);
        }
        return abi.encodeWithSelector(FixedERC20Approval.approve.selector, spender, amount);
    }

    function getTransferFromCalldata(address from, address to, uint256 amount) internal pure override returns (bytes memory) {
        return abi.encodeWithSelector(FixedERC20Approval.transferFrom.selector, from, to, amount);
    }

    function _fundAlice(address alice, uint256 amount) internal override {
        fixedContract.mint(alice, amount);
    }
}
