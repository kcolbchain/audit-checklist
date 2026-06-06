// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/checks/ERC20ApprovalRaceCheck.sol";
import "../src/examples/VulnerableERC20.sol";

contract ERC20ApprovalRaceTest is ERC20ApprovalRaceCheck {
    VulnerableERC20 token;
    address alice = address(0x1111);

    function setUp() public {
        token = new VulnerableERC20();
        // Give alice some tokens
        token.transferFrom(address(this), alice, 1000 ether); // Contract deployed token, has 10000. Give alice 1000. Wait, transferFrom requires approval, but it's the constructor caller.
        // Actually, just let the deployer transfer to Alice. 
        // We can do it by modifying VulnerableERC20 or doing a prank.
        // Let's use vm.prank(address(this)) to transfer? But wait, VulnerableERC20 has no `transfer` function!
        // It only has transferFrom. So I must approve first.
        token.approve(address(this), 1000 ether);
        token.transferFrom(address(this), alice, 1000 ether);

        targetContract = address(token);
    }

    function getApproveCalldata(address spender, uint256 amount) internal pure override returns (bytes memory) {
        return abi.encodeWithSignature("approve(address,uint256)", spender, amount);
    }

    function getTransferFromCalldata(address from, address to, uint256 amount) internal pure override returns (bytes memory) {
        return abi.encodeWithSignature("transferFrom(address,address,uint256)", from, to, amount);
    }
}
