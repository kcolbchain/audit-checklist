// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/checks/ERC777ReentrancyCheck.sol";
import "../src/examples/VulnerableERC777Vault.sol";

/// @title ExampleERC777ReentrancyAudit — demonstrates ERC777ReentrancyCheck
///        against VulnerableERC777Vault. The check must flag the vault as
///        vulnerable.
/// @notice Run with: forge test --match-contract ExampleERC777ReentrancyAudit -vvv
contract ExampleERC777ReentrancyAudit is ERC777ReentrancyCheck {
    MockERC777Token token;
    VulnerableERC777Vault vault;

    function setUp() public {
        token = new MockERC777Token();
        vault = new VulnerableERC777Vault(address(token));
        targetContract = address(vault);
    }

    function getWithdrawCalldata() internal pure override returns (bytes memory) {
        return abi.encodeWithSignature("withdraw()");
    }

    function getERC777Token() internal view override returns (MockERC777Token) {
        return token;
    }

    function performDeposit(address depositor, uint256 amount) internal override {
        // VulnerableERC777Vault.deposit mints-then-credits for the fixture.
        // Real targets typically pull tokens — override there.
        vm.prank(depositor);
        vault.deposit(amount);
    }
}
