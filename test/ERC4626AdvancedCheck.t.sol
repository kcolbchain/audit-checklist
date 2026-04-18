// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/checks/ERC4626AdvancedCheck.sol";
import "../src/examples/VulnerableERC4626.sol";

/// @title TestERC4626AdvancedCheck — runs advanced ERC-4626 checks against VulnerableERC4626
contract TestERC4626AdvancedCheck is ERC4626AdvancedCheck {
    VulnerableERC4626 public vaultContract;
    MockERC20 public underlying;

    function setUp() public override {
        underlying = new MockERC20("Mock USDC", "USDC", 6);
        vaultContract = new VulnerableERC4626(address(underlying));
        targetContract = address(vaultContract);
        super.setUp();
    }

    function getSmallDepositAmount() internal pure override returns (uint256) {
        return 1e6; // 1 USDC
    }

    function getLargeDepositAmount() internal pure override returns (uint256) {
        return 1000e6; // 1000 USDC
    }

    // --- Confirm that each vulnerability check CATCHES the bug ---

    function test_detects_inflation_attack() public {
        // Should FAIL because VulnerableERC4626 has no dead shares
        vm.expectRevert();
        this.test_first_depositor_inflation_attack();
    }

    function test_detects_preview_inaccuracy() public {
        // Should FAIL because previewDeposit adds +3 noise
        vm.expectRevert();
        this.test_preview_deposit_accuracy();
    }

    function test_detects_rounding_violation() public {
        // Should FAIL because deposit rounds UP instead of DOWN
        vm.expectRevert();
        this.test_rounding_deposit_shares_round_down();
    }

    function test_detects_donation_manipulation() public {
        // Should FAIL because direct transfers inflate share price
        vm.expectRevert();
        this.test_share_price_manipulation_via_donation();
    }

    function test_detects_round_trip_loss() public {
        // Should FAIL because rounding errors accumulate
        vm.expectRevert();
        this.test_round_trip_tolerance();
    }

    // --- Positive test: flash deposit/withdraw should not leak on this contract ---
    function test_flash_no_leak_passes() public {
        // This should pass because the vault doesn't leak on simple round-trips
        // (the vulnerability is in rounding, not in flash mechanics)
        this.test_flash_deposit_withdraw_no_leak();
    }
}

/// @dev Simple ERC20 for testing
contract MockERC20 {
    string public name;
    string public symbol;
    uint8 public decimals;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    constructor(string memory _name, string memory _symbol, uint8 _decimals) {
        name = _name;
        symbol = _symbol;
        decimals = _decimals;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        require(balanceOf[msg.sender] >= amount, "insufficient balance");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        require(allowance[from][msg.sender] >= amount, "insufficient allowance");
        require(balanceOf[from] >= amount, "insufficient balance");
        allowance[from][msg.sender] -= amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}
