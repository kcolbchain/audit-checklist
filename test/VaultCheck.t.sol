// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/checks/VaultCheck.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

/// @title SimpleERC4626 — minimal ERC-4626 vault for testing
/// @notice This is a REFERENCE IMPLEMENTATION for testing VaultCheck.
///         Not production-ready.
contract SimpleERC4626 is ERC20 {
    using Math for uint256;

    ERC20 public immutable asset;
    uint256 public totalAssets;

    mapping(address => uint256) internal _shares;

    constructor(ERC20 _asset) { asset = _asset; }

    function deposit(uint256 assets, address receiver) external returns (uint256 shares) {
        uint256 supply = totalSupply();
        shares = supply == 0 ? assets : assets * supply / totalAssets;
        _mint(receiver, shares);
        _shares[receiver] += shares;
        totalAssets += assets;
        asset.transferFrom(msg.sender, address(this), assets);
    }

    function withdraw(uint256 assets, address receiver, address owner) external returns (uint256 shares) {
        uint256 supply = totalSupply();
        shares = supply == 0 ? assets : assets * supply / totalAssets;
        asset.transfer(receiver, assets); // BUG: reentrancy before state update
        _burn(owner, shares);
        _shares[owner] -= shares;
        totalAssets -= assets;
    }

    function mint(uint256 shares, address receiver) external returns (uint256 assets) {
        uint256 supply = totalSupply();
        assets = supply == 0 ? shares : shares * totalAssets / supply;
        _mint(receiver, shares);
        _shares[receiver] += shares;
        totalAssets += assets;
        asset.transferFrom(msg.sender, address(this), assets);
    }

    function redeem(uint256 shares, address receiver, address owner) external returns (uint256 assets) {
        uint256 supply = totalSupply();
        assets = supply == 0 ? shares : shares * totalAssets / supply;
        _burn(owner, shares);
        _shares[owner] -= shares;
        totalAssets -= assets;
        asset.transfer(receiver, assets);
    }

    function assetToken() external view returns (address) { return address(asset); }
    function totalAssets() external view returns (uint256) { return totalAssets; }
    function maxDeposit(address) external pure returns (uint256) { return type(uint256).max; }
    function maxWithdraw(address owner) external view returns (uint256) {
        return _shares[owner] * totalAssets / totalSupply();
    }
    function maxRedeem(address owner) external view returns (uint256) { return _shares[owner]; }
    function maxMint(address) external pure returns (uint256) { return type(uint256).max; }

    function convertToShares(uint256 a) external view returns (uint256) {
        uint256 s = totalSupply();
        return s == 0 ? a : a * s / totalAssets;
    }
    function convertToAssets(uint256 s) external view returns (uint256) {
        uint256 supply = totalSupply();
        return supply == 0 ? s : s * totalAssets / supply;
    }
    function previewDeposit(uint256 a) external view returns (uint256) {
        uint256 s = totalSupply();
        return s == 0 ? a : a * s / totalAssets;
    }
    function previewWithdraw(uint256 a) external view returns (uint256) {
        uint256 s = totalSupply();
        return s == 0 ? a : a * s / totalAssets;
    }
    function previewMint(uint256 s) external view returns (uint256) {
        uint256 supply = totalSupply();
        return supply == 0 ? s : s * totalAssets / supply;
    }
    function previewRedeem(uint256 s) external view returns (uint256) {
        uint256 supply = totalSupply();
        return supply == 0 ? s : s * totalAssets / supply;
    }

    function balanceOf(address a) public view override returns (uint256) { return _shares[a]; }
    function _update(address f, address t, uint256 v) internal override { super._update(f, t, v); }
}

/// @title VaultCheckTests — run VaultCheck against SimpleERC4626
contract VaultCheckTest is Test, VaultCheck {
    SimpleERC4626 public vault;
    ERC20 public underlying;

    function setUp() public {
        underlying = new ERC20("Test Asset", "TSTA");
        vault = new SimpleERC4626(underlying);
        targetContract = address(vault);
    }

    function getVaultAddress() internal view override returns (address) {
        return address(vault);
    }

    function test_vault_first_depositor_inflation_attack() public override {
        address alice = makeAddr("alice");
        address bob = makeAddr("bob");
        uint256 seed = 1e18;
        uint256 donation = 1000e18;

        // Seed: alice is first depositor
        deal(address(underlying), alice, seed * 10, false);
        vm.prank(alice);
        underlying.approve(address(vault), type(uint256).max);
        vm.prank(alice);
        vault.deposit(seed, alice);

        // Alice donates to inflate share price
        deal(address(underlying), alice, donation, false);
        vm.prank(alice);
        underlying.transfer(address(vault), donation);

        // Bob deposits same seed amount
        deal(address(underlying), bob, seed * 10, false);
        vm.prank(bob);
        underlying.approve(address(vault), type(uint256).max);
        uint256 bobShares = vault.previewDeposit(seed);

        if (bobShares == 0) {
            emit log("VULNERABILITY: First-depositor inflation - Bob got 0 shares");
            fail();
        }
    }

    function test_vault_share_price_donation_attack() public override {
        address attacker = makeAddr("attacker");
        uint256 depositAmt = 1e18;
        uint256 donation = 1000e18;

        deal(address(underlying), attacker, depositAmt * 2 + donation, false);
        vm.prank(attacker);
        underlying.approve(address(vault), type(uint256).max);
        vm.prank(attacker);
        uint256 shares = vault.deposit(depositAmt, attacker);
        uint256 balanceBefore = underlying.balanceOf(attacker);

        // Donate to inflate price
        vm.prank(attacker);
        underlying.transfer(address(vault), donation);

        // Withdraw
        vm.prank(attacker);
        vault.redeem(shares, attacker, attacker);

        uint256 balanceAfter = underlying.balanceOf(attacker);
        int256 profit = int256(balanceAfter) - int256(balanceBefore) - int256(depositAmt);

        if (profit > 0) {
            emit log("VULNERABILITY: Donation attack - attacker profited");
            emit log_named_int("profit", profit);
            fail();
        }
    }

    function test_vault_rounding_direction_consistency() public override {
        address user = makeAddr("user");
        uint256 seed = 100e18;

        // Seed vault
        deal(address(underlying), makeAddr("seed"), seed * 10, false);
        address seedAddr = makeAddr("seed");
        deal(address(underlying), seedAddr, seed * 10, false);
        vm.prank(seedAddr);
        underlying.approve(address(vault), type(uint256).max);
        vm.prank(seedAddr);
        vault.deposit(seed, seedAddr);

        uint256 withdrawAmt = 1e18;
        uint256 sharesOut = vault.previewWithdraw(withdrawAmt);
        uint256 assetsBack = vault.previewDeposit(sharesOut);

        if (assetsBack < withdrawAmt) {
            emit log("VULNERABILITY: Rounding inconsistency");
            fail();
        }
    }

    function test_vault_preview_functions_do_not_revert() public override {
        // Seed vault
        address seedAddr = makeAddr("seed");
        deal(address(underlying), seedAddr, 1000e18, false);
        vm.prank(seedAddr);
        underlying.approve(address(vault), type(uint256).max);
        vm.prank(seedAddr);
        vault.deposit(100e18, seedAddr);

        uint256[] memory amounts = new uint256[](3);
        amounts[0] = 1;
        amounts[1] = 1e18;
        amounts[2] = 100e18;

        for (uint256 i = 0; i < amounts.length; i++) {
            uint256 amt = amounts[i];
            (bool pd, ) = address(vault).staticcall(abi.encodeCall(vault.previewDeposit, amt));
            if (!pd) { emit log("previewDeposit reverted"); fail(); }
            (bool pw, ) = address(vault).staticcall(abi.encodeCall(vault.previewWithdraw, amt));
            if (!pw) { emit log("previewWithdraw reverted"); fail(); }
            (bool pm, ) = address(vault).staticcall(abi.encodeCall(vault.previewMint, amt));
            if (!pm) { emit log("previewMint reverted"); fail(); }
            (bool pr, ) = address(vault).staticcall(abi.encodeCall(vault.previewRedeem, amt));
            if (!pr) { emit log("previewRedeem reverted"); fail(); }
        }
    }
}
