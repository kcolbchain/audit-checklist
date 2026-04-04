// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "../ChecklistBase.sol";
import {IERC4626} from "@openzeppelin/contracts/interfaces/IERC4626.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

/// @title VaultCheck — ERC-4626 vault security audit checks
/// @notice Tests for first-depositor inflation attack, share price manipulation
///         via donation, rounding direction consistency, and preview function accuracy.
/// @author kas-storksoft
abstract contract VaultCheck is ChecklistBase {
    /// @dev Override to return the ERC-4626 vault address
    function getVault() internal view virtual returns (address);

    /// @dev Override to return the underlying asset address
    function getAsset() internal view virtual returns (address);

    /// @dev Override to provide an address with sufficient asset balance for testing
    function getAssetWhale() internal view virtual returns (address);

    /// @dev Amount of assets to use in standard tests (override for different decimals)
    function getTestAmount() internal view virtual returns (uint256) {
        return 1e18;
    }

    /// @dev Large amount for donation attack testing
    function getDonationAmount() internal view virtual returns (uint256) {
        return 1000e18;
    }

    // ═══════════════════════════════════════════════════════════════
    //                  FIRST DEPOSITOR INFLATION ATTACK
    // ═══════════════════════════════════════════════════════════════

    /// @notice Test that the vault is resistant to the first-depositor inflation attack.
    /// @dev Attack vector: Attacker deposits 1 wei, donates large amount of assets
    ///      directly to vault, causing subsequent depositors to receive 0 shares
    ///      due to rounding, effectively stealing their deposits.
    function test_first_depositor_inflation_attack() public {
        IERC4626 vault = IERC4626(getVault());
        IERC20 asset = IERC20(getAsset());
        address whale = getAssetWhale();
        uint256 donationAmount = getDonationAmount();
        uint256 victimDeposit = getTestAmount();

        address attacker = makeAddr("attacker");
        address victim = makeAddr("victim");

        // Fund attacker and victim
        vm.startPrank(whale);
        asset.transfer(attacker, donationAmount + 1);
        asset.transfer(victim, victimDeposit);
        vm.stopPrank();

        // Step 1: Attacker deposits 1 wei of assets
        vm.startPrank(attacker);
        asset.approve(address(vault), type(uint256).max);
        vault.deposit(1, attacker);
        vm.stopPrank();

        // Step 2: Attacker donates large amount directly to vault
        vm.prank(whale);
        asset.transfer(address(vault), donationAmount);

        // Step 3: Victim deposits — should still receive > 0 shares
        vm.startPrank(victim);
        asset.approve(address(vault), type(uint256).max);
        uint256 victimShares = vault.deposit(victimDeposit, victim);
        vm.stopPrank();

        if (victimShares == 0) {
            emit log("VULNERABILITY: First depositor inflation attack possible");
            emit log_named_uint("Donation amount", donationAmount);
            emit log_named_uint("Victim deposit", victimDeposit);
            emit log_named_uint("Victim shares received", victimShares);
            fail();
        }

        // Also check that victim can redeem a non-trivial portion
        uint256 redeemable = vault.previewRedeem(victimShares);
        uint256 loss = victimDeposit > redeemable ? victimDeposit - redeemable : 0;
        uint256 lossPercent = (loss * 100) / victimDeposit;

        if (lossPercent > 1) {
            emit log("VULNERABILITY: Excessive value loss from inflation attack");
            emit log_named_uint("Loss percent", lossPercent);
            emit log_named_uint("Deposited", victimDeposit);
            emit log_named_uint("Redeemable", redeemable);
            fail();
        }
    }

    // ═══════════════════════════════════════════════════════════════
    //                  SHARE PRICE MANIPULATION VIA DONATION
    // ═══════════════════════════════════════════════════════════════

    /// @notice Test that direct asset transfers don't create exploitable share price jumps
    function test_donation_share_price_manipulation() public {
        IERC4626 vault = IERC4626(getVault());
        IERC20 asset = IERC20(getAsset());
        address whale = getAssetWhale();
        uint256 depositAmount = getTestAmount();
        uint256 donationAmount = getDonationAmount();

        address depositor = makeAddr("depositor");

        // Setup: depositor makes initial deposit
        vm.prank(whale);
        asset.transfer(depositor, depositAmount);

        vm.startPrank(depositor);
        asset.approve(address(vault), type(uint256).max);
        uint256 sharesBefore = vault.deposit(depositAmount, depositor);
        vm.stopPrank();

        uint256 assetsBefore = vault.previewRedeem(sharesBefore);

        // Donate directly to vault
        vm.prank(whale);
        asset.transfer(address(vault), donationAmount);

        uint256 assetsAfter = vault.previewRedeem(sharesBefore);

        // Share price should either:
        // a) Not change (vault ignores donations), or
        // b) Increase proportionally (vault socializes gains)
        // It should NOT be possible for the donation to be extracted by a single user
        // if there are other depositors

        emit log_named_uint("Assets before donation", assetsBefore);
        emit log_named_uint("Assets after donation", assetsAfter);
        emit log_named_uint("Donation amount", donationAmount);

        // The key invariant: total assets should account for all deposits + donations
        uint256 totalAssets = vault.totalAssets();
        uint256 vaultBalance = asset.balanceOf(address(vault));

        if (totalAssets < vaultBalance) {
            emit log("WARNING: totalAssets() < actual balance — donations may be unaccounted");
            emit log_named_uint("totalAssets()", totalAssets);
            emit log_named_uint("actual balance", vaultBalance);
        }
    }

    // ═══════════════════════════════════════════════════════════════
    //                  ROUNDING DIRECTION CONSISTENCY
    // ═══════════════════════════════════════════════════════════════

    /// @notice Verify rounding favors the vault (protects existing depositors)
    /// @dev Per EIP-4626: deposit/mint should round UP shares cost (against depositor),
    ///      withdraw/redeem should round DOWN assets returned (against withdrawer)
    function test_rounding_direction_favors_vault() public {
        IERC4626 vault = IERC4626(getVault());
        IERC20 asset = IERC20(getAsset());
        address whale = getAssetWhale();

        address user = makeAddr("rounding_tester");
        uint256 amount = getTestAmount();

        // Fund and deposit
        vm.prank(whale);
        asset.transfer(user, amount * 10);

        vm.startPrank(user);
        asset.approve(address(vault), type(uint256).max);
        vault.deposit(amount, user);

        // Test: convertToShares should round DOWN (fewer shares per asset = vault wins)
        uint256 sharesForAssets = vault.convertToShares(amount);
        uint256 assetsForShares = vault.convertToAssets(sharesForAssets);

        // roundtrip: assets -> shares -> assets should not increase
        if (assetsForShares > amount) {
            emit log("VULNERABILITY: Rounding allows free value extraction");
            emit log_named_uint("Original assets", amount);
            emit log_named_uint("After roundtrip", assetsForShares);
            fail();
        }

        // Test small amounts where rounding matters most
        for (uint256 i = 1; i <= 10; i++) {
            uint256 smallShares = vault.convertToShares(i);
            uint256 smallAssets = vault.convertToAssets(smallShares);
            if (smallAssets > i) {
                emit log("VULNERABILITY: Small amount rounding extracts value");
                emit log_named_uint("Input assets", i);
                emit log_named_uint("Output assets", smallAssets);
                fail();
            }
        }

        // Test: previewWithdraw should round UP shares needed
        uint256 sharesToWithdraw = vault.previewWithdraw(amount / 2);
        uint256 actualAssets = vault.previewRedeem(sharesToWithdraw);
        
        // Redeeming the shares from previewWithdraw should give >= requested amount
        if (actualAssets < amount / 2) {
            emit log("WARNING: previewWithdraw may underestimate shares needed");
            emit log_named_uint("Requested assets", amount / 2);
            emit log_named_uint("Shares quoted", sharesToWithdraw);
            emit log_named_uint("Actual assets from redeem", actualAssets);
        }

        vm.stopPrank();
    }

    // ═══════════════════════════════════════════════════════════════
    //                  PREVIEW FUNCTION ACCURACY
    // ═══════════════════════════════════════════════════════════════

    /// @notice Test that preview functions match actual execution results
    /// @dev EIP-4626 requires preview functions to return values that match
    ///      or are more conservative than actual operations
    function test_preview_deposit_accuracy() public {
        IERC4626 vault = IERC4626(getVault());
        IERC20 asset = IERC20(getAsset());
        address whale = getAssetWhale();
        uint256 amount = getTestAmount();

        address user = makeAddr("preview_tester");

        vm.prank(whale);
        asset.transfer(user, amount * 3);

        vm.startPrank(user);
        asset.approve(address(vault), type(uint256).max);

        // Test previewDeposit accuracy
        uint256 previewShares = vault.previewDeposit(amount);
        uint256 actualShares = vault.deposit(amount, user);

        assertEq(
            previewShares,
            actualShares,
            "previewDeposit must match actual deposit shares"
        );

        // Test previewMint accuracy
        uint256 sharesToMint = actualShares; // Mint the same number of shares
        uint256 previewAssets = vault.previewMint(sharesToMint);
        uint256 actualAssets = vault.mint(sharesToMint, user);

        assertEq(
            previewAssets,
            actualAssets,
            "previewMint must match actual mint cost"
        );

        vm.stopPrank();
    }

    /// @notice Test previewWithdraw and previewRedeem accuracy
    function test_preview_withdraw_redeem_accuracy() public {
        IERC4626 vault = IERC4626(getVault());
        IERC20 asset = IERC20(getAsset());
        address whale = getAssetWhale();
        uint256 amount = getTestAmount();

        address user = makeAddr("withdraw_tester");

        // Setup: deposit first
        vm.prank(whale);
        asset.transfer(user, amount * 2);

        vm.startPrank(user);
        asset.approve(address(vault), type(uint256).max);
        uint256 shares = vault.deposit(amount, user);

        // Test previewRedeem accuracy
        uint256 previewRedeemAssets = vault.previewRedeem(shares / 2);
        uint256 actualRedeemAssets = vault.redeem(shares / 2, user, user);

        assertEq(
            previewRedeemAssets,
            actualRedeemAssets,
            "previewRedeem must match actual redeem assets"
        );

        // Test previewWithdraw accuracy
        uint256 remainingAssets = vault.previewRedeem(vault.balanceOf(user));
        if (remainingAssets > 0) {
            uint256 withdrawAmount = remainingAssets / 2;
            uint256 previewWithdrawShares = vault.previewWithdraw(withdrawAmount);
            uint256 actualWithdrawShares = vault.withdraw(withdrawAmount, user, user);

            assertEq(
                previewWithdrawShares,
                actualWithdrawShares,
                "previewWithdraw must match actual withdraw shares"
            );
        }

        vm.stopPrank();
    }

    // ═══════════════════════════════════════════════════════════════
    //                  MAX FUNCTIONS CONSISTENCY
    // ═══════════════════════════════════════════════════════════════

    /// @notice Verify maxDeposit/maxMint/maxWithdraw/maxRedeem are consistent
    function test_max_functions_consistency() public {
        IERC4626 vault = IERC4626(getVault());
        IERC20 asset = IERC20(getAsset());
        address whale = getAssetWhale();
        uint256 amount = getTestAmount();

        address user = makeAddr("max_tester");

        // Deposit some assets first
        vm.prank(whale);
        asset.transfer(user, amount);

        vm.startPrank(user);
        asset.approve(address(vault), type(uint256).max);
        vault.deposit(amount, user);

        // maxWithdraw should be <= balance converted to assets
        uint256 maxW = vault.maxWithdraw(user);
        uint256 balanceAsAssets = vault.convertToAssets(vault.balanceOf(user));
        assertTrue(
            maxW <= balanceAsAssets,
            "maxWithdraw should not exceed balance in assets"
        );

        // maxRedeem should be <= share balance
        uint256 maxR = vault.maxRedeem(user);
        assertTrue(
            maxR <= vault.balanceOf(user),
            "maxRedeem should not exceed share balance"
        );

        vm.stopPrank();
    }
}
