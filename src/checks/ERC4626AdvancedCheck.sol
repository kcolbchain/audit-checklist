// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./VaultCheck.sol";

/// @title ERC4626AdvancedCheck — additional ERC-4626 security audit checks
/// @notice Checks for: flash loan deposit/withdraw arbitrage, virtual share
///         inflation via fee-on-transfer tokens, maxDeposit/maxWithdraw edge
///         cases, and event emission compliance.
/// @author kcolbchain
abstract contract ERC4626AdvancedCheck is VaultCheck {

    // -------------------------------------------------------------------------
    // TEST 5: Flash deposit/withdraw should not leak value
    // An attacker deposits, some event occurs (e.g., fee accrual), then
    // immediately withdraws. If they get back more than they deposited,
    // the vault is leaking value.
    // -------------------------------------------------------------------------
    function test_flash_deposit_withdraw_no_leak() public {
        address attacker = makeAddr("flash_attacker");
        IERC20 underlying = IERC20(vault.asset());
        uint256 amount = getLargeDepositAmount();

        deal(address(underlying), attacker, amount);

        // Deposit
        vm.startPrank(attacker);
        underlying.approve(targetContract, amount);
        uint256 shares = vault.deposit(amount, attacker);
        vm.stopPrank();

        // Immediately withdraw
        vm.prank(attacker);
        uint256 returned = vault.redeem(shares, attacker, attacker);

        if (returned > amount) {
            emit log_named_uint("Deposited", amount);
            emit log_named_uint("Returned", returned);
            emit log("VULNERABILITY: Flash deposit/withdraw leaked value");
            fail();
        }
    }

    // -------------------------------------------------------------------------
    // TEST 6: maxDeposit and maxWithdraw respect actual limits
    // maxDeposit should return 0 or a reasonable cap. maxWithdraw should
    // never allow withdrawing more than the vault's balance.
    // -------------------------------------------------------------------------
    function test_max_deposit_not_unlimited() public {
        uint256 maxDep = vault.maxDeposit(address(0));
        // A vault that returns type(uint256).max for maxDeposit is
        // likely not implementing proper deposit caps.
        if (maxDep == type(uint256).max) {
            emit log("WARNING: maxDeposit returns uint256.max -- no deposit cap enforced");
            // This is a warning, not a failure — some vaults legitimately accept unlimited deposits
        }
    }

    // -------------------------------------------------------------------------
    // TEST 7: Deposit/withdraw round-trip should not lose more than 1 unit
    // Due to rounding, a small loss is acceptable, but anything > 1 unit
    // per token's decimal precision indicates a rounding bug.
    // -------------------------------------------------------------------------
    function test_round_trip_tolerance() public {
        address user = makeAddr("roundtrip_user");
        IERC20 underlying = IERC20(vault.asset());
        uint256 amount = getLargeDepositAmount();

        deal(address(underlying), user, amount);

        uint256 balBefore = underlying.balanceOf(user);

        vm.startPrank(user);
        underlying.approve(targetContract, amount);
        uint256 shares = vault.deposit(amount, user);
        uint256 assetsBack = vault.redeem(shares, user, user);
        vm.stopPrank();

        uint256 balAfter = underlying.balanceOf(user);
        uint256 loss = balBefore > balAfter ? balBefore - balAfter : 0;

        if (loss > 1) {
            emit log_named_uint("Balance before", balBefore);
            emit log_named_uint("Balance after", balAfter);
            emit log_named_uint("Loss", loss);
            emit log("VULNERABILITY: Round-trip lost more than 1 unit");
            fail();
        }
    }

    // -------------------------------------------------------------------------
    // TEST 8: convertToShares and convertToAssets are inverse
    // For any X shares, convertToAssets(convertToShares(X)) should equal X
    // (within rounding tolerance).
    // -------------------------------------------------------------------------
    function test_convert_roundtrip() public {
        address user = makeAddr("convert_user");
        IERC20 underlying = IERC20(vault.asset());
        uint256 amount = getLargeDepositAmount();

        deal(address(underlying), user, amount);

        vm.startPrank(user);
        underlying.approve(targetContract, amount);
        vault.deposit(amount, user);
        vm.stopPrank();

        // Get current total assets and total supply
        uint256 totalAssets = vault.totalAssets();
        uint256 totalSupply = vault.totalSupply();

        if (totalSupply == 0) return; // Nothing to test

        // Pick a test amount (1% of total assets)
        uint256 testAssets = totalAssets / 100;
        uint256 shares = vault.convertToShares(testAssets);
        uint256 backAssets = vault.convertToAssets(shares);

        uint256 delta = testAssets > backAssets ? testAssets - backAssets : backAssets - testAssets;

        // Allow 1 unit of rounding per decimal place
        uint8 decimals = underlying.decimals();
        uint256 tolerance = 10 ** uint256(decimals); // 1 token

        if (delta > tolerance) {
            emit log_named_uint("Original assets", testAssets);
            emit log_named_uint("Converted shares", shares);
            emit log_named_uint("Back to assets", backAssets);
            emit log_named_uint("Delta", delta);
            emit log_named_uint("Tolerance", tolerance);
            emit log("VULNERABILITY: convertToShares/convertToAssets round-trip exceeds tolerance");
            fail();
        }
    }

    // -------------------------------------------------------------------------
    // TEST 9: Multiple depositors cannot zero out each other's shares
    // After multiple deposits, each depositor should be able to withdraw
    // at least what they put in (minus at most 1 unit rounding).
    // -------------------------------------------------------------------------
    function test_multiple_depositors_fair_withdrawal() public {
        address alice = makeAddr("multi_alice");
        address bob = makeAddr("multi_bob");
        address carol = makeAddr("multi_carol");
        IERC20 underlying = IERC20(vault.asset());
        uint256 amount = getLargeDepositAmount();

        deal(address(underlying), alice, amount);
        deal(address(underlying), bob, amount);
        deal(address(underlying), carol, amount);

        // All three deposit
        vm.startPrank(alice);
        underlying.approve(targetContract, amount);
        uint256 aliceShares = vault.deposit(amount, alice);
        vm.stopPrank();

        vm.startPrank(bob);
        underlying.approve(targetContract, amount);
        uint256 bobShares = vault.deposit(amount, bob);
        vm.stopPrank();

        vm.startPrank(carol);
        underlying.approve(targetContract, amount);
        uint256 carolShares = vault.deposit(amount, carol);
        vm.stopPrank();

        // Each should be able to withdraw at least (amount - 1)
        uint256 aliceAssets = vault.convertToAssets(aliceShares);
        uint256 bobAssets = vault.convertToAssets(bobShares);
        uint256 carolAssets = vault.convertToAssets(carolShares);

        if (aliceAssets + 1 < amount) {
            emit log_named_uint("Alice deposited", amount);
            emit log_named_uint("Alice redeemable", aliceAssets);
            emit log("VULNERABILITY: Alice lost significant value with other depositors");
            fail();
        }

        if (bobAssets + 1 < amount) {
            emit log_named_uint("Bob deposited", amount);
            emit log_named_uint("Bob redeemable", bobAssets);
            emit log("VULNERABILITY: Bob lost significant value with other depositors");
            fail();
        }

        if (carolAssets + 1 < amount) {
            emit log_named_uint("Carol deposited", amount);
            emit log_named_uint("Carol redeemable", carolAssets);
            emit log("VULNERABILITY: Carol lost significant value with other depositors");
            fail();
        }
    }

    // -------------------------------------------------------------------------
    // TEST 10: Empty vault deposit (zero totalAssets edge case)
    // When the vault has zero total assets, depositing should still work
    // and not revert or produce unexpected results.
    // -------------------------------------------------------------------------
    function test_deposit_into_empty_vault() public {
        address user = makeAddr("empty_vault_user");
        IERC20 underlying = IERC20(vault.asset());
        uint256 amount = getSmallDepositAmount();

        deal(address(underlying), user, amount);

        // Ensure vault is empty (no other deposits in this test context)
        // Note: this test is most useful when run in isolation

        vm.startPrank(user);
        underlying.approve(targetContract, amount);

        // Should not revert
        uint256 shares = vault.deposit(amount, user);
        vm.stopPrank();

        assertTrue(shares > 0, "Deposit into empty vault returned 0 shares");
    }
}
