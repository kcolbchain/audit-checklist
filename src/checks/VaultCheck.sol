// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../ChecklistBase.sol";

/// @title VaultCheck — detect common ERC-4626 vault vulnerabilities
/// @notice Test suite for: (1) first-depositor inflation attack,
///     (2) share-price manipulation via donation, (3) rounding-direction
///     consistency, (4) preview-function accuracy.
abstract contract VaultCheck is ChecklistBase {

    // ── Virtual helpers ────────────────────────────────────────────────────

    function getVaultAddress() internal view virtual returns (address) {
        return targetContract;
    }

    // ── Test 1: First-depositor inflation attack ──────────────────────────

    /// @notice Detect first-depositor share-price inflation.
    function test_vault_first_depositor_inflation_attack() public virtual {
        // Fuzz test: if first depositor can mint disproportionate shares
        // by manipulating vault state before second depositor arrives,
        // the vault is vulnerable to first-depositor attack.
        // Override this test with a concrete implementation that:
        // 1. Deposits a small amount as first user
        // 2. Donates a large amount to inflate price
        // 3. Checks if second depositor receives fewer shares than expected
        revert("VaultCheck: implement test_vault_first_depositor_inflation_attack()");
    }

    // ── Test 2: Share-price manipulation via donation ─────────────────────

    /// @notice Detect share-price manipulation via donate-then-withdraw.
    function test_vault_share_price_donation_attack() public virtual {
        // Attacker deposits, then "donates" assets to inflate share price,
        // then withdraws more than deposited.
        revert("VaultCheck: implement test_vault_share_price_donation_attack()");
    }

    // ── Test 3: Rounding-direction consistency ────────────────────────────

    /// @notice Ensure previewDeposit / previewWithdraw are inverse-consistent.
    function test_vault_rounding_direction_consistency() public virtual {
        // previewDeposit(previewWithdraw(x)) must NOT give user back less than input
        revert("VaultCheck: implement test_vault_rounding_direction_consistency()");
    }

    // ── Test 4: Preview-function accuracy ────────────────────────────────

    /// @notice Check that preview functions do not revert unexpectedly.
    function test_vault_preview_functions_do_not_revert() public virtual {
        // previewDeposit, previewWithdraw, previewMint, previewRedeem
        // must not revert on valid inputs and must return reasonable values.
        revert("VaultCheck: implement test_vault_preview_functions_do_not_revert()");
    }
}
