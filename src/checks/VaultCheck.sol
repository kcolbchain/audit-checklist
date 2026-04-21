// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "../ChecklistBase.sol";

interface IERC4626 {
    function asset() external view returns (address);
    function totalAssets() external view returns (uint256);
    function totalSupply() external view returns (uint256);
    function convertToShares(uint256 assets) external view returns (uint256);
    function convertToAssets(uint256 shares) external view returns (uint256);
    function previewDeposit(uint256 assets) external view returns (uint256);
    function previewMint(uint256 shares) external view returns (uint256);
    function previewWithdraw(uint256 assets) external view returns (uint256);
    function previewRedeem(uint256 shares) external view returns (uint256);
    function deposit(uint256 assets, address receiver) external returns (uint256 shares);
    function mint(uint256 shares, address receiver) external returns (uint256 assets);
    function withdraw(uint256 assets, address owner, address receiver) external returns (uint256 shares);
    function redeem(uint256 shares, address owner, address receiver) external returns (uint256 assets);
    function maxDeposit(address receiver) external view returns (uint256);
}

// Minimal IERC20 used by VaultCheck & ERC4626AdvancedCheck. Named `IERC20Minimal`
// so it does not collide with OpenZeppelin's `IERC20` when a test imports both
// this file and an OZ-based vault (e.g. `VulnerableERC4626.sol`) into the same
// compilation unit.
interface IERC20Minimal {
    function approve(address spender, uint256 amount) external returns (bool);
    function transfer(address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
    function decimals() external view returns (uint8);
}

/// @title VaultCheck -- ERC-4626 vault security audit checks
/// @notice Checks for: first depositor inflation attack, share price manipulation via donation,
///         rounding direction consistency, and preview function accuracy.
/// @author kcolbchain
abstract contract VaultCheck is ChecklistBase {
    IERC4626 internal vault;

    /// @dev Override to return the amount of underlying tokens to use as the test deposit (min = 1)
    function getSmallDepositAmount() internal view virtual returns (uint256) {
        return 1;
    }

    /// @dev Override to return a larger deposit amount for normal-path tests
    function getLargeDepositAmount() internal view virtual returns (uint256) {
        return 1000e18;
    }

    function setUp() public virtual {
        vault = IERC4626(targetContract);
    }

    // -------------------------------------------------------------------------
    // TEST 1: First depositor inflation attack
    // A malicious first depositor mints 1 share, then donates a large amount of
    // underlying to the vault. The share price inflates, making subsequent small
    // deposits result in 0 shares (effectively stealing the deposited tokens).
    // -------------------------------------------------------------------------
    function test_first_depositor_inflation_attack() public {
        address attacker = makeAddr("inflation_attacker");
        address victim   = makeAddr("inflation_victim");

        IERC20Minimal underlying = IERC20Minimal(vault.asset());
        uint8  dec        = underlying.decimals();
        uint256 smallDep  = getSmallDepositAmount();
        uint256 donation  = 10 ** (dec + 3); // 1000 tokens worth of underlying

        // Fund attacker and victim
        deal(address(underlying), attacker, smallDep + donation);
        deal(address(underlying), victim,   smallDep);

        // Step 1: Attacker deposits 1 wei to become the sole share holder
        vm.startPrank(attacker);
        underlying.approve(targetContract, smallDep + donation);
        uint256 attackerShares = vault.deposit(smallDep, attacker);
        vm.stopPrank();

        // Step 2: Attacker directly transfers (donates) a large amount to inflate share price
        vm.prank(attacker);
        underlying.transfer(targetContract, donation);

        // Step 3: Victim deposits the same small amount
        vm.startPrank(victim);
        underlying.approve(targetContract, smallDep);
        uint256 victimShares = vault.deposit(smallDep, victim);
        vm.stopPrank();

        if (victimShares == 0) {
            emit log("VULNERABILITY: First depositor inflation attack succeeded");
            emit log("Victim received 0 shares for a non-zero deposit -- tokens are lost");
            fail();
        }

        // Additional check: attacker should not redeem more than deposited + donated
        uint256 attackerRedeemable = vault.convertToAssets(attackerShares);
        if (attackerRedeemable > smallDep + donation) {
            emit log("VULNERABILITY: Attacker can redeem more assets than deposited + donated");
            fail();
        }
    }

    // -------------------------------------------------------------------------
    // TEST 2: Share price manipulation via donation
    // Verifies that a direct token transfer (donation) cannot be used to extract
    // value from other depositors.
    // -------------------------------------------------------------------------
    function test_share_price_manipulation_via_donation() public {
        address alice    = makeAddr("alice");
        address attacker = makeAddr("donate_attacker");

        IERC20Minimal underlying = IERC20Minimal(vault.asset());
        uint256 aliceDeposit    = getLargeDepositAmount();
        uint256 attackerDeposit = getLargeDepositAmount();
        uint256 donationAmount  = getLargeDepositAmount();

        deal(address(underlying), alice,    aliceDeposit);
        deal(address(underlying), attacker, attackerDeposit + donationAmount);

        // Alice deposits first
        vm.startPrank(alice);
        underlying.approve(targetContract, aliceDeposit);
        uint256 aliceShares = vault.deposit(aliceDeposit, alice);
        vm.stopPrank();

        // Attacker deposits, then donates to inflate share price
        vm.startPrank(attacker);
        underlying.approve(targetContract, attackerDeposit);
        uint256 attackerShares = vault.deposit(attackerDeposit, attacker);
        underlying.transfer(targetContract, donationAmount);
        vm.stopPrank();

        // Attacker redeems -- should not recover more than deposit + donation
        vm.prank(attacker);
        uint256 attackerReturned = vault.redeem(attackerShares, attacker, attacker);
        uint256 attackerInvested = attackerDeposit + donationAmount;

        if (attackerReturned > attackerInvested) {
            emit log("VULNERABILITY: Attacker extracted more than invested via donation");
            fail();
        }

        // Alice position should not have decreased below her deposit
        uint256 aliceRedeemable = vault.convertToAssets(aliceShares);
        if (aliceRedeemable < aliceDeposit) {
            emit log("WARNING: Alice's position was diluted by the donation attack");
            emit log_named_uint("Alice deposited", aliceDeposit);
            emit log_named_uint("Alice can redeem", aliceRedeemable);
        }
    }

    // -------------------------------------------------------------------------
    // TEST 3: Rounding direction consistency (ERC-4626 spec compliance)
    // EIP-4626 requires: deposit/mint round DOWN shares, withdraw/redeem round UP
    // shares -- always in favor of the vault.
    // -------------------------------------------------------------------------
    function test_rounding_deposit_shares_round_down() public {
        uint256 assets    = getSmallDepositAmount();
        uint256 preview   = vault.previewDeposit(assets);
        uint256 converted = vault.convertToShares(assets);
        assertTrue(
            preview <= converted,
            "previewDeposit must round down (vault-favoring) -- must not exceed convertToShares"
        );
    }

    function test_rounding_withdraw_shares_round_up() public {
        uint256 assets    = getSmallDepositAmount();
        uint256 preview   = vault.previewWithdraw(assets);
        uint256 converted = vault.convertToShares(assets);
        assertTrue(
            preview >= converted,
            "previewWithdraw must round up (vault-favoring) -- must not be less than convertToShares"
        );
    }

    // -------------------------------------------------------------------------
    // TEST 4: Preview function accuracy (EIP-4626 off-by-one tolerance)
    // preview* functions must be accurate to within 1 unit when no other
    // transactions occur between preview and execution.
    // -------------------------------------------------------------------------
    function test_preview_deposit_accuracy() public {
        address user = makeAddr("preview_user");
        IERC20Minimal underlying = IERC20Minimal(vault.asset());
        uint256 amount = getLargeDepositAmount();

        deal(address(underlying), user, amount);

        uint256 predicted = vault.previewDeposit(amount);

        vm.startPrank(user);
        underlying.approve(targetContract, amount);
        uint256 actual = vault.deposit(amount, user);
        vm.stopPrank();

        uint256 delta = predicted >= actual ? predicted - actual : actual - predicted;
        if (delta > 1) {
            emit log_named_uint("previewDeposit predicted", predicted);
            emit log_named_uint("deposit actual shares", actual);
            emit log_named_uint("delta", delta);
            emit log("VIOLATION: previewDeposit off by more than 1 -- EIP-4626 non-compliant");
            fail();
        }
    }

    function test_preview_redeem_accuracy() public {
        address user = makeAddr("redeem_user");
        IERC20Minimal underlying = IERC20Minimal(vault.asset());
        uint256 amount = getLargeDepositAmount();

        deal(address(underlying), user, amount);

        vm.startPrank(user);
        underlying.approve(targetContract, amount);
        uint256 shares = vault.deposit(amount, user);
        vm.stopPrank();

        uint256 predicted = vault.previewRedeem(shares);

        vm.prank(user);
        uint256 actual = vault.redeem(shares, user, user);

        uint256 delta = predicted >= actual ? predicted - actual : actual - predicted;
        if (delta > 1) {
            emit log_named_uint("previewRedeem predicted", predicted);
            emit log_named_uint("redeem actual assets", actual);
            emit log_named_uint("delta", delta);
            emit log("VIOLATION: previewRedeem off by more than 1 -- EIP-4626 non-compliant");
            fail();
        }
    }
}
