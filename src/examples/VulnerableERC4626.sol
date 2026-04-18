// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/math/Math.sol";

/// @title VulnerableERC4626 — intentionally vulnerable ERC-4626 vault
/// @notice DO NOT USE IN PRODUCTION. This contract has deliberate vulnerabilities
///         to demonstrate the audit-checklist detection capabilities.
/// @author kcolbchain
///
/// VULNERABILITIES:
/// 1. First depositor inflation attack (no dead shares on creation)
/// 2. Donation amplification (direct transfers inflate share price)
/// 3. Rounding error in deposit (rounds UP shares, not DOWN as EIP-4626 requires)
/// 4. Preview functions inaccurate (off by more than 1)
contract VulnerableERC4626 is ERC20, ReentrancyGuard {
    using SafeERC20 for IERC20;

    IERC20 public immutable asset;
    uint256 public totalAssets;
    uint256 public constant FEE_BPS = 100; // 1% fee

    // BUG 1: No initial shares minted — first depositor gets exact 1:1 ratio
    // allowing inflation attack
    constructor(address _asset) ERC20("Vulnerable Vault Shares", "vVLT") {
        asset = ERC20(_asset);
    }

    function deposit(uint256 amount, address receiver) external nonReentrant returns (uint256 shares) {
        // BUG 3: Rounds UP instead of DOWN (EIP-4626 violation)
        // Should be: shares = _convertToShares(amount, Math.Rounding.Down);
        shares = (amount * totalSupply() + totalAssets - 1) / totalAssets; // BUG 3: rounds UP

        if (totalSupply() == 0) {
            shares = amount; // BUG 1: 1:1 mapping enables inflation attack
        }

        _mint(receiver, shares);
        totalAssets += amount;
        asset.safeTransferFrom(msg.sender, address(this), amount);
    }

    function withdraw(uint256 assets, address owner, address receiver) external nonReentrant returns (uint256 shares) {
        shares = _convertToShares(assets, /* rounds down */ false);
        uint256 maxShares = balanceOf(owner);
        require(shares <= maxShares, "withdraw exceeds balance");

        _burn(owner, shares);
        totalAssets -= assets;
        asset.safeTransfer(receiver, assets);
    }

    function redeem(uint256 shares, address owner, address receiver) external nonReentrant returns (uint256 assets) {
        assets = _convertToAssets(shares, /* rounds down */ false);
        require(balanceOf(owner) >= shares, "redeem exceeds balance");

        _burn(owner, shares);
        totalAssets -= assets;
        asset.safeTransfer(receiver, assets);
    }

    function previewDeposit(uint256 assets) external view returns (uint256) {
        // BUG 4: Intentionally off by a few units to fail accuracy test
        return _convertToShares(assets, /* rounds down */ false) + 3; // adds noise
    }

    function previewRedeem(uint256 shares) external view returns (uint256) {
        return _convertToAssets(shares, /* rounds down */ false);
    }

    function convertToShares(uint256 assets) external view returns (uint256) {
        return _convertToShares(assets, false);
    }

    function convertToAssets(uint256 shares) external view returns (uint256) {
        return _convertToAssets(shares, false);
    }

    function maxDeposit(address) external pure returns (uint256) {
        return type(uint256).max; // No deposit cap
    }

    // --- Internal helpers ---

    function _convertToShares(uint256 assets, bool) internal view returns (uint256) {
        if (totalSupply() == 0) return assets;
        return (assets * totalSupply()) / totalAssets;
    }

    function _convertToAssets(uint256 shares, bool) internal view returns (uint256) {
        if (totalSupply() == 0) return shares;
        return (shares * totalAssets) / totalSupply();
    }
}
