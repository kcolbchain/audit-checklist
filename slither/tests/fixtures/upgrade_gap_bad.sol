// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract Initializable {}

contract UUPSUpgradeable is Initializable {}

contract BadUpgradeGap is UUPSUpgradeable {
    uint256 public existingValue;
    uint256[50] private __gap;

    uint256 public newFeeBps;
}
