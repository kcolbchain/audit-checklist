// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract Initializable {}

contract UUPSUpgradeable is Initializable {}

contract GoodUpgradeGap is UUPSUpgradeable {
    uint256 public existingValue;
    uint256 public newFeeBps;

    uint256[49] private __gap;
}
