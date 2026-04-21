// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "../ChecklistBase.sol";

/// @title UpgradeCheck — verify proxy upgrade safety
/// @notice Checks for uninitialized proxies and storage slot collisions.
/// @author kcolbchain
abstract contract UpgradeCheck is ChecklistBase {
    /// @dev Override to return the proxy address
    function getProxyAddress() internal view virtual returns (address);

    /// @dev Override to return the implementation address
    function getImplementationAddress() internal view virtual returns (address);

    /// @dev EIP-1967 implementation slot
    bytes32 constant IMPL_SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

    /// @dev EIP-1967 admin slot
    bytes32 constant ADMIN_SLOT = 0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103;

    function test_implementation_slot_is_set() public {
        address proxy = getProxyAddress();
        bytes32 implSlotValue = vm.load(proxy, IMPL_SLOT);
        address storedImpl = address(uint160(uint256(implSlotValue)));

        assertTrue(storedImpl != address(0), unicode"VULNERABILITY: Implementation slot is zero — proxy not initialized");
        assertEq(storedImpl, getImplementationAddress(), "Implementation slot doesn't match expected");
    }

    function test_implementation_cannot_be_initialized_directly() public {
        address impl = getImplementationAddress();
        // Try calling initialize on the implementation directly — it should revert
        // (if it doesn't, anyone can take over the implementation)
        bytes memory initCall = abi.encodeWithSignature("initialize()");
        (bool success,) = impl.call(initCall);
        if (success) {
            emit log("VULNERABILITY: Implementation contract can be initialized directly");
            emit log("An attacker could call initialize() on the implementation and take control");
            fail();
        }
    }
}
