// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title VulnerableUncheckedCall — demonstrates unchecked .call() return value
/// @notice This contract silently discards the success boolean from low-level calls,
///         which can lead to silent failures where the caller thinks an operation
///         succeeded but it actually failed.
contract VulnerableUncheckedCall {
    mapping(address => uint256) public balances;
    address public lastRecipient;
    bool public transferComplete;

    /// @dev VULNERABILITY: .call() return value is discarded
    function withdraw(address payable to, uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient balance");
        balances[msg.sender] -= amount;

        // BUG: return value of .call() is not checked!
        // If this call fails (e.g., recipient reverts in receive()),
        // the balance is already decremented but the ETH was never sent.
        to.call{value: amount}("");

        transferComplete = true;
    }

    /// @dev VULNERABILITY: another pattern — result assigned but never checked
    function transferToken(address token, address to, uint256 amount) external {
        bytes memory data = abi.encodeWithSignature("transfer(address,uint256)", to, amount);
        bytes memory result = new bytes(0);

        // BUG: success boolean is ignored, only data is captured
        (, result) = token.call(data);

        lastRecipient = to;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    receive() external payable {}
}
