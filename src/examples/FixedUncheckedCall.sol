// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title FixedUncheckedCall — demonstrates proper .call() return value handling
/// @notice This contract properly checks the success boolean and reverts on failure.
contract FixedUncheckedCall {
    mapping(address => uint256) public balances;
    address public lastRecipient;
    bool public transferComplete;

    /// @dev FIXED: .call() return value is properly checked
    function withdraw(address payable to, uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient balance");
        balances[msg.sender] -= amount;

        // FIX: Check the success boolean and propagate failure
        (bool success,) = to.call{value: amount}("");
        require(success, "ETH transfer failed");

        transferComplete = true;
    }

    /// @dev FIXED: both success and result are checked
    function transferToken(address token, address to, uint256 amount) external {
        bytes memory data = abi.encodeWithSignature("transfer(address,uint256)", to, amount);

        // FIX: Check success and validate return data
        (bool success, bytes memory result) = token.call(data);
        require(success, "token call failed");

        // Check the ERC-20 return value (true for success)
        if (result.length > 0) {
            bool returned = abi.decode(result, (bool));
            require(returned, "token transfer returned false");
        }

        lastRecipient = to;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    receive() external payable {}
}
